"""Phase D selection: build the wide single-bug injection job list (train-only).

NO LEAKAGE:
- reads ONLY Train_Labels.csv (label CSV) + Source/*.sol pragmas; asserts it never
  opens DIVE/Val/Test label CSVs.
- cross-split dedup guard: holdout = {all Source IDs} - {train IDs} (derived without
  reading any label CSV); exclude any base whose normalized-source hash matches a holdout.

Output: work/cache/injection_jobs.json = {targets:{...}, jobs:[{cid,target,bug_type,family,labels}]}
Disjoint: each base assigned to at most one class.
"""
import glob
import hashlib
import json
import os
import re
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "work", "SolidiFI"))
import version_utils  # noqa: E402

DATASET = os.path.join(ROOT, "Dataset")
SPLITS = os.path.join(DATASET, "splits")
SOURCE = os.path.join(DATASET, "Source")
CACHE = os.path.join(ROOT, "work", "cache")
DENY = {"DIVE_Labels.csv", "Val_Labels.csv", "Test_Labels.csv"}

LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]
ALL_TARGETS = {
    "Front Running": "TOD",
    "Bad Randomness": "Bad-Randomness",
    "DoS": "DoS",
    "Reentrancy": "Re-entrancy",
    "Access Control": "tx.origin",
    "Arithmetic": "Overflow-Underflow",
    "Unchecked Return Values": "Unchecked-Send",
    "Time manipulation": "Timestamp-Dependency",
}
# CLASSES env (comma-separated) selects which classes to target; default = the 3 minority.
_sel = os.environ.get("CLASSES", "Front Running,Bad Randomness,DoS")
TARGETS = {c.strip(): ALL_TARGETS[c.strip()] for c in _sel.split(",")}
PER_CLASS_TARGET = int(os.environ.get("TARGET", "1000"))
PER_CLASS_CAP = int(os.environ.get("CAP", "1800"))   # over-provision to absorb failures
SEED = int(os.environ.get("SEED", "42"))


def norm_hash(path):
    t = open(path, encoding="utf-8", errors="ignore").read()
    t = re.sub(r"//.*", "", t)
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    t = re.sub(r"\s+", "", t)
    return hashlib.md5(t.encode()).hexdigest()


def main():
    train_csv = os.path.join(SPLITS, "Train_Labels.csv")
    assert os.path.basename(train_csv) not in DENY
    tr = pd.read_csv(train_csv)
    tr["contractID"] = tr["contractID"].astype(str)
    train_ids = set(tr["contractID"])

    # --- cross-split dedup guard (no label CSV read) ---
    all_ids = {os.path.splitext(os.path.basename(p))[0] for p in glob.glob(os.path.join(SOURCE, "*.sol"))}
    holdout_ids = all_ids - train_ids
    holdout_hashes = set()
    for cid in holdout_ids:
        holdout_hashes.add(norm_hash(os.path.join(SOURCE, f"{cid}.sol")))
    print(f"train={len(train_ids)} holdout={len(holdout_ids)} holdout_hashes={len(holdout_hashes)}")

    # --- resolve each train contract's solc + family, drop dedup twins ---
    pragma_cache = json.load(open(os.path.join(CACHE, "train_pragma.json")))
    solc_of = {}
    twin = 0
    for cid in train_ids:
        p = os.path.join(SOURCE, f"{cid}.sol")
        if not os.path.isfile(p):
            continue
        src = open(p, encoding="utf-8", errors="ignore").read()
        if norm_hash(p) in holdout_hashes:
            twin += 1
            continue
        v = version_utils.pick_solc(src)
        if v:
            solc_of[cid] = v
    print(f"excluded {twin} holdout-twin bases; {len(solc_of)} bases have an installed solc")

    labels_of = {r["contractID"]: {c: int(r[c]) for c in LABELS} for _, r in tr.iterrows()}

    # Exclude bases already injected in prior batches (keep the corpus globally disjoint).
    append_path = os.path.join(SPLITS, "Train_Labels_append.csv")
    used_bases = set()
    if os.path.isfile(append_path):
        prev = pd.read_csv(append_path)
        used_bases = {str(cid).split("_")[1] for cid in prev["contractID"]}
        print(f"excluding {len(used_bases)} bases already used in prior batches")

    rng = __import__("random").Random(SEED)
    assigned = set(used_bases)
    jobs = []
    for cls, bug in TARGETS.items():
        pool = [c for c in solc_of
                if c not in assigned and labels_of[c][cls] == 0]
        rng.shuffle(pool)
        take = pool[:PER_CLASS_CAP]
        for c in take:
            assigned.add(c)
            row = dict(labels_of[c])
            row[cls] = 1
            jobs.append({
                "cid": c,
                "target": cls,
                "bug_type": bug,
                "solc": solc_of[c],
                "family": "v" + version_utils.major(solc_of[c]).split(".")[1].zfill(2),
                "labels": [row[l] for l in LABELS],
            })
        print(f"{cls:16s} -> {bug:14s} eligible={len(pool):5d} queued={len(take)}")

    out = {"labels_order": LABELS, "targets": {c: PER_CLASS_TARGET for c in TARGETS},
           "per_class_cap": PER_CLASS_CAP, "jobs": jobs}
    os.makedirs(CACHE, exist_ok=True)
    with open(os.path.join(CACHE, "injection_jobs.json"), "w") as f:
        json.dump(out, f)
    print(f"total queued jobs: {len(jobs)} -> work/cache/injection_jobs.json")


if __name__ == "__main__":
    main()
