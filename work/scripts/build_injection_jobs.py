"""Phase D selection: build the wide single-bug injection job list (train-only).

NO LEAKAGE:
- reads ONLY Train_Labels.csv (label CSV) + Source/*.sol pragmas; asserts it
  never opens DIVE/Val/Test label CSVs.
- the corpus was already bytecode-deduped at split time (step0_split.py), so the
  source-text twin guard is no longer needed. We still defensively assert that
  no train ID's canon hash appears in holdout_canon_hashes.json.

Per-class TARGET and CAP are hardcoded below — this is a campaign-specific
script, not a reusable library. Edit TARGETS to change the run.

BASE REUSE: only ~5,300 train contracts have a pragma matching an installed
solc (most of the rest are 0.8.x, which SolidiFI's legacy --ast-json can't
handle). Single-use bases would cap the campaign at ~5,300 synthetics. To reach
the requested 2-3x, each base may be reused ACROSS DIFFERENT bug types (at most
once per type). Different bug type -> different injected snippet -> different
bytecode, and the in-container canon-hash gate rejects any injected contract
whose metadata-stripped bytecode duplicates another synthetic or a val/test
contract. So every emitted row is still a distinct compiled program with zero
holdout leakage; what's relaxed is structural diversity of the base skeletons.

Output: work/cache/injection_jobs.json = {targets:{...}, jobs:[{cid,target,bug_type,family,labels}]}
Each (base, bug_type) pair is unique; a base may appear under multiple types.
"""
import glob
import json
import os
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "work", "SolidiFI"))
sys.path.insert(0, os.path.join(ROOT, "work", "scripts"))
import version_utils  # noqa: E402

DATASET = os.path.join(ROOT, "Dataset")
SPLITS = os.path.join(DATASET, "splits")
SOURCE = os.path.join(DATASET, "Source")
CACHE = os.path.join(ROOT, "work", "cache")
DENY = {"DIVE_Labels.csv", "Val_Labels.csv", "Test_Labels.csv"}

LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]

# Per-class { target, cap, bug_type }. cap = jobs queued (> target to absorb
# injection + dedup attrition). Bases are NOT consumed across classes, so each
# class independently draws from the full injectable, label=0 pool.
#
# TUNING: don't edit these defaults. Drop a JSON at work/targets.json (or point
# $TARGETS_FILE at one) mapping class name -> {"target": int, "cap": int} to
# override any subset. bug_type stays fixed. cap is the run-time ceiling: the
# injector can be re-tuned up to cap without rebuilding, but never beyond the
# jobs queued here. See work/targets.example.json for a template.
DEFAULT_TARGETS = {
    "Front Running":           {"target": 3500, "cap": 4800, "bug_type": "TOD"},
    "Bad Randomness":          {"target": 3500, "cap": 4800, "bug_type": "Bad-Randomness"},
    "DoS":                     {"target": 3500, "cap": 4800, "bug_type": "DoS"},
    "Reentrancy":              {"target":  500, "cap":  900, "bug_type": "Re-entrancy"},
    "Access Control":          {"target":  500, "cap":  900, "bug_type": "tx.origin"},
    "Arithmetic":              {"target":  500, "cap":  900, "bug_type": "Overflow-Underflow"},
    "Unchecked Return Values": {"target":  500, "cap":  900, "bug_type": "Unchecked-Send"},
    "Time manipulation":       {"target":  500, "cap":  900, "bug_type": "Timestamp-Dependency"},
}
SEED = int(os.environ.get("SPLIT_SEED", "42"))
TARGETS_FILE = os.environ.get("TARGETS_FILE", os.path.join(ROOT, "work", "targets.json"))


def load_targets():
    """DEFAULT_TARGETS overlaid with work/targets.json (or $TARGETS_FILE) if it
    exists. Only per-class target/cap are tunable; bug_type is fixed."""
    t = {cls: dict(v) for cls, v in DEFAULT_TARGETS.items()}
    if os.path.isfile(TARGETS_FILE):
        override = json.load(open(TARGETS_FILE))
        for cls, vals in override.items():
            if cls.startswith("_"):  # allow "_comment" keys in the JSON
                continue
            assert cls in t, f"unknown class in {TARGETS_FILE}: {cls!r}"
            for k, val in vals.items():
                assert k in ("target", "cap"), \
                    f"{cls}: only target/cap are tunable, got {k!r}"
                t[cls][k] = int(val)
        print(f"applied per-class overrides from {TARGETS_FILE}")
    for cls, v in t.items():
        assert v["cap"] >= v["target"], \
            f"{cls}: cap {v['cap']} < target {v['target']} (cap must absorb attrition)"
    return t


def main():
    TARGETS = load_targets()
    train_csv = os.path.join(SPLITS, "Train_Labels.csv")
    assert os.path.basename(train_csv) not in DENY
    tr = pd.read_csv(train_csv)
    tr["contractID"] = tr["contractID"].astype(str)
    train_ids = set(tr["contractID"])

    # Defensive: no train ID's canon hash should appear in holdout (step0 guarantees this).
    holdout = set(json.load(open(os.path.join(CACHE, "holdout_canon_hashes.json"))))
    real_canon = json.load(open(os.path.join(CACHE, "real_canon_bytecode.json")))
    leaks = [cid for cid in train_ids if real_canon.get(cid) in holdout]
    assert not leaks, f"train-side bytecode leakage survived step0: {leaks[:5]}"
    print(f"train_ids={len(train_ids)}  holdout_hashes={len(holdout)}  "
          f"defensive check passed (zero train-side leaks)")

    # --- resolve solc per train contract ---
    pragma_cache = json.load(open(os.path.join(CACHE, "train_pragma.json")))
    solc_of = {}
    for cid in train_ids:
        p = os.path.join(SOURCE, f"{cid}.sol")
        if not os.path.isfile(p):
            continue
        src = open(p, encoding="utf-8", errors="ignore").read()
        v = version_utils.pick_solc(src)
        if v:
            solc_of[cid] = v
    print(f"{len(solc_of)} train bases have an installed solc")

    labels_of = {r["contractID"]: {c: int(r[c]) for c in LABELS} for _, r in tr.iterrows()}

    rng = __import__("random").Random(SEED)
    jobs = []
    summary = []
    for cls, spec in TARGETS.items():
        bug = spec["bug_type"]
        cap = spec["cap"]
        # Bases reusable across classes: draw independently from the full
        # injectable, label=0 pool for this class.
        pool = [c for c in solc_of if labels_of[c][cls] == 0]
        rng.shuffle(pool)
        take = pool[:cap]
        for c in take:
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
        summary.append((cls, bug, len(pool), len(take), spec["target"]))
        print(f"{cls:24s} -> {bug:18s} eligible={len(pool):5d} queued={len(take):5d} "
              f"target={spec['target']}")

    out = {
        "labels_order": LABELS,
        "targets": {c: TARGETS[c]["target"] for c in TARGETS},
        "caps": {c: TARGETS[c]["cap"] for c in TARGETS},
        "jobs": jobs,
    }
    os.makedirs(CACHE, exist_ok=True)
    with open(os.path.join(CACHE, "injection_jobs.json"), "w") as f:
        json.dump(out, f)
    print(f"total queued jobs: {len(jobs)} -> work/cache/injection_jobs.json")


if __name__ == "__main__":
    main()
