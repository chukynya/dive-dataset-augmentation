"""Step 0: bytecode-deduped, stratified multi-label 70/10/20 split.

Order matters: we MUST collapse bytecode duplicates BEFORE the split. Otherwise
two source files that compile to identical runtime bytecode can land in
different splits and the model leaks across train/val/test.

Pipeline:
  1. Read Dataset/DIVE_Labels.csv (the only step allowed to read it) +
     Bytecode_filled.csv.
  2. Canon-hash every contract (metadata-stripped runtime bytecode sha256).
  3. Group contracts by canon hash. For each group:
       - keep the lowest contractID as representative
       - OR-merge labels across the group (label is a property of the bytecode;
         if any contract in the group is annotated positive, the bytecode is
         positive)
     Contracts missing or with empty bytecode are kept un-grouped (treated
     as singletons keyed by their ID).
  4. Stratified multi-label split the deduped representative set 70/10/20
     with seed 42.
  5. Hash-pin Val/Test, write split_manifest.json.
  6. Write work/cache/real_canon_bytecode.json (full {ID: hash} including
     non-representatives — used by the injector to sanity-check)
     and holdout_canon_hashes.json (hashes of val+test representatives).

This is the ONLY step permitted to read DIVE_Labels.csv. Subsequent steps must
read only the split CSVs.
"""
import hashlib
import json
import os
import stat
import sys
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from iterstrat.ml_stratifiers import MultilabelStratifiedShuffleSplit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "work", "scripts"))
from canon_bytecode import canon_hash  # noqa: E402

DATASET = os.path.join(ROOT, "Dataset")
SPLITS = os.path.join(DATASET, "splits")
CACHE = os.path.join(ROOT, "work", "cache")
SOURCE_CSV = os.path.join(DATASET, "DIVE_Labels.csv")
BYTECODE_CSV = os.path.join(DATASET, "Bytecode_filled.csv")

LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]
SEED = int(os.environ.get("SPLIT_SEED", "42"))

# Tunable split ratios. Override per run, e.g.:
#   TRAIN_FRAC=0.60 VAL_FRAC=0.20 TEST_FRAC=0.20 python work/scripts/step0_split.py
# Re-running this invalidates everything downstream (jobs + augmentation): the
# train pool, the locked val/test hashes, and the leakage gate all change. After
# a re-split, rebuild jobs and re-run injection (see README.md).
TRAIN_FRAC = float(os.environ.get("TRAIN_FRAC", "0.70"))
VAL_FRAC = float(os.environ.get("VAL_FRAC", "0.10"))
TEST_FRAC = float(os.environ.get("TEST_FRAC", "0.20"))
# DEDUP=0 disables bytecode-duplicate collapsing: every raw contract becomes its
# own split row. The canon (CBOR-stripped) hashes are still computed and used for
# the synthetic leakage gate, but identical-bytecode contracts are NOT merged, so
# they may land in different splits (accepted by the user; see README split note).
DEDUP = os.environ.get("DEDUP", "1") != "0"
assert abs(TRAIN_FRAC + VAL_FRAC + TEST_FRAC - 1.0) < 1e-9, \
    f"ratios must sum to 1: {TRAIN_FRAC}+{VAL_FRAC}+{TEST_FRAC}"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    os.makedirs(SPLITS, exist_ok=True)
    os.makedirs(CACHE, exist_ok=True)

    labels_df = pd.read_csv(SOURCE_CSV)
    assert list(labels_df.columns) == ["contractID"] + LABELS, \
        f"unexpected columns: {list(labels_df.columns)}"
    labels_df["contractID"] = labels_df["contractID"].astype(str)
    n_raw = len(labels_df)

    bc_df = pd.read_csv(BYTECODE_CSV, dtype=str).fillna("")
    bc_df["contractID"] = bc_df["contractID"].astype(str)
    bc_map = dict(zip(bc_df["contractID"], bc_df["bytecode"]))

    # --- canon hash per contract ---
    hashes = {}
    no_bc = 0
    for cid in labels_df["contractID"]:
        hexstr = bc_map.get(cid, "")
        if not hexstr or len(hexstr) < 4:
            no_bc += 1
            continue
        try:
            hashes[cid] = canon_hash(hexstr)
        except ValueError:
            no_bc += 1
    print(f"raw contracts: {n_raw}  canon-hashed: {len(hashes)}  "
          f"no/invalid bytecode: {no_bc}")

    # --- group by canon hash (DEDUP), or one group per contract (DEDUP=0) ---
    by_hash = {}
    for cid in labels_df["contractID"]:
        key = (hashes.get(cid, f"__nobytecode__{cid}") if DEDUP else cid)
        by_hash.setdefault(key, []).append(cid)

    int_ids = lambda lst: sorted(lst, key=lambda s: (len(s), s))
    rows = []
    for h, ids in by_hash.items():
        ids = int_ids(ids)
        rep = ids[0]
        merged = labels_df[labels_df["contractID"].isin(ids)][LABELS].max().astype(int)
        rows.append([rep] + merged.tolist())
    dedup = pd.DataFrame(rows, columns=["contractID"] + LABELS)
    if DEDUP:
        print(f"unique canon hashes (= deduped representatives): {len(dedup)}")
        print(f"collapsed {n_raw - len(dedup)} duplicate-bytecode contracts")
    else:
        print(f"DEDUP=0: splitting all {len(dedup)} raw contracts (no collapsing)")

    # --- stratified multi-label split on representatives ---
    # Stage 1: hold out (val+test) = 1 - TRAIN_FRAC. Stage 2: within that
    # remainder, test's share is TEST_FRAC / (VAL_FRAC + TEST_FRAC).
    X = dedup[["contractID"]].to_numpy()
    Y = dedup[LABELS].to_numpy()
    stage1_test = VAL_FRAC + TEST_FRAC
    stage2_test = TEST_FRAC / (VAL_FRAC + TEST_FRAC)
    print(f"ratios: train={TRAIN_FRAC} val={VAL_FRAC} test={TEST_FRAC} "
          f"(stage1_test={stage1_test:.4f} stage2_test={stage2_test:.4f})")
    s1 = MultilabelStratifiedShuffleSplit(n_splits=1, test_size=stage1_test, random_state=SEED)
    train_idx, rem_idx = next(s1.split(X, Y))
    s2 = MultilabelStratifiedShuffleSplit(n_splits=1, test_size=stage2_test, random_state=SEED)
    val_local, test_local = next(s2.split(X[rem_idx], Y[rem_idx]))
    val_idx = rem_idx[val_local]
    test_idx = rem_idx[test_local]

    assert len(set(train_idx) & set(val_idx)) == 0
    assert len(set(train_idx) & set(test_idx)) == 0
    assert len(set(val_idx) & set(test_idx)) == 0
    assert len(train_idx) + len(val_idx) + len(test_idx) == len(dedup)

    out = {}
    for name, idx in [("Train", train_idx), ("Val", val_idx), ("Test", test_idx)]:
        part = dedup.iloc[np.sort(idx)].reset_index(drop=True)
        path = os.path.join(SPLITS, f"{name}_Labels.csv")
        part.to_csv(path, index=False)
        out[name] = (path, len(part))

    # --- hash-pin val/test + chmod 0444 ---
    locked = {}
    for name in ("Val", "Test"):
        path = out[name][0]
        locked[name] = sha256_file(path)
        os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)

    # --- side products: canon-hash maps for downstream ---
    with open(os.path.join(CACHE, "real_canon_bytecode.json"), "w") as f:
        json.dump(hashes, f)

    rep_to_split = {}
    for name, idx in (("train", train_idx), ("val", val_idx), ("test", test_idx)):
        for r in dedup.iloc[idx]["contractID"]:
            rep_to_split[r] = name
    holdout_hashes = sorted({hashes[r] for r in rep_to_split
                             if rep_to_split[r] in ("val", "test") and r in hashes})
    with open(os.path.join(CACHE, "holdout_canon_hashes.json"), "w") as f:
        json.dump(holdout_hashes, f)

    # Map every original contract (including deduped duplicates) to its rep's split.
    # Used by assemble_final to expand all 22,330 originals back into the final CSVs.
    hash_to_split = {hashes.get(r, f"__nobytecode__{r}"): s
                     for r, s in rep_to_split.items()}
    all_assignments = {}
    for cid in labels_df["contractID"]:
        h = hashes.get(cid, f"__nobytecode__{cid}")
        all_assignments[cid] = hash_to_split.get(h, "train")
    with open(os.path.join(CACHE, "all_split_assignments.json"), "w") as f:
        json.dump(all_assignments, f)
    print(f"all_split_assignments: {len(all_assignments)} contracts "
          f"(train={sum(v=='train' for v in all_assignments.values())} "
          f"val={sum(v=='val' for v in all_assignments.values())} "
          f"test={sum(v=='test' for v in all_assignments.values())})")

    manifest = {
        "source": "Dataset/DIVE_Labels.csv",
        "source_rows": n_raw,
        "bytecode_dedup": {
            "enabled": DEDUP,
            "method": "canonical runtime bytecode "
                      "(Solidity CBOR metadata stripped, sha256)",
            "unique_representatives": len(dedup),
            "collapsed_duplicates": n_raw - len(dedup),
            "label_merge_rule": "OR across each duplicate group" if DEDUP else "n/a",
            "missing_bytecode_count": no_bc,
        },
        "split_ratios": {"train": TRAIN_FRAC, "val": VAL_FRAC, "test": TEST_FRAC},
        "random_state": SEED,
        "train_rows": out["Train"][1],
        "val_rows": out["Val"][1],
        "test_rows": out["Test"][1],
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "method": "MultilabelStratifiedShuffleSplit (iterative-stratification), "
                  "two-stage, on bytecode-deduplicated representatives",
        "locked_sha256": locked,
        "holdout_canon_hash_count": len(holdout_hashes),
        "read_deny_list": [
            "Dataset/DIVE_Labels.csv",
            "Dataset/splits/Val_Labels.csv",
            "Dataset/splits/Test_Labels.csv",
        ],
    }
    with open(os.path.join(SPLITS, "split_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    print(json.dumps({k: manifest[k] for k in
                      ("train_rows", "val_rows", "test_rows",
                       "locked_sha256", "holdout_canon_hash_count")}, indent=2))
    tr = pd.read_csv(out["Train"][0])
    print("train class positives:", {c: int(tr[c].sum()) for c in LABELS})


if __name__ == "__main__":
    main()
