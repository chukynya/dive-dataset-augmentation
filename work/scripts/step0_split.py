"""Step 0: stratified multi-label 70/10/20 split, then lock val/test.

Reads ONLY Dataset/DIVE_Labels.csv (the source of truth). Writes the three split
CSVs, hash-pins + read-only-locks val/test, and records split_manifest.json.
This is the ONLY step permitted to read DIVE_Labels.csv.
"""
import hashlib
import json
import os
import stat
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from iterstrat.ml_stratifiers import MultilabelStratifiedShuffleSplit

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(ROOT, "Dataset")
SPLITS = os.path.join(DATASET, "splits")
SOURCE_CSV = os.path.join(DATASET, "DIVE_Labels.csv")

LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]
SEED = 42


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    os.makedirs(SPLITS, exist_ok=True)
    df = pd.read_csv(SOURCE_CSV)
    assert list(df.columns) == ["contractID"] + LABELS, f"unexpected columns: {list(df.columns)}"
    n = len(df)
    X = df[["contractID"]].to_numpy()
    Y = df[LABELS].to_numpy()

    # Stage 1: 70% train vs 30% remainder.
    s1 = MultilabelStratifiedShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    train_idx, rem_idx = next(s1.split(X, Y))

    # Stage 2: split the 30% remainder into 1/3 val (~10% total), 2/3 test (~20% total).
    Xr, Yr = X[rem_idx], Y[rem_idx]
    s2 = MultilabelStratifiedShuffleSplit(n_splits=1, test_size=2.0 / 3.0, random_state=SEED)
    val_local, test_local = next(s2.split(Xr, Yr))
    val_idx = rem_idx[val_local]
    test_idx = rem_idx[test_local]

    # Sanity: partitions are disjoint and complete.
    assert len(set(train_idx) & set(val_idx)) == 0
    assert len(set(train_idx) & set(test_idx)) == 0
    assert len(set(val_idx) & set(test_idx)) == 0
    assert len(train_idx) + len(val_idx) + len(test_idx) == n

    out = {}
    for name, idx in [("Train", train_idx), ("Val", val_idx), ("Test", test_idx)]:
        part = df.iloc[np.sort(idx)].reset_index(drop=True)
        path = os.path.join(SPLITS, f"{name}_Labels.csv")
        part.to_csv(path, index=False)
        out[name] = (path, len(part))

    # Lock val/test FIRST: hash-pin then make read-only.
    locked = {}
    for name in ("Val", "Test"):
        path = out[name][0]
        digest = sha256(path)
        locked[name] = digest
        os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)  # 0444

    manifest = {
        "source": "Dataset/DIVE_Labels.csv",
        "source_rows": n,
        "split_ratios": {"train": 0.70, "val": 0.10, "test": 0.20},
        "random_state": SEED,
        "train_rows": out["Train"][1],
        "val_rows": out["Val"][1],
        "test_rows": out["Test"][1],
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "method": "MultilabelStratifiedShuffleSplit (iterative-stratification), two-stage",
        "locked_sha256": locked,
        "read_deny_list": [
            "Dataset/DIVE_Labels.csv",
            "Dataset/splits/Val_Labels.csv",
            "Dataset/splits/Test_Labels.csv",
        ],
    }
    with open(os.path.join(SPLITS, "split_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)

    print(json.dumps({k: manifest[k] for k in
                      ("train_rows", "val_rows", "test_rows", "locked_sha256")}, indent=2))
    # Per-class positives in train (informational).
    tr = pd.read_csv(out["Train"][0])
    print("train class positives:", {c: int(tr[c].sum()) for c in LABELS})


if __name__ == "__main__":
    main()
