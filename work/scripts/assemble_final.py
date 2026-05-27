"""Step 9: assemble the self-contained final/ deliverable + verify no leakage.

final/
  Train_Labels.csv  = splits/Train_Labels.csv + Train_Labels_append.csv
  Val_Labels.csv    = copy of frozen splits/Val_Labels.csv
  Test_Labels.csv   = copy of frozen splits/Test_Labels.csv
  train/  real train .sol + injected buggy .sol      + train/bytecode/ (injected .bin.json)
  val/    real val .sol
  test/   real test .sol

Real-contract bytecode is NOT duplicated; it lives in Dataset/Bytecode_filled.csv
keyed by contractID. Only the injected augmentations carry their .bin here.
"""
import hashlib
import json
import os
import shutil

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(ROOT, "Dataset")
SPLITS = os.path.join(DATASET, "splits")
SOURCE = os.path.join(DATASET, "Source")
BUGGY = os.path.join(DATASET, "buggy")
FINAL = os.path.join(DATASET, "final")
LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_split_sol(ids, dst):
    os.makedirs(dst, exist_ok=True)
    n = 0
    for cid in ids:
        src = os.path.join(SOURCE, f"{cid}.sol")
        if os.path.isfile(src):
            shutil.copyfile(src, os.path.join(dst, f"{cid}.sol"))
            n += 1
    return n


def main():
    # ---- LEAKAGE CHECK: frozen val/test must match locked hashes ----
    manifest = json.load(open(os.path.join(SPLITS, "split_manifest.json")))
    for name in ("Val", "Test"):
        cur = sha256(os.path.join(SPLITS, f"{name}_Labels.csv"))
        pinned = manifest["locked_sha256"][name]
        assert cur == pinned, f"LEAKAGE: {name}_Labels.csv changed since lock!"
    print("leakage check OK: Val/Test byte-identical to lock-time hashes")

    train = pd.read_csv(os.path.join(SPLITS, "Train_Labels.csv"))
    train["contractID"] = train["contractID"].astype(str)
    val = pd.read_csv(os.path.join(SPLITS, "Val_Labels.csv"))
    test = pd.read_csv(os.path.join(SPLITS, "Test_Labels.csv"))
    # no train/val/test ID overlap
    assert not (set(train.contractID) & set(val.contractID.astype(str)))
    assert not (set(train.contractID) & set(test.contractID.astype(str)))
    print("no train<->val/test ID overlap")

    append_path = os.path.join(SPLITS, "Train_Labels_append.csv")
    appended = pd.read_csv(append_path)

    os.makedirs(FINAL, exist_ok=True)

    # ---- label CSVs ----
    pd.concat([train, appended], ignore_index=True).to_csv(
        os.path.join(FINAL, "Train_Labels.csv"), index=False)
    shutil.copyfile(os.path.join(SPLITS, "Val_Labels.csv"), os.path.join(FINAL, "Val_Labels.csv"))
    shutil.copyfile(os.path.join(SPLITS, "Test_Labels.csv"), os.path.join(FINAL, "Test_Labels.csv"))

    # ---- .sol files ----
    n_tr = copy_split_sol(train.contractID, os.path.join(FINAL, "train"))
    n_val = copy_split_sol(val.contractID.astype(str), os.path.join(FINAL, "val"))
    n_test = copy_split_sol(test.contractID.astype(str), os.path.join(FINAL, "test"))

    # ---- injected .sol + bytecode into train/ and train/bytecode/ ----
    bc_dir = os.path.join(FINAL, "train", "bytecode")
    os.makedirs(bc_dir, exist_ok=True)
    n_inj = n_bin = 0
    for bug_type in sorted(os.listdir(BUGGY)) if os.path.isdir(BUGGY) else []:
        d = os.path.join(BUGGY, bug_type)
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if f.endswith(".sol"):
                shutil.copyfile(os.path.join(d, f), os.path.join(FINAL, "train", f))
                n_inj += 1
            elif f.endswith(".bin.json"):
                shutil.copyfile(os.path.join(d, f), os.path.join(bc_dir, f))
                n_bin += 1

    print(f"train: {n_tr} real .sol + {n_inj} injected .sol ; bytecode files: {n_bin}")
    print(f"val: {n_val} .sol ; test: {n_test} .sol")
    print(f"final Train_Labels rows: {len(train) + len(appended)} "
          f"(= {len(train)} real + {len(appended)} injected)")
    # invariant: one bytecode per injected sol
    assert n_bin == n_inj == len(appended), (n_bin, n_inj, len(appended))
    print("invariant OK: injected .sol == bytecode files == appended label rows ==", len(appended))


if __name__ == "__main__":
    main()
