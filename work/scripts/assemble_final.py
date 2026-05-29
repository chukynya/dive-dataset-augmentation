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
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "work", "scripts"))
from canon_bytecode import canon_hash  # noqa: E402

DATASET = os.path.join(ROOT, "Dataset")
SPLITS = os.path.join(DATASET, "splits")
SOURCE = os.path.join(DATASET, "Source")
BUGGY = os.path.join(DATASET, "buggy")
FINAL = os.path.join(DATASET, "final")
CACHE = os.path.join(ROOT, "work", "cache")
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

    # ---- injected .sol into train/ ----
    n_inj = 0
    inj_ids = set()
    for bug_type in sorted(os.listdir(BUGGY)) if os.path.isdir(BUGGY) else []:
        d = os.path.join(BUGGY, bug_type)
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if f.endswith(".sol"):
                shutil.copyfile(os.path.join(d, f), os.path.join(FINAL, "train", f))
                inj_ids.add(f[:-4])
                n_inj += 1

    # ---- bytecode: ONE CSV (Bytecode_filled schema), not per-file json ----
    staging = os.path.join(ROOT, "work", "cache", "synthetic_bytecode.csv")
    bc = pd.read_csv(staging, dtype=str).fillna("")
    bc.to_csv(os.path.join(FINAL, "Synthetic_Bytecode.csv"), index=False)
    assert list(bc.columns) == ["contractID", "contractAddress", "bytecode"], bc.columns.tolist()
    n_bin = len(bc)

    print(f"train: {n_tr} real .sol + {n_inj} injected .sol")
    print(f"val: {n_val} .sol ; test: {n_test} .sol")
    print(f"Synthetic_Bytecode.csv rows: {n_bin}")
    print(f"final Train_Labels rows: {len(train) + len(appended)} "
          f"(= {len(train)} real + {len(appended)} injected)")
    # invariants
    assert n_inj == len(appended) == n_bin, (n_inj, len(appended), n_bin)
    assert inj_ids == set(appended["contractID"]) == set(bc["contractID"]), "id mismatch across sol/labels/bytecode"
    assert all(len(x) > 0 for x in bc["bytecode"]), "empty bytecode present"
    # bases reused across bug types: enforce (base,bug) row uniqueness + train-only bases
    assert appended["contractID"].is_unique, "duplicate synthetic contractID (base,bug) row"
    bases = [cid.split("_")[1] for cid in appended["contractID"]]
    assert set(bases) <= set(train.contractID), "an injected base is not a train ID"
    print(f"invariants OK: injected .sol == labels == bytecode == {n_inj}; "
          f"rows unique & all bases train-only ({len(set(bases))} distinct bases reused)")

    # ---- BYTECODE LEAKAGE ASSERT: train (real+synthetic) disjoint from val/test ----
    real_canon = json.load(open(os.path.join(CACHE, "real_canon_bytecode.json")))
    holdout = set(json.load(open(os.path.join(CACHE, "holdout_canon_hashes.json"))))
    train_real_hashes = {real_canon[c] for c in train.contractID if c in real_canon}
    synth_hashes = {canon_hash(x) for x in bc["bytecode"] if x}
    train_all = train_real_hashes | synth_hashes
    overlap = train_all & holdout
    assert not overlap, f"BYTECODE LEAKAGE: {len(overlap)} train hashes appear in val/test"
    # synthetic rows must also be internally unique (no two injected contracts share bytecode)
    assert len(synth_hashes) == n_bin, \
        f"synthetic bytecode not unique: {n_bin} rows -> {len(synth_hashes)} hashes"
    # and disjoint from the real train contracts (no augment is a byte-identical clone)
    synth_real_overlap = synth_hashes & train_real_hashes
    assert not synth_real_overlap, \
        f"{len(synth_real_overlap)} synthetic bytecodes duplicate a real train contract"
    print(f"bytecode-leakage assert OK: 0 of {len(train_all)} train canon-hashes "
          f"intersect {len(holdout)} holdout hashes; {len(synth_hashes)} unique synthetic "
          f"(disjoint from {len(train_real_hashes)} real-train hashes)")


if __name__ == "__main__":
    main()
