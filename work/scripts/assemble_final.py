"""Step 9: assemble the self-contained final/ deliverable + verify no leakage.

final/
  Train_Labels.csv  = all original train-assigned contracts (original labels) + synthetic
  Val_Labels.csv    = all original val-assigned contracts (original labels)
  Test_Labels.csv   = all original test-assigned contracts (original labels)
  Bytecode.csv      = Bytecode_filled.csv (all 22,330 real) + synthetic_bytecode.csv (6k)

All 22,330 original contracts appear in the final label CSVs using their original
(non-OR-merged) labels from DIVE_Labels.csv. Duplicate-bytecode contracts are
expanded back from the deduped split reps via all_split_assignments.json.
Clean bases are kept alongside their injected buggy twins (additive, no drop).
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
FINAL = os.environ.get("FINAL_DIR", os.path.join(DATASET, "final"))
CACHE = os.path.join(ROOT, "work", "cache")
LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    # ---- LEAKAGE CHECK: frozen val/test must match locked hashes ----
    manifest = json.load(open(os.path.join(SPLITS, "split_manifest.json")))
    for name in ("Val", "Test"):
        cur = sha256(os.path.join(SPLITS, f"{name}_Labels.csv"))
        pinned = manifest["locked_sha256"][name]
        assert cur == pinned, f"LEAKAGE: {name}_Labels.csv changed since lock!"
    print("leakage check OK: Val/Test byte-identical to lock-time hashes")

    # ---- expand all 22,330 originals using split assignments ----
    assignments = json.load(open(os.path.join(CACHE, "all_split_assignments.json")))
    dive = pd.read_csv(os.path.join(DATASET, "DIVE_Labels.csv"))
    dive["contractID"] = dive["contractID"].astype(str)
    assert list(dive.columns) == ["contractID"] + LABELS, \
        f"unexpected columns: {list(dive.columns)}"

    dive["_split"] = dive["contractID"].map(assignments)
    assert dive["_split"].notna().all(), "some contracts missing from all_split_assignments"

    train_real = dive[dive["_split"] == "train"].drop(columns="_split").reset_index(drop=True)
    val_real   = dive[dive["_split"] == "val"].drop(columns="_split").reset_index(drop=True)
    test_real  = dive[dive["_split"] == "test"].drop(columns="_split").reset_index(drop=True)
    print(f"real contracts: train={len(train_real)} val={len(val_real)} test={len(test_real)} "
          f"total={len(train_real)+len(val_real)+len(test_real)}")

    # ---- synthetic rows ----
    append_path = os.path.join(SPLITS, "Train_Labels_append.csv")
    appended = pd.read_csv(append_path)
    appended["contractID"] = appended["contractID"].astype(str)

    # bases must be deduped train reps (from splits/Train_Labels.csv)
    rep_train_ids = set(pd.read_csv(os.path.join(SPLITS, "Train_Labels.csv"))
                        ["contractID"].astype(str))
    inj_bases = {cid.split("_")[1] for cid in appended["contractID"]}
    assert inj_bases <= rep_train_ids, "an injected base is not a deduped train rep"
    print(f"synthetic: {len(appended)} rows, {len(inj_bases)} distinct bases")

    # ---- no ID overlap between real splits ----
    assert not (set(train_real.contractID) & set(val_real.contractID))
    assert not (set(train_real.contractID) & set(test_real.contractID))
    # synthetic IDs must not collide with any real ID
    synth_ids = set(appended.contractID)
    assert not (synth_ids & set(dive.contractID)), "synthetic ID collides with a real contractID"
    print("no train/val/test ID overlap; synthetic IDs distinct from real")

    os.makedirs(FINAL, exist_ok=True)

    # ---- label CSVs ----
    pd.concat([train_real, appended], ignore_index=True).to_csv(
        os.path.join(FINAL, "Train_Labels.csv"), index=False)
    val_real.to_csv(os.path.join(FINAL, "Val_Labels.csv"), index=False)
    test_real.to_csv(os.path.join(FINAL, "Test_Labels.csv"), index=False)
    print(f"Train_Labels: {len(train_real)+len(appended)} rows "
          f"({len(train_real)} real + {len(appended)} synthetic)")
    print(f"Val_Labels: {len(val_real)} | Test_Labels: {len(test_real)}")

    # ---- unified Bytecode.csv ----
    real_bc = pd.read_csv(os.path.join(DATASET, "Bytecode_filled.csv"), dtype=str).fillna("")
    synth_bc = pd.read_csv(os.path.join(CACHE, "synthetic_bytecode.csv"), dtype=str).fillna("")
    assert list(real_bc.columns) == ["contractID", "contractAddress", "bytecode"], \
        f"unexpected real_bc columns: {real_bc.columns.tolist()}"
    assert list(synth_bc.columns) == ["contractID", "contractAddress", "bytecode"], \
        f"unexpected synth_bc columns: {synth_bc.columns.tolist()}"
    all_bc = pd.concat([real_bc, synth_bc], ignore_index=True)
    all_bc.to_csv(os.path.join(FINAL, "Bytecode.csv"), index=False)
    print(f"Bytecode.csv: {len(all_bc)} rows ({len(real_bc)} real + {len(synth_bc)} synthetic)")

    # ---- invariants ----
    all_label_ids = (set(train_real.contractID) | set(appended.contractID)
                     | set(val_real.contractID) | set(test_real.contractID))
    bc_ids = set(all_bc["contractID"].astype(str))
    missing = all_label_ids - bc_ids
    assert not missing, f"{len(missing)} label IDs missing from Bytecode.csv: {list(missing)[:5]}"
    assert len(all_bc) == len(train_real) + len(val_real) + len(test_real) + len(appended), \
        "Bytecode.csv row count != total label rows"
    print("invariants OK: all label IDs present in Bytecode.csv")

    # ---- SYNTHETIC-ONLY bytecode leakage check ----
    # Real duplicates intentionally straddle splits; only synthetic contracts must
    # be disjoint from val/test canonical hashes.
    holdout = set(json.load(open(os.path.join(CACHE, "holdout_canon_hashes.json"))))
    synth_hashes = {canon_hash(x) for x in synth_bc["bytecode"] if x}
    overlap = synth_hashes & holdout
    assert not overlap, \
        f"SYNTHETIC BYTECODE LEAKAGE: {len(overlap)} synthetic hashes in val/test holdout"
    assert len(synth_hashes) == len(synth_bc), \
        f"synthetic bytecodes not unique: {len(synth_bc)} rows -> {len(synth_hashes)} hashes"
    print(f"synthetic leakage check OK: {len(synth_hashes)} unique synthetic hashes, "
          f"0 overlap with {len(holdout)} holdout hashes")


if __name__ == "__main__":
    main()
