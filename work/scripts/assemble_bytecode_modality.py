"""Assemble the CBOR-stripped, bytecode-modality deliverable (Linux+Windows CSVs).

Produces, per split, a bytecode CSV (contractID, contractAddress, bytecode) and a
label CSV (contractID + 8 labels). ALL bytecode is CBOR-metadata-stripped
(canon_bytecode.strip_metadata) so the model sees only program code, never the
source-derived swarm/IPFS metadata tail.

Split membership comes from the frozen seed-42, bytecode-deduped, multi-label
stratified split (step0_split.py). Train = real-train + SolidiFI synthetic;
val/test = 100% real, frozen. DROP_ORIGINAL (default 1) drops each injected base's
clean twin from train (its buggy descendant inherited its labels), mirroring
assemble_final.py so train size stays ~constant.

Outputs are written with LF (\\n) line endings + UTF-8 (no BOM) so the same files
load identically on Linux and Windows. The bytecode field is pure lowercase hex
and IDs contain no commas/quotes, so no CSV quoting is needed.

No-leakage asserts (hard-fail): no train<->val/test ID overlap; no canonical
(stripped) bytecode shared between train (real+synthetic) and val/test; every
synthetic bytecode unique and distinct from every real-train bytecode.
"""
import json
import os
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "work", "scripts"))
from canon_bytecode import canon_hash, strip_metadata  # noqa: E402

# --- inputs (dataset-generation copy == user's Dataset, byte-identical) ---
SPLITS = os.path.join(ROOT, "Dataset", "splits")
REAL_BYTECODE_CSV = os.environ.get(
    "REAL_BYTECODE_CSV", os.path.join(ROOT, "Dataset", "Bytecode_filled.csv"))
SYNTH_BYTECODE_CSV = os.environ.get(
    "SYNTH_BYTECODE_CSV", os.path.join(ROOT, "work", "cache", "synthetic_bytecode.csv"))
CACHE = os.path.join(ROOT, "work", "cache")
# --- output: the user's Dataset/ by default ---
OUT = os.environ.get("OUT_DIR",
                     r"C:\Users\henry\Desktop\research-methodology\Dataset\augmented")

LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]
DROP_ORIGINAL = os.environ.get("DROP_ORIGINAL", "1") != "0"
DEDUP = os.environ.get("DEDUP", "1") != "0"


def strip_hex(h):
    """CBOR-stripped lowercase hex (no 0x). '' stays ''."""
    if not h:
        return ""
    return strip_metadata(h).hex()


def write_csv(df, path):
    """LF + UTF-8 (no BOM), no index -- identical on Linux and Windows."""
    df.to_csv(path, index=False, lineterminator="\n", encoding="utf-8")


def main():
    os.makedirs(OUT, exist_ok=True)

    train = pd.read_csv(os.path.join(SPLITS, "Train_Labels.csv"), dtype={"contractID": str})
    val = pd.read_csv(os.path.join(SPLITS, "Val_Labels.csv"), dtype={"contractID": str})
    test = pd.read_csv(os.path.join(SPLITS, "Test_Labels.csv"), dtype={"contractID": str})
    appended = pd.read_csv(os.path.join(SPLITS, "Train_Labels_append.csv"),
                           dtype={"contractID": str})

    # ---- DROP_ORIGINAL: injected base's clean twin is replaced by its buggy form
    inj_bases = {cid.split("_")[1] for cid in appended["contractID"]}
    assert inj_bases <= set(train.contractID), "an injected base is not a train ID"
    kept = train[~train.contractID.isin(inj_bases)].reset_index(drop=True) \
        if DROP_ORIGINAL else train
    train_labels = pd.concat([kept, appended], ignore_index=True)

    # ---- bytecode maps (CBOR-stripped) ----
    real = pd.read_csv(REAL_BYTECODE_CSV, dtype=str).fillna("")
    real_addr = dict(zip(real["contractID"], real["contractAddress"]))
    real_strip = {cid: strip_hex(b) for cid, b in zip(real["contractID"], real["bytecode"])}
    synth = pd.read_csv(SYNTH_BYTECODE_CSV, dtype=str).fillna("")
    synth_strip = {cid: strip_hex(b) for cid, b in zip(synth["contractID"], synth["bytecode"])}

    def bytecode_rows(label_df):
        rows = []
        for cid in label_df["contractID"]:
            if cid in synth_strip:                       # synthetic (buggy_*)
                rows.append((cid, "", synth_strip[cid]))
            else:                                        # real
                rows.append((cid, real_addr.get(cid, ""), real_strip.get(cid, "")))
        return pd.DataFrame(rows, columns=["contractID", "contractAddress", "bytecode"])

    splits = {"train": (train_labels, bytecode_rows(train_labels)),
              "val":   (val,          bytecode_rows(val)),
              "test":  (test,         bytecode_rows(test))}

    # ---- LEAKAGE ASSERTS ----
    tr_ids, va_ids, te_ids = set(train_labels.contractID), set(val.contractID), set(test.contractID)
    assert not (tr_ids & va_ids) and not (tr_ids & te_ids) and not (va_ids & te_ids), \
        "ID overlap across splits"
    holdout = set(json.load(open(os.path.join(CACHE, "holdout_canon_hashes.json"))))
    train_canon = {canon_hash(b) for _, _, b in splits["train"][1].itertuples(index=False) if b}
    synth_canon_set = {canon_hash(b) for b in synth_strip.values() if b}
    real_train_canon = train_canon - synth_canon_set
    overlap = train_canon & holdout
    if DEDUP and overlap:
        raise AssertionError(f"BYTECODE LEAKAGE: {len(overlap)} train canon-hashes in val/test")
    # synthetic must NEVER leak into val/test regardless of dedup mode (it's generated)
    synth_holdout = synth_canon_set & holdout
    assert not synth_holdout, \
        f"SYNTHETIC LEAKAGE: {len(synth_holdout)} synthetic bytecodes match a val/test contract"
    synth_canon = [canon_hash(b) for b in synth_strip.values() if b]
    assert len(synth_canon) == len(set(synth_canon)), "synthetic bytecode not internally unique"
    if not DEDUP and overlap:
        real_overlap = real_train_canon & holdout
        print(f"[DEDUP=0] note: {len(real_overlap)} REAL train canon-hashes also appear in "
              f"val/test (accepted: corpus dedup disabled). Synthetic is leakage-free.")
    print(f"leakage check: synthetic disjoint from {len(holdout)} holdout; "
          f"{len(set(synth_canon))} unique synthetic")

    # ---- write + per-split stats ----
    for name, (labs, bc) in splits.items():
        assert list(labs.contractID) == list(bc.contractID), f"{name}: label/bytecode ID order mismatch"
        n_empty = int((bc["bytecode"] == "").sum())
        write_csv(labs, os.path.join(OUT, f"{name}_labels.csv"))
        write_csv(bc, os.path.join(OUT, f"{name}_bytecode.csv"))
        pos = {c: int(labs[c].sum()) for c in LABELS}
        print(f"{name:5s}: {len(labs):6d} rows | empty_bytecode={n_empty} | positives={pos}")

    # ---- manifest ----
    n_real_train = len(kept)
    manifest = {
        "deliverable": "CBOR-stripped bytecode-modality DIVE augmentation",
        "csv_format": {"line_ending": "\\n (LF)", "encoding": "utf-8 (no BOM)",
                       "index": False, "note": "loads identically on Linux and Windows"},
        "bytecode": {"field": "bytecode",
                     "transform": "Solidity CBOR metadata trailer stripped "
                                  "(canon_bytecode.strip_metadata); lowercase hex, no 0x",
                     "modality": "runtime bytecode"},
        "split": {"method": "MultilabelStratifiedShuffleSplit (iterative stratification), "
                            "two-stage 70/10/20 on bytecode-deduplicated representatives",
                  "seed": 42,
                  "dedup": "identical CBOR-stripped runtime bytecode collapsed pre-split "
                           "(OR-merged labels) to prevent train/val/test leakage"},
        "train": {"real_kept": n_real_train, "synthetic": len(appended),
                  "total": len(train_labels),
                  "drop_original": DROP_ORIGINAL},
        "val_rows": len(val), "test_rows": len(test),
        "augmentation": "SolidiFI bug injection on TRAIN ONLY; val/test 100% real & frozen; "
                        "synthetic deduped against val/test and real-train by canonical bytecode",
        "files": {f"{n}_bytecode.csv": "contractID,contractAddress,bytecode (stripped)"
                  for n in ("train", "val", "test")} |
                 {f"{n}_labels.csv": "contractID," + ",".join(LABELS)
                  for n in ("train", "val", "test")},
    }
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nwrote deliverable to {OUT}")


if __name__ == "__main__":
    main()
