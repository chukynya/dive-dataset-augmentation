"""Classify each TRAIN contract's solc major version (for SolidiFI 0.5.x filter).

Reads ONLY splits/Train_Labels.csv for the ID set + the matching Source/*.sol
files. Never touches DIVE/Val/Test. Writes work/cache/train_pragma.json.
"""
import json
import os
import re

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPLITS = os.path.join(ROOT, "Dataset", "splits")
SOURCE = os.path.join(ROOT, "Dataset", "Source")
CACHE = os.path.join(ROOT, "work", "cache")

DENY = {"DIVE_Labels.csv", "Val_Labels.csv", "Test_Labels.csv"}


def classify(pragma):
    if pragma is None:
        return "none"
    for v in ("0.4", "0.5", "0.6", "0.7", "0.8"):
        if v in pragma:
            return v + ".x"
    return "other"


def main():
    train_csv = os.path.join(SPLITS, "Train_Labels.csv")
    assert os.path.basename(train_csv) not in DENY
    ids = pd.read_csv(train_csv)["contractID"].astype(str).tolist()
    os.makedirs(CACHE, exist_ok=True)
    out = {}
    counts = {}
    for cid in ids:
        path = os.path.join(SOURCE, f"{cid}.sol")
        if not os.path.isfile(path):
            out[cid] = "missing"
        else:
            txt = open(path, encoding="utf-8", errors="ignore").read(2000)
            m = re.search(r"pragma solidity([^;]*)", txt)
            out[cid] = classify(m.group(1).strip() if m else None)
        counts[out[cid]] = counts.get(out[cid], 0) + 1
    with open(os.path.join(CACHE, "train_pragma.json"), "w") as f:
        json.dump(out, f)
    print("train contracts:", len(ids))
    print("by bucket:", dict(sorted(counts.items(), key=lambda x: -x[1])))
    print("0.5.x train candidates:", counts.get("0.5.x", 0))


if __name__ == "__main__":
    main()
