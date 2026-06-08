"""Phase D selection: build the wide single-bug injection job list (train-only).

NO LEAKAGE:
- reads ONLY Train_Labels.csv (label CSV) + Source/*.sol pragmas; asserts it
  never opens DIVE/Val/Test label CSVs.
- the corpus was already bytecode-deduped at split time (step0_split.py), so the
  source-text twin guard is no longer needed. We still defensively assert that
  no train ID's canon hash appears in holdout_canon_hashes.json.

Per-class TARGET and CAP are hardcoded below — this is a campaign-specific
script, not a reusable library. Edit TARGETS to change the run.

DISJOINT BASES (default): now that the 0.8-aware engine compiles the 0.8.x
corpus (the majority of train), ~14k bases are injectable -- enough that every
synthetic can come from a DISTINCT base. The allocator partitions the injectable
pool so each base is assigned to AT MOST ONE class/bug_type (no cross-class
reuse). A two-pass, most-constrained-class-first allocation guarantees every
class its `target` before any slack is spent toward `cap`. If a class still ends
up queued < target, the run prints a loud warning (the pool is too small for a
fully disjoint campaign at these targets).

Set DISJOINT_BASES=0 to fall back to the legacy mode where each class draws
independently from the full label=0 pool (a base may then recur across bug
types). Either way the in-container canon-hash gate rejects any injected contract
whose metadata-stripped bytecode duplicates another synthetic or a val/test
contract, so every emitted row is a distinct compiled program with zero leakage.

Output: work/cache/injection_jobs.json = {targets:{...}, jobs:[{cid,target,bug_type,family,labels}]}
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
    if os.environ.get("DEDUP", "1") != "0":
        assert not leaks, f"train-side bytecode leakage survived step0: {leaks[:5]}"
        print(f"train_ids={len(train_ids)}  holdout_hashes={len(holdout)}  "
              f"defensive check passed (zero train-side leaks)")
    else:
        print(f"train_ids={len(train_ids)}  holdout_hashes={len(holdout)}  "
              f"[DEDUP=0] {len(leaks)} train contracts share canonical bytecode with "
              f"val/test (accepted: corpus dedup disabled; only affects REAL contracts). "
              f"Synthetic augmentation is still gated against holdout in-container.")

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
    disjoint = os.environ.get("DISJOINT_BASES", "1") != "0"
    # A base is eligible for a class only if it is currently label=0 there, so
    # injecting creates a genuinely new positive.
    eligible = {cls: [c for c in solc_of if labels_of[c][cls] == 0] for cls in TARGETS}

    # Class processing order: most-constrained (smallest eligible pool) first, so
    # scarce classes get first pick of contested bases at run time.
    emit_order = sorted(TARGETS, key=lambda c: len(eligible[c]))

    if disjoint:
        # Verify-and-keep disjoint: queue EVERY eligible base per class (shuffled),
        # NOT a pre-reserved target/cap slice. The injector keeps a single global
        # consumed-set, so each base emits for AT MOST ONE class and a FAILED
        # injection costs nothing (it just falls through to the next eligible
        # base). This shares the ~14% injection attrition across the whole pool
        # instead of reserving a per-class buffer up front -- the only way the
        # 13,089-base pool reaches 3000/3000/3000+500x5 (11,500) after attrition.
        # Scarce-first ordering (emit_order) lets constrained classes claim bases
        # before abundant ones drain the pool.
        take_of = {}
        for cls in emit_order:
            pool = list(eligible[cls])
            rng.shuffle(pool)
            take_of[cls] = pool
    else:
        # Legacy: each class draws independently; a base may recur across types.
        take_of = {cls: rng.sample(eligible[cls], min(TARGETS[cls]["cap"], len(eligible[cls])))
                   for cls in TARGETS}

    jobs = []
    short = []
    # Emit scarce-first so the injector meets constrained classes before abundant
    # ones drain the shared base pool (matters for run-time disjoint contention).
    for cls in emit_order:
        spec = TARGETS[cls]
        bug = spec["bug_type"]
        take = take_of[cls]
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
        # In disjoint mode `take` is the full eligible list (an attrition buffer),
        # so a build-time queue < target is normal; trouble is only when even the
        # eligible pool (before attrition) can't cover the target.
        gate = len(eligible[cls]) if disjoint else len(take)
        if gate < spec["target"]:
            short.append((cls, gate, spec["target"]))
        print(f"{cls:24s} -> {bug:18s} eligible={len(eligible[cls]):5d} "
              f"queued={len(take):5d} target={spec['target']} cap={spec['cap']}")

    print(f"mode: {'DISJOINT (each base used once)' if disjoint else 'cross-class reuse'}")
    if short:
        print("\n[!] WARNING: pool too small for a fully disjoint campaign at these "
              "targets -- the following classes have eligible pool BELOW target:")
        for cls, q, t in short:
            print(f"    {cls}: eligible={q} < target={t}")
        print("    Raise 0.8 coverage, lower targets (work/targets.json), or set "
              "DISJOINT_BASES=0 to allow cross-class base reuse.")

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
