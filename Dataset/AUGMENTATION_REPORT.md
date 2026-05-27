# DIVE Augmentation Report — Wide Single-Bug Injection (All 8 Classes)

Generated 2026-05-27. Method: **SolidiFI bug injection** into **training-split** contracts, via a
**multi-version SolidiFI** (solc 0.4/0.5/0.6/0.7). Original goal was boosting the **minority** classes;
extended to **+ injected positives for all 8 classes** at the user's request.

## 1. Strategy — wide, single-bug, disjoint

Each target class gets a **disjoint subset** of train contracts; each contract receives **exactly one**
injected bug type (wide, not deep). Every base used **once** across the whole campaign (max structural
diversity). Run in three appended batches; bases globally disjoint.

| Target class | SolidiFI type | Deliberately injected | Base filter |
|---|---|---|---|
| Front Running | `TOD` (built-in) | 1,300 | train, label=0 for Front Running |
| Bad Randomness | `Bad-Randomness` (custom) | 1,300 | train, label=0 for Bad Randomness |
| DoS | `DoS` (custom) | 1,300 | train, label=0 for DoS |
| Reentrancy | `Re-entrancy` (built-in) | 300 | train, label=0 for Reentrancy |
| Access Control | `tx.origin` (built-in) | 300 | train, label=0 for Access Control |
| Arithmetic | `Overflow-Underflow` (built-in) | 300 | train, label=0 for Arithmetic |
| Unchecked Return Values | `Unchecked-Send` (built-in) | 300 | train, label=0 |
| Time manipulation | `Timestamp-Dependency` (built-in) | 300 | train, label=0 |

**5,400 synthetic contracts** total, all from **distinct base contracts** (disjoint). Per-batch yield:
minority 3×1,000 (97.8%), minority top-up 3×300 (95%), majority 5×300 (93%). Synthetic row labels =
the base's original train labels **OR** the injected target class (base may carry other real
vulnerabilities; only the target class is guaranteed added).

> Access Control was base-limited: most contracts already have AC=1, so only ~380 AC-negative,
> compilable, unused, non-twin bases remained — enough for its 300.

## 2. No-leakage enforcement

- **Train only**: bases restricted to `Train_Labels.csv` IDs; the selection/injection code never reads
  `DIVE/Val/Test` label CSVs (asserted).
- **Val/test frozen + hash-pinned** (`split_manifest.json`); re-verified at assembly — byte-identical:
  - Val  `62bd33c5…48dc7`  ·  Test `9b614b9f…06716`
- Zero train↔val/test ID overlap.
- **Cross-split dedup guard**: excluded train bases whose normalized source (comments+whitespace
  stripped, md5) matches any holdout (val∪test) contract — so we never augment a structural twin of a
  val/test contract. Holdout IDs derived as `{all Source IDs} − {train IDs}` **without reading any
  label CSV**. 216 twin bases excluded corpus-wide.

## 3. Multi-version SolidiFI port

SolidiFI ships pinned to solc 0.5.12 and consumes the legacy `--ast-json` AST. To inject across the
train corpus we built `solidifi-multi` (Docker + `solc-select` with 0.4.26/0.5.17/0.6.12/0.7.6) and
made `solidifi.py` pick the solc version per contract pragma (`version_utils.pick_solc`). Legacy
`--ast-json` is identical across 0.4–0.7, so SolidiFI's injection engine works unchanged for those.
Per-family snippets: existing 0.5-style set serves 0.5/0.6/0.7; **v04 variants** (no `address payable`,
legacy idioms) added for the three target types (`bugs/<Type>/v04/tf/`). The family-aware injector
prefers `bugs/<Type>/<family>/` when present.

> solc 0.8 was **not needed**: 0.4.x alone supplied the bulk of bases. (0.8 would have required a
> compact-AST adapter since `--ast-json` was removed in 0.8.0 — deferred, out of scope.)

Injected-base solc family: `0.4.x=2,788 · 0.6.x=130 · 0.5.x=43 · 0.7.x=28 · other≈11`.

## 4. Result — class lift (training set)

Final = real train positives + positives across all 5,400 synthetic rows (column sums; a row counts
toward its injected target **and** any original labels its base carried).

| Class | Real train | +Synthetic (col sum) | Final train | Deliberately injected |
|---|---|---|---|---|
| **Front Running** | 424 | +1,596 | **2,020** | 1,300 |
| **Bad Randomness** | 444 | +1,480 | **1,924** | 1,300 |
| **DoS** | 2,647 | +2,480 | **5,127** | 1,300 |
| Reentrancy | 7,980 | +2,724 | 10,704 | 300 |
| Access Control | 11,706 | +4,483 | 16,189 | 300 |
| Arithmetic | 6,679 | +1,916 | 8,595 | 300 |
| Unchecked Return Values | 4,138 | +1,256 | 5,394 | 300 |
| Time manipulation | 4,425 | +1,530 | 5,955 | 300 |

(Column sums exceed the deliberate counts because injected bases carry their own original labels.
"Deliberately injected" = rows where that class was the injection target: 1,300 each for FR/BR/DoS,
300 each for the other five — 5,400 total.)

## 5. Layout & how to consume

```
Dataset/
├── splits/
│   ├── Train_Labels.csv          15,631 real (labels)
│   ├── Train_Labels_append.csv   5,400 injected (labels)
│   ├── Val_Labels.csv / Test_Labels.csv   FROZEN, read-only, hash-pinned
│   └── split_manifest.json
├── buggy/<8 bug-type dirs>/
│   ├── buggy_<id>_<type>.sol
│   └── BugLog_<id>_<type>.csv
└── final/                                  ← self-contained deliverable
    ├── Train_Labels.csv   21,031 rows (15,631 real + 5,400 injected)
    ├── Val_Labels.csv     2,233 (real)
    ├── Test_Labels.csv    4,466 (real)
    ├── Synthetic_Bytecode.csv   5,400 rows  (contractID,contractAddress,bytecode — runtime hex,
    │                                          address blank; same schema as Bytecode_filled.csv)
    ├── train/   15,631 real .sol + 5,400 injected .sol
    ├── val/     2,233 real .sol
    └── test/    4,466 real .sol
```

Bytecode modality is **one CSV** (`final/Synthetic_Bytecode.csv`) per request. Real-contract bytecode
is not duplicated — it lives in `Dataset/Bytecode_filled.csv` keyed by `contractID`.

**ML contract:** train on `final/Train_Labels.csv` (+ `.sol` / synthetic bytecode), tune on
`final/Val_Labels.csv`, evaluate once on `final/Test_Labels.csv` (100% real, untouched).

## 6. Reproduce

```bash
python work/scripts/step0_split.py                 # split + lock val/test (one-time)
docker build -f work/SolidiFI/Dockerfile.multi -t solidifi-multi work/SolidiFI
python work/scripts/gen_custom_snippets.py          # DoS/Bad-Randomness v05 snippets + conf
python work/scripts/gen_v04_snippets.py             # v04 for TOD/DoS/Bad-Randomness
python work/scripts/gen_v04_snippets_majority.py    # v04 for the 5 built-in types
python work/scripts/build_pragma_cache.py
# one batch per class-set; CLASSES/TARGET/CAP via env. build excludes already-used bases (disjoint).
CLASSES="Front Running,Bad Randomness,DoS" TARGET=1000 CAP=1800 python work/scripts/build_injection_jobs.py
docker run --rm -v <repo>/work/SolidiFI:/solidifi -v <repo>:/data -w /solidifi \
  solidifi-multi python3 incontainer_inject.py      # appends to Train_Labels_append.csv + bytecode csv
# repeat build+run for the +300 minority top-up and the 5 majority classes
python work/scripts/assemble_final.py
```

## 7. Caveats
- Injected positives share SolidiFI snippet patterns; a model could learn the snippet rather than the
  concept. Wide single-bug + one-use bases + dedup guard mitigate but don't eliminate this.
- This pipeline produces augmented training data only. **Measuring the minority-recall boost is a
  separate downstream training run** the user performs (baseline vs augmented).
- ~28 contracts with exact 0.7.x pins (e.g. `0.7.4`) and any exact-pin misses were skipped (only
  0.7.6 installed); negligible vs the 0.4.x-dominated pool.
