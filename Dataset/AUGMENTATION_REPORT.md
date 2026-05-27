# DIVE Augmentation Report — SolidiFI Bug-Injection (Validation Batch)

Generated: 2026-05-27. Method: **SolidiFI bug injection** on real training-split contracts
(per `README.md`). This run is a **validation batch** to prove the end-to-end pipeline before
any larger run.

## 1. Data split (Step 0) — val/test locked FIRST

Stratified multi-label split of `DIVE_Labels.csv` (22,330 contracts), `random_state=42`,
two-stage `MultilabelStratifiedShuffleSplit` (`iterative-stratification`).

| Split | Rows | Ratio |
|---|---|---|
| Train | 15,631 | 70.0% |
| Val   | 2,233  | 10.0% |
| Test  | 4,466  | 20.0% |

**No-leakage enforcement:**
- `Val_Labels.csv` / `Test_Labels.csv` were SHA-256 hash-pinned in `splits/split_manifest.json`
  and set read-only (`0444`) **before any augmentation began**.
- `DIVE_Labels.csv`, `Val_Labels.csv`, `Test_Labels.csv` form a hard **read-deny list**; the
  selection/weight code asserts against it and only ever reads `Train_Labels.csv` +
  `Train_Labels_append.csv`.
- Injection bases are restricted to `contractID`s present in `Train_Labels.csv`.
- Verified at assembly time: val/test re-hash **byte-identical** to lock-time; **zero**
  train↔val/test ID overlap.

Lock hashes (`split_manifest.json`):
- Val:  `62bd33c5a6a2617de1ce881ab41be8fb79c2568090aa884d6a91c88569048dc7`
- Test: `9b614b9f05686726f6cd202dc9f7746ca5513642db03d7950a95bc987af06716`

## 2. SolidiFI toolchain

- Cloned to `work/SolidiFI/`; built a **slim injection-only Docker image** (`solidifi-slim`,
  `work/SolidiFI/Dockerfile.slim`) with **solc 0.5.12** (SolidiFI's pinned compiler) — the heavy
  analyzer stack (Slither/Mythril/Manticore/Securify) from the upstream Dockerfile is omitted.
- Injection runs in-container; outputs written to host via bind mounts.

### Custom bug types (DoS & Bad Randomness)
SolidiFI ships 7 bug types covering 6 DIVE labels. **DoS** and **Bad Randomness** are not
built in, so custom 0.5.12-compatible snippets were authored (`work/SolidiFI/bugs/DoS/tf/`,
`work/SolidiFI/bugs/Bad-Randomness/tf/`, 12 variants each) and registered as bug types `[8]`/`[9]`
in `bug_types.conf`. No self-labeling comments (per rulebook §B2).
- **DoS**: external `.transfer()` inside an unbounded loop over a dynamic array (gas-griefing).
- **Bad Randomness**: entropy derived from `block.timestamp` / `block.number` / `blockhash(...)`.

## 3. The solc-0.5.12 constraint (important for scale-up)

SolidiFI is hard-pinned to solc 0.5.12, so only contracts that compile under it are injectable.
Of 15,631 train contracts: 200 declare a `0.5.x` pragma, and **99 actually satisfy 0.5.12 across
all pragma statements in the file** (some pin `0.5.13`–`0.5.17`, or mix pragmas across multiple
contracts in one file). These 99 are the candidate pool. **Lifting this ceiling for a large run
requires multi-solc support (patching SolidiFI) — out of scope for this batch.**

## 4. Injection batch results

- **30 contracts injected** (target 30), 36 attempted, **6 skipped** (3 primary-injection
  compile/AST failures, 3 post-injection bytecode-compile failures) — skip-on-error per README §4.
- Primary class rotated between the two rarest classes (**Front Running → `TOD`** and
  **Bad Randomness**, 15 each); co-occurring types sampled from README §2's co-occurrence table
  and injected as additional sequential passes on the same file.
- Every injected contract carries: `buggy_<id>_<type>.sol`, merged `BugLog`, and compiled
  **bytecode** (`*.bin.json`, `solc --combined-json bin,bin-runtime`).

Per-class positives added to the training set (multi-label, OR-ed onto each source's original labels):

| Class | Real train | +Injected | Final train |
|---|---|---|---|
| Reentrancy | 7,980 | +22 | 8,002 |
| Access Control | 11,706 | +30 | 11,736 |
| Arithmetic | 6,679 | +17 | 6,696 |
| Unchecked Return Values | 4,138 | +2 | 4,140 |
| DoS | 2,647 | +9 | 2,656 |
| **Bad Randomness** | 444 | **+15** | 459 |
| **Front Running** | 424 | **+15** | 439 |
| Time manipulation | 4,425 | +10 | 4,435 |

## 5. Layout & how to consume

```
Dataset/
├── splits/
│   ├── Train_Labels.csv          15,631 real (labels)
│   ├── Train_Labels_append.csv   30 injected (labels)
│   ├── Val_Labels.csv  / Test_Labels.csv   FROZEN, read-only, hash-pinned
│   └── split_manifest.json
├── buggy/<BugType>/
│   ├── buggy_<id>_<type>.sol
│   ├── BugLog_<id>_<type>.csv
│   └── buggy_<id>_<type>.bin.json     ← bytecode modality
└── final/                              ← self-contained deliverable
    ├── Train_Labels.csv   15,661 rows (15,631 real + 30 injected)
    ├── Val_Labels.csv     2,233 (real)
    ├── Test_Labels.csv    4,466 (real)
    ├── train/   15,631 real .sol + 30 injected .sol
    │   └── bytecode/   30 injected *.bin.json
    ├── val/     2,233 real .sol
    └── test/    4,466 real .sol
```

Real-contract bytecode is **not** duplicated into `final/` — it already exists in
`Dataset/Bytecode_filled.csv` keyed by `contractID`. Only injected augmentations carry their
`.bin.json` here (the new modality).

**ML training contract:** train on `final/Train_Labels.csv` (+ matching `.sol` / bytecode), tune
on `final/Val_Labels.csv`, evaluate ONCE on `final/Test_Labels.csv`. Val/Test are 100% real and
mathematically untouched by augmentation.

## 6. Reproduce / extend

```bash
python work/scripts/step0_split.py            # one-time; refuses to re-split if manifest matches
docker build -f work/SolidiFI/Dockerfile.slim -t solidifi-slim work/SolidiFI
python work/scripts/gen_custom_snippets.py    # DoS / Bad-Randomness snippets + conf
python work/scripts/build_pragma_cache.py     # train-only pragma scan
BATCH_TARGET=30 python work/scripts/run_injection_batch.py
python work/scripts/assemble_final.py
```

## 7. Follow-ups (out of scope here)
- Multi-solc support to lift the 99-contract 0.5.12 ceiling for large-scale runs.
- Bytecode for the full real train/val/test sets beyond `Bytecode_filled.csv`.
