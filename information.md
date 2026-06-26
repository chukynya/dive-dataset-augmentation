# Dataset Augmentation Pipeline

## Overview

```
DIVE_Labels.csv (22,330 contracts)
         │
         ▼
1. step0_split.py          ← bytecode-dedup + stratified split
         │
         ├─ splits/Train_Labels.csv   (13,143 deduped reps, 70%)
         ├─ splits/Val_Labels.csv     (1,878 reps, 10%)
         ├─ splits/Test_Labels.csv    (3,756 reps, 20%)
         └─ cache/all_split_assignments.json  (maps all 22,330 originals → their split)
         │
         ▼
2. build_injection_jobs.py ← select train bases for injection
         │
         └─ cache/injection_jobs.json  (job entries for 3 bug classes)
         │
         ▼
3. run_injection.sh        ← compile + inject buggy patterns via SolidiFI
         │
         ├─ Dataset/buggy/DoS/            (2,000 .sol files)
         ├─ Dataset/buggy/Bad-Randomness/ (2,000 .sol files)
         ├─ Dataset/buggy/TOD/            (2,000 .sol files)
         └─ cache/synthetic_bytecode.csv
         │
         ▼
4. assemble_final.py       ← expand originals + merge everything
         │
         ├─ final/Train_Labels.csv   (~15,928 real + 6,000 synthetic = ~21,928 rows)
         ├─ final/Val_Labels.csv     (~2,062 real originals)
         ├─ final/Test_Labels.csv    (~4,340 real originals)
         └─ final/Bytecode.csv       (22,330 real + 6,000 synthetic = ~28,330 rows)
```

## Design Decisions

- **Split uses dedup**: contracts with identical bytecode (CBOR-stripped SHA-256) are collapsed to one representative before splitting. This prevents the same bytecode from leaking across train/val/test.
- **Final output uses all 22,330 originals**: `all_split_assignments.json` maps every original contract (including collapsed duplicates) back to its rep's split, so all original contracts appear in the final label CSVs with their own labels from `DIVE_Labels.csv`.
- **Additive augmentation**: the clean base contract is kept alongside its injected buggy twin — nothing is dropped.
- **One unified `Bytecode.csv`**: real bytecodes (`Bytecode_filled.csv`) and synthetic bytecodes are merged into a single file. The `contractID` column links it to the label CSVs.
- **CSVs only in `final/`**: no `.sol` source files are copied — only the 3 label CSVs and `Bytecode.csv`.

## Label CSV Schema

All label CSVs share the same columns:

| contractID | Reentrancy | Access Control | Arithmetic | Unchecked Return Values | DoS | Bad Randomness | Front Running | Time manipulation |
|---|---|---|---|---|---|---|---|---|

- Real contracts use their original numeric ID (e.g. `5`, `1042`)
- Synthetic contracts use `buggy_<baseID>_<BugType>` (e.g. `buggy_3387_DoS`)

## Bytecode.csv Schema

| contractID | contractAddress | bytecode |

- `contractID` links to the label CSVs
- `bytecode` is the raw hex-encoded runtime bytecode

## How to Run

### Foreground (logs to terminal + file simultaneously)
```bash
bash work/run_injection.sh
# Logs automatically tee'd to work/cache/run.log while printing to screen
```

### Background (detached, survives logout)
```bash
nohup bash work/run_injection.sh > work/cache/run.log 2>&1 &
echo "PID: $!"

# Watch progress in another terminal:
tail -f work/cache/run.log
```

### From scratch (full clean re-run)
```bash
# 1. Clean stale artifacts
chmod +w Dataset/splits/Val_Labels.csv Dataset/splits/Test_Labels.csv 2>/dev/null || true
rm -f Dataset/splits/*.csv Dataset/splits/split_manifest.json
rm -rf Dataset/final/ Dataset/buggy/DoS Dataset/buggy/Bad-Randomness Dataset/buggy/TOD
rm -f work/cache/injection_jobs.json work/cache/synthetic_bytecode.csv
rm -f work/cache/all_split_assignments.json work/cache/real_canon_bytecode.json work/cache/holdout_canon_hashes.json

# 2. Rebuild splits + jobs
.venv/bin/python3 work/scripts/step0_split.py
.venv/bin/python3 work/scripts/build_injection_jobs.py

# 3. Run injection + assembly (with logs)
nohup bash work/run_injection.sh > work/cache/run.log 2>&1 &
tail -f work/cache/run.log
```

The injection step (~15h) is resumable — re-running `run_injection.sh` picks up from where it left off.

## Targets (work/targets.json)

| Class | Bug Type | Target |
|---|---|---|
| Front Running | TOD | 2,000 |
| Bad Randomness | Bad-Randomness | 2,000 |
| DoS | DoS | 2,000 |
| Others | — | 0 (suppressed) |
