# DIVE Smart-Contract Vulnerability Dataset — Full Pipeline

Multi-label vulnerability detection for Ethereum smart contracts. Each contract is labelled
across **8 vulnerability classes** (a contract can be positive in several at once). The dataset
combines real Etherscan-verified contracts with **SolidiFI bug-injected** synthetic contracts that
augment the rare classes.

This file is both human documentation **and** a self-contained agent prompt. Any agent with
file-system access (Claude Code, Cursor, Antigravity, VS Code Agent, etc.) can use it as its
complete instruction set.

> [!CAUTION]
> **Data-Leakage Prevention Rule**: All synthetic generation (bug injection) operates
> exclusively on the **training split**. The Validation and Test sets are frozen at the
> point of the initial split and must never be read, modified, or used for weight
> calculations by this agent. Any model evaluation must happen on the purely real,
> mathematically untouched Test set.

---

## Cloning (with Git LFS)

The two large binaries — `Dataset.zip` (~363 MB) and `solidifi-multi.tar` (~184 MB,
the prebuilt Docker image) — are stored in **Git LFS**, so you must have git-lfs
installed *before* cloning for them to download automatically.

```bash
# 1. Install git-lfs once per machine:
#    macOS:           brew install git-lfs
#    Debian/Ubuntu:   sudo apt-get install git-lfs
#    Windows:         ships with Git for Windows, or https://git-lfs.com
git lfs install

# 2. Clone — the LFS files come down automatically:
git clone https://github.com/chukynya/dive-dataset-augmentation.git
```

Already cloned **without** git-lfs? You'll have small pointer files instead of the
real binaries. Fix it with:

```bash
git lfs install
git lfs pull
```

Verify you got the real files (not pointers): `git lfs ls-files` should list both,
and their sizes should be ~363 MB / ~184 MB.

> [!NOTE]
> GitHub's free LFS tier is **1 GB storage + 1 GB/month bandwidth**. Each full
> clone/pull of these files draws on that monthly bandwidth, so frequent clones
> can hit the limit.

---

## The 8 Labels

`Reentrancy`, `Access Control`, `Arithmetic`, `Unchecked Return Values`, `DoS`,
`Bad Randomness`, `Front Running`, `Time manipulation` — each a binary column (1 = present).

---

## Folder Structure

```
Dataset/
├── DIVE_Labels.csv                      ← Original raw labels (READ-ONLY after split)
├── Bytecode_filled.csv                  ← contractID, contractAddress, bytecode
├── Transaction-based.csv               ← Per-contract transaction features
├── Source/
│   └── <contractID>.sol                 ← Original real Solidity source files
├── splits/
│   ├── split_manifest.json              ← Split metadata & reproducibility info
│   ├── Train_Labels.csv                 ← 70% real contracts (training partition)
│   ├── Train_Labels_append.csv          ← Bug-injected synthetic labels (appended by agent)
│   ├── Val_Labels.csv                   ← 10% real contracts (FROZEN — never touched)
│   └── Test_Labels.csv                  ← 20% real contracts (FROZEN — never touched)
├── buggy/                               ← SolidiFI output: bug-injected .sol files + logs
│   ├── <BugType>/
│   │   ├── buggy_<id>.sol               ← Injected contract
│   │   └── BugLog_<id>.csv              ← Injection log (location, bug type, approach)
│   └── ...
└── final/                               ← Ready-to-use dataset (assembled after injection)
    ├── Train_Labels.csv                 ← Combined labels: real train + synthetic (parent)
    ├── Val_Labels.csv                   ← Labels: real validation only (parent)
    ├── Test_Labels.csv                  ← Labels: real test only (parent)
    ├── train/
    │   ├── <contractID>.sol             ← Real training .sol files
    │   ├── buggy_<id>.sol               ← Bug-injected .sol files
    │   └── bytecode/                    ← Compiled bytecode for training contracts
    ├── val/
    │   ├── <contractID>.sol             ← Real validation .sol files
    │   └── bytecode/                    ← Compiled bytecode for validation contracts
    └── test/
        ├── <contractID>.sol             ← Real test .sol files
        └── bytecode/                    ← Compiled bytecode for test contracts
```

| Folder / File | Contents | Purpose |
|---|---|---|
| `DIVE_Labels.csv` | 22,330 real contracts × 8 labels | **Source of truth** — original ground-truth labels. READ-ONLY after the initial split. |
| `Bytecode_filled.csv` | `contractID, contractAddress, bytecode` | EVM bytecode for real contracts. |
| `Transaction-based.csv` | Per-contract transaction features | On-chain behavioral features. |
| `Source/<id>.sol` | Original Solidity source, one file per `contractID` | Real contract source code. |
| `splits/Train_Labels.csv` | ~70% of real contracts (labels only) | Training partition — bug injection reads from here. |
| `splits/Train_Labels_append.csv` | Bug-injected contract labels | Appended by the agent each iteration. Combined with `Train_Labels.csv` for training. |
| `splits/Val_Labels.csv` | ~10% of real contracts (labels only) | Hyperparameter tuning — **FROZEN, 100% real**. |
| `splits/Test_Labels.csv` | ~20% of real contracts (labels only) | Final evaluation — **FROZEN, 100% real**. |
| `splits/split_manifest.json` | Split metadata | Reproducibility record. |
| `buggy/<BugType>/` | SolidiFI output per bug type | Bug-injected `.sol` files and injection logs. |
| `final/` | Assembled dataset with `train/`, `val/`, `test/` subdirs | **The ready-to-use dataset.** `.sol` files and bytecode per split, label CSVs at parent level. |

### Split Philosophy

The split is performed **before** any synthetic augmentation (bug injection):

```
DIVE_Labels.csv (22,330 real contracts)
        │
        ├── 70%  →  Train_Labels.csv     ← Bug injection targets THIS partition only
        ├── 10%  →  Val_Labels.csv       ← Frozen, real only
        └── 20%  →  Test_Labels.csv      ← Frozen, real only
```

After augmentation, the training set grows while validation and test remain fixed.
The final distribution is **not** a clean 70/10/20 — it shifts because bug-injected
contracts are added only to train. This is intentional and correct.

### Guarantees

- **Multi-label stratified** split (seed 42) — rare classes are spread across folds.
- **Synthetic (bug-injected) data lives in `train` only.** `val` and `test` are **100% real**.
- **No leakage:** every injected contract is derived from a training-set source contract;
  the agent never reads validation or test data.
- **ID convention:** real `contractID` ≤ 22,330; bug-injected files are prefixed `buggy_`.

---

## Augmentation Method: SolidiFI Bug Injection

Instead of generating contracts from scratch via LLMs, this pipeline uses
**[SolidiFI](https://github.com/DependableSystemsLab/SolidiFI)** — an automated bug injection
framework that takes **real, compilable** `.sol` source files and injects vulnerability patterns
into them via AST-guided code snippet insertion, code transformation, and security mechanism
weakening.

### How SolidiFI Works

SolidiFI uses three injection approaches:

| Approach | Description |
|---|---|
| **Code Snippet Injection** | Parses the contract AST, identifies valid injection points (variable declarations, expression statements, function/modifier blocks), and inserts pre-written vulnerable code snippets from the `bugs/` directory. |
| **Code Transformation** | Replaces secure patterns with insecure equivalents (e.g. `msg.sender == owner` → `tx.origin = owner`, `uint256` → `uint8`). Configured in `code_trans.conf`. |
| **Security Mechanism Weakening** | Comments out or removes existing security checks (e.g. `revert()` → `//revert()`). Configured in `sec_methods.conf`. |

### SolidiFI Bug Types → DIVE Labels Mapping

| SolidiFI Bug Type | DIVE Label |
|---|---|
| `Re-entrancy` | Reentrancy |
| `Timestamp-Dependency` | Time manipulation |
| `Unchecked-Send` | Unchecked Return Values |
| `Unhandled-Exceptions` | Unchecked Return Values |
| `TOD` (Transaction Order Dependence) | Front Running |
| `Overflow-Underflow` | Arithmetic |
| `tx.origin` | Access Control |

> [!NOTE]
> SolidiFI's 7 bug types cover 6 of the 8 DIVE labels. **DoS** and **Bad Randomness** are
> not directly covered by SolidiFI's built-in bug snippets. These may require custom bug
> snippets to be added to the `bugs/` directory (see Section B below), or alternative
> augmentation strategies.

### SolidiFI Usage

```bash
# Inject a single bug type into a contract
python3 solidifi.py -i <path-to-contract.sol> <Bug-type>

# Example: inject Timestamp-Dependency bugs into contract 1.sol
python3 solidifi.py -i Dataset/Source/1.sol Timestamp-Dependency

# Output: buggy/Timestamp-Dependency/buggy_1.sol + BugLog_1.csv
```

Each injection produces:
- `buggy_<id>.sol` — the contract with bugs injected
- `BugLog_<id>.csv` — a log recording each injection point: `loc, length, bug type, approach`

---

## Class Distribution (Real Contracts, n = 22,330)

| Class | Positives | % | | Class | Positives | % |
|---|---|---|---|---|---|---|
| Access Control | 16,723 | 74.9 | | Time manipulation | 6,322 | 28.3 |
| Reentrancy | 11,400 | 51.1 | | Unchecked Return Values | 5,911 | 26.5 |
| Arithmetic | 9,542 | 42.7 | | DoS | 3,781 | 16.9 |
| | | | | Bad Randomness | 634 | 2.8 |
| | | | | Front Running | 606 | 2.7 |

The bug injection targets the rarest classes (Front Running, Bad Randomness, DoS).

---

## File Schemas

| File | Columns |
|---|---|
| `DIVE_Labels.csv` | `contractID` + 8 label columns |
| `Bytecode_filled.csv` | `contractID, contractAddress, bytecode` |
| `Transaction-based.csv` | per-contract transaction features (`contractID, NoOfTransactions, …`) |
| `Source/<id>.sol` | original Solidity source, one file per `contractID` |
| `splits/*.csv` | `contractID` + 8 label columns |
| `buggy/<BugType>/BugLog_*.csv` | `loc, length, bug type, approach` |
| `final/*.csv` | `contractID` + 8 label columns |
| `final/{train,val,test}/*.sol` | Solidity source files per split |

---

## Load Example

```python
import pandas as pd

LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]

# Load from final/ — the assembled, ready-to-use dataset
train_labels = pd.read_csv("Dataset/final/Train_Labels.csv")
val_labels   = pd.read_csv("Dataset/final/Val_Labels.csv")
test_labels  = pd.read_csv("Dataset/final/Test_Labels.csv")

y_train = train_labels[LABELS]
y_val   = val_labels[LABELS]
y_test  = test_labels[LABELS]
```

---
---

# AUTONOMOUS AGENT PIPELINE — Bug Injection Rulebook

**Your objective**: Systematically inject bugs into real Solidity contracts from the training
partition to balance the vulnerability dataset. Each iteration you must: read the
**training-only** CSV counts → select a target contract and bug type by weight → run
SolidiFI injection → save the output → update the labels CSV → update this file → loop.

Do not stop until the session ends or you are told to stop.

---

## PIPELINE — Follow Every Step, Every Iteration

---

### STEP 0 — Split the Raw Data (One-Time Setup)

> This step runs **once**, before any bug injection begins. If the split files already exist, skip to Step 1.

1. Read the original `Dataset/DIVE_Labels.csv` (22,330 real contracts).
2. Perform a **stratified multi-label split** into three partitions:

   | Split          | Ratio | Output File                         | Purpose                              |
   |----------------|-------|-------------------------------------|--------------------------------------|
   | **Train**      | 70%   | `Dataset/splits/Train_Labels.csv`   | Bug injection + model training       |
   | **Validation** | 10%   | `Dataset/splits/Val_Labels.csv`     | Hyperparameter tuning                |
   | **Test**       | 20%   | `Dataset/splits/Test_Labels.csv`    | Final evaluation only                |

3. Use `iterative_train_test_split` from `scikit-multilearn` (or equivalent stratified multi-label splitter) seeded with `random_state=42` for reproducibility.
   - First split: 70% train vs 30% remainder.
   - Second split: split the 30% remainder into 1/3 validation (≈10% of total) and 2/3 test (≈20% of total).
4. All three output CSVs share the same column schema:
   ```
   contractID,Reentrancy,Access Control,Arithmetic,Unchecked Return Values,DoS,Bad Randomness,Front Running,Time manipulation
   ```
5. Create a lockfile `Dataset/splits/split_manifest.json` recording:
   ```json
   {
     "source": "Dataset/DIVE_Labels.csv",
     "source_rows": 22330,
     "split_ratios": {"train": 0.70, "val": 0.10, "test": 0.20},
     "random_state": 42,
     "train_rows": "<n>",
     "val_rows": "<n>",
     "test_rows": "<n>",
     "created_utc": "<ISO-8601 timestamp>",
     "method": "iterative_train_test_split"
   }
   ```
6. **Lock the Validation and Test sets away.** After this step, the agent must never touch `Val_Labels.csv` or `Test_Labels.csv` again. All subsequent steps operate **only** on the training partition.

> [!IMPORTANT]
> If `Dataset/splits/Train_Labels.csv` already exists and `split_manifest.json` is present, verify the manifest's `source_rows` matches the current `DIVE_Labels.csv` row count. If they match, skip this step entirely. If they don't match, **STOP and alert the user** — the raw data has changed and a re-split decision is needed.

---

### STEP 1 — Read Current Distribution From Disk (Train Only)

Read these two CSV files:

| File | Notes |
|------|-------|
| `Dataset/splits/Train_Labels.csv` | Training partition of the real dataset — created in Step 0 |
| `Dataset/splits/Train_Labels_append.csv` | Bug-injected additions to training set — create if missing |

Both files share the same column schema (exact names, case-sensitive):
```
contractID,Reentrancy,Access Control,Arithmetic,Unchecked Return Values,DoS,Bad Randomness,Front Running,Time manipulation
```

Compute:
- `total_train_contracts` = total row count across both files
- `count[class]` = sum of that column across both files (for all 8 vulnerability classes)

> **Always read from disk at the start of every loop iteration.** Do not rely solely on the cached table at the bottom of this file — it may be one contract behind if another agent is running in parallel.

> [!WARNING]
> Do **NOT** read `Dataset/DIVE_Labels.csv`, `Dataset/splits/Val_Labels.csv`, or `Dataset/splits/Test_Labels.csv` in this step. Only the training partition files are used for weight calculations.

---

### STEP 2 — Compute Weights and Select Bug Type

**Weight formula** (inversely proportional to representation):
```
weight[class] = max(count.values()) / (count[class] + 1)
```
Higher weight = more underrepresented = higher selection priority.

**Select the primary vulnerability class:**
- Pick the class with the highest weight.
- Within a single session, rotate — do not pick the same primary class consecutively. If the top class was picked last iteration, pick the second-highest instead.

**Map the selected DIVE label to a SolidiFI bug type:**

| DIVE Label | SolidiFI Bug Type |
|---|---|
| Reentrancy | `Re-entrancy` |
| Access Control | `tx.origin` |
| Arithmetic | `Overflow-Underflow` |
| Unchecked Return Values | `Unchecked-Send` or `Unhandled-Exceptions` (alternate) |
| Front Running | `TOD` |
| Time manipulation | `Timestamp-Dependency` |
| DoS | ⚠️ No built-in SolidiFI type — requires custom snippets in `bugs/DoS/` |
| Bad Randomness | ⚠️ No built-in SolidiFI type — requires custom snippets in `bugs/Bad-Randomness/` |

**Co-occurring vulnerabilities**: SolidiFI can inject **multiple bug types** into the same contract sequentially. After the primary injection, select additional bug types using the co-occurrence table below and run additional injection passes on the same (already-injected) file.

| Primary Class           | Co-occurrence rates (use as relative selection weights)                                   |
|-------------------------|------------------------------------------------------------------------------------------|
| Reentrancy              | Access Control 94%, Arithmetic 53%, Unchecked Return Values 40%, Time manipulation 33%, DoS 24% |
| Access Control          | Reentrancy 64%, Arithmetic 50%, Unchecked Return Values 34%, Time manipulation 28%, DoS 21% |
| Arithmetic              | Access Control 88%, Reentrancy 63%, Unchecked Return Values 40%, Time manipulation 34%, DoS 21% |
| Time manipulation       | Access Control 74%, Reentrancy 59%, Arithmetic 51%, Unchecked Return Values 38%, DoS 24% |
| Unchecked Return Values | Access Control 96%, Reentrancy 77%, Arithmetic 64%, Time manipulation 41%, DoS 28%       |
| DoS                     | Access Control 92%, Reentrancy 71%, Arithmetic 52%, Unchecked Return Values 43%, Time manipulation 40% |
| Bad Randomness          | Access Control 93%, Reentrancy 73%, Arithmetic 57%, Time manipulation 41%, DoS 37%       |
| Front Running           | Access Control 94%, Reentrancy 70%, DoS 49%, Arithmetic 42%, Time manipulation 38%       |

---

### STEP 3 — Select Source Contract for Injection

Pick a source `.sol` file from `Dataset/Source/` for injection:

1. The contract's `contractID` must be in `Dataset/splits/Train_Labels.csv` (training set only).
2. Prefer contracts that have **not** already been used as injection bases in this session.
3. The file must exist and be non-empty.
4. Avoid contracts that already have the target vulnerability (label = 1 in Train_Labels.csv) — inject into contracts that are currently **clean** for the target class, so the injection creates a meaningful new positive.

---

### STEP 4 — Run SolidiFI Bug Injection

Execute SolidiFI from the `work/SolidiFI/` directory:

```bash
python3 solidifi.py -i <path-to-source.sol> <Bug-type>
```

SolidiFI will:
1. Compile the contract to verify it's valid
2. Generate the AST (`ast/<id>.json`)
3. Identify injection points in the source
4. Insert bug snippets from `bugs/<Bug-type>/ts/` (statement-level) and `bugs/<Bug-type>/tf/` (function/block-level)
5. Write output to `buggy/<Bug-type>/buggy_<filename>.sol`
6. Write injection log to `buggy/<Bug-type>/BugLog_<filename>.csv`

**For multi-bug injection**: run SolidiFI multiple times on the same file, once per bug type. Use the output of the previous pass as input for the next pass.

> [!WARNING]
> If SolidiFI reports "Contract file contains compilation errors" or fails to generate the AST, skip this contract and select another one in Step 3.

---

### STEP 5 — Assign Contract ID and Build the Label Line

- `contract_id` = `buggy_<original_contractID>_<Bug-type>` (e.g. `buggy_1234_Re-entrancy`)
- `labels_line` = one CSV row in this exact column order:
  ```
  <contract_id>,<Reentrancy>,<Access Control>,<Arithmetic>,<Unchecked Return Values>,<DoS>,<Bad Randomness>,<Front Running>,<Time manipulation>
  ```
  Start with the original contract's labels from `Train_Labels.csv`, then set the injected bug type's label(s) to `1`.

---

### STEP 6 — Copy Output to buggy/ Directory

SolidiFI writes output directly to `buggy/<Bug-type>/`. Verify the output exists:
- `buggy/<Bug-type>/buggy_<filename>.sol` — the injected contract
- `buggy/<Bug-type>/BugLog_<filename>.csv` — the injection log

If multi-bug injection was performed, the final file contains all injected bugs.

---

### STEP 7 — Append the Label Row to Training CSV

- File: `Dataset/splits/Train_Labels_append.csv`
- If the file does not exist yet, write the header row first:
  ```
  contractID,Reentrancy,Access Control,Arithmetic,Unchecked Return Values,DoS,Bad Randomness,Front Running,Time manipulation
  ```
- Append exactly one new line: the `labels_line` from Step 5

> [!CAUTION]
> Only append to `Train_Labels_append.csv` inside `Dataset/splits/`. Never write to `Val_Labels.csv`, `Test_Labels.csv`, or the original `DIVE_Labels.csv`. The synthetic data must remain confined to the training partition.

---

### STEP 8 — Update the Live Distribution Table in This File

Rewrite only the block between `<!-- LIVE_DISTRIBUTION_START -->` and `<!-- LIVE_DISTRIBUTION_END -->` at the bottom of this file.

Update it with: incremented counts for the classes you just injected, `total_train_contracts + 1`, recalculated weights and gaps, and the current UTC timestamp. Sort rows by weight descending (highest priority at top).

Format each row as:
```
| <class> | <new_count> | <target> | <new_gap> | <new_weight>x | <priority_emoji> <LEVEL> |
```

Priority levels: weight ≥ 10.0 → 🔴 CRITICAL, ≥ 3.5 → 🟠 HIGH, ≥ 2.0 → 🟡 MEDIUM, ≥ 1.2 → 🟢 LOW, else → ⚪ LOWEST

> Note: The distribution table reflects **training-set-only** counts. Targets are scaled to the training partition size (not the full dataset).

---

### STEP 9 — Assemble the final/ Directory (Periodic or End-of-Session)

After a batch of injections is complete (or at the end of a session), assemble the `final/` directory:

1. **Create directory structure**: `final/train/`, `final/val/`, `final/test/`
2. **Copy .sol files**:
   - `final/train/` ← all `.sol` files whose `contractID` is in `Train_Labels.csv` (from `Source/`) + all bug-injected `.sol` files (from `buggy/`)
   - `final/val/` ← all `.sol` files whose `contractID` is in `Val_Labels.csv` (from `Source/`)
   - `final/test/` ← all `.sol` files whose `contractID` is in `Test_Labels.csv` (from `Source/`)
3. **Compile bytecode** (if needed): compile each `.sol` and place bytecode in `final/{split}/bytecode/`
4. **Copy label CSVs** to `final/` parent directory:
   - `final/Train_Labels.csv` ← concatenation of `splits/Train_Labels.csv` + `splits/Train_Labels_append.csv`
   - `final/Val_Labels.csv` ← copy of `splits/Val_Labels.csv`
   - `final/Test_Labels.csv` ← copy of `splits/Test_Labels.csv`

> [!IMPORTANT]
> The `final/` directory is the **deliverable**. It is self-contained: a consumer of this dataset only needs `final/` to train and evaluate a model.

---

### STEP 10 — Evaluation Philosophy (Reference — Do Not Execute)

This step is **not** executed by the injection agent. It documents the downstream evaluation contract for the researcher:

1. **Train** the model on: `final/Train_Labels.csv` (real training data + bug-injected augmentation).
2. **Tune hyperparameters** using: `final/Val_Labels.csv` (real validation data, zero synthetic contamination).
3. **Final evaluation** on: `final/Test_Labels.csv` (purely real, mathematically untouched test data).

This ensures the model's reported performance reflects its ability to generalize to **real-world contracts it has never seen**, not its ability to memorize injected patterns.

---

### STEP 11 — Loop

Return to **STEP 1**. Reread the CSV files from disk (your new contract is already there), recompute everything, and inject the next contract. Continue until the session ends.

---

## SECTION B — Bug Injection Rules

### B1 — Contract Selection Criteria

- Only inject into contracts from the **training partition** (`Train_Labels.csv`).
- Prefer contracts that are **clean** for the target vulnerability class (label = 0).
- Avoid re-injecting the same source contract with the same bug type twice.
- Prefer contracts with more complex structure (more functions, modifiers, state variables) — these provide more injection points and produce more realistic results.

### B2 — Multi-Bug Injection

- SolidiFI supports injecting one bug type per invocation.
- For multi-label contracts, run SolidiFI sequentially: inject bug type A, then use the output as input for bug type B.
- The co-occurrence table in Step 2 guides which bug types to combine.
- After multi-bug injection, the label line must reflect **all** injected bug types (logical OR with the original labels).

### B3 — Custom Bug Snippets (DoS, Bad Randomness)

SolidiFI does not ship with built-in snippets for DoS or Bad Randomness. To inject these:

1. Create directories `bugs/DoS/ts/`, `bugs/DoS/tf/`, `bugs/Bad-Randomness/ts/`, `bugs/Bad-Randomness/tf/`
2. Add `bug_types.conf` entries:
   ```ini
   [8]
   bug_type_id=8
   bug_type=DoS
   bug_type_dir=DoS

   [9]
   bug_type_id=9
   bug_type=Bad-Randomness
   bug_type_dir=Bad-Randomness
   ```
3. Write bug snippets:
   - **DoS**: unbounded loops over dynamic arrays, gas-griefing patterns, external call in loop
   - **Bad Randomness**: `block.timestamp` / `block.number` / `blockhash` as entropy source

### B4 — Injection Logging

Every injection produces a `BugLog_<id>.csv` with columns: `loc, length, bug type, approach`.
This log is essential for:
- Verifying that bugs were actually injected (not just attempted)
- Tracing which lines contain injected vulnerabilities
- Auditing the dataset for quality

### B5 — Forbidden Patterns

| Pattern | Why |
|---------|-----|
| Injecting into validation or test contracts | Data leakage — contaminates evaluation |
| Injecting the same bug type into a contract that already has it (label = 1) | Doesn't add new positive signal |
| Ignoring SolidiFI compilation check failures | Produces non-compilable contracts that are useless for training |
| Skipping the BugLog verification | Cannot confirm injection actually succeeded |

---

## DATA SPLIT REFERENCE

```
Dataset/
├── DIVE_Labels.csv                      ← Original raw labels (READ-ONLY after split)
├── splits/
│   ├── split_manifest.json              ← Split metadata & reproducibility info
│   ├── Train_Labels.csv                 ← 70% real contracts (training partition)
│   ├── Train_Labels_append.csv          ← Bug-injected contracts (appended by agent)
│   ├── Val_Labels.csv                   ← 10% real contracts (FROZEN — never touched)
│   └── Test_Labels.csv                  ← 20% real contracts (FROZEN — never touched)
├── buggy/
│   └── <BugType>/                       ← SolidiFI injection outputs
│       ├── buggy_<id>.sol
│       └── BugLog_<id>.csv
└── final/                               ← Assembled deliverable
    ├── Train_Labels.csv                 ← Labels CSV (real + injected)
    ├── Val_Labels.csv                   ← Labels CSV (real only)
    ├── Test_Labels.csv                  ← Labels CSV (real only)
    ├── train/                           ← .sol files + bytecode/
    ├── val/                             ← .sol files + bytecode/
    └── test/                            ← .sol files + bytecode/
```

---

## LIVE DISTRIBUTION STATUS

> Cached snapshot — **training split only**. Always recompute from disk in Step 1. Updated by the agent after every injected contract.

<!-- LIVE_DISTRIBUTION_START -->
_Last updated: awaiting first run after train/val/test split — run Step 0 to initialize_
| Vulnerability Class | Current (Train) | Target | Gap | Weight | Priority |
|---|---|---|---|---|---|
| _Run Step 0 to populate_ | — | — | — | — | — |
<!-- LIVE_DISTRIBUTION_END -->
