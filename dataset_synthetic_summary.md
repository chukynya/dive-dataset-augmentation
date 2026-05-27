# Smart Contract Synthetic Generation — Autonomous Agent Rulebook

You are an expert Solidity developer and security auditor. This file is your complete, self-contained instruction set. It can be fed as a prompt to any agent with file system access — Claude Code, Cursor, Zed, Antigravity, VS Code Agent, or any other agentic IDE.

**Your objective**: Repeatedly generate realistic, compilable Solidity smart contracts to balance a machine learning vulnerability dataset. Each iteration you must: read the **training-only** CSV counts → pick vulnerabilities by weight → generate the contract → save the file → update the labels CSV → update this file → loop.

> [!CAUTION]
> **Data-Leakage Prevention Rule**: All synthetic generation operates exclusively on the **training split**. The Validation and Test sets are frozen at the point of the initial split and must never be read, modified, or used for weight calculations by this agent. Any model evaluation must happen on the purely real, mathematically untouched Test set.

Do not stop until the session ends or you are told to stop.

---

## PIPELINE — Follow Every Step, Every Iteration

---

### STEP 0 — Split the Raw Data (One-Time Setup)

> This step runs **once**, before any synthetic generation begins. If the split files already exist, skip to Step 1.

1. Read the original `Dataset/DIVE_Labels.csv` (22,330 real contracts).
2. Perform a **stratified multi-label split** into three partitions:

   | Split       | Ratio | Output File                          | Purpose                   |
   |-------------|-------|--------------------------------------|---------------------------|
   | **Train**   | 70%   | `Dataset/splits/Train_Labels.csv`    | Synthetic generation + model training |
   | **Validation** | 15% | `Dataset/splits/Val_Labels.csv`      | Hyperparameter tuning     |
   | **Test**    | 15%   | `Dataset/splits/Test_Labels.csv`     | Final evaluation only     |

3. Use `iterative_train_test_split` from `scikit-multilearn` (or equivalent stratified multi-label splitter) seeded with `random_state=42` for reproducibility.
4. All three output CSVs share the same column schema:
   ```
   contractID,Reentrancy,Access Control,Arithmetic,Unchecked Return Values,DoS,Bad Randomness,Front Running,Time manipulation
   ```
5. Create a lockfile `Dataset/splits/split_manifest.json` recording:
   ```json
   {
     "source": "Dataset/DIVE_Labels.csv",
     "source_rows": 22330,
     "split_ratios": {"train": 0.70, "val": 0.15, "test": 0.15},
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
| `Dataset/splits/Train_Labels_append.csv` | Synthetic additions to training set — create if missing |

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

### STEP 2 — Compute Weights and Select Vulnerabilities

**Weight formula** (inversely proportional to representation):
```
weight[class] = max(count.values()) / (count[class] + 1)
```
Higher weight = more underrepresented = higher selection priority.

**Select the primary vulnerability class:**
- Pick the class with the highest weight.
- Within a single session, rotate — do not pick the same primary class consecutively. If the top class was picked last iteration, pick the second-highest instead.

**Select the total number of vulnerabilities for this contract:**

| Primary Class             | Total Vuln Count Rule                        |
|---------------------------|----------------------------------------------|
| Bad Randomness            | Always 3–5 (never appears alone in dataset)  |
| Front Running             | Always 3–5 (never appears alone in dataset)  |
| DoS                       | Prefer 3–4                                   |
| Unchecked Return Values   | Prefer 3–4                                   |
| Time manipulation         | 1 or 4–5 (bimodal — pick one of the two peaks) |
| Reentrancy / Arithmetic   | Prefer 2–3                                   |
| Access Control            | 1–3 (can appear alone)                       |

**Select co-occurring classes** (if total > 1):
After the primary class is selected, add co-occurring classes by sampling from the table below. Higher percentage = pick it first. Stop once you've reached the chosen total count.

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

### STEP 3 — Pick Pragma Version

Sample from this distribution every contract (do not reuse the same pragma repeatedly):

| Probability | Pragma Range                                               |
|-------------|-------------------------------------------------------------|
| 88%         | `^0.8.X` where X is a random integer 0–24                  |
| 8%          | `^0.4.X` where X is a random integer 11–26                 |
| 4%          | One of: `^0.5.X` (0–17), `^0.6.X` (0–12), `^0.7.X` (0–6) |

---

### STEP 4 — Assign Contract ID and Pre-build the Label Line

- `contract_id` = `synthetic_<unix_timestamp_milliseconds>` using the current real time
- `labels_line` = one CSV row in this exact column order:
  ```
  <contract_id>,<Reentrancy>,<Access Control>,<Arithmetic>,<Unchecked Return Values>,<DoS>,<Bad Randomness>,<Front Running>,<Time manipulation>
  ```
  Each field is `1` if that class is assigned to this contract, `0` otherwise.

- Build the metadata header block that will go at the top of the `.sol` file:
  ```
  /**
   * @dev DATASET_SYNTHETIC_METADATA
   * Format: contractID,Reentrancy,Access Control,Arithmetic,Unchecked Return Values,DoS,Bad Randomness,Front Running,Time manipulation
   * LABELS: <labels_line>
   */
  ```

---

### STEP 5 — Generate the Solidity Contract

Write the complete `.sol` file content following all rules in **SECTION B** below.

The metadata header from Step 4 must be the **first thing in the file**, before even the pragma line.

---

### STEP 6 — Save the Contract File

- Directory: `Dataset/Synthetic_LLMs/` — create it if it does not exist
- Filename: `synthetic_<timestamp>.sol` (same timestamp used in Step 4)
- Write the raw Solidity content directly — no markdown fences in the saved file

---

### STEP 7 — Append the Label Row to Training CSV

- File: `Dataset/splits/Train_Labels_append.csv`
- If the file does not exist yet, write the header row first:
  ```
  contractID,Reentrancy,Access Control,Arithmetic,Unchecked Return Values,DoS,Bad Randomness,Front Running,Time manipulation
  ```
- Append exactly one new line: the `labels_line` from Step 4 (without the `LABELS: ` prefix)

> [!CAUTION]
> Only append to `Train_Labels_append.csv` inside `Dataset/splits/`. Never write to `Val_Labels.csv`, `Test_Labels.csv`, or the original `DIVE_Labels.csv`. The synthetic data must remain confined to the training partition.

---

### STEP 8 — Update the Live Distribution Table in This File

Rewrite only the block between `<!-- LIVE_DISTRIBUTION_START -->` and `<!-- LIVE_DISTRIBUTION_END -->` at the bottom of this file.

Update it with: incremented counts for the classes you just generated, `total_train_contracts + 1`, recalculated weights and gaps, and the current UTC timestamp. Sort rows by weight descending (highest priority at top).

Format each row as:
```
| <class> | <new_count> | <target> | <new_gap> | <new_weight>x | <priority_emoji> <LEVEL> |
```

Priority levels: weight ≥ 10.0 → 🔴 CRITICAL, ≥ 3.5 → 🟠 HIGH, ≥ 2.0 → 🟡 MEDIUM, ≥ 1.2 → 🟢 LOW, else → ⚪ LOWEST

> Note: The distribution table now reflects **training-set-only** counts. Targets are scaled to the training partition size (not the full dataset).

---

### STEP 9 — Evaluation Philosophy (Reference — Do Not Execute)

This step is **not** executed by the generation agent. It documents the downstream evaluation contract for the researcher:

1. **Train** the model on: `Train_Labels.csv` + `Train_Labels_append.csv` (real training data + synthetic augmentation).
2. **Tune hyperparameters** using: `Val_Labels.csv` (real validation data, zero synthetic contamination).
3. **Final evaluation** on: `Test_Labels.csv` (purely real, mathematically untouched test data).

This ensures the model's reported performance reflects its ability to generalize to **real-world contracts it has never seen**, not its ability to memorize synthetic patterns.

---

### STEP 10 — Loop

Return to **STEP 1**. Reread the CSV files from disk (your new contract is already there), recompute everything, and generate the next contract. Continue until the session ends.

---

## SECTION B — Contract Generation Rules

### B1 — Structural Realism

- **Lines**: 200–750. Never below 100. Real dataset median is 367 lines.
- **Multiple contracts per file**: Always include ~4 Solidity structures — a main contract plus at least one interface (e.g. `IERC20`, `IERC721`), one library or base contract, and one helper/abstract contract. Real-world `.sol` files are never isolated single contracts.
- **Rotate archetypes** across contracts — never reuse the same template:
  `ERC-20 token` · `ERC-721 NFT` · `DEX / AMM pool` · `Lending protocol` · `Yield farming / staking` · `DAO governance` · `Lottery / prize draw` · `Auction` · `ICO / token sale` · `Multi-sig wallet` · `Vesting / timelock` · `Escrow` · `Bridge / cross-chain relay`
- **Completeness**: Always include events, custom modifiers, a constructor, realistic state variables. Vary naming conventions — mix camelCase, snake_case, and abbreviated identifiers across contracts.

### B2 — Vulnerability Integration

- **Natural developer mistakes only**: Vulnerabilities must be embedded as plausible logic flaws — wrong operation ordering, missing access guards, using block variables as entropy source, unbounded loops, state updates after external calls, etc.
- **No self-labelling**: Never write `// VULNERABLE`, `// BUG`, `// INSECURE`, or any comment that names a flaw. Real contracts do not annotate their own weaknesses.
- **Critical class focus**: If the assigned set includes **Bad Randomness**, **Front Running**, or **DoS**, design the contract's core business flow around that vulnerability. It must be structurally central, not a trivial add-on.
- **Weave multiple vulnerabilities together logically**:
  - Access Control gap → enables a Reentrancy drain
  - Time manipulation → bypasses a lock period → triggers an Arithmetic overflow
  - Front Running window → lives alongside a DoS griefing vector in the same settlement function

### B3 — Pragma Syntax Rules

| Version       | Arithmetic                                            | External calls              | Error handling                  |
|---------------|-------------------------------------------------------|-----------------------------|---------------------------------|
| 0.4.x – 0.7.x | Use `SafeMath` library for all arithmetic             | `addr.call.value(n)()`      | `require(cond, "msg")`          |
| 0.8.x+        | Built-in overflow protection; use `unchecked { }` **only** when Arithmetic is an assigned vulnerability | `addr.call{value: n}("")`   | Custom errors + `revert CustomError()` |

### B4 — Forbidden Patterns

| Pattern | Why |
|---------|-----|
| Reusing the same structural template | Model learns the template, not the vulnerability |
| Single contract per file | Dataset median is 4 structures per file |
| File under 100 lines | Statistical outlier — flags synthetic origin |
| Comments naming vulnerabilities | Real contracts never self-document flaws |
| Same pragma for every contract in a session | Creates a synthetic-vs-real shortcut feature |
| Missing events, modifiers, or constructor | Incomplete Solidity idiom — looks machine-generated |

---

## DATA SPLIT REFERENCE

```
Dataset/
├── DIVE_Labels.csv                      ← Original raw labels (READ-ONLY after split)
├── splits/
│   ├── split_manifest.json              ← Split metadata & reproducibility info
│   ├── Train_Labels.csv                 ← 70% real contracts (training partition)
│   ├── Train_Labels_append.csv          ← Synthetic contracts (appended by this agent)
│   ├── Val_Labels.csv                   ← 15% real contracts (FROZEN — never touched)
│   └── Test_Labels.csv                  ← 15% real contracts (FROZEN — never touched)
├── Synthetic_LLMs/
│   └── synthetic_*.sol                  ← Generated .sol files
└── Source/
    └── <contractID>.sol                 ← Original real .sol files
```

---

## LIVE DISTRIBUTION STATUS

> Cached snapshot — **training split only**. Always recompute from disk in Step 1. Updated by the agent after every saved contract.

<!-- LIVE_DISTRIBUTION_START -->
_Last updated: awaiting first run after train/val/test split — run Step 0 to initialize_
| Vulnerability Class | Current (Train) | Target | Gap | Weight | Priority |
|---|---|---|---|---|---|
| _Run Step 0 to populate_ | — | — | — | — | — |
<!-- LIVE_DISTRIBUTION_END -->