# Running the injection campaign on another PC

The workload runs **entirely inside Docker**. The target PC needs only Docker —
no Python, no solc, no pip installs. Everything else (SolidiFI code, bug
snippets, scripts, `Source/`, the prebuilt job list) is mounted from this repo.

---

## What to copy to the other PC

> **Easiest path: `git clone` with Git LFS.** Both `Dataset.zip` and
> `solidifi-multi.tar` are stored in Git LFS, so if you `git lfs install` first
> and then clone, you get the repo *and* the Docker image tarball in one step —
> skip the manual copy below. See "Cloning (with Git LFS)" in the root README.
> (Then `unzip Dataset.zip` if the `Dataset/` tree isn't already present.)

If you'd rather copy files manually, two things, into the same parent folder:

1. **This whole repo folder** (`dataset-generation/`). The big part is
   `Dataset/Source/` (22,330 `.sol` files). The prebuilt inputs the run needs
   are already inside it:
   - `work/cache/injection_jobs.json`      (17,892 queued jobs)
   - `work/cache/holdout_canon_hashes.json` (val/test leakage gate)
   - `work/cache/real_canon_bytecode.json`
   - `work/scripts/`, `work/SolidiFI/` (code + snippets)
   - `Dataset/splits/` (the bytecode-deduped split + locked manifest)

2. **The Docker image tarball** `solidifi-multi.tar`, placed in the repo root
   (next to `Dataset/` and `work/`). Produced on this PC with:
   ```bash
   docker save solidifi-multi -o solidifi-multi.tar
   ```
   (~800 MB. Optional: `gzip solidifi-multi.tar` to shrink for transfer, then
   `gunzip` on the target — `docker load` also accepts the `.gz` directly if you
   rename it back to `.tar`.)

> Do **not** copy `Dataset/buggy/`, `Dataset/final/`, or
> `work/cache/synthetic_bytecode.csv` — those are outputs and will be created by
> the run. If they exist from a partial run, delete them first for a clean start.

---

## Prereqs on the target PC

- Docker installed and the daemon running (`docker info` succeeds).
- That's it.

---

## Tuning the per-class augmentation

How many synthetic contracts to emit per class lives in **one file**:
`work/targets.json`. It's optional — if absent, the built-in defaults apply
(Front Running / Bad Randomness / DoS = 3,500 each; the 5 majority classes =
500 each). To customise:

```bash
cp work/targets.example.json work/targets.json
# then edit the numbers
```

Each class has two knobs:
- **`target`** — how many synthetic contracts to actually emit (the injector
  stops the class here).
- **`cap`** — how many injection jobs to queue. Must be `>= target`; the slack
  absorbs injection + dedup attrition. **`cap` is the ceiling for run-time
  tuning** (see below).

There are two ways to apply a change, depending on whether you can run Python:

1. **Run-time re-tune (target PC, no rebuild, Docker-only).** Edit the
   `target` values in `work/targets.json` and just re-run. The injector reads
   this file every run and overrides its stop counts. You can dial any class
   **down freely, or up to its `cap`** — beyond `cap` there simply aren't
   enough queued jobs. The shipped `injection_jobs.json` is queued at the
   default caps (4,800 / 900), so that's your current ceiling per class.

2. **Build-time re-tune (source PC, needs Python).** To change `cap` (raise the
   ceiling) you must regenerate the job list:
   ```bash
   python work/scripts/build_injection_jobs.py     # reads work/targets.json
   ```
   then re-copy `work/cache/injection_jobs.json` to the target PC. Do this only
   if you want a higher ceiling than the queued caps allow.

> Rule of thumb: queue generous `cap`s once on the source PC, then tune the
> `target`s freely on the target PC across runs without ever rebuilding.

---

## Run it

From the repo root on the target PC:

```bash
bash work/run_injection.sh
```

To leave it running overnight and survive logout:

```bash
nohup bash work/run_injection.sh > work/cache/run.log 2>&1 &
```

The script:
1. Loads `solidifi-multi.tar` if the image isn't already present.
2. Runs injection in the container (the long step — appends to
   `Dataset/splits/Train_Labels_append.csv` and
   `work/cache/synthetic_bytecode.csv`, writes `Dataset/buggy/`).
3. Assembles `Dataset/final/` (also in-container).

---

## What the run produces

- `Dataset/buggy/<BugType>/buggy_<id>_<type>.sol` + `BugLog_*.csv`
- `Dataset/splits/Train_Labels_append.csv` — synthetic label rows
- `Dataset/final/` — the self-contained deliverable (train/val/test `.sol`,
  label CSVs, `Synthetic_Bytecode.csv`)

**Targets:** Front Running / Bad Randomness / DoS = 3,500 each; the 5 majority
classes = 500 each (~13,000 synthetic rows, attrition permitting). The injector
stops each class at its target.

---

## Leakage guarantees enforced by the run (no manual checking needed)

- **Bytecode-level split.** The corpus was deduplicated by canonical
  (metadata-stripped) runtime bytecode *before* splitting, so no compiled
  program spans train/val/test. (`step0_split.py`)
- **In-container gate.** Every injected contract is compiled, canon-hashed, and
  **rejected** if its bytecode matches any val/test contract or any
  already-emitted synthetic. (`incontainer_inject.py`)
- **Final assert.** `assemble_final.py` fails loud if any train hash (real or
  synthetic) intersects the val/test holdout, or if synthetic bytecodes aren't
  unique.

If any assert fires, the run exits non-zero — check `work/cache/run.log`.

---

## Monitoring progress

```bash
tail -f work/cache/run.log                       # if launched with nohup
wc -l Dataset/splits/Train_Labels_append.csv      # rows emitted so far
```

The injector prints a progress line every 50 contracts with per-class counts
and rejection tallies (`rej_holdout`, `rej_dup`).

---

## Note on scale (base reuse)

Only ~5,300 train contracts compile under the installed solc versions (most of
the rest are Solidity 0.8.x, which SolidiFI's legacy AST can't parse). To reach
the requested 2–3x volume, each base is reused across **different** bug types
(at most once per type). The bytecode gate guarantees every emitted row is still
a distinct compiled program with zero holdout leakage — what's relaxed is
structural diversity of the base skeletons. To fall back to a single-use-base
dataset, filter `Train_Labels_append.csv` to one row per base ID
(`buggy_<id>_*`); it's a strict subset, so nothing is lost by generating the
larger set first.
