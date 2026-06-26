#!/usr/bin/env bash
# Native Linux injection + assembly runner (no Docker).
#
# Requires:
#   - A local .venv created in the repo root with py-solc-x, ijson, pandas installed
#     (run:  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)
#   - solc versions installed via py-solc-x. Quick install in Python:
#       from solcx import install_solc
#       for v in ["0.4.26","0.5.17","0.6.12","0.7.6","0.8.20"]: install_solc(v)
#
# Usage (from the repo root):
#     bash work/run_injection.sh
# To detach and keep running after logout:
#     nohup bash work/run_injection.sh > work/cache/run.log 2>&1 &

set -euo pipefail
trap 'echo "[!] injection interrupted — progress saved. Re-run to continue." >&2' ERR

# repo root = parent of this script's dir
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

# When run in a terminal, tee a full copy of this run's telemetry to
# work/cache/run.log (screen + file). Skipped when output is already redirected.
if [ -t 1 ]; then
  mkdir -p work/cache
  exec > >(tee work/cache/run.log) 2>&1
fi

PYTHON=".venv/bin/python3"

echo "[*] repo: $REPO"

# --- sanity checks ---
if [ ! -x "$PYTHON" ]; then
  echo "[!] .venv not found. Create it first:" >&2
  echo "    python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

for f in work/cache/injection_jobs.json work/scripts/canon_bytecode.py \
         Dataset/DIVE_Labels.csv Dataset/Bytecode_filled.csv; do
  [ -f "$f" ] || { echo "[!] missing required input: $f" >&2; exit 1; }
done
echo "[*] inputs present"

# --- STEP 0a: generate train/val/test splits (first time only) ---
# Produces Dataset/splits/{Train,Val,Test}_Labels.csv, split_manifest.json,
# work/cache/real_canon_bytecode.json, and holdout_canon_hashes.json.
# Guard: skip if manifest already exists (splits are locked and must not change).
if [ ! -f Dataset/splits/split_manifest.json ]; then
  echo "[*] generating splits (first run only) ..."
  "$PYTHON" work/scripts/step0_split.py
  echo "[*] splits ready"
else
  echo "[*] splits exist, skipping step0"
fi

# confirm the cache files now exist (either pre-existing or just produced)
for f in work/cache/holdout_canon_hashes.json work/cache/real_canon_bytecode.json; do
  [ -f "$f" ] || { echo "[!] missing cache file after step0: $f" >&2; exit 1; }
done

echo "[*] regenerating snippets ..."
"$PYTHON" work/scripts/gen_v08_snippets.py
"$PYTHON" work/scripts/gen_custom_snippets.py
"$PYTHON" work/scripts/gen_v04_snippets.py
echo "[*] snippets ready"

# --- STEP 0.5: ensure all needed solc versions are installed ---
echo "[*] installing solc versions (skips already-installed) ..."
"$PYTHON" -c "
import json, solcx
with open('work/cache/injection_jobs.json') as f:
    data = json.load(f)
needed = set(j['solc'] for j in data['jobs'])
installed = {str(v) for v in solcx.get_installed_solc_versions()}
missing = sorted(needed - installed)
if missing:
    print(f'  installing {len(missing)} missing versions: {missing[:5]}...')
    for v in missing:
        solcx.install_solc(v)
    print(f'  done')
else:
    print('  all versions present')
"
echo "[*] solc versions ready"
mkdir -p Dataset/splits

# --- STEP 1: injection (the long part) ---
echo "[*] $(date) starting injection ..."
"$PYTHON" -u work/SolidiFI/incontainer_inject.py
echo "[*] $(date) injection done"

# --- STEP 2: assemble final/ ---
echo "[*] $(date) assembling final/ ..."
"$PYTHON" -u work/scripts/assemble_final.py
echo "[*] $(date) ALL DONE -> Dataset/final/"
