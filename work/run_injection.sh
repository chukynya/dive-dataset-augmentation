#!/usr/bin/env bash
# Portable overnight injection + assembly runner.
#
# Runs entirely inside the solidifi-multi container; the host only needs Docker.
# Everything else (SolidiFI code, bug snippets, scripts, Source/, the prebuilt
# injection_jobs.json and holdout hashes) is mounted from this repo, so the
# image itself never needs rebuilding.
#
# Usage (from the repo root, on the target PC):
#     bash work/run_injection.sh
# To detach and keep running after logout:
#     nohup bash work/run_injection.sh > work/cache/run.log 2>&1 &
#
# Prereqs on the target PC:
#   - Docker installed and the daemon running
#   - The solidifi-multi image present. If not, this script loads it from
#     ./solidifi-multi.tar (produced by `docker save` on the source PC).

set -euo pipefail
export MSYS_NO_PATHCONV=1   # harmless on Linux/macOS; stops Git-Bash mangling -v paths

# repo root = parent of this script's dir
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
IMAGE="solidifi-multi"
TAR="$REPO/solidifi-multi.tar"

echo "[*] repo: $REPO"

# --- ensure the image exists ---
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  if [ -f "$TAR" ]; then
    echo "[*] image not found; loading from $TAR"
    docker load -i "$TAR"
  else
    echo "[!] image '$IMAGE' missing and $TAR not found." >&2
    echo "    On the source PC run:  docker save $IMAGE -o solidifi-multi.tar" >&2
    echo "    then copy solidifi-multi.tar into the repo root here." >&2
    exit 1
  fi
fi

# --- sanity: required inputs present ---
for f in work/cache/injection_jobs.json work/cache/holdout_canon_hashes.json \
         work/cache/real_canon_bytecode.json work/scripts/canon_bytecode.py; do
  [ -f "$f" ] || { echo "[!] missing required input: $f" >&2; exit 1; }
done
echo "[*] inputs present"

# --- STEP 1: injection (the long part) ---
echo "[*] $(date) starting injection ..."
docker run --rm \
  -v "$REPO/work/SolidiFI:/solidifi" \
  -v "$REPO:/data" \
  -w /solidifi \
  "$IMAGE" python3 incontainer_inject.py
echo "[*] $(date) injection done"

# --- STEP 2: assemble final/ (also in-container, so host needs no Python) ---
echo "[*] $(date) assembling final/ ..."
docker run --rm \
  -v "$REPO:/data" \
  -w /data \
  "$IMAGE" python3 work/scripts/assemble_final.py
echo "[*] $(date) ALL DONE -> Dataset/final/"
