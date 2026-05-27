"""Train-only SolidiFI injection batch (README Steps 1-7).

NO LEAKAGE: reads only splits/Train_Labels.csv + Train_Labels_append.csv and the
work/cache candidate list (built from train only). Asserts it never opens the
deny-listed files. Targets the rarest classes by inverse-frequency weight, maps
to a SolidiFI bug type (incl. custom DoS / Bad-Randomness), injects via Docker,
compiles bytecode, and appends one multi-label row per injected contract.

Outputs (host):
  Dataset/buggy/<BugType>/buggy_<id>_<BugType>.sol
  Dataset/buggy/<BugType>/BugLog_<id>_<BugType>.csv
  Dataset/buggy/<BugType>/buggy_<id>_<BugType>.bin.json   (bytecode modality)
  Dataset/splits/Train_Labels_append.csv                  (label rows)
"""
import json
import os
import random
import shutil
import subprocess
import sys

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(ROOT, "Dataset")
SPLITS = os.path.join(DATASET, "splits")
SOURCE = os.path.join(DATASET, "Source")
BUGGY = os.path.join(DATASET, "buggy")
CACHE = os.path.join(ROOT, "work", "cache")
SOLIDIFI = os.path.join(ROOT, "work", "SolidiFI")
IMAGE = "solidifi-slim"

LABELS = ["Reentrancy", "Access Control", "Arithmetic", "Unchecked Return Values",
          "DoS", "Bad Randomness", "Front Running", "Time manipulation"]
DENY = {"DIVE_Labels.csv", "Val_Labels.csv", "Test_Labels.csv"}

# DIVE label -> SolidiFI bug type (selection direction)
LABEL_TO_BUG = {
    "Reentrancy": "Re-entrancy",
    "Access Control": "tx.origin",
    "Arithmetic": "Overflow-Underflow",
    "Unchecked Return Values": "Unchecked-Send",
    "DoS": "DoS",
    "Bad Randomness": "Bad-Randomness",
    "Front Running": "TOD",
    "Time manipulation": "Timestamp-Dependency",
}
# SolidiFI bug type -> DIVE label(s) it creates
BUG_TO_LABELS = {
    "Re-entrancy": ["Reentrancy"],
    "tx.origin": ["Access Control"],
    "Overflow-Underflow": ["Arithmetic"],
    "Unchecked-Send": ["Unchecked Return Values"],
    "Unhandled-Exceptions": ["Unchecked Return Values"],
    "TOD": ["Front Running"],
    "Timestamp-Dependency": ["Time manipulation"],
    "DoS": ["DoS"],
    "Bad-Randomness": ["Bad Randomness"],
}
# README Step 2 co-occurrence rates (primary DIVE label -> [(label, rate)])
COOCCUR = {
    "Reentrancy": [("Access Control", .94), ("Arithmetic", .53), ("Unchecked Return Values", .40), ("Time manipulation", .33), ("DoS", .24)],
    "Access Control": [("Reentrancy", .64), ("Arithmetic", .50), ("Unchecked Return Values", .34), ("Time manipulation", .28), ("DoS", .21)],
    "Arithmetic": [("Access Control", .88), ("Reentrancy", .63), ("Unchecked Return Values", .40), ("Time manipulation", .34), ("DoS", .21)],
    "Time manipulation": [("Access Control", .74), ("Reentrancy", .59), ("Arithmetic", .51), ("Unchecked Return Values", .38), ("DoS", .24)],
    "Unchecked Return Values": [("Access Control", .96), ("Reentrancy", .77), ("Arithmetic", .64), ("Time manipulation", .41), ("DoS", .28)],
    "DoS": [("Access Control", .92), ("Reentrancy", .71), ("Arithmetic", .52), ("Unchecked Return Values", .43), ("Time manipulation", .40)],
    "Bad Randomness": [("Access Control", .93), ("Reentrancy", .73), ("Arithmetic", .57), ("Time manipulation", .41), ("DoS", .37)],
    "Front Running": [("Access Control", .94), ("Reentrancy", .70), ("DoS", .49), ("Arithmetic", .42), ("Time manipulation", .38)],
}

SEED = 42
SUCCESS_TARGET = int(os.environ.get("BATCH_TARGET", "30"))
MAX_COOCCUR = 2  # cap additional co-occurring injections per contract


def safe_read_csv(path):
    assert os.path.basename(path) not in DENY, f"LEAKAGE GUARD: refusing to read {path}"
    return pd.read_csv(path)


def docker_inject(rel_input, bug_type):
    """Run SolidiFI in-container. rel_input is relative to /solidifi. Returns
    (ok, output_rel_sol, buglog_rel_csv)."""
    cmd = ["docker", "run", "--rm",
           "-v", f"{SOLIDIFI}:/solidifi",
           "-v", f"{SOURCE}:/src:ro",
           "-w", "/solidifi", IMAGE,
           "python3", "solidifi.py", "-i", rel_input, bug_type]
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    out = p.stdout + p.stderr
    if "compilation errors" in out or "requires different compiler" in out or "unable to generate AST" in out:
        return False, None, None
    tail = os.path.basename(rel_input)
    sol = f"buggy/{bug_type}/buggy_{tail}"
    log = f"buggy/{bug_type}/BugLog_{os.path.splitext(tail)[0]}.csv"
    if not os.path.isfile(os.path.join(SOLIDIFI, sol)):
        return False, None, None
    # require >=1 logged injection (header + >=1 row)
    lp = os.path.join(SOLIDIFI, log)
    if not os.path.isfile(lp) or sum(1 for _ in open(lp)) < 2:
        return False, None, None
    return True, sol, log


def docker_bytecode(rel_sol, dst_json):
    cmd = ["docker", "run", "--rm", "-v", f"{SOLIDIFI}:/solidifi", "-w", "/solidifi", IMAGE,
           "solc", "--combined-json", "bin,bin-runtime", rel_sol]
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if p.returncode != 0 or not p.stdout.strip().startswith("{"):
        return False
    data = json.loads(p.stdout)
    # require at least one contract with non-empty creation bytecode
    if not any(c.get("bin") for c in data.get("contracts", {}).values()):
        return False
    with open(dst_json, "w") as f:
        f.write(p.stdout)
    return True


def main():
    random.seed(SEED)
    base = safe_read_csv(os.path.join(SPLITS, "Train_Labels.csv"))
    base["contractID"] = base["contractID"].astype(str)
    append_path = os.path.join(SPLITS, "Train_Labels_append.csv")
    appended = (safe_read_csv(append_path) if os.path.isfile(append_path)
                else pd.DataFrame(columns=["contractID"] + LABELS))

    counts = {c: int(base[c].sum() + (appended[c].sum() if len(appended) else 0)) for c in LABELS}
    orig_labels = {r["contractID"]: {c: int(r[c]) for c in LABELS} for _, r in base.iterrows()}

    candidates = json.load(open(os.path.join(CACHE, "train_0512_candidates.json")))
    random.shuffle(candidates)

    new_rows = []
    used = set()
    last_primary = None
    successes = 0
    attempts = 0

    while successes < SUCCESS_TARGET:
        # ---- select primary class by weight (rotate, no consecutive repeat) ----
        mx = max(counts.values())
        ranked = sorted(LABELS, key=lambda c: mx / (counts[c] + 1), reverse=True)
        primary = ranked[0] if ranked[0] != last_primary else ranked[1]

        # ---- pick a source contract clean for primary, unused ----
        cid = next((c for c in candidates
                    if c not in used and orig_labels.get(c, {}).get(primary, 1) == 0), None)
        if cid is None:
            print(f"no more clean candidates for {primary}; stopping at {successes}")
            break

        used.add(cid)
        attempts += 1

        # ---- build bug-type plan: primary + sampled co-occurring (capped) ----
        plan = [LABEL_TO_BUG[primary]]
        extra = 0
        for lbl, rate in COOCCUR.get(primary, []):
            if extra >= MAX_COOCCUR:
                break
            if orig_labels[cid].get(lbl, 0) == 1:
                continue  # already positive; injection adds no new signal
            if random.random() < rate:
                bt = LABEL_TO_BUG[lbl]
                if bt not in plan:
                    plan.append(bt)
                    extra += 1

        # ---- sequential injection passes (output of pass k feeds pass k+1) ----
        rel_input = f"/src/{cid}.sol"   # first pass reads the real source (read-only mount)
        injected_types = []
        last_sol = None
        for k, bt in enumerate(plan):
            ok, sol, log = docker_inject(rel_input, bt)
            if not ok:
                break
            injected_types.append((bt, sol, log))
            last_sol = sol
            rel_input = sol  # next pass injects into the already-buggy file (inside /solidifi)
        if not injected_types:
            print(f"  skip {cid}: primary {plan[0]} injection failed")
            continue

        primary_bug = injected_types[0][0]
        contract_id = f"buggy_{cid}_{primary_bug}"
        dst_dir = os.path.join(BUGGY, primary_bug)
        os.makedirs(dst_dir, exist_ok=True)
        dst_sol = os.path.join(dst_dir, f"{contract_id}.sol")
        dst_log = os.path.join(dst_dir, f"BugLog_{cid}_{primary_bug}.csv")
        dst_bin = os.path.join(dst_dir, f"{contract_id}.bin.json")

        # ---- compile bytecode from the FINAL injected file (must succeed) ----
        if not docker_bytecode(last_sol, dst_bin):
            print(f"  skip {cid}: final bytecode compile failed")
            continue

        # ---- persist sol + merged buglog ----
        shutil.copyfile(os.path.join(SOLIDIFI, last_sol), dst_sol)
        merged = []
        header = None
        for _, _, log in injected_types:
            lines = open(os.path.join(SOLIDIFI, log)).read().splitlines()
            if lines:
                header = lines[0]
                merged.extend(lines[1:])
        with open(dst_log, "w", newline="\n") as f:
            f.write((header or "loc,length,bug type,approach") + "\n" + "\n".join(merged) + "\n")

        # ---- build multi-label row: original train labels OR injected classes ----
        row = dict(orig_labels[cid])
        new_classes = set()
        for bt, _, _ in injected_types:
            for lbl in BUG_TO_LABELS[bt]:
                row[lbl] = 1
                new_classes.add(lbl)
        row_out = {"contractID": contract_id, **{c: row[c] for c in LABELS}}
        new_rows.append(row_out)
        for lbl in new_classes:
            counts[lbl] += 1

        successes += 1
        last_primary = primary
        print(f"[{successes}/{SUCCESS_TARGET}] {contract_id} | injected {[b for b,_,_ in injected_types]} | +{sorted(new_classes)}")

    # ---- append all new rows (header if file missing) ----
    if new_rows:
        df = pd.DataFrame(new_rows, columns=["contractID"] + LABELS)
        if os.path.isfile(append_path):
            df.to_csv(append_path, mode="a", header=False, index=False)
        else:
            df.to_csv(append_path, index=False)
    print(f"\nDONE: {successes} injected, {attempts} contracts attempted.")
    print("append file:", append_path, "rows added:", len(new_rows))


if __name__ == "__main__":
    sys.exit(main())
