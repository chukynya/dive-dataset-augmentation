"""Verify the regenerated SolidiFI rare-class snippets.

For each (solc version, snippet dir):
  1. compile every fragment individually (wrapped in a contract) -> catches syntax errors
     with precise file attribution;
  2. compile ALL fragments of a class together in one contract -> reproduces the worst case
     where SolidiFI injects many fragments into a single base, catching cross-file identifier
     collisions (which would silently drop bases at injection time);
  3. scan for synthetic-fingerprint tokens and self-labeling comments.

Run: python work/scripts/check_snippets.py
(uses py-solc-x; 0.4.26, 0.5.17, and 0.8.20 must be installed)
"""
import os
import re
import sys

import solcx

SOLIDIFI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SolidiFI")
BUGS = os.path.join(SOLIDIFI, "bugs")

# (solc version, pragma, [(bug_type_dir, relative tf path)])
SPECS = [
    ("0.5.17", "^0.5.0", [("DoS", "tf"), ("Bad-Randomness", "tf"), ("TOD", "tf")]),
    ("0.4.26", "^0.4.0", [("TOD", "v04/tf"), ("DoS", "v04/tf"), ("Bad-Randomness", "v04/tf")]),
    ("0.8.20", "^0.8.0", [("DoS", "v08/tf"), ("Bad-Randomness", "v08/tf"), ("TOD", "v08/tf")]),
]

FINGERPRINTS = ["_BR", "BR_", "_DoS", "DoS_", "_TOD", "TOD_", "_v04", "_v05",
                "VULNERABLE", "INSECURE", "// BUG", "//BUG"]


def load_fragments(bug_dir, rel):
    d = os.path.join(BUGS, bug_dir, *rel.split("/"))
    files = sorted([f for f in os.listdir(d) if f.endswith(".txt")],
                   key=lambda x: int(os.path.splitext(x)[0]))
    return [(f, open(os.path.join(d, f), encoding="utf-8").read()) for f in files]


def compile_ok(pragma, version, body):
    src = f"pragma solidity {pragma};\ncontract Probe {{\n{body}\n}}\n"
    try:
        solcx.compile_source(src, solc_version=version)
        return None
    except Exception as e:  # SolcError etc.
        msg = str(e).splitlines()
        return " | ".join(m for m in msg if "Error" in m or "error" in m)[:300] or str(e)[:300]


def main():
    failures = 0
    for version, pragma, types in SPECS:
        for bug_dir, rel in types:
            frags = load_fragments(bug_dir, rel)
            print(f"\n=== {bug_dir}/{rel}  (solc {version})  {len(frags)} fragments ===")

            # 1. individual compile
            for fname, body in frags:
                err = compile_ok(pragma, version, body)
                if err:
                    failures += 1
                    print(f"  COMPILE FAIL {fname}: {err}")

            # 2. all-together compile (cross-file identifier collisions)
            combined = "\n".join(b for _, b in frags)
            err = compile_ok(pragma, version, combined)
            if err:
                failures += 1
                print(f"  COMBINED COMPILE FAIL (identifier collision?): {err}")
            else:
                print("  all-together compile: OK (no cross-file identifier collisions)")

            # 3. fingerprint / self-label scan
            for fname, body in frags:
                hits = [t for t in FINGERPRINTS if t in body]
                if hits:
                    failures += 1
                    print(f"  FINGERPRINT {fname}: {hits}")

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} FAILURES'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
