"""Canonical runtime-bytecode hash.

Solidity 0.5+ appends a CBOR metadata blob to runtime bytecode whose tail two
bytes encode the blob length (big-endian uint16). The blob contains a swarm/IPFS
hash of the *source*, so two semantically identical contracts compiled from
different source files have different metadata. Hashing raw bytecode therefore
misses real collisions. The standard fix (Sourcify / etherscan-verifier) is to
strip the metadata tail before hashing.

0.4.x has no metadata blob; the length-prefix heuristic below also handles that
case safely (it only strips when the trailing length is in a sane range).
"""
import hashlib


def strip_metadata(bytecode_hex: str) -> bytes:
    s = bytecode_hex.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    bc = bytes.fromhex(s)
    if len(bc) >= 2:
        meta_len = int.from_bytes(bc[-2:], "big")
        if 30 <= meta_len <= 500 and meta_len + 2 <= len(bc):
            bc = bc[: -(meta_len + 2)]
    return bc


def canon_hash(bytecode_hex: str) -> str:
    return hashlib.sha256(strip_metadata(bytecode_hex)).hexdigest()
