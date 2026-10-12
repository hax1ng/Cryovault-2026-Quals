#!/usr/bin/env python3
"""
The Alphabet That Wasn't There -- final decryption.

Once the 16x16 Type3-glyph grid has been decoded in the page's default user
space (rows top->bottom by descending baseline y, left->right within a row),
the CaseID + grid are the two evidence fields. The grid below is the one
recovered from the correctly repaired PDF (old free object 10, the overlay,
left unresolved -- see glyph_decode.py and the README).

Run:  python3 decrypt_flag.py
"""
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

case_id = "9697624543591457a15dc6d9a4797c45"
grid = (
    "e7463684552dfb02"
    "7076afdf977a1a94"
    "bb89d9112b4ace4b"
    "c9207e7c18b3fbf5"
    "5526ba3a9e437c7d"
    "6c4a3ef3bf7e0dcd"
    "4694f7288fc5d4c1"
    "89be389bbbaadd51"
    "4031b50de7eba382"
    "0e5230915ddfa4bc"
    "c793d2b7aa7c880f"
    "1900cd60b1caedd9"
    "507009b6658d86d3"
    "ce052d46f8f4c16d"
    "13c9e5e6302733f3"
    "906ff5e24f690ab6"
)
assert len(grid) == 256

evidence = [case_id, grid]
E = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")
key = hashlib.scrypt(
    b"isfcr-forensics\x00" + E,
    salt=bytes.fromhex("8a251a8101ffa67ed383a445a05e77f2"),
    n=131072, r=8, p=1, maxmem=2**28, dklen=32,
)
flag = AESGCM(key).decrypt(
    bytes.fromhex("cf5d90d20b821db4c5bf1b73"),
    bytes.fromhex(
        "27b4469da3cc30f3ec487d60be3053aa2d5aa00c9f4da69fe"
        "54e7d51da8463883b4aa1b0a10a69c45c4e974171133f"
    ),
    b"the-alphabet-that-wasnt-there",
)
print("FLAG:", flag.decode())
