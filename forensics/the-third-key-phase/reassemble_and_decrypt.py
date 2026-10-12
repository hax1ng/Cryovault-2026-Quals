#!/usr/bin/env python3
"""
The Third Key Phase -- final stage.

The accepted upload for request 6e26102a48d71fe1d7f68231 was striped in
119-byte units, round-robin, across logical parts [0, 4, 8, 12]. Control
streams replaced two corrupted parts, so the accepted physical streams are:

    part 0  -> stream 0      (875_stream_CLIENT_0.bin)
    part 4  -> stream 20     (875_stream_CLIENT_20.bin)  replacement
    part 8  -> stream 16     (875_stream_CLIENT_16.bin)  replacement
    part 12 -> stream 12     (875_stream_CLIENT_12.bin)

De-stripe -> raw DEFLATE (no zlib/gzip wrapper) -> the exact accepted file.
Its SHA-256, the request id, and the winning connection's client_random form
the evidence fed to scrypt + AES-GCM to reveal the flag.

Run:  python3 reassemble_and_decrypt.py
"""
import zlib
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

UNIT = 119
parts = [
    open("875_stream_CLIENT_0.bin", "rb").read(),
    open("875_stream_CLIENT_20.bin", "rb").read(),   # replacement for part 4
    open("875_stream_CLIENT_16.bin", "rb").read(),   # replacement for part 8
    open("875_stream_CLIENT_12.bin", "rb").read(),
]

striped = bytearray()
for offset in range(0, max(map(len, parts)), UNIT):
    for part in parts:
        striped += part[offset:offset + UNIT]
print("striped (compressed) bytes:", len(striped))

accepted = zlib.decompress(bytes(striped), -zlib.MAX_WBITS)   # raw DEFLATE
print("accepted file bytes:", len(accepted))

sha = hashlib.sha256(accepted).hexdigest()
print("sha256:", sha)

evidence = [
    "6e26102a48d71fe1d7f68231",                                           # request id
    "87566bdc267eee5e8a8a7d0251033ec0ce2aef613ef35623cf1e6dc5fc1310d3",   # client_random
    sha,                                                                  # file hash
]
E = json.dumps(evidence, ensure_ascii=True, separators=(",", ":")).encode("ascii")
key = hashlib.scrypt(
    b"isfcr-forensics\x00" + E,
    salt=bytes.fromhex("55cfbdc7a31326404d59e133d991dc88"),
    n=131072, r=8, p=1, maxmem=2**28, dklen=32,
)
flag = AESGCM(key).decrypt(
    bytes.fromhex("f684f2db484cdd8e6f38b16e"),
    bytes.fromhex(
        "c4805539a3db8bc0bba5f5fb6ad76c1125d889aab86af180"
        "41007f8f49e30d2b5822be5cf8d26d21ddb576b25d06bc"
    ),
    b"the-third-key-phase",
)
print("FLAG:", flag.decode())
