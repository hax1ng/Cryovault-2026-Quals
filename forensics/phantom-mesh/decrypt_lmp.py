#!/usr/bin/env python3
"""
Phantom Mesh -- stage 2: use the CPA-recovered Trust Center Link Key to
unwrap the Network Key, then decrypt the rogue diagnostics report (frame 81).

The TC Link Key below is the output of the CPA attack in solve_cpa.py
(verified against the plaintext KEY_CONFIRM tags in the capture).

LMP rides on IEEE 802.15.4 and uses AES-CCM* (L=2, M=4). The source EUI-64 is
byte-ordered differently in the CCM nonce vs. the authenticated data -- see
docs/LMP-protocol.md.

Run:  python3 decrypt_lmp.py        (needs pycryptodome)
"""
from Crypto.Cipher import AES


def decrypt_lmp(key, payload_hex):
    packet = bytes.fromhex(payload_hex)
    body = packet[3:]                 # strip 1c 03 <cmd>
    sec_ctl = body[0:1]
    counter = body[1:5]
    eui_le = body[5:13]
    ciphertext = body[13:-4]
    mic = body[-4:]
    nonce = eui_le[::-1] + counter + sec_ctl
    aad = sec_ctl + counter + eui_le
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, mic)


# Trust Center Link Key recovered via CPA (solve_cpa.py).
tc_key = bytes.fromhex("7cf8b0b78be9f36a225c1e70692e1e1c")

# Sanity check: KEY_CONFIRM tag == AES-ECB(tc_key, nonce)[:8] for frame 32.
nonce32 = bytes.fromhex("fa834b9abd379d2c17b312c34411b815")
tag32 = AES.new(tc_key, AES.MODE_ECB).encrypt(nonce32)[:8]
assert tag32.hex() == "c38d863b06d04469", tag32.hex()
print("KEY_CONFIRM tag check OK:", tag32.hex())

# Frame 40: TRANSPORT_KEY (cmd 0x11), protected by the TC Link Key.
transport = (
    "1c031105640000000100aa25004b1200"
    "516193f8b8e2fd2a41acb21f8ef850a4e85b1ffe"
)
network_key = decrypt_lmp(tc_key, transport)
print("Network Key:", network_key.hex())

# Frame 81: the oversized SECURE_REPORT (cmd 0x21), protected by the NWK Key.
report = (
    "1c032105ad0d00004000aa25004b1200"
    "bb6ba385d9752ee4ad9786702f05b53dd3c76a01bdeda3b881778716fd0e3235"
    "860e0f56d46783e6e0a2fae81d0dc739e6ee24945c442468e2cb58a89c4f"
)
plaintext = decrypt_lmp(network_key, report)
# First 6 bytes: cluster_id | attribute_id | vlen (all LE); the rest is the flag.
print("Report plaintext:", plaintext.hex())
print("FLAG:", plaintext[6:].decode())
