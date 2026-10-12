#!/usr/bin/env python3
"""Recover the KELPIE firmware activation key from the supplied binary."""

from hashlib import sha256
import hmac
from pathlib import Path

from Crypto.Cipher import AES


BIN = Path(__file__).with_name("kelpie").read_bytes()

# This ELF is non-PIE and .rodata's file offsets are VA - 0x400000.
PROGRAM = BIN[0x23C0 : 0x23C0 + 0x4D1]
PERM51 = [list(BIN[0x2C80 + 16 * n : 0x2C80 + 16 * (n + 1)]) for n in range(2)]
PERM50 = [list(BIN[0x2CA0 + 16 * n : 0x2CA0 + 16 * (n + 1)]) for n in range(2)]
AES_INV_SBOX = list(BIN[0x2CC0:0x2DC0])
AES_SBOX = list(BIN[0x2DC0:0x2EC0])

HMAC_KEY = BIN[0x28A4:0x28B4]
GCM_IV = BIN[0x28B4:0x28C0]
GCM_TAG = BIN[0x28C0:0x28D0]
CIPHERTEXT = BIN[0x28D4 : 0x28D4 + 0x39C]

# The official hint is the otherwise-unrecoverable AES-256-GCM key.  It is
# HMAC-SHA256(HMAC_KEY, stage1_state) for the correct activation value.
HINT_KEY = bytes.fromhex(
    "9aebadceb2ae07382a9b56afa8a03c7a"
    "7b68f84ddc493d778f0ec0d8a242360f"
)


def rol8(x: int, n: int) -> int:
    n &= 7
    return ((x << n) | (x >> ((8 - n) & 7))) & 0xFF


def ror8(x: int, n: int) -> int:
    return rol8(x, -n)


def run_vm(program: bytes, state: bytes, *, comparisons: bool = True):
    """Run the three-byte-instruction VM at 0x4015e0.

    Returns (final_state, mismatch_accumulator).  The first-stage program only
    touches 16-byte state, while the decrypted second stage additionally uses
    opcode 0x71 to compare bytes against immediates.
    """
    d = list(state)
    mismatch = 0
    pc = 0
    while pc + 3 <= len(program):
        op, a, b = program[pc : pc + 3]
        pc += 3

        if op == 0x00:       # halt
            break
        elif op == 0x10:     # xor another state byte
            d[a] ^= d[b]
        elif op == 0x11:     # add another state byte
            d[a] = (d[a] + d[b]) & 0xFF
        elif op == 0x12:     # subtract another state byte
            d[a] = (d[a] - d[b]) & 0xFF
        elif op == 0x13:     # swap
            d[a], d[b] = d[b], d[a]
        elif op == 0x20:     # xor immediate
            d[a] ^= b
        elif op == 0x21:     # add immediate
            d[a] = (d[a] + b) & 0xFF
        elif op == 0x22:     # subtract immediate
            d[a] = (d[a] - b) & 0xFF
        elif op == 0x23:     # multiply modulo 256
            d[a] = (d[a] * b) & 0xFF
        elif op == 0x30:     # rotate left
            d[a] = rol8(d[a], b)
        elif op == 0x31:     # rotate right
            d[a] = ror8(d[a], b)
        elif op == 0x40:     # AES S-box
            d[a] = AES_SBOX[d[a]]
        elif op == 0x41:     # inverse AES S-box
            d[a] = AES_INV_SBOX[d[a]]
        elif op in (0x50, 0x51):
            table = (PERM50 if op == 0x50 else PERM51)[a]
            old = d[:16]
            d[:16] = [old[table[i]] for i in range(16)]
        elif op == 0x60:
            d[a] ^= rol8(d[b], 3)
        elif op == 0x71:
            if comparisons:
                mismatch |= d[a] != b
        elif op == 0x70:
            mismatch |= 1
        else:
            raise ValueError(f"invalid opcode {op:#x} at {pc - 3:#x}")

    return bytes(d), int(bool(mismatch))


def invert_program(program: bytes, output: bytes) -> bytes:
    """Invert the state-transforming instructions in a VM program."""
    d = list(output)
    insns = [program[o : o + 3] for o in range(0, len(program), 3)]
    for raw in reversed(insns):
        op, a, b = raw
        if op in (0x00, 0x71):  # HALT and comparisons do not alter state
            continue
        elif op == 0x10:
            assert a != b
            d[a] ^= d[b]
        elif op == 0x11:
            assert a != b
            d[a] = (d[a] - d[b]) & 0xFF
        elif op == 0x12:
            assert a != b
            d[a] = (d[a] + d[b]) & 0xFF
        elif op == 0x13:
            d[a], d[b] = d[b], d[a]
        elif op == 0x20:
            d[a] ^= b
        elif op == 0x21:
            d[a] = (d[a] - b) & 0xFF
        elif op == 0x22:
            d[a] = (d[a] + b) & 0xFF
        elif op == 0x23:
            d[a] = (d[a] * pow(b, -1, 256)) & 0xFF
        elif op == 0x30:
            d[a] = ror8(d[a], b)
        elif op == 0x31:
            d[a] = rol8(d[a], b)
        elif op == 0x40:
            d[a] = AES_INV_SBOX[d[a]]
        elif op == 0x41:
            d[a] = AES_SBOX[d[a]]
        elif op in (0x50, 0x51):
            table = (PERM50 if op == 0x50 else PERM51)[a]
            old = [0] * 16
            for i in range(16):
                old[table[i]] = d[i]
            d = old
        elif op == 0x60:
            assert a != b
            d[a] ^= rol8(d[b], 3)
        else:
            raise ValueError(f"inverse missing opcode {op:#x}")
    return bytes(d)


def invert_stage1(output: bytes) -> bytes:
    """Invert the known, bijective first-stage program."""
    return invert_program(PROGRAM, output)


def comparison_target(program: bytes) -> bytes:
    """Extract the 16-byte state required by a terminal comparison block."""
    target = [None] * 16
    comparing = False
    for pc in range(0, len(program), 3):
        op, a, b = program[pc : pc + 3]
        if op == 0x71:
            comparing = True
            if target[a] is not None and target[a] != b:
                raise ValueError(f"conflicting comparison for state byte {a}")
            target[a] = b
        elif comparing and op != 0x00:
            raise ValueError("state transformation found after comparison block")
    if any(x is None for x in target):
        raise ValueError("comparison block does not constrain all 16 bytes")
    return bytes(target)


def decrypt_stage2(stage1_state: bytes):
    key = hmac.new(HMAC_KEY, stage1_state, sha256).digest()
    cipher = AES.new(key, AES.MODE_GCM, nonce=GCM_IV)
    try:
        return cipher.decrypt_and_verify(CIPHERTEXT, GCM_TAG)
    except ValueError:
        return None


def decrypt_stage2_with_hint() -> bytes:
    cipher = AES.new(HINT_KEY, AES.MODE_GCM, nonce=GCM_IV)
    return cipher.decrypt_and_verify(CIPHERTEXT, GCM_TAG)


def check_raw_key(raw: bytes):
    stage1, bad = run_vm(PROGRAM, raw)
    assert not bad
    plaintext = decrypt_stage2(stage1)
    if plaintext is None:
        return False, stage1, None
    _, bad = run_vm(plaintext, stage1)
    return not bad, stage1, plaintext


if __name__ == "__main__":
    test = bytes(range(16))
    got, bad = run_vm(PROGRAM, test)
    assert not bad
    assert got.hex() == "d3e4dd75211d03215a37de7164eb510a"
    assert invert_stage1(got) == test
    print(f"selftest: {got.hex()} (matches)")

    stage2 = decrypt_stage2_with_hint()
    target = comparison_target(stage2)
    stage1 = invert_program(stage2, target)
    derived_key = hmac.new(HMAC_KEY, stage1, sha256).digest()
    assert derived_key == HINT_KEY

    raw = invert_stage1(stage1)
    ok, checked_stage1, checked_stage2 = check_raw_key(raw)
    assert ok and checked_stage1 == stage1 and checked_stage2 == stage2

    print(f"stage-2 target: {target.hex()}")
    print(f"stage-1 state:  {stage1.hex()}")
    print(f"activation:     {raw.hex()}")
    print(f"flag:           isfcr{{{raw.hex()}}}")
