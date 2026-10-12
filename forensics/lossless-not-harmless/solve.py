#!/usr/bin/env python3
"""
Lossless, Not Harmless -- full solve.

Two covert channels hidden in the PNG's DEFLATE stream:

  1. Equivalent-match parity: at every LZ77 match where both an even- and an
     odd-distance match reproduce the same bytes, the parity of the chosen
     distance carries one bit. These bits spell out an encrypted blob plus
     the instructions for decrypting it.
  2. Discarded sync-flush padding: each stored-block header is byte aligned;
     the bits skipped to reach the next byte boundary carry the 128-bit key.

Inputs are the two infgen (DEFLATE disassembler) dumps of the PNG's zlib stream:

    # extract the zlib/DEFLATE stream from the IDAT chunks first (extract_idat.py)
    infgen -q   stream.zlib > tokens.txt   # literal/match token listing
    infgen -ddq stream.zlib > bits.txt     # detailed bit-level listing

Run:  python3 solve.py
"""
from pathlib import Path
import hashlib
import hmac


def pack_msb(bits):
    """Pack a string/iterable of 0/1 values, first bit as the MSB."""
    bits = "".join(str(bit) for bit in bits)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))


# --- Channel 1: rebuild output from infgen tokens, read match-parity bits ---
lines = Path("tokens.txt").read_text(encoding="latin-1").splitlines()
output = bytearray()
matches = []

for line in lines:
    if line.startswith("literal"):
        value = line[len("literal"):].lstrip()
        # infgen prints non-printable bytes as decimals, printable ones after '.
        if "'" in value:
            numbers, text = value.split("'", 1)
            literal = [int(item) for item in numbers.split()]
            literal += list(text.encode("latin-1"))
        else:
            literal = [int(item) for item in value.split()] if value else []
        output.extend(literal)
    elif line.startswith("match"):
        _, length, distance = line.split()
        length = int(length)
        distance = int(distance)
        position = len(output)
        matches.append((position, length, distance))
        for i in range(length):                 # copy byte-wise: matches overlap
            output.append(output[position - distance + i])

data = bytes(output)
hidden_bits = []

for position, length, selected_distance in matches:
    target = data[position:position + length]
    earliest = max(0, position - 32768)          # 32 KiB DEFLATE window
    candidates = []
    cp = earliest - 1
    while True:
        cp = data.find(target[:3], cp + 1, position + 3)
        if cp < 0 or cp >= position:
            break
        if data[cp:cp + length] == target:
            candidates.append(position - cp)
    # A match can encode a bit only if both parities are reachable.
    if {d & 1 for d in candidates} == {0, 1}:
        hidden_bits.append(selected_distance & 1)

record = pack_msb(hidden_bits)
assert record[:4] == b"DFL8", record[:8]
payload_length = int.from_bytes(record[4:6], "big")
payload = record[6:6 + payload_length]
instructions, blob = payload.split(b"\0", 1)
print("INSTRUCTIONS:", instructions.decode())

# --- Channel 2: recover the 128 discarded stored-block padding bits ---
detail = Path("bits.txt").read_text().splitlines()
runs = []
for i, line in enumerate(detail):
    if line.startswith("stored"):
        padding = detail[i + 1].split("!", 1)[1].strip()
        # infgen shows the value MSB-first; DEFLATE consumes it LSB-first.
        runs.append(padding[::-1])

key_bits = "".join(runs)
assert len(key_bits) == 128, len(key_bits)
key = pack_msb(key_bits)
print("KEY:", key.hex())

# --- Decrypt + authenticate the blob ---
nonce = blob[:8]
ciphertext = blob[8:-8]
tag = blob[-8:]

expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()[:8]
assert hmac.compare_digest(tag, expected), "HMAC verification failed"

keystream = bytearray()
counter = 0
while len(keystream) < len(ciphertext):
    keystream.extend(hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest())
    counter += 1

plaintext = bytes(v ^ keystream[i] for i, v in enumerate(ciphertext))
print("FLAG:", plaintext.decode())
