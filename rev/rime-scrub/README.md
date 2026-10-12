# rime-scrub

**Category:** rev · **Points:** 500 · **Solves:** 0 (uncaptured at event close) · **Flag:** `isfcr{rime_8834_scrub_10912526_cleared}`

## Challenge

> The vault's key bank sits behind a controller that will never read the key out. You get the controller's firmware and the image of a decommissioned bank. Every connection powers the rig up fresh. Open the vault.

Attachments: `scrubd` (controller firmware), `bench.img` (image of a decommissioned bank), `README.txt`. Remote: `nc <HOST> <PORT>` (a fresh per-connection instance; the live target was a `chals.io` rig).

The challenge-provided `README.txt` (included here as [`challenge-README.txt`](./challenge-README.txt)) also gives the local run command:

```
cat bench.img - | qemu-hexagon-static ./scrubd
```

## Initial Analysis

`file` immediately tells us this isn't a normal binary:

```console
$ file scrubd
scrubd: ELF 32-bit LSB executable, QUALCOMM DSP6, statically linked, stripped
```

It's a **Qualcomm Hexagon (DSP6)** binary. Modern LLVM can disassemble it and QEMU can run it:

```bash
llvm-objdump-21 -d --no-show-raw-insn --print-imm-hex scrubd > scrubd.asm
cat bench.img - | qemu-hexagon ./scrubd
```

The trailing `-` matters: the first 128 bytes `scrubd` reads are the bank image; everything after is treated as live controller commands. The program is small and nearly string-free, so there's essentially one function to understand.

**The controller protocol.** It reads one opcode at a time and replies with six bytes: `[ echoed opcode | status | data0 | data1 | data2 | data3 ]`.

| Opcode | Request | Meaning |
|---|---:|---|
| `Z` | `Z` | return scrub budget/status |
| `l` | `l + addr + uint32_le` | write a public word |
| `m` | `m + addr` | read a public word |
| `q` | `q + addr + bit` | queue a physical cell fault |
| `r` | `r` | clear queued faults |
| `~` | `~` | perform one scrub |

Only **two cell faults** can be queued per scrub, and there are **150 scrubs** per connection. Addresses `0x00`–`0x0f` are plain writable memory; `0x30` is a readable control word; `0x38`–`0x3f` hold the protected key material and **cannot be read** with `m`. Faulting a protected address returns status `0xc4` *unless* bit 0 of the control word is set.

**`bench.img` layout** (128 bytes, describes the coding scheme and initial contents):

```
0x00  four-byte magic
0x04  38 ECC column values
0x2a  parameters for the deterministic cell pattern
0x30  readable control word
0x34  four key/share words
0x44  four masking words
```

Every logical 32-bit word is stored as a **38-bit codeword** (32 data + 6 check bits): a small Hamming-style ECC.

## Vulnerability / Core Concept

Two independent mechanisms combine into the attack.

### 1. Single-vs-double ECC error = a one-bit side channel

ECC repairs any *single* disturbed bit in a word. But a `q(address, bit)` "fault" doesn't toggle a bit — it **forces the physical cell to a deterministic "rime/frost" value**. The firmware computes roughly:

```
forced_bit = mode XOR parity((address AND row_mask) XOR (bit AND bit_mask))
```

For the live bank's data bits 0–31, probing known zero-filled public words reduced this to a simple affine form we can compute without any secret:

```
forced_bit(address, bit) = 1 XOR (address & 1) XOR (bit & 1)
```

The measurement loop: pick a word with known contents → queue one cell → scrub → read response byte 2 of `~`. If the forced value already matched the stored cell, nothing changed (correction count 0). If it differed, the scrub introduced one error, ECC repaired it (count 1). **The correction counter leaks whether the old cell matched the known forced value.**

### 2. Double-error miscorrection unlocks the protected words

The `q` command refuses `0x38`–`0x3f` while control bit 0 is clear — but the control word at `0x30` is itself faultable. Forcing *two* cells in one word creates a double error; the decoder mistakes the combined syndrome for a *different* single-bit error and "repairs" a third bit:

```
q(0x30, 2); q(0x30, 8); scrub
```

This flips logical bits 0, 2, and 8 of the control word (a `0x105` delta). Bit 0 becomes one → protected faults are now accepted. (The pair was found by testing candidate pairs against the readable control word on fresh connections: a good pair leaves a valid word with bit 0 set and bit 1 still clear.)

### 3. The masking scheme cancels

For each of four word positions the firmware stores a masked key share:

```
L = K XOR R                 # lives at 0x38..0x3b
H = ROL32(R, 13)            # lives at 0x3c..0x3f
```

`K` is 32 bits of the real key, `R` is a random mask refreshed on *every* scrub:

```
L' = L XOR R XOR R'
H' = ROL32(R', 13)
```

But the invariant `L' XOR ROR32(H', 13) == K` holds forever — the bag keeps changing, the object inside stays the same. (A fresh session key/mask is generated per connection, so the whole leak must happen in one connection.)

### Putting it together — leaking one real key bit

To get bit `b` of key word `i`, probe the matching stored bits in **two different ECC words**:

```
L bit:  address 0x38+i, bit b
R bit:  address 0x3c+i, bit (b+13) mod 32     # undo the ROL13 in H
```

Queue both, scrub. Each word has at most one error, so ECC repairs both independently and the correction count is `eL + eR ∈ {0,1,2}`, where `eX = X_bit XOR forced_X`. Its **parity** cancels the random mask:

```
K_bit = L_bit XOR R_bit
      = (eL XOR forced_L) XOR (eR XOR forced_R)
      = (corrections & 1) XOR forced_L XOR forced_R
```

Two queued cells + one scrub = one genuine key bit, despite neither masked bit being readable. Budget: 1 scrub to enable protected faults + 128 to recover the key = **129 ≤ 150**. ✓

### The final, undocumented opcode

The recovered 16-byte key is random per connection, so it isn't the flag itself. While probing the remote endpoint, byte `0x33` behaved differently from local firmware — remotely it waits for exactly 16 more bytes, so it belongs to the *outer vault rig*, not `scrubd`:

```python
sock.sendall(b"\x33" + raw_session_key)
```

A success reply is a six-byte binary header followed by the flag.

## Exploitation

The full solver is [`solve.py`](./solve.py). Flow: enable protected faults via the `0x30` double-error, loop 128 bits leaking each via correction-count parity, reassemble the little-endian key, then send `0x33 + key`.

```python
def frozen_bit(address, bit):
    # Affine rime pattern inferred from public, known bank cells.
    return 1 ^ (address & 1) ^ (bit & 1)

# Turn on control bit 0 through a two-error ECC miscorrection.
command(sock, b"q" + bytes((0x30, 2)))
command(sock, b"q" + bytes((0x30, 8)))
command(sock, b"~")

key = 0
for word in range(4):
    for bit in range(32):
        low_address, high_address = 0x38 + word, 0x3c + word
        high_bit = (bit + 13) & 31
        command(sock, b"q" + bytes((low_address, bit)))
        command(sock, b"q" + bytes((high_address, high_bit)))
        corrections = command(sock, b"~")[2]          # response byte 2
        key_bit = ((corrections & 1)
                   ^ frozen_bit(low_address, bit)
                   ^ frozen_bit(high_address, high_bit))
        key |= key_bit << (32 * word + bit)

raw_key = key.to_bytes(16, "little")
sock.sendall(b"\x33" + raw_key)       # outer rig unlock
```

> Note: `HOST`/`PORT` in `solve.py` are the generic `nc` target from the challenge page — no session token. Start your own instance and point the script at it.

## Running It

Because the session key is random per connection, the recovered `KEYHEX` differs every run — the flag does not. A representative run is saved in [`final-output.txt`](./final-output.txt):

```
enable: 71 00 01 00 00 00 71 00 02 00 00 00 7e 00 01 00 95 00
KEYHEX 6dc75daad9d63e7f24d701022e54887d
FLAG   isfcr{6dc75daad9d63e7f24d701022e54887d}          # the *session key*, not the flag
UNLOCK b'3\x00\x04\x00\x00\x00isfcr{rime_8834_scrub_10912526_cleared}\n'
```

The `0x33` unlock response (`UNLOCK`) carries the real, constant flag after its six-byte header.

## Flag

```
isfcr{rime_8834_scrub_10912526_cleared}
```

## Key Takeaways

- **ECC correction counts are a side channel.** The controller never reads the key out, but forcing cells and watching how many words needed correction makes the error counter *describe* the key one bit at a time.
- **Double-error miscorrection is a primitive, not just a bug** — two forced cells in one Hamming word flip a predictable third logical bit, which here flips the protection enable.
- **Mask that refreshes every operation still cancels** if the representation has an invariant (`L XOR ROR13(H) = K`); probe the paired bits together so the mask drops out of the parity.
- Don't forget the **outer harness**: the thing you reverse (`scrubd`) may not be the thing that holds the flag. The undocumented `0x33` opcode lived in the rig, not the firmware.
- Hexagon/DSP6 binaries are tractable: `llvm-objdump` disassembles and `qemu-hexagon` runs them.
