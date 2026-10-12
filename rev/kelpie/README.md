# Kelpie

**Category:** rev · **Points:** 128 · **Solves:** 63 · **Flag:** `isfcr{5b2d4c7961307f588d9dd95bada5647b}`

## Challenge

> We pulled this activation stub off a decommissioned "KELPIE" hardware token.
> It guards the firmware unlock routine behind an activation key. Legend says the
> key was printed on a sticker that peeled off years ago.
>
> The binary runs a small custom byte-machine over whatever key you type. Feed it
> the real activation key and it reports "Unlocked"; anything else is "Denied".
>
> ```
> $ ./kelpie
> KELPIE firmware unlock console
> enter activation key: isfcr{................................}
> ```
>
> There is also an undocumented factory self-test that runs the first stage over a
> fixed test vector — handy for checking your re-implementation of the machine:
>
> ```
> $ ./kelpie selftest
> ```
>
> The activation key is the flag, in the form `isfcr{<32 hex chars>}`. Recover the key. Unlock the firmware.

Attachment: `kelpie`. The challenge had a single locked hint (cost 100) — it turns out to be essential, see below.

## Initial Analysis

`kelpie` is a stripped, **non-PIE** x86-64 ELF linked against OpenSSL 3. Because it is non-PIE, `.rodata` sits at a fixed virtual address and file offsets are simply `VA - 0x400000` — this makes it easy to pull embedded tables straight out of the file.

Input must match `isfcr{<32 hex chars>}`; the 32 hex characters decode to **16 raw bytes** that get fed into a custom virtual machine.

The documented self-test gives us a free oracle for verifying our re-implementation:

```console
$ ./kelpie selftest
d3e4dd75211d03215a37de7164eb510a
```

That is stage 1 run over the counter vector `000102030405060708090a0b0c0d0e0f`.

The control flow is two stages:

1. **Stage 1** — a VM at `0x4015e0` runs fixed-width three-byte bytecode (at file offset `0x23c0`, length `0x4d1`) over the 16-byte input, producing a transformed state.
2. **Key derivation + stage 2** — the binary computes `derived_key = HMAC-SHA256(key=rodata[0x28a4:0x28b4], data=stage1_state)` and uses that 32-byte digest as an **AES-256-GCM** key. It decrypts an embedded 924-byte ciphertext (IV at `0x28b4`, tag at `0x28c0`, ciphertext at `0x28d4`). The authenticated plaintext is a *second* VM program, run over the stage-1 state. If its comparison accumulator stays zero, the binary prints the unlock message.

## Vulnerability / Core Concept

The VM is a toy bytecode interpreter. Every instruction is three bytes — `(opcode, a, b)` — operating on 16 bytes of state:

| Opcode | Operation |
|---|---|
| `10` | `s[a] ^= s[b]` |
| `11` / `12` | add / subtract `s[b]` mod 256 |
| `13` | swap two state bytes |
| `20` / `21` / `22` | xor / add / subtract an immediate |
| `23` | multiply by an immediate mod 256 |
| `30` / `31` | rotate a byte left / right |
| `40` / `41` | AES S-box / inverse AES S-box |
| `50` / `51` | apply one of two permutation-table families |
| `60` | `s[a] ^= rol8(s[b], 3)` |
| `71` | compare `s[a]` with immediate `b` (sets a mismatch flag) |
| `00` | halt |

**Every transformation is a bijection.** Multipliers are always odd (so their modular inverse exists), the substitution is the AES S-box, and the permutation tables are full permutations with exact inverses. That means both stages can be run *backward* — but it also means stage 1 on its own contains no comparison, so it cannot pin down its input. The constraint on the activation key lives entirely inside the *encrypted* stage-2 program.

Here's the catch: stage 2 is encrypted under a key derived by `HMAC-SHA256(fixed_key, stage1_state)`. For a random 128-bit activation value, stage 1 is a permutation and HMAC behaves as a PRF, so the GCM blob is just a generic 128-bit key-confirmation oracle. Recovering the key from the binary *alone* would take ~2^128 trials. (We confirmed this the hard way — see "Dead ends" below.)

**This is exactly what the hint is for.** The official hint is the otherwise-unrecoverable 32-byte AES key:

```
9aebadceb2ae07382a9b56afa8a03c7a7b68f84ddc493d778f0ec0d8a242360f
```

With the derived key in hand, the whole thing unravels backward:

1. Use the hint key to authenticate + decrypt the 924-byte ciphertext → the stage-2 VM program (291 reversible transforms, then 16 comparisons, then halt).
2. Read the 16 comparison immediates (opcode `71`) → the **required terminal state** `4c9a3fe619eab4efa7efd87a5c49e4d8`.
3. Walk the 291 stage-2 transforms backward from that state → the **stage-1 state** `b0dd9edc83f370dad4f5399447579076`.
4. Sanity check: `HMAC-SHA256(embedded_key, stage1_state)` equals the hint exactly. ✓
5. Walk the static stage-1 bytecode backward from that state → the **activation value** `5b2d4c7961307f588d9dd95bada5647b`.

## Exploitation

The full solver is [`solve.py`](./solve.py). It pulls all tables directly from the binary (non-PIE, so offsets are fixed), implements the VM forward and inverse, and reproduces the self-test byte-for-byte before running the reversal.

Key pieces:

```python
# Tables lifted straight from the ELF (file offset = VA - 0x400000)
PROGRAM     = BIN[0x23C0 : 0x23C0 + 0x4D1]
HMAC_KEY    = BIN[0x28A4:0x28B4]
GCM_IV      = BIN[0x28B4:0x28C0]
GCM_TAG     = BIN[0x28C0:0x28D0]
CIPHERTEXT  = BIN[0x28D4 : 0x28D4 + 0x39C]

# The official hint == the AES-256-GCM key
HINT_KEY = bytes.fromhex("9aebadceb2ae07382...a242360f")
```

The inverse VM mirrors each opcode: subtract becomes add, `rol` becomes `ror`, S-box becomes inverse S-box, multiply uses `pow(b, -1, 256)`, and a permutation is undone by scattering instead of gathering (`old[table[i]] = new[i]`). Comparisons and halt don't touch state, so they're skipped during inversion.

The driver ties it together:

```python
stage2     = decrypt_stage2_with_hint()          # authenticate + decrypt
target     = comparison_target(stage2)           # read the 16 compare immediates
stage1     = invert_program(stage2, target)      # reverse stage-2 transforms
assert hmac.new(HMAC_KEY, stage1, sha256).digest() == HINT_KEY   # hint checks out
raw        = invert_stage1(stage1)               # reverse stage-1 bytecode
# flag = isfcr{ raw.hex() }
```

## Running It

```console
$ python3 solve.py
selftest: d3e4dd75211d03215a37de7164eb510a (matches)
stage-2 target: 4c9a3fe619eab4efa7efd87a5c49e4d8
stage-1 state:  b0dd9edc83f370dad4f5399447579076
activation:     5b2d4c7961307f588d9dd95bada5647b
flag:           isfcr{5b2d4c7961307f588d9dd95bada5647b}

$ printf 'isfcr{5b2d4c7961307f588d9dd95bada5647b}\n' | ./kelpie
KELPIE firmware unlock console
enter activation key: Unlocked. Activation accepted.
```

### Dead ends worth noting

Before the hint, we tried to beat the GCM oracle directly: every natural fixed-target (zeros, counter bytes, self-test output, embedded key/IV/tag, thematic strings, common hashes), a 23M-entry phrase grammar on kracken, all 2^32 completions for four IV-leak layouts with a validated OpenCL HMAC/AES kernel, and MT19937 / CPython `Random(seed)` state searches. None authenticated. The takeaway: with a bijective stage 1 and HMAC acting as a PRF, there is no static constraint to hand a solver — the hint supplying the derived key is the intended low-entropy relation.

## Flag

```
isfcr{5b2d4c7961307f588d9dd95bada5647b}
```

## Key Takeaways

- **Non-PIE binaries are a gift** — fixed `.rodata` means you can slice bytecode, S-boxes, and permutation tables straight out of the file (`file offset = VA - 0x400000`).
- When every VM op is a **bijection**, build the inverse interpreter and walk the program backward from the known target state — no brute force needed.
- **Read the hint economy.** When the only verifier is `HMAC-SHA256`-keyed AES-GCM over a 128-bit input, the search is ~2^128; recognizing that early tells you the hint (the derived key) isn't optional flavor, it's the whole attack.
- A "selftest" / factory mode is a free oracle — use it to validate your re-implementation before trusting your inversion.
