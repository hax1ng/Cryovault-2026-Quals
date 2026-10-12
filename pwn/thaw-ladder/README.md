# thaw-ladder

**Category:** pwn (custom VM / side channel) · **Flag:** `isfcr{pod_seven_bb3a_woke_1a161ac6_in_bay_c}`

## Challenge

> Pod 7 went into vitrification with the rest of bay C. Its controller still
> runs. Wake the pod.

We're given a kit (see `handout/`) documenting **FROSTLANG 7.2**, a tiny made-up
16-bit CPU, plus a reference controller — but the remote server (`nc <host> <port>`)
runs the **undocumented 7.3 field build**. `FIELD-NOTES.md` is explicit: *"where
the pod and the bench disagree, the pod is right."* Every TCP connection is a
fresh session with fresh randomness; per-session limits are 16384 plans / 3600 s.

Handout contents (`handout/`):

- `FROSTLANG.md` — the 7.2 programmer's manual (instructions + protocol)
- `frostbench.py` — the 7.2 reference controller (stdlib Python)
- `FIELD-NOTES.md` — what's known about the 7.3 field build
- `README.md` — protocol/session limits
- `seccomp.policy` — sandbox filter each session runs under

## Initial Analysis

FROSTLANG is a 16-register VM with a few arithmetic/memory ops and a budget of
65,536 retired instructions per submitted program ("plan"). The memory map that
matters:

| Range | Purpose |
|---|---|
| `0x0000`–`0x7fff` | writable RAM |
| `0x8000`–`0x80ff` | read-only boot data |
| `0x8100`–`0x81ff` | mailbox for attestation challenges |
| `0x8200`–`0x82ff` | gated control area |
| `0x9000`+ | protected controller data (documented build) |

`SEAL` is a badge scanner: it checks 32 cells against a secret 32-byte profile.
Pass it and the gate opens, letting us write a continuation word `CONT` at
`0x8200`; a later `HALT` then resumes our plan in **privileged mode**, where
`ATT` (attestation) becomes legal. Four correct `ATT` rounds yield
`THAWED <n> <flag>`. The intended path:

```text
pass SEAL -> write CONT -> HALT into privileged -> 4x ATT -> THAWED
```

The catch: the 32-byte profile is secret and its normal storage is unreadable.

## Vulnerability / Core Concept

Three distinct 7.3 bugs/quirks stack into the exploit.

### 1. `SEAL` has a signedness bug (bounds check → pointer bug)

The 7.2 manual says `SEAL`'s offset must be `0..32`. On the remote:

```text
offset 0x0021 -> FAULT      (33, correctly rejected)
offset 0x8000 -> SETTLED    (should be out of range!)
```

`0x8000` is 32768 unsigned but **-32768 signed**. The 7.3 check is effectively
`(int16_t)off <= 32`, so every high-bit value `0x8000..0xffff` slips through as
"negative." The subsequent address math still wraps in 16-bit space, redirecting
`SEAL`'s 32-cell comparison out of the protected area and into **ordinary
writable RAM** — which we control. We still can't *read* the secret profile, but
we can control the bytes being compared against it.

### 2. The response "meter" is a one-unit work side channel

On the 7.2 bench the response number is a retired-instruction count. The 7.3
banner shows a coarse cumulative **work meter**:

```text
thawd 7.3 pod 07 session 2b0f68d936d131e4 meter 128508 ready
```

It's an exact quantized counter: `new_meter = old + floor((residue + cost)/q)`
with a hidden per-session quantum `q` (~40–64), fixed per-plan overhead `h`, and
a leftover `residue`. Calibrate `q`, `h`, residue by spamming `HALT` and
`NOP;HALT` plans (the extra `NOP` kills aliased floor-models). Then pad with
`NOP`s to park the residue at exactly `q-1`: now **one extra unit of hidden work
clicks the visible meter over by one**. `SEAL` short-circuits on the first
mismatch, so a correct next byte makes it examine one more cell = one extra work
unit = one visible meter tick. That's our byte-recovery oracle.

### 3. The ladder is shuffled

Redirecting `SEAL` into RAM does **not** give a contiguous compare
(`RAM[A+0] vs P[0]`, `RAM[A+1] vs P[1]`, ...). Recovering byte 0 worked, but
placing guess 1 at `A+1` went nowhere. The breakthrough: **fill all of RAM** with
the candidate — that produced a hit for byte 1, proving the next compared cell
exists in RAM but *isn't adjacent*. 7.3 walks a **shuffled 32-rung ladder**: each
rung has a RAM source address and an expected byte, and the addresses turn out to
be a permutation of one contiguous 32-byte block. So every rung needs two
separate recoveries: **its byte value** and **its RAM address**.

## Exploitation

Full implementation (keep the single TCP connection alive the whole time — a new
connection reshuffles everything):

- `solve.py` — instruction encoders, assembler, client, and the ATT fold generator
- `meter_solve.py` — meter calibration + first-byte / mapping side-channel machinery
- `ladder_solve.py` — shuffled-ladder byte/address recovery + final thaw plan (driver)

Run it:

```bash
python3 -u ladder_solve.py | tee ladder_solve.out
```

**Recovering a rung's byte.** To test candidate `g` for rung `k`, build one plan
that (1) fills all 32 KiB of RAM with `g`, (2) restores every already-known
address to its correct byte, (3) runs `SEAL 0x8000`, (4) pads NOPs to align the
meter, (5) halts. The RAM fill is a tight word-store loop:

```python
p.emit(ldi(1, (g << 8) | g))   # two copies of candidate g
p.emit(ldi(2, 0))              # dest pointer
p.emit(ldi(3, 16384))          # 32768 bytes / 2
p.label("fill")
p.emit(stw(1, 2, 0))
p.emit(alui(2, 2, "ADD", 2))
p.emit_djnz(3, "fill")
```

That's ~49,158 retired instructions plus `2k` for restoring known rungs — under
the 65,536 budget. Wrong `g` → `SEAL` stops after the known prefix; right `g` →
one extra compare → one aligned meter tick. After a hit the residue is uncertain
(the compare may have run further by luck), so `fast_residue()` keeps the set of
possible residues and picks NOP-padded plans that best bisect it — recovering the
residue in ~`log2(q)` plans instead of `q`.

**Locating the rung's address.** Binary-search RAM (~15 probes): fill the lower
half with the known byte, restore earlier rungs, run the aligned `SEAL` probe; a
match means the source is in the filled half. The word-store loop pins a 2-byte
word; one single-byte probe splits even/odd. Zero needs inversion (fresh RAM is
already zero, so poison the tested half with `1` instead and invert the logic).

**The last byte needs a different oracle.** With byte 31 wrong or right, `SEAL`
examines all 32 cells either way — equal work, nothing to leak. So use the
**gate itself** as a 1-bit oracle: for each candidate, fill RAM, restore the 31
known rungs, `SEAL 0x8000`, try to store a valid `CONT` to `0x8200`, `HALT`,
and run one privileged `ATT`. Wrong → gate closed → the control store `FAULT`s;
right → store works → `ATT` draws a challenge → `SETTLED`. The same gate/no-gate
test binary-searches rung 31's address.

**Two orders in play.** The 32 recovered bytes are in *comparison* order, not the
*linear* order `ATT`'s fold expects. Feeding the ladder order straight to the
fold gave a clean `REJECT` (not a fault) — proving privilege/challenge handling
was already correct and only the ordering was wrong. Pairing each byte with its
recovered source address and sorting by address rebuilds the real profile:

```python
pairs = sorted(zip(all_addrs, ladder_profile))
fold_profile = bytes(value for address, value in pairs)
```

Recovered in the winning session:

```text
ladder order : b99ab3f0526b3a08846b50f4d16015446254ef098a12168591f82ff199450208
addresses    : 0x183d .. 0x185c (shuffled)
fold order   : 3ab9080860b3f144992fd1846202f8ef12855250096b9af015166b91f48a5445
```

**Final thaw plan** (one execution, since state resets per plan): fill RAM with
the last ladder byte → restore the 31 scattered addresses → `SEAL 0x8000` (all 32
pass) → **only now** write the linear `fold_profile` to a clean table at `0x1000`
(writing it earlier would clobber the scattered source block) → store privileged
`CONT` at `0x8200` → `HALT` into privileged mode → run the documented 16-step
fold for four `ATT` rounds:

```text
for t = 0 .. 15:
    j = (t + (y >> 12)) & 15
    x = rol16(x ^ K[j], y & 15)
    x = (x + N[t & 3]) & 0xffff
    y = (y * 0x9e35 + x + t) & 0xffff
    y = y ^ rol16(x, 7)
```

The generated final program was 204 words (privileged code starting at word 105),
well inside both limits. Total recovery used 7,158 probing plans, under the
16,384/session cap.

## Flag

```
isfcr{pod_seven_bb3a_woke_1a161ac6_in_bay_c}
```

Winning run tail:

```text
P[31]=08 PROFILE=b99ab3f0526b3a08846b50f4d16015446254ef098a12168591f82ff199450208 plans=7158
SRC[31]=0x1840 FOLD_PROFILE=3ab9080860b3f144992fd1846202f8ef12855250096b9af015166b91f48a5445
final words 204 priv 105
FINAL THAWED 2969013 isfcr{pod_seven_bb3a_woke_1a161ac6_in_bay_c}
```

## Key Takeaways

- **Signedness bugs turn bounds checks into pointer bugs.** `(int16_t)off <= 32`
  passed values a `uint16_t` check would have rejected, redirecting a protected
  comparison into attacker-controlled RAM.
- **Coarse telemetry is still a side channel.** Rounding the work counter wasn't
  enough once we could deliberately park its hidden residue at `q-1`, making a
  single extra comparison visible.
- **A prefix oracle need not walk memory linearly.** Recovering each expected
  byte and locating its (shuffled) source address were two separate searches.
- **Black-box replies are evidence.** `FAULT` vs `SETTLED` vs `REJECT` each
  isolated a different stage — the clean `REJECT` is what pointed at the
  comparison-order-vs-fold-order distinction.
