# brine

**Category:** Crypto · **Points:** 494 · **Solves:** 2 · **Flag:** `isfcr{shard_f37c_brine_27d059a2_jacket}`

## Challenge

> A Kestrel CT-9 sounding head holds the brine loop's calibration profile in a
> sealed table, and the vault's recovery bundle was sealed against it: open the
> bundle. Send `{"cmd":"SESSION"}` first for a head of your own, and start with
> README.md.
>
> `nc 0.cloud.chals.io 12312`

We get a line-delimited JSON service over TCP and an attachment (`brine.zip`)
containing a README, a local simulator (`brine_sim.py`), and the firmware 2.4.1
source drop under `challenge/`. The extracted source is included here under
[`challenge/`](challenge/).

The device stores a sorted table of 32 secret 32-bit setpoints (`sigma_1 ..
sigma_32`). That table never leaves the device. The recovery bundle we must open
is AES-256-GCM encrypted under a key derived directly from the table:

```
key = SHA256(b"BRINE-SEAL-v2" || sigma_1 || ... || sigma_32)   # each a big-endian uint32, ascending
```

So SHA-256 and AES-GCM are not the target. The job is to recover the 32 inputs
to SHA-256.

## Initial Analysis

Each connection starts with `SESSION` (new head, new profile, new bundle) or
`RESUME <token>` (rebind to an existing head). The useful commands:

- `HELLO` — returns `instance_id`, firmware version, round counter `t`, and the
  `session_key`.
- `SOUND` — takes a 32-bit test value `w` and a repetition count `reps` (1–2048),
  returns that many timing samples called `deltas`.
- `BUNDLE` — returns the sealed AES-256-GCM recovery bundle.

Two things stood out immediately:

- **Request auth is not the puzzle.** Every `SOUND` carries a "FROSTWRAP-24" tag,
  which [`challenge/src/ct9_auth.py`](challenge/src/ct9_auth.py) reveals is just a
  truncated HMAC-SHA256 over `instance_id || t || w || reps`. Since `HELLO` hands
  us the `session_key`, we can compute the tag ourselves — no cracking needed. The
  bundled advisory (`KES-2026-0114`) about an early-exit tag comparison is a red
  herring; it was fixed in 2.4.0, before both the supplied 2.4.1 source and the
  live 2.5.3 firmware.
- **The live head reports firmware 2.5.3, but the source is 2.4.1.** The source
  explains the *design*, but the live timing behaviour has to be measured, not
  assumed — this bit us later (see Dead Ends).

## Vulnerability / Core Concept

The whole attack rests on a timing side channel in the table lookup, visible in
[`challenge/src/ct9_sounder.py`](challenge/src/ct9_sounder.py).

The head keeps a "finger" (a bookmark) at the rank of the last lookup. A new
lookup galops from the finger to the new rank, and the number of gallop steps
depends on how far the finger has to move:

```python
def rank(profile, w):      # number of setpoints <= w
    ...
def gallop_steps(finger, target_rank):
    d = abs(target_rank - finger)
    return 1 if d == 0 else 1 + floor(log2(d))
```

The returned `deltas` are synthesized as `BASE_NS + CAV_DELTA_NS * cav + jitter`,
where each active gallop step gets an independent chance to add a "cavitation
event" (`+12000 ns`). More gallop steps → a different distribution of cavitation
counts. Because jitter lives in tiny 240 ns ticks while a cavitation event is
12000 ns, we can cleanly recover the event count per sample with integer
division and average over all repetitions:

```python
BASE_NS, CAV_DELTA_NS = 48000, 12000
def cavitation_score(deltas):
    return sum((d - BASE_NS) // CAV_DELTA_NS for d in deltas) / len(deltas)
```

With 2048 reps the groups are obvious and widely separated, so a simple
threshold classifies each probe into a leakage class (low / medium / high).

**Why a class change reveals an exact secret.** For a sorted table,
`rank(w) = #{ sigma_i <= w }`. For a secret entry `x`, `rank(x-1)` does not count
it but `rank(x)` does — the rank jumps at the *exact integer* `x`. If we fix the
lookup state (anchor) so those two ranks land in different leakage classes, the
observed class also flips at `x`. A binary search on `w` then pins the exact
32-bit boundary in ~32 probes. The `reps`-up-to-2048 cap turns a noisy
statistical channel into a clean yes/no oracle: one rate-limited request gives us
2048 samples to average.

## Exploitation

**1. Recover setpoints from the side channel.** Starting from a known anchor
rank `k`, ranks `k` and `k+1` fall in the low class and `sigma_(k+2)` is the
first non-low point — so we binary-search that transition, then walk the odd and
even subsequences across the whole table. The driver is
[`solve_brine.py`](solve_brine.py) (the per-session `RESUME` token is redacted).
Its core:

```python
def is_low(self, anchor_w, test_w):
    self.sound(anchor_w, 1)                 # set the finger
    ds = self.sound(test_w, TEST_REPS)      # 2048 samples
    mean = sum((d - BASE_NS)//CAV_DELTA_NS for d in ds) / TEST_REPS
    return mean < LOW_CUTOFF

# first transition = sigma_1; then walk odd/even subsequences:
sigma[k+2] = boundary(sigma[k], U32_MAX,
                      lambda w, a=sigma[k]: not is_low(a, w), True)
```

Each candidate boundary is re-checked at `x-1`, `x`, (`x+1`) under a stable
anchor before being accepted.

**2. Brute the one stubborn entry against the GCM tag.** On the live 2.5.3 head,
one setpoint never landed on a usable observable boundary for the anchor
sequences we had. Rather than hand-craft more anchor chains, we used the bundle
as a perfect offline checker: for any candidate 32-bit integer, insert it into
the 31 known values, derive the SHA-256 seal key, and test whether it reproduces
the bundle's 128-bit GCM tag. A wrong candidate matching is negligibly unlikely.

```python
for candidate in range(1, 2**32 - 1):
    profile = sorted(known31 + [candidate])
    key = sha256(b"BRINE-SEAL-v2" + b"".join(x.to_bytes(4,"big") for x in profile)).digest()
    if valid_gcm_tag(key, nonce, ciphertext, wanted_tag):
        break
```

4 billion SHA-256 + AES-GCM checks is too slow in Python, so this ran as a small
CUDA kernel split across two GPUs (each candidate inserts itself at the right
sorted position, runs the SHA-256 compression blocks, expands the AES-256 key,
and checks the GCM tag). The lower half reported the match in ~44.5 s:

```
missing setpoint = 253627290   # sorts between 116270928 and 271114478
```

**3. Open the bundle.** With all 32 setpoints
([`profile.txt`](profile.txt)), derive the key and decrypt. See
[`decrypt_bundle.py`](decrypt_bundle.py):

```python
material = b"BRINE-SEAL-v2" + b"".join(x.to_bytes(4,"big") for x in profile)
key = hashlib.sha256(material).digest()
nonce, ciphertext, tag = sealed[:12], sealed[12:-16], sealed[-16:]
plaintext = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
```

Output ([`plaintext.bin`](plaintext.bin)):

```
CT-9 CALIBRATION RECOVERY BUNDLE
profile-entries: 32
isfcr{shard_f37c_brine_27d059a2_jacket}
```

### Dead Ends

The first attempt assumed the live firmware behaved exactly like the 2.4.1 Python
class (one anchor sets `finger` to the anchor's rank, full stop). That produced
convincing-looking but *false* boundaries — the service says 2.5.3 for a reason.
The fix was to treat the live head as a black box: fix a reset/anchor sequence,
only compare probes using the same sequence, learn the leakage classes
experimentally, and re-validate every boundary. Two initially plausible values
were slightly wrong and failed the `x-1`/`x` recheck under a stable prefix.

## Flag

```
isfcr{shard_f37c_brine_27d059a2_jacket}
```

## Key Takeaways

- Strong encryption doesn't help when the key's secret inputs leak elsewhere —
  here, through a lookup-timing side channel.
- A `reps`-up-to-2048 knob turns a noisy statistical leak into a clean oracle:
  averaging kills the jitter and makes the cavitation classes trivially separable.
- Old source reveals the design flaw even when the live firmware differs — but
  live timing behaviour must be *measured*, not assumed.
- AES-GCM authentication cuts both ways: once the unknown key-space is small
  enough (one 32-bit value), the 128-bit tag is an unambiguous offline
  correctness check — ideal for a targeted GPU brute force.
