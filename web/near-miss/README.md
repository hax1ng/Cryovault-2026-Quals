# near-miss

**Category:** Web · **Points:** 488 · **Solves:** 3 · **Flag:** `isfcr{frostline_5e05_keeper_56e7c6c4_runbook}`

## Challenge

> Frostline's runbook is shared with every operator except one line: the keeper's seal, re-cut every minute and redacted on your copy. Open a console at the address below; each console is a runbook service of its own.

Author: AJ. Target: `https://isfcrpesu-near-miss.chals.io`. Ships a `README.md` handout and a stdlib [`client.py`](./client.py). Each session (`POST /session`) is an isolated runbook service under `BASE = URL/s/<token>`.

Three session endpoints matter:

- `GET /runbook` — our copy of the runbook, with the seal blanked to `######`.
- `POST /hunks/check` — checks whether proposed replacement text is "close enough" to the keeper's secret master copy.
- `POST /unseal` — accepts the current six-character seal and returns the flag.

The seal is re-cut every 60 seconds and only three `/unseal` attempts are allowed per cut. Our runbook line looked like:

```text
keeper seal: ###### · cut 15:10:00Z
```

## Initial Analysis

We never see the seal, and we only get three guesses a minute against a 6-char alphabet of 32 symbols (`0123456789abcdefghjkmnpqrstvwxyz`) — brute force (32⁶ ≈ 1 billion) is hopeless. The leverage has to be `/hunks/check`.

A `hunk` is `{near, find, put}`: it asks whether `find` applies at offset `near` in the keeper's master. Crucially, the comparison is **fuzzy** — it accepts approximate matches. Probing a known 16-byte string showed the exact tolerance:

```text
7 deliberate substitutions in 16 bytes  -> applies
8 consecutive substitutions in 16 bytes -> does NOT apply
```

So the matcher forgives up to 7 wrong bytes out of 16.

## Vulnerability / Core Concept

**A fuzzy "is this close enough?" oracle leaks the exact secret** once you spend its entire error budget on bytes you don't care about.

Build a 16-byte probe as:

```text
XXXXXXX  <candidate>  <8 known bytes after the candidate>
```

The seven leading `X`s are intentionally wrong, using up all seven allowed errors. Now the probe applies **iff** the candidate byte is correct (a wrong candidate makes 8 errors → rejected). The yes/no answer has become an exact one-character test.

Two facts make this devastatingly efficient:

- The alphabet is 32 symbols and `/hunks/check` accepts **32 hunks per request** — so one request tests every candidate for a position at once.
- `/hunks/check` has its own rate limit, separate from `/unseal`'s 3-guess cap.

**Recover right-to-left.** Attacking the last seal byte, everything after it (`· cut …`) is public. Once it's known, it joins the known suffix for the byte before it, and so on:

```text
?????p → ????3p → ???r3p → ??yr3p → ?jyr3p → mjyr3p
```

Going left-to-right would leave *unknown* seal bytes after the candidate, which would silently eat into the 7-error budget and break the oracle. Backward keeps the suffix fully known.

**One calibration wrinkle:** the byte offset in our exported runbook is not the matching offset in the keeper's master. We calibrate the `shift` by sending the 7-wrong-byte probe while sweeping `near` up and down; the accepted range's midpoint gives the local adjustment (85 bytes in the sample session):

```python
redacted = runbook.index(b"######")
copy_prefix_start = redacted - 16
known_prefix = runbook[copy_prefix_start:redacted]   # b"ar\nkeeper seal: "
location_probe = b"XXXXXXX" + known_prefix[7:]
# sweep near up to find the low edge, down to find the high edge, take the midpoint
shift = (lower + upper) // 2 - copy_prefix_start
```

## Exploitation

[`solve.py`](./solve.py) is self-contained: it opens a session, calibrates the shift, waits for a fresh cut so all six probes + the unseal land inside one minute, leaks the seal backward, and submits it. The leak loop:

```python
for index in range(5, -1, -1):
    target = redacted + index
    start = target - 7
    suffix = b"".join(secret[later].encode() for later in range(index + 1, 6))
    suffix = bytes((suffix + runbook[redacted + 6:])[:8])   # 8 known bytes after candidate

    hunks = []
    for candidate in ALPHABET:                              # all 32 at once
        probe = b"XXXXXXX" + candidate.encode() + suffix    # 16 bytes
        text = probe.decode()
        hunks.append({"near": start + shift, "find": text, "put": text})

    hits = [c for c, applies in zip(ALPHABET, check_hunks(base, hunks)) if applies]
    assert len(hits) == 1
    secret[index] = hits[0]
```

Byte strings are used throughout because the runbook contains UTF-8 (`·`) and the endpoint's length limits are counted in bytes. Overlapping hunks in a batch can interfere after one applies, but that's harmless here: wrong candidates all fail, the correct one is the single `true`.

## Running It

```text
keeper-line adjustment: +85 bytes
partial: ?????p
partial: ????3p
partial: ???r3p
partial: ??yr3p
partial: ?jyr3p
partial: mjyr3p
seal: mjyr3p
response: 200 {"flag":"isfcr{frostline_5e05_keeper_56e7c6c4_runbook}"}
```

Six `/hunks/check` requests recover the whole seal, then a single `/unseal` returns the flag.

## Flag

```
isfcr{frostline_5e05_keeper_56e7c6c4_runbook}
```

## Key Takeaways

- A fuzzy/approximate-match oracle is still an oracle: deliberately exhaust its error tolerance on don't-care bytes and the remaining byte becomes an exact test.
- Leak **toward the known data** (here, right-to-left) so unknown bytes never sit inside the comparison window and drain your error budget.
- Align the batch size with the secret's alphabet (32 hunks ↔ 32 symbols) to pin each position in exactly one request — essential when a time window and a separate attempt cap are ticking.
- Exported/redacted copies rarely share the server's internal offsets; calibrate the `near` offset instead of assuming it.
