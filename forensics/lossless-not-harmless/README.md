# Lossless, Not Harmless

**Category:** Forensics · **Points:** 56 · **Solves:** 75 · **Flag:** `isfcr{ch0ic3s_th3_d3c0d3r_n3v3r_s33s}`

## Challenge

> An archive server re-compresses every image that comes through it with its own in-house compressor. One picture that passed through is hiding a message.
>
> You are given one file, `mosaic_0417.png`. The flag is in `isfcr{...}` format.

## Initial Analysis

The visible picture is innocent — a valid 256×300 indexed-color PNG. The interesting part is *how its pixel data was compressed*. The usual checks surface two suspicious text fields:

```bash
file mosaic_0417.png
pngcheck -vv mosaic_0417.png
exiftool mosaic_0417.png
```

```text
Software : dfl-stitch 2.3 (equivalent-match mode, flush=sync)
Comment  : aXNmY3J7bm9wZV9ub3RfdGhpc19vbmV9
```

The `Comment` is Base64 and decodes to `isfcr{nope_not_this_one}` — a deliberate **decoy**. The real clue is the `Software` field:

- `dfl` → **DEFLATE**, the compression used inside PNG `IDAT` chunks.
- `equivalent-match mode` → the compressor chooses between LZ77 matches that decompress to identical bytes.
- `flush=sync` → look at the padding produced by DEFLATE sync flushes.

Both of those are places a normal decoder ignores — i.e. two covert channels.

## Vulnerability / Core Concept

"Lossless" only means decompression recreates the original pixels. It does **not** mean there is a single valid compressed representation of those pixels. This compressor exploits two degrees of freedom invisible to any standard decoder:

**Channel 1 — equivalent-match parity.** DEFLATE replaces repeats with LZ77 *length/distance* matches ("copy 12 bytes from 120 back"). Often the same bytes appear at several earlier distances, so the compressor can pick an **even distance for `0`, odd for `1`**. A match only carries a bit when both an even- and an odd-distance candidate exist in the 32 KiB window. These bits spell out an encrypted blob **and the plaintext instructions for decrypting it**.

**Channel 2 — discarded sync-flush padding.** A DEFLATE *stored block* is byte-aligned. If the stored-block header ends mid-byte, the decoder skips the remaining bits to the next byte boundary. Normally those bits are zero junk; here they hold the **128-bit key**. There are 31 sync-flush blocks whose padding runs concatenate to exactly 128 bits.

The recovered instructions describe an authenticated stream cipher:

```text
ks_i = SHA256(key | nonce | u32be(i));  ct = pt ^ ks;
tag  = HMAC-SHA256(key, nonce | ct)[:8];  blob = nonce8 | ct | tag8
```

## Exploitation

1. **Extract the DEFLATE stream** by concatenating the `IDAT` chunks (`extract_idat.py` → `stream.zlib`).
2. **Disassemble it with [`infgen`](https://github.com/madler/infgen)** to get both the token listing and the bit-level listing:

   ```bash
   infgen -q   stream.zlib > tokens.txt   # literal/match tokens
   infgen -ddq stream.zlib > bits.txt     # detailed bit-level dump
   ```
3. **Channel 1:** replay the tokens to rebuild the output, and at every match search the 32 KiB window for equivalent distances. Keep only matches where both parities are reachable, and record the parity of the chosen distance. Packed MSB-first, the bits start with the magic `DFL8`, a `u16` length, the ASCII instructions, a NUL, then `nonce8 | ct | tag8`.
4. **Channel 2:** for each `stored` block in `bits.txt`, take the padding bits. infgen prints each run MSB-first while DEFLATE consumes it LSB-first, so **reverse each run**, concatenate, and pack MSB-first → the 128-bit key `2814c69217b303ec00c6280fa2c50286`.
5. **Decrypt + verify:** confirm the HMAC tag, then XOR the SHA-256 counter keystream against the ciphertext.

`solve.py` does all of the above from `tokens.txt` and `bits.txt`:

```text
$ python3 solve.py
INSTRUCTIONS: key: 128 pad bits discarded by decoder ...
KEY: 2814c69217b303ec00c6280fa2c50286
FLAG: isfcr{ch0ic3s_th3_d3c0d3r_n3v3r_s33s}
```

## Flag

```
isfcr{ch0ic3s_th3_d3c0d3r_n3v3r_s33s}
```

## Key Takeaways

- Lossless compression has representational slack: equivalent LZ77 matches and ignored alignment bits are classic steganographic carriers.
- `infgen` is the right tool for reading DEFLATE at the token and bit level.
- Watch bit endianness — DEFLATE packs bits LSB-first within a byte; infgen displays runs MSB-first.
- Metadata can lie (the Base64 decoy) *and* tell the truth (the `Software` string naming the exact technique).

## Files

- `README.md` — this writeup
- `mosaic_0417.png` — the challenge PNG
- `extract_idat.py` — joins the `IDAT` chunks into `stream.zlib`
- `solve.py` — full solve: both covert channels + decrypt (reads `tokens.txt`, `bits.txt`)
- `tokens.txt`, `bits.txt` — infgen dumps of the stream (regenerable from the PNG via the commands above)
