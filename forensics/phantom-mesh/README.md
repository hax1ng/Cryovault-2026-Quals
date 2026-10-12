# Phantom Mesh

**Category:** Forensics · **Points:** 50 · **Solves:** 107 · **Flag:** `isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}`

## Challenge

> A smart lighting mesh at an office has a device on it that nobody added, and it sends a short diagnostics report at the same time every day. You get an over-the-air radio capture, the raw signal straight off the coordinator antenna, and the vendor's notes on their protocol. Nobody has the network key. Recover the report and read the flag out of it.
>
> You are given `mesh.pcap`, the raw I/Q trace and nonces under `traces/`, and the vendor protocol notes under `docs/`. The flag is in `isfcr{...}` format, with printable ASCII and no spaces inside the braces.

## Initial Analysis

Three artifacts matter:

- `mesh.pcap` — IEEE 802.15.4 frames carrying the Lumeta Mesh Protocol (LMP).
- `traces/iq.npz` — 2,500 aligned I/Q recordings (one per transmitted `KEY_CONFIRM`). **Not committed here — 43 MB.**
- `traces/nonces.csv` — the public 16-byte nonce that went on air during each recording.

Listing the raw 802.15.4 payloads shows the traffic shape:

```bash
tshark -r mesh.pcap -T fields -e frame.number -e wpan.src16 -e wpan.dst16 -e data.data
```

Every LMP PDU begins `1c 03 <cmd>`. Most frames are small `SECURE_REPORT`s (`cmd 0x21`). The notable ones:

- Frames 32–39: plaintext `KEY_CONFIRM` (`cmd 0x12`).
- Frame 40: a protected `TRANSPORT_KEY` (`cmd 0x11`) — carries the site Network Key, wrapped under the fleet-wide **Trust Center (TC) Link Key**.
- Frame 81: an oversized `SECURE_REPORT` from `0x1040` — big enough to hold a flag (this is the rogue device's report).

The key hierarchy (from `docs/LMP-protocol.md`): the TC Link Key is **the same across every Lumeta coordinator in the world** and protects `TRANSPORT_KEY`; the Network Key is per-site and protects reports. We have neither.

## Vulnerability / Core Concept

The crypto (AES-CCM*) is fine — the weakness is **hardware**. `docs/sdr-capture.md` is a lab notebook full of tells:

- the PA bias feed ships without the recommended decoupling cap ("envelope stability adequate for lighting but not for metrology");
- the AES stack runs **in software** on the main core;
- every record is hardware-aligned to the same instant (`tx_start()` trigger on the PPS input);
- all 2,500 nonces are known.

A software AES byte-op draws slightly different power depending on the Hamming weight of its intermediate values. Because the PA's supply isn't isolated, that load variation modulates the transmitted RF envelope. One trace is pure noise, but the relationship becomes statistically visible across 2,500 aligned traces — a textbook **Correlation Power Analysis (CPA)** attack.

For one key byte, the first-round intermediate is `SBOX[nonce_byte ^ key_byte]`. For each of the 256 guesses, correlate the predicted Hamming weight against every time sample of the measured power `|iq|²`. The correct guess peaks far above the rest — and the 16 bytes peak at evenly spaced samples (1051, 1097, 1146, …), exactly what a byte-sequential software routine looks like.

## Exploitation

**Stage 1 — CPA to recover the TC Link Key** (`solve_cpa.py`). The script builds all 16×256 Hamming-weight hypotheses, normalizes both hypotheses and power columns, and does the correlation as one matrix multiply (torch/GPU for speed; `iq.npz` required):

```bash
python3 solve_cpa.py traces/iq.npz traces/nonces.csv
```

Winning bytes → **TC Link Key `7cf8b0b78be9f36a225c1e70692e1e1c`**.

**Confirming it's real.** `KEY_CONFIRM` carries a tag derived "deterministically from `nonce` under the TC Link Key, truncated to 8 octets." The natural construction `AES-ECB(tc_key, nonce)[:8]` exactly matches the frame-32 tag `c38d863b06d04469` (and the others) — not a false positive.

**Stage 2 — unwrap and decrypt** (`decrypt_lmp.py`). LMP is AES-CCM* with a deliberate byte-order mismatch for the source EUI-64:

```python
nonce = eui64_le[::-1] + counter + sec_ctl   # EUI-64 big-endian in the nonce
aad   = sec_ctl + counter + eui64_le          # little-endian in the AAD
```

Decrypt frame 40 with the TC key → **Network Key `ffa0be732cd8f56eae8caa21359baf06`** (the CCM tag verifies). Decrypt frame 81 with the Network Key; strip the 6-byte ZCL-style header (`cluster_id | attribute_id | vlen`, all LE) and the remaining 52 bytes are the flag:

```text
$ python3 decrypt_lmp.py
KEY_CONFIRM tag check OK: c38d863b06d04469
Network Key: ffa0be732cd8f56eae8caa21359baf06
FLAG: isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}
```

## Flag

```
isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}
```

## Key Takeaways

- A side channel can live in the *transmitter*: a sloppy PA supply turned the radio envelope itself into a power trace.
- CPA on the first-round `SBOX[nonce ^ key]` with known nonces + many aligned traces recovers an AES key one byte at a time.
- AEAD tags are free verification — the KEY_CONFIRM match and the CCM tag both confirm each recovered key before you trust it.
- Read the "flavor" docs carefully; the missing decoupling cap and "software AES" lines *are* the vulnerability.

## Files

- `README.md` — this writeup
- `mesh.pcap` — the 802.15.4/LMP capture
- `docs/LMP-protocol.md`, `docs/sdr-capture.md` — vendor protocol + SDR capture notes
- `traces/nonces.csv` — per-trace known nonces
- `solve_cpa.py` — CPA attack recovering the TC Link Key (needs `traces/iq.npz`)
- `decrypt_lmp.py` — unwraps the Network Key and decrypts the rogue report → flag

**Excluded for size:** `traces/iq.npz` (43 MB I/Q trace, required by `solve_cpa.py`) and the original `phantom-mesh.zip` (44 MB).
