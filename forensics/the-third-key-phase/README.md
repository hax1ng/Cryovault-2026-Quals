# The Third Key Phase

**Category:** Forensics · **Points:** 170 · **Solves:** 56 · **Flag:** `isfcr{7d6bae9970a1173284046064}`

## Challenge

> Recover the exact bytes of the file the intake service accepted for request `6e26102a48d71fe1d7f68231`. Evidence fields, in order: the request id, the `client_random` of the connection that delivered the file, and the SHA-256 of the file (lowercase hex). Those three strings are fed through `scrypt` + `AES-GCM` (recipe supplied) to produce the flag.

Given: one capture, `capture.pcapng`. Flag format `isfcr{...}`.

## Initial Analysis

```bash
capinfos capture.pcapng
tshark -r capture.pcapng -q -z conv,udp
```

265 UDP packets on port 443 → **QUIC**, not TCP/TLS. Two pieces of PCAPNG metadata are decisive:

- A **Decryption Secrets Block** (NSS keylog) with TLS application traffic secrets. Extract it with:

  ```bash
  editcap --extract-secrets capture.pcapng secret
  ```

  Each line is `CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>` — the `client_random` also identifies the connection.
- A **capture comment** giving `largest_client_pn` / `largest_server_pn` per connection. QUIC only sends the low 1–4 bytes of a packet number; you reconstruct the full value from the largest one already seen, so those starting points are essential.

The capture begins **after** the QUIC handshakes, so Wireshark can't auto-derive every connection ID / cipher / version. The short-header packets must be decrypted manually with `aioquic`'s crypto primitives.

## Vulnerability / Core Concept

Peel the layers: `PCAPNG → QUIC decryption → QUIC streams → de-striped compressed data → raw DEFLATE → exact file → SHA-256 → flag`. The traps:

- **Connection migration + variable CID lengths.** The winning connection starts at `192.0.2.10:57949`, migrates to `203.0.113.37:37187`, and its destination connection IDs change length (8 → 12 bytes client-side; 5 bytes server-side on the new path, recovered from decrypted `NEW_CONNECTION_ID` frames). A single fixed CID length makes decryption fail.
- **The "third key phase."** This connection is **QUIC v2 + ChaCha20-Poly1305** and performs several key updates. The next traffic secret is `HKDF-Expand-Label(secret, "quicv2 ku", "", 32)`, and keys/IVs use the `quicv2 key` / `quicv2 iv` labels. The target packets reach **key generation 3**. Crucially, **header protection does not rotate on a key update** — keep the original `quicv2 hp` key to unmask the header/packet number, then pick the updated key for the payload. AEAD authentication makes the search self-checking: a wrong CID length, packet number, secret, or generation simply fails to authenticate.
- **Decoy earlier attempt.** The same `request_id` appears first on connection `bfa624226cf1...` (QUIC v1), which never completes — the server sends `STOP_SENDING` and the client closes. The successful upload is on `87566bdc267e...`.
- **Striping + replacements.** The winning connection's metadata stream says the compressed upload was split into **119-byte units**, round-robin across logical parts `[0, 4, 8, 12]`. Control streams then *replace* corrupted parts: stream 8 is bad → replaced by stream 16; part 4 → stream 20; a later copy on stream 24 is corrupt (status 26) and must be ignored. Accepted physical streams: `0, 20, 16, 12`.
- **Raw DEFLATE.** De-striping yields **raw DEFLATE** (no zlib/gzip wrapper) — inflate with `wbits = -15`. Hashing the compressed bytes (a natural first mistake) fails; you must hash the *decompressed* file.

## Exploitation

The pipeline (scripts included):

1. `editcap --extract-secrets capture.pcapng secret` — pull the TLS secrets out of the pcapng. *(The `secret` keylog is intentionally not committed — regenerate it with this one command.)*
2. `python3 decrypt_875.py > dec875.txt` — decrypt the winning QUIC v2 connection across all key generations (header-protection key fixed; payload key per generation; CID length by path).
3. `python3 parse_875.py` — parse QUIC frames from the decrypted packets and reassemble each `STREAM` by stream-id/offset, writing `875_stream_<role>_<id>.bin`.
4. `python3 reassemble_and_decrypt.py` — de-stripe the four accepted parts, raw-inflate, SHA-256, then run the supplied `scrypt` + `AES-GCM` recipe.

`analyze_target.py` is the QUIC v1 frame parser used to analyze the earlier **failed** attempt (`bfa624...`) and confirm it was abandoned; `parse_875.py` imports its `frames()` parser.

The de-stripe + decrypt output:

```text
$ python3 reassemble_and_decrypt.py
striped (compressed) bytes: 10027
accepted file bytes: 16456
sha256: 43669914701c2add27583d67043e96c02f44d622a78116f10fea5fac66e233dd
FLAG: isfcr{7d6bae9970a1173284046064}
```

The accepted file is a readable transfer ledger beginning `# transfer 6e26102a48d71fe1d7f68231`.

Final evidence:

```python
evidence = [
    "6e26102a48d71fe1d7f68231",                                           # request id
    "87566bdc267eee5e8a8a7d0251033ec0ce2aef613ef35623cf1e6dc5fc1310d3",   # client_random
    "43669914701c2add27583d67043e96c02f44d622a78116f10fea5fac66e233dd",   # SHA-256 of file
]
```

## Flag

```
isfcr{7d6bae9970a1173284046064}
```

## Key Takeaways

- Captures starting after the handshake force manual QUIC decryption — `aioquic`'s `CryptoContext` + the extracted NSS secrets do the heavy lifting.
- QUIC v2 uses different labels (`quicv2 ku/key/iv/hp`); key updates rotate the AEAD key but **not** header protection.
- Connection migration can change destination CID lengths mid-stream.
- AEAD auth turns a huge brute-force (CID length × packet number × generation) into a safe, self-verifying search.
- Reassembling striped streams gives *compressed* data, and here it's raw DEFLATE — hash the decompressed file, not the wire bytes.

## Files

- `README.md` — this writeup
- `capture.pcapng` — the challenge capture
- `decrypt_875.py` — QUIC v2 / ChaCha20-Poly1305 decryption of the winning connection across key generations (reads `secret`, `capture.pcapng`)
- `analyze_target.py` — QUIC v1 frame parser; analyzes the earlier failed attempt (reads `secret`, `capture.pcapng`)
- `parse_875.py` — reassembles QUIC `STREAM` frames from `decrypt_875.py`'s output (`dec875.txt`)
- `reassemble_and_decrypt.py` — de-stripe the accepted parts → raw DEFLATE → SHA-256 → flag
- `875_stream_CLIENT_0.bin`, `875_stream_CLIENT_20.bin`, `875_stream_CLIENT_16.bin`, `875_stream_CLIENT_12.bin` — the four accepted stream parts (inputs to the reassembler)

**Excluded:** the extracted `secret` keylog (regenerate with `editcap --extract-secrets`), the original `handout.zip`, and the dozens of throwaway intermediate `.bin` / `.txt` experiment dumps from the solve.
