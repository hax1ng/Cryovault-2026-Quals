# Cryovault 2026 Quals — Writeups

Solutions, exploits, and writeups by **CyberdyneSystemsT800** (solo) for the **Cryovault 2026 Qualifiers**.

- **Event:** Cryovault 2026 Quals
- **When:** 10 Oct 2026, 00:30 EDT → 11 Oct 2026, 00:30 EDT (24 hours)
- **Platform:** CTFd
- **Flag format:** `isfcr{...}`
- **Team:** CyberdyneSystemsT800 (solo)
- **Placement:** 🥈 2nd

**21 challenges solved** across **8 categories** (the four boot2root machines were each rooted end-to-end — both user and root flags).

---

## Challenges

### boot2root
Full-chain machines — each writeup covers the complete path from initial foothold to root.

| Challenge | Points | Solves | Flags | Writeup |
|---|---:|---:|---|---|
| Dont Trust Me | 488 | 3 | user + root | [writeup](boot2root/dont-trust-me/) |
| echochamber | 170 | 56 | user + root | [writeup](boot2root/echochamber/) |
| KeyStone | — | — | user + root | [writeup](boot2root/keystone/) |
| Quite | 464 | 7 | user + root | [writeup](boot2root/quite/) |

### crypto

| Challenge | Points | Solves | Flag | Writeup |
|---|---:|---:|---|---|
| brine | 494 | 2 | `isfcr{shard_f37c_brine_27d059a2_jacket}` | [writeup](crypto/brine/) |
| one-more | 86 | 70 | `isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}` | [writeup](crypto/one-more/) |

### forensics

| Challenge | Points | Solves | Flag | Writeup |
|---|---:|---:|---|---|
| Lossless, Not Harmless | 56 | 75 | `isfcr{ch0ic3s_th3_d3c0d3r_n3v3r_s33s}` | [writeup](forensics/lossless-not-harmless/) |
| Phantom Mesh | 50 | 107 | `isfcr{ph4nt0m_m3sh_h4rm0n1cs_un14sk_th3_tc_l1nk_k3y}` | [writeup](forensics/phantom-mesh/) |
| the alphabet that wasn't there | 104 | 67 | `isfcr{d7ef3d5dd98bd325c3b50114}` | [writeup](forensics/the-alphabet-that-wasnt-there/) |
| the third key phase | 170 | 56 | `isfcr{7d6bae9970a1173284046064}` | [writeup](forensics/the-third-key-phase/) |

### ml

| Challenge | Points | Solves | Flag | Writeup |
|---|---:|---:|---|---|
| the deletion echo | 50 | 116 | `isfcr{763c8479fac095a9e471ad3d}` | [writeup](ml/the-deletion-echo/) |

### osint

| Challenge | Points | Solves | Flag | Writeup |
|---|---:|---:|---|---|
| short-final | 446 | 10 | `isfcr{VT-ATE_USI}` | [writeup](osint/short-final/) |
| The Wrong Landmark | 212 | 49 | `isfcr{23.4279_88.3905}` | [writeup](osint/the-wrong-landmark/) |

### pwn

| Challenge | Points | Solves | Flag | Writeup |
|---|---:|---:|---|---|
| mirage | — | — | `isfcr{bl1nd_f0rmat_str1ng_h4s_n0_b1n4ry}` | [writeup](pwn/mirage/) |
| quorum | 494 | 2 | `isfcr{d4t4_0nly_c0rrupt_th3_0p3r4nds_n0t_th3_fl0w}` | [writeup](pwn/quorum/) |
| thaw-ladder | — | — | `isfcr{pod_seven_bb3a_woke_1a161ac6_in_bay_c}` | [writeup](pwn/thaw-ladder/) |

### rev

| Challenge | Points | Solves | Flag | Writeup |
|---|---:|---:|---|---|
| Kelpie | 128 | 63 | `isfcr{5b2d4c7961307f588d9dd95bada5647b}` | [writeup](rev/kelpie/) |
| rime-scrub | 500 | 0 | `isfcr{rime_8834_scrub_10912526_cleared}` | [writeup](rev/rime-scrub/) |

### web

| Challenge | Points | Solves | Flag | Writeup |
|---|---:|---:|---|---|
| moraine | — | — | `isfcr{moraine_7d48_slot_e3f0955a_reclaimed}` | [writeup](web/moraine/) |
| near-miss | 488 | 3 | `isfcr{frostline_5e05_keeper_56e7c6c4_runbook}` | [writeup](web/near-miss/) |
| The Hidden Test Case | 152 | 59 | `isfcr{tw0_sum_h1dd3n_t3st_c4s3_a91c3e7}` | [writeup](web/the-hidden-test-case/) |

> Points and solve counts are the dynamic-scoring values recorded at capture time; a dash means the figure wasn't captured for that challenge.

---

## Notable solves

- **rime-scrub** (rev, 500 pts) — reversing Qualcomm **Hexagon/DSP6** firmware and abusing an ECC correction-count **side channel**: deliberately inducing a double-bit error to miscorrect and flip a protect bit, leaking the key one bit per scrub. Showed 0 solves on the board at capture time.
- **brine** (crypto, 494 pts, 2 solves) — a **timing side channel** in a firmware "SOUND" routine turned each secret setpoint into a binary-searchable rank boundary; 31/32 recovered online, the last brute-forced offline against the AES-GCM tag.
- **quorum** (pwn, 494 pts, 2 solves) — a pure **data-only** exploit: an off-by-one index aliasing bug plus an unbounded negative offset reads the in-memory flag without ever hijacking control flow.
- **near-miss** (web, 488 pts, 3 solves) — a "close enough" fuzzy-match endpoint turned into a **backward byte-leak oracle** against a sealed runbook.
- **boot2root sweep** — all four machines fully rooted, chaining web bugs (SSTI, stored XSS, SSRF→Redis RESP) into kernel LPE, TPM quote forgery, and eBPF/TOCTOU tricks.

## Repository layout

```
<category>/<challenge>/
  README.md     # the writeup
  solve.*       # final exploit / solver
  ...           # challenge-provided source & key artifacts
```

Each challenge directory holds the writeup plus the final solve/exploit script(s) and any small text-based source or notes. To keep this archive lean for long-term storage, bulky and binary challenge inputs — provided binaries, packet captures, PDFs, images, and regenerable tool dumps — have been removed; the writeups and scripts still document them and how to obtain or regenerate them. Throwaway experiments, live-instance session secrets, and infrastructure credentials were never included.
