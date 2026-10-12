# one-more

**Category:** Crypto · **Points:** 86 · **Solves:** 70 · **Flag:** `isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}`

## Challenge

> One signature per session, no exceptions. Come back with more than that.
>
> `wss://one-more.isfcr.xyz`

We get [`server.py`](server.py) and [`client.py`](client.py): a **blind Schnorr**
signing service on `secp256k1`. On connect the server sends its per-connection
public key `X = xG`. Then:

- `open` → `id <k> R <hex64>` — opens a session with a fresh nonce point `R = rG`.
- `sign <k> <c>` → `s <int>` — answers one scalar challenge per session:
  `s = r + c·x mod n`.
- `submit` → send a JSON list of signatures `[[msg_hex, Rx, Ry, s], ...]`.

A signature `(R, s)` on `m` is valid iff `s·G == R + H(R,m)·X`, with
`H(R,m) = SHA256(x || y || m) mod n`. The service is *blind*: it only ever sees
the scalar `c`, never the message. To win, hand back **more valid signatures on
distinct messages than the number of challenges it answered**.

## Initial Analysis

The server enforces exactly what it advertises: `sign` pops the nonce from the
pending set (`self.pending.pop(k)`), so each session is answered at most once.
One session gives one equation `s = r + c·x` with two unknowns (`r`, `x`) — no
key recovery, and extra sessions each bring their own independent random nonce.

The crucial, deliberate weakness is in the limits:

```python
MAX_SESSIONS   = 512     # "open" calls per connection
MAX_CONCURRENT = 512     # simultaneous connections
```

Hundreds of signing sessions can stay open under the *same* key at once. That is
exactly the setting in which blind Schnorr falls to the **ROS attack** (Random
inhomogeneities in an Overdetermined Solvable system) — the "one-more forgery."

## Vulnerability / Core Concept

Schnorr responses are linear in the challenge. If we hold `ℓ = 256` open
sessions with nonces `R_i`, we can combine their eventual responses `s_i` with
any scalar coefficients `a_i` and a constant `k`:

```
(Σ a_i·s_i + k)·G = Σ a_i·R_i + kG + (Σ a_i·c_i)·X
```

A real forged signature on a fresh message `m_f` needs the combined challenge to
equal `H(R_f, m_f)` for the combined nonce `R_f`. That looks circular — the
forged nonce fixes the hash, but the hash is supposed to fix our challenges. ROS
breaks the circle by committing to *two* options per session and only deciding
between them **after** the forgery hash is known.

**Per-session selectable bit.** For each `R_i`, pick two messages and hash them
locally: `c_{i,0} = H(R_i, m_{i,0})`, `c_{i,1} = H(R_i, m_{i,1})`. Define the
affine switch `z_i(t) = (t − c_{i,0}) / (c_{i,1} − c_{i,0}) mod n`, so
`z_i(c_{i,0}) = 0` and `z_i(c_{i,1}) = 1`. Then

```
rho(t_0,...,t_255) = Σ 2^i · z_i(t_i)   =   Σ a_i·t_i + k        (affine)
with   a_i = 2^i / (c_{i,1} − c_{i,0}) mod n,   k = −Σ a_i·c_{i,0} mod n
```

If every `t_i` is chosen from its pair `{c_{i,0}, c_{i,1}}`, `rho` evaluates to
the integer whose binary digits are those 256 choices. Since `n` is 256 bits,
these 256 switches can represent *any* challenge value.

**Forged nonce.** Build `R_f = Σ a_i·R_i + kG − kX`. The `kG − kX` term carries
the affine constant so the same map `rho` applies to both the group elements and
the scalars. Now hash it: `c_f = H(R_f, m_f)`. Crucially, `R_f` depends only on
both options per session, not on which one we pick — so computing `c_f` is not
circular. Read `c_f`'s bits `b_i`, and in session `i` submit `c_i = c_{i,b_i}`.

**The extra signature.** From the 256 responses `s_i`, set
`s_f = Σ a_i·s_i + k`. Then:

```
s_f·G = Σ a_i·(R_i + c_i·X) + kG = (Σ a_i·R_i + kG) + (Σ a_i·c_i)·X
      = (R_f + kX) + rho(c_0,...,c_255)·X = R_f + c_f·X = R_f + H(R_f, m_f)·X
```

...because our bit choices made `rho(c_0,...,c_255) = c_f`. That is a 257th valid
signature. The server answered 256 challenges; we walk away with 257 distinct
signed messages. No private key, no discrete log.

## Exploitation

Full exploit in [`solve.py`](solve.py). The one implementation subtlety that
matters: the requests are **pipelined** so we don't eat one RTT per command, and
we only choose each session's challenge after `c_f` is known.

1. Connect, read `X`, send `open` 256 times, collect all `R_i`.
2. For each `R_i` make two messages / two challenges `c_{i,0}, c_{i,1}`
   (re-roll a nonce in the message on the rare `c0 == c1` collision).
3. Build coefficients `a_i` and constant `k`:
   ```python
   a = (pow(2, i, N) * pow((cs1[i] - cs0[i]) % N, -1, N)) % N
   constant = (constant - a * cs0[i]) % N
   ```
4. Construct `R_forge = G*constant + X*(-constant) + Σ a_i·R_i`, then
   `c_forge = H(R_forge, m_forge)` and read its bits.
5. Submit the selected challenge per session, collect the 256 responses.
6. Form `s_forge = constant + Σ a_i·s_i`, and assert locally before spending the
   one-shot submit:
   ```python
   assert G * s_forge == R_forge + X * c_forge
   ```
7. `submit` the 256 real signatures plus the forgery.

Run:

```bash
python3 solve.py wss://one-more.isfcr.xyz
```

Output ([`solve-output.txt`](solve-output.txt)):

```
[+] connected; opening 256 concurrent sessions
[+] received all commitments (2.2s)
[+] received 256 responses (3.3s)
valid 257 answered 256
one more! isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}
```

## Flag

```
isfcr{r0s_1s_n0t_h4rd_f0r_l0g_p}
```

> Note: the included `server.py` carries a placeholder flag
> (`isfcr{placeholder__real_flag_is_on_the_live_service}`) — that is the
> challenge's own source. The real flag above came from the live service.

## Key Takeaways

- Blind Schnorr is secure per-session but breaks under **concurrency**: the ROS
  "one-more forgery" needs ~`log2(n)` = 256 simultaneously open sessions under one
  key. The fix is to forbid that overlap, not to limit each session.
- The trick is deferring the signing challenges until *after* the forgery hash is
  known. Two messages per session give one controllable bit each; 256 bits cover
  any 256-bit challenge.
- Schnorr's linearity is the lever — responses, nonces, and challenges all combine
  with the same affine map, which is why `kG − kX` makes the group-element and
  scalar arithmetic line up.
- Practical note: pipeline the WebSocket commands and verify the forgery locally
  before consuming the single `submit`.
