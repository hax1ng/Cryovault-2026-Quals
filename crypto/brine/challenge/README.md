# BRINE THERMOCLINE

The SHARD-24 brine loop keeps the vault's outer jacket at -42 C. Its sounding head, a
Kestrel CT-9 thermocline sounder, holds the loop's calibration profile in a sealed
table and will not release the profile to anyone, including us. We need it: the
vault's cryo-recovery bundle was sealed against that profile before the head was
potted.

## Your head

    nc <host> <port>

Every team shares this service; a session is a head of your own. Line-delimited JSON,
one object per line each way. The first line on every connection is one of

    -> {"cmd":"SESSION"}
    <- {"ok":true,"token":"<22 chars>"}

    -> {"cmd":"RESUME","token":"<22 chars>"}
    <- {"ok":true}

`SESSION` provisions a new head and binds the connection to it; `RESUME` binds a later
connection to the head you already have. Keep the token: it is the only way back to
that head. A new session is a new head, with its own device key, profile and bundle. A
session unused for 3 hours expires, and a service restart ends every session.

    -> {"cmd":"HELLO"}
    <- {"ok":true,"instance_id":"<32 hex>","firmware":"CT-9 v2.5.3","t":<int>,
        "session_key":"<64 hex>"}

    -> {"cmd":"SOUND","t":<int>,"w":<uint32>,"reps":<1..2048>,"tag":"<32 hex>"}
    <- {"ok":true,"t":<int+1>,"deltas":[<ns>, ... reps of them]}

    -> {"cmd":"BUNDLE"}
    <- {"ok":true,"sealed":"<hex>","note":"..."}

`t` is the head's round counter: a `SOUND` must carry its current value, which `HELLO`
reports. `tag` is FROSTWRAP-24 over `instance_id || t || w || reps` under `session_key`
(`src/ct9_auth.py`). Errors: `ESEQ` (wrong `t`; the reply carries the current one),
`ETAG`, `EARG` (malformed request, or a line over 4096 bytes), `ESESSION` (no session on
this connection, or the token is not a live session), `EBUSY` (too many open connections
or new sessions; the connection is closed, retry shortly), `EINT` (internal fault;
please report it). An error reply does not advance `t`.

Soundings are limited to 20 per second per head, shared by every connection to it. A
connection idle for 10 minutes is closed, and when the head is at its connection limit
the connection idle longest may be closed to admit a new one; reconnect, `RESUME` and
carry on.

`BUNDLE` returns your head's AES-256-GCM recovery bundle: 12-byte nonce, ciphertext,
16-byte tag. The key is `SHA256(b"BRINE-SEAL-v2" + sigma_1||...||sigma_32)`, the
setpoints in ascending order, each a big-endian uint32. Every head has its own device
key and therefore its own profile.

## Firmware

Field heads run CT-9 2.5.3. Kestrel has not released 2.5 source to integrators. `src/`
is the most recent drop we have, 2.4.1, with its changelog; `docs/` holds the SDK's
engineering notes and a vendor advisory. `brine_sim.py` runs a 2.4.1 head locally
(`python3 brine_sim.py --help`); it accepts `SESSION` and `RESUME` and ignores them.

## A 2.4.1 session

Captured by Kestrel from a 2.4.1 test head; `python3 brine_sim.py --selftest` replays it.

    -> {"cmd":"HELLO"}
    <- {"ok":true,"instance_id":"f22d048ad214c29207ca24a853c0dc8f","firmware":"CT-9 v2.4.1","t":0,"session_key":"1ff2b5dd851d070a811d3155f28ba966ebbd1f0e0a233c1d2304b0491f75fa3a"}

    -> {"cmd":"SOUND","t":0,"w":853462973,"reps":12,"tag":"d55278a1292d5f633c824a740d35cd64"}
    <- {"ok":true,"t":1,"deltas":[48000,48000,48000,48000,48000,48000,48000,48000,48000,48480,60720,48000]}

    -> {"cmd":"SOUND","t":1,"w":3978599269,"reps":4,"tag":"7e5f99ddb213097b78c206ff69b18c47"}
    <- {"ok":true,"t":2,"deltas":[48000,48000,48000,48000]}

    -> {"cmd":"SOUND","t":2,"w":335460141,"reps":4,"tag":"0af72c5c483def78c500e8cb9cb24578"}
    <- {"ok":true,"t":3,"deltas":[48000,60000,72000,60000]}
