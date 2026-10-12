#!/usr/bin/env python3
"""Recover a CT-9 profile through the SOUND cavitation side channel."""

import hashlib
import hmac
import json
import socket
import time
from pathlib import Path


HOST = "0.cloud.chals.io"
PORT = 12312
TOKEN = "REDACTED"  # per-session RESUME token (ephemeral; redacted)

U32_MAX = 0xFFFFFFFF
BASE_NS = 48000
CAV_DELTA_NS = 12000
TEST_REPS = 2048

# On 2.5.3, a rank distance of zero or one produces one cavitation trial,
# while a distance of two produces two.  The event probability is 12/256.
# Thus this midpoint separates the two cases with a very wide margin at 2048
# repetitions.
LOW_CUTOFF = 18 / 256

STATE_PATH = Path(__file__).with_name("brine_state.json")
LOG_PATH = Path(__file__).with_name("brine_probes.jsonl")


class Client:
    def __init__(self, token):
        self.token = token
        self.sock = None
        self.file = None
        self.iid = None
        self.key = None
        self.t = None
        self.last_sound = 0.0
        self.connect()

    def connect(self):
        if self.file:
            try:
                self.file.close()
            except Exception:
                pass
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = socket.create_connection((HOST, PORT), timeout=20)
        self.file = self.sock.makefile("rwb", buffering=0)
        r = self.raw({"cmd": "RESUME", "token": self.token})
        if not r.get("ok"):
            raise RuntimeError("RESUME failed: %r" % (r,))
        h = self.raw({"cmd": "HELLO"})
        if not h.get("ok"):
            raise RuntimeError("HELLO failed: %r" % (h,))
        self.iid = bytes.fromhex(h["instance_id"])
        self.key = bytes.fromhex(h["session_key"])
        self.t = h["t"]
        print("connected at t=%d (%s)" % (self.t, h["firmware"]), flush=True)

    def raw(self, obj):
        data = json.dumps(obj, separators=(",", ":")).encode() + b"\n"
        self.file.write(data)
        line = self.file.readline()
        if not line:
            raise EOFError("service closed connection")
        return json.loads(line)

    def _tag(self, w, reps):
        msg = (self.iid + self.t.to_bytes(8, "big")
               + w.to_bytes(4, "big") + reps.to_bytes(2, "big"))
        return hmac.new(self.key, msg, hashlib.sha256).hexdigest()[:32]

    def sound(self, w, reps):
        while True:
            # The documented head-wide limit is 20 SOUNDs/s.
            delay = 0.052 - (time.monotonic() - self.last_sound)
            if delay > 0:
                time.sleep(delay)
            try:
                q = {"cmd": "SOUND", "t": self.t, "w": w, "reps": reps,
                     "tag": self._tag(w, reps)}
                self.last_sound = time.monotonic()
                r = self.raw(q)
            except (EOFError, OSError, socket.timeout) as e:
                print("reconnecting after %s" % (e,), flush=True)
                time.sleep(0.5)
                self.connect()
                continue
            if r.get("ok"):
                self.t = r["t"]
                return r["deltas"]
            if r.get("err") == "ESEQ":
                self.t = r["t"]
                continue
            if r.get("err") == "EBUSY":
                time.sleep(0.5)
                continue
            raise RuntimeError("SOUND failed: %r" % (r,))

    def is_low(self, anchor_w, test_w):
        # First put the lookup finger at the known anchor rank.
        self.sound(anchor_w, 1)
        ds = self.sound(test_w, TEST_REPS)
        cav = sum((d - BASE_NS) // CAV_DELTA_NS for d in ds)
        mean = cav / TEST_REPS
        low = mean < LOW_CUTOFF
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"t": self.t, "anchor": anchor_w,
                                "test": test_w, "cav_mean": mean,
                                "low": low}) + "\n")
        return low

    def bundle(self):
        return self.raw({"cmd": "BUNDLE"})


def boundary(lo, hi, pred, want_hi=True):
    """First integer for which pred is want_hi; endpoints bracket it."""
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if pred(mid) == want_hi:
            hi = mid
        else:
            lo = mid
    return hi


def save_state(profile):
    STATE_PATH.write_text(json.dumps({"token": TOKEN, "profile": profile},
                                     indent=2) + "\n", encoding="utf-8")


def main():
    c = Client(TOKEN)
    sigma = [None] * 33                 # use the challenge's 1-based indices

    # With the anchor at rank 32, distance 32 wraps into the low-leakage case.
    # Any ordinary interior point is non-low, so locate the first transition:
    # exactly sigma_1.
    anchor32 = U32_MAX
    interior = 1 << 31
    if c.is_low(anchor32, interior):
        raise RuntimeError("unexpected profile: midpoint is not an interior rank")
    sigma[1] = boundary(0, interior,
                        lambda w: not c.is_low(anchor32, w), True)
    print("sigma[ 1] = %d" % sigma[1], flush=True)
    save_state(sigma[1:])

    # From rank 1, the first non-low distance is 2, hence sigma_3.
    sigma[3] = boundary(sigma[1], U32_MAX,
                        lambda w: not c.is_low(sigma[1], w), True)
    print("sigma[ 3] = %d" % sigma[3], flush=True)

    # From rank 3 and inside [sigma_1, sigma_3], the first low distance is
    # rank 2, hence sigma_2.
    sigma[2] = boundary(sigma[1], sigma[3],
                        lambda w: c.is_low(sigma[3], w), True)
    print("sigma[ 2] = %d" % sigma[2], flush=True)
    save_state(sigma[1:])

    # Walk the odd and even subsequences.  From an anchor of rank k, ranks k
    # and k+1 are low, and sigma_(k+2) is the first non-low point.
    for start in (3, 2):
        k = start
        while k <= 30:
            sigma[k + 2] = boundary(
                sigma[k], U32_MAX,
                lambda w, a=sigma[k]: not c.is_low(a, w), True)
            print("sigma[%2d] = %d" % (k + 2, sigma[k + 2]), flush=True)
            save_state(sigma[1:])
            k += 2

    profile = sigma[1:]
    assert all(isinstance(x, int) for x in profile)
    assert all(a < b for a, b in zip(profile, profile[1:]))
    print("profile:", " ".join(map(str, profile)), flush=True)

    b = c.bundle()
    if not b.get("ok"):
        raise RuntimeError("BUNDLE failed: %r" % (b,))
    sealed = bytes.fromhex(b["sealed"])
    nonce, ciphertext, tag = sealed[:12], sealed[12:-16], sealed[-16:]
    h = hashlib.sha256()
    h.update(b"BRINE-SEAL-v2")
    for x in profile:
        h.update(x.to_bytes(4, "big"))
    from Crypto.Cipher import AES
    cipher = AES.new(h.digest(), AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    print("plaintext:", plaintext.decode(errors="replace"), flush=True)


if __name__ == "__main__":
    main()
