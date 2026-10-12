#!/usr/bin/env python3
"""
CT-9 2.4.1 head, run locally on stdin/stdout. Tags are not checked.

  python3 brine_sim.py --selftest             check against the captured 2.4.1 session
  python3 brine_sim.py --profile FILE         32 ascending integers in [1, 2**32 - 2]
  python3 brine_sim.py --seed N               a random profile from N (default 1)
  python3 brine_sim.py --seed N --show        print that profile and exit

One JSON object per line:
  {"cmd":"HELLO"}
  {"cmd":"SOUND","t":0,"w":123456,"reps":2048}
SESSION and RESUME (the shared service's session commands) are accepted and ignored.
"""
import argparse
import hashlib
import json
import os
import random
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "src"), _HERE):
    if os.path.isfile(os.path.join(_p, "ct9_sounder.py")):
        sys.path.insert(0, _p)
        break

import ct9_auth                      # noqa: E402
import ct9_sounder as snd            # noqa: E402

SIM_INSTANCE_ID = b"\xa5" * 16

FACTORY = {
    "instance_id": "f22d048ad214c29207ca24a853c0dc8f",
    "session_key": "1ff2b5dd851d070a811d3155f28ba966ebbd1f0e0a233c1d2304b0491f75fa3a",
    "trial_key": "765e1f43649c67c8aa257ae119c6ba45be417accbf523879df36df0af92bc9cf",
    "profile": [
        188208027, 449478419, 720519875, 734481893,
        806917650, 834048951, 929724880, 998808312,
        1140567372, 1183157794, 1266825048, 1276413496,
        1374452039, 1444571184, 1570696264, 1859413017,
        2001871585, 2443867167, 2642904745, 2646881695,
        2800363507, 2822643898, 2859542127, 3159450486,
        3200277050, 3275199278, 3380710100, 3449667326,
        3526628652, 3966129997, 4074110722, 4262202962,
    ],
    "soundings": [
        {"t": 0, "w": 853462973, "reps": 12, "tag": "d55278a1292d5f633c824a740d35cd64",
         "deltas": [48000, 48000, 48000, 48000, 48000, 48000, 48000, 48000, 48000, 48480, 60720, 48000]},
        {"t": 1, "w": 3978599269, "reps": 4, "tag": "7e5f99ddb213097b78c206ff69b18c47",
         "deltas": [48000, 48000, 48000, 48000]},
        {"t": 2, "w": 335460141, "reps": 4, "tag": "0af72c5c483def78c500e8cb9cb24578",
         "deltas": [48000, 60000, 72000, 60000]},
        {"t": 3, "w": 1582788132, "reps": 16, "tag": "6599b1307945f0052dfe15f07a927043",
         "deltas": [72000, 49200, 60000, 48000, 60000, 48000, 48000, 60000, 48000, 48000, 48000, 48000, 48000, 72000, 48000, 48000]},
        {"t": 4, "w": 1807822632, "reps": 4, "tag": "8df88be5af398d334f995caf68cd51a8",
         "deltas": [48000, 48480, 48000, 48000]},
        {"t": 5, "w": 3735656110, "reps": 12, "tag": "9b03cc67f87bdce47852b624b4daefae",
         "deltas": [48000, 60000, 48000, 84000, 48000, 60000, 48000, 48000, 60000, 48000, 48000, 48000]},
    ],
}


def make_profile(seed):
    r = random.Random(seed)
    return sorted(r.sample(range(1, snd.U32_MAX - 1), snd.TABLE_ENTRIES))


def load_profile(path):
    with open(path, encoding="utf-8") as f:
        text = f.read().replace(",", " ")
    try:
        prof = [int(x, 0) for x in text.split()]
    except ValueError as e:
        raise SystemExit("profile: %s" % e)
    if len(prof) != snd.TABLE_ENTRIES:
        raise SystemExit("profile: need %d entries, got %d" % (snd.TABLE_ENTRIES, len(prof)))
    if any(not 1 <= v <= snd.U32_MAX - 1 for v in prof):
        raise SystemExit("profile: every entry must be in [1, 2**32 - 2]")
    if any(a >= b for a, b in zip(prof, prof[1:])):
        raise SystemExit("profile: entries must be strictly increasing")
    return prof


def sim_trial_key(seed):
    return snd.derive_trial_key(hashlib.sha256(b"CT9-SIM-%d" % seed).digest())


def selftest():
    if not FACTORY:
        print("selftest: no factory vectors in this build")
        return 1
    iid = bytes.fromhex(FACTORY["instance_id"])
    skey = bytes.fromhex(FACTORY["session_key"])
    head = snd.SoundingHead(iid, list(FACTORY["profile"]),
                            bytes.fromhex(FACTORY["trial_key"]))
    good = 0
    for v in FACTORY["soundings"]:
        tag_ok = ct9_auth.tag(skey, iid, v["t"], v["w"], v["reps"]) == v["tag"]
        deltas, err = head.sound(v["t"], v["w"], v["reps"])
        d_ok = err is None and deltas == v["deltas"]
        print("t=%d w=%d reps=%d  tag %s  deltas %s"
              % (v["t"], v["w"], v["reps"], "ok" if tag_ok else "MISMATCH",
                 "ok" if d_ok else "MISMATCH"))
        good += tag_ok and d_ok
    n = len(FACTORY["soundings"])
    print("selftest %s (%d/%d vectors)" % ("passed" if good == n else "FAILED", good, n))
    return 0 if good == n else 1


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def serve(head):
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            if not isinstance(req, dict):
                raise ValueError
        except ValueError:
            resp = {"ok": False, "err": "EARG"}
        else:
            cmd = req.get("cmd")
            if cmd == "SESSION":
                resp = {"ok": True, "token": "local"}
            elif cmd == "RESUME":
                resp = {"ok": True}
            elif cmd == "HELLO":
                resp = {"ok": True, "instance_id": head.instance_id.hex(),
                        "firmware": "CT-9 v2.4.1 (simulator)", "t": head.t,
                        "session_key": "00" * 32}
            elif cmd == "SOUND" and all(_is_int(req.get(k)) for k in ("t", "w", "reps")):
                d, err = head.sound(req["t"], req["w"], req["reps"])
                resp = ({"ok": False, "err": err, "t": head.t} if err
                        else {"ok": True, "t": head.t, "deltas": d})
            else:
                resp = {"ok": False, "err": "EARG"}
        out.write(json.dumps(resp, separators=(",", ":")) + "\n")
        out.flush()


def main():
    ap = argparse.ArgumentParser(description="CT-9 local sounding head")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--profile", help="file with 32 ascending integers")
    ap.add_argument("--show", action="store_true", help="print the profile and exit")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    prof = load_profile(a.profile) if a.profile else make_profile(a.seed)
    if a.show:
        print(" ".join(str(v) for v in prof))
        return 0
    serve(snd.SoundingHead(SIM_INSTANCE_ID, prof, sim_trial_key(a.seed)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
