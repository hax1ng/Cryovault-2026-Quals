"""
Kestrel CT-9 thermocline sounder - firmware 2.4.1, sounder core.
"""

import hashlib
import math

# --- configuration, mirrored from ct9_config.toml --------------------------------
BASE_NS        = 48000
CAV_DELTA_NS   = 12000
CAV_THRESHOLD  = 24        # of 256
JITTER_TICK_NS  = 240
JITTER_P_ZERO   = 0.95
JITTER_TAIL_K   = 1.5
TABLE_ENTRIES   = 32
MAX_REPS        = 2048
U32_MAX         = 0xFFFFFFFF

GALLOP_MAX      = TABLE_ENTRIES.bit_length()


# --- provisioning ----------------------------------------------------------------

def derive_profile(key: bytes, entries: int = TABLE_ENTRIES):
    """Calibration profile (2.2.0, 2.2.1): `entries` distinct setpoints in
    [1, 2**32 - 2], ascending, drawn from SHAKE256(K || tag) with rejection."""
    xof = hashlib.shake_256(key + b"BRINE-PROFILE-v2")
    stream = xof.digest(entries * 64)
    vals, pos = set(), 0
    while len(vals) < entries:
        if pos + 4 > len(stream):
            stream += hashlib.shake_256(key + b"BRINE-PROFILE-v2-ext"
                                        + len(stream).to_bytes(4, "big")).digest(4096)
        v = int.from_bytes(stream[pos:pos + 4], "big")
        pos += 4
        if 1 <= v <= U32_MAX - 1:
            vals.add(v)
    return sorted(vals)


def derive_trial_key(key: bytes) -> bytes:
    return hashlib.shake_256(key + b"BRINE-TRIALS-v2").digest(32)


def seal_key(profile) -> bytes:
    """Recovery bundle key (2.1.0): SHA256(b"BRINE-SEAL-v2" || sigma_1 .. sigma_n),
    each setpoint a big-endian uint32."""
    h = hashlib.sha256()
    h.update(b"BRINE-SEAL-v2")
    for s in profile:
        h.update(s.to_bytes(4, "big"))
    return h.digest()


# --- lookup ----------------------------------------------------------------------

def rank(profile, w: int) -> int:
    """#{i : sigma_i <= w}, in [0, len(profile)]."""
    lo, hi = 0, len(profile)
    while lo < hi:
        mid = (lo + hi) // 2
        if profile[mid] <= w:
            lo = mid + 1
        else:
            hi = mid
    return lo


def gallop_steps(finger: int, target_rank: int) -> int:
    d = abs(target_rank - finger)
    return 1 if d == 0 else 1 + int(math.floor(math.log2(d)))


# --- counter ---------------------------------------------------------------------

def _h64(trial_key: bytes, *parts: bytes) -> int:
    h = hashlib.blake2s(b"".join(parts), digest_size=8, key=trial_key).digest()
    return int.from_bytes(h, "big")


def synth_deltas(trial_key: bytes, instance_id: bytes, t: int, w: int, reps: int,
                 steps: int):
    """Per-pass deltas, ns (2.3.2)."""
    if not 1 <= steps <= GALLOP_MAX:
        raise ValueError("gallop depth out of range")
    tb = t.to_bytes(8, "big")
    wb = w.to_bytes(4, "big")
    out = []
    for i in range(reps):
        ib = i.to_bytes(4, "big")
        cav = 0
        for j in range(1, GALLOP_MAX + 1):
            fired = (_h64(trial_key, b"BRINE-CAV-v2", instance_id, tb, wb, ib,
                          j.to_bytes(2, "big")) >> 56) < CAV_THRESHOLD
            cav += fired & (j <= steps)
        u = _h64(trial_key, b"BRINE-JIT-v2", instance_id, tb, wb, ib) / 2 ** 64
        if u < JITTER_P_ZERO:
            jit = 0
        else:
            v = (u - JITTER_P_ZERO) / (1.0 - JITTER_P_ZERO)
            v = min(v, 1.0 - 1e-15)
            jit = JITTER_TICK_NS * (1 + int(-JITTER_TAIL_K * math.log(1.0 - v)))
        out.append(BASE_NS + CAV_DELTA_NS * cav + jit)
    return out


# --- the head --------------------------------------------------------------------

class SoundingHead:

    def __init__(self, instance_id: bytes, profile, trial_key: bytes):
        self.instance_id = instance_id
        self.profile = profile
        self.trial_key = trial_key
        self.t = 0
        self.finger = 0

    def sound(self, t: int, w: int, reps: int):
        if t != self.t:
            return None, "ESEQ"
        if not (0 <= w <= U32_MAX) or not (1 <= reps <= MAX_REPS):
            return None, "EARG"
        r = rank(self.profile, w)
        steps = gallop_steps(self.finger, r)
        deltas = synth_deltas(self.trial_key, self.instance_id, self.t, w, reps, steps)
        self.finger = r
        self.t += 1
        return deltas, None
