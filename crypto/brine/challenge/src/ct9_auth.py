"""
FROSTWRAP-24 command authentication - CT-9 firmware v2.4.1.

A SOUND request carries a tag binding it to the head's instance and round counter.
The session key is issued at HELLO.
"""

import hashlib
import hmac


def tag(session_key: bytes, instance_id: bytes, t: int, w: int, reps: int) -> str:
    """FROSTWRAP-24 tag over instance_id || t || w || reps
    (t as u64, w as u32, reps as u16, all big-endian)."""
    msg = (instance_id
           + t.to_bytes(8, "big")
           + w.to_bytes(4, "big")
           + reps.to_bytes(2, "big"))
    return hmac.new(session_key, msg, hashlib.sha256).hexdigest()[:32]


def verify(session_key: bytes, instance_id: bytes, t: int, w: int, reps: int,
           given: str) -> bool:
    want = tag(session_key, instance_id, t, w, reps)
    return hmac.compare_digest(want.encode(), (given or "").encode())
