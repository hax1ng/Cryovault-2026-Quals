#!/usr/bin/env python3
"""Final step for brine: derive the seal key from the recovered 32-entry
profile and open the AES-256-GCM recovery bundle.

The key is SHA256(b"BRINE-SEAL-v2" || sigma_1 || ... || sigma_32), each
setpoint a big-endian uint32, setpoints in ascending order. The sealed blob is
laid out as 12-byte nonce || ciphertext || 16-byte GCM tag.

The `sealed` hex below is the bundle returned by BUNDLE for our head; it is
session-specific ciphertext (not a secret). Replace it with your own head's
BUNDLE output to reproduce on a fresh session.
"""

import hashlib
from Crypto.Cipher import AES

# The complete recovered profile (see profile.txt). 31 entries came from the
# SOUND cavitation side channel; the 32nd (253627290) was found by brute-forcing
# the last 32-bit setpoint against the bundle's GCM tag on a GPU.
profile = [
    116270928, 253627290, 271114478, 280839249,
    396249577, 638355194, 733053514, 738715377,
    979315336, 1067980009, 1116367004, 1472486423,
    1515386961, 1674061169, 1920998223, 2053453639,
    2307668893, 2391610577, 2392825155, 2685666937,
    2765836044, 2858096023, 3108845208, 3323023863,
    3424719491, 3508956982, 3515163184, 3515722557,
    3643281896, 3694499845, 3798822593, 4194399467,
]

sealed = bytes.fromhex(
    "1dea927d2a172a77fd21bed48cb105e95848b7839790689bd5206400ff58fdea"
    "8b6307dda74ce1609894131b36aa66e89309369d31bc338c3185e0d9ce250b6"
    "5e02dd9d3b742a6d8414bf0390ae7815818fb9515a53d8935e2bf01e755c58c"
    "a463d3f450b12d2336c9ad2f123bfc28f41ecee2c580ce1e9510"
)

material = b"BRINE-SEAL-v2" + b"".join(x.to_bytes(4, "big") for x in profile)
key = hashlib.sha256(material).digest()

nonce, ciphertext, tag = sealed[:12], sealed[12:-16], sealed[-16:]
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext.decode())
