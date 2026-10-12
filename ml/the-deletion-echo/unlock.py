"""Check a list of deleted-record answers and print the flag if the list is correct."""
import hashlib, json, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

SEALED = {"challenge_id": "the-deletion-echo", "kdf": "scrypt", "kdf_params": {"n": 131072, "r": 8, "p": 1}, "salt": "ebc25f61972a2d04f7419e9b57ad5b31", "nonce": "bb5a83d7a714d17917be8434", "ciphertext": "46ea64a711ec20465fbe914316aaafbcfa1e1e37b5c6c4a488124bdd3534d175fe4910d6b5c728f200a9930c4fb893"}


def unlock(answer):
    enc = json.dumps(answer, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    key = hashlib.scrypt(b'isfcr-ml\0' + enc, salt=bytes.fromhex(SEALED['salt']),
                         **SEALED['kdf_params'], maxmem=2**28, dklen=32)
    return AESGCM(key).decrypt(bytes.fromhex(SEALED['nonce']), bytes.fromhex(SEALED['ciphertext']),
                               SEALED['challenge_id'].encode('ascii')).decode('ascii')


if __name__ == '__main__':
    try:
        print(unlock(json.loads(sys.argv[1])))
    except (InvalidTag, ValueError):
        print('Rejected.')
