#!/usr/bin/env python3
"""Exploit the concurrent blind-Schnorr service with the polynomial ROS attack."""

import asyncio
import hashlib
import json
import sys
import time

from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from websockets.asyncio.client import connect


G = SECP256k1.generator
CURVE = SECP256k1.curve
N = int(SECP256k1.order)
ELL = N.bit_length()  # 256 for secp256k1; 2**ELL > N


def parse_point(raw_hex: str) -> Point:
    raw = bytes.fromhex(raw_hex)
    if len(raw) != 64:
        raise ValueError(f"bad point length: {len(raw)}")
    return Point(CURVE, int.from_bytes(raw[:32], "big"),
                 int.from_bytes(raw[32:], "big"), N)


def challenge(R, message: bytes) -> int:
    enc = (int(R.x()).to_bytes(32, "big") +
           int(R.y()).to_bytes(32, "big"))
    return int.from_bytes(hashlib.sha256(enc + message).digest(), "big") % N


async def recv_text(ws) -> str:
    msg = await ws.recv()
    return msg.decode() if isinstance(msg, bytes) else msg


async def exploit(url: str) -> None:
    started = time.monotonic()
    async with connect(url, max_size=None, ping_interval=20,
                       ping_timeout=20, open_timeout=30) as ws:
        greeting = (await recv_text(ws)).split()
        if len(greeting) != 2 or greeting[0] != "X":
            raise RuntimeError(f"unexpected greeting: {' '.join(greeting)}")
        X = parse_point(greeting[1])
        print(f"[+] connected; opening {ELL} concurrent sessions", flush=True)

        # Pipelining avoids paying one network RTT for every session.
        for _ in range(ELL):
            await ws.send("open")

        Rs = [None] * ELL
        for _ in range(ELL):
            reply = (await recv_text(ws)).split()
            if len(reply) != 4 or reply[0] != "id" or reply[2] != "R":
                raise RuntimeError(f"unexpected open reply: {' '.join(reply)}")
            idx = int(reply[1])
            Rs[idx] = parse_point(reply[3])
        print(f"[+] received all commitments ({time.monotonic()-started:.1f}s)",
              flush=True)

        # For each row rho_i(x)=x_i, make two RO queries.  Normalizing these
        # pairs lets rho_f evaluate to any ELL-bit integer based only on which
        # member of each pair is selected.
        messages = []
        cs0, cs1 = [], []
        for i, R in enumerate(Rs):
            nonce = 0
            while True:
                m0 = f"ros/{i}/0/{nonce}".encode()
                m1 = f"ros/{i}/1/{nonce}".encode()
                c0, c1 = challenge(R, m0), challenge(R, m1)
                if c0 != c1:
                    break
                nonce += 1
            messages.append((m0, m1))
            cs0.append(c0)
            cs1.append(c1)

        # rho_f(x) = sum_i 2^i * (x_i-c_i,0)/(c_i,1-c_i,0)
        coeffs = []
        constant = 0
        for i in range(ELL):
            a = (pow(2, i, N) * pow((cs1[i] - cs0[i]) % N, -1, N)) % N
            coeffs.append(a)
            constant = (constant - a * cs0[i]) % N

        # If affine maps are evaluated on group elements, their constant is
        # constant*G.  Subtract constant*X too so the same affine map applies
        # to both the responses s and their challenges c.
        R_forge = G * constant + X * ((-constant) % N)
        for a, R in zip(coeffs, Rs):
            R_forge = R_forge + R * a

        m_forge = b"ros/forgery"
        c_forge = challenge(R_forge, m_forge)
        bits = [(c_forge >> i) & 1 for i in range(ELL)]
        selected_c = [cs1[i] if bits[i] else cs0[i] for i in range(ELL)]

        # Close exactly ELL sessions only after the forged challenge tells us
        # which element of every pair to choose.
        for i, c in enumerate(selected_c):
            await ws.send(f"sign {i} {c}")

        ss = [None] * ELL
        for i in range(ELL):
            reply = (await recv_text(ws)).split()
            if len(reply) != 2 or reply[0] != "s":
                raise RuntimeError(f"unexpected sign reply: {' '.join(reply)}")
            ss[i] = int(reply[1])
        print(f"[+] received {ELL} responses ({time.monotonic()-started:.1f}s)",
              flush=True)

        s_forge = constant
        for a, s in zip(coeffs, ss):
            s_forge = (s_forge + a * s) % N

        # Catch implementation mistakes before consuming the one-shot submit.
        assert G * s_forge == R_forge + X * c_forge

        signatures = []
        for i, (R, s, bit) in enumerate(zip(Rs, ss, bits)):
            m = messages[i][bit]
            signatures.append([m.hex(), int(R.x()), int(R.y()), s])
        signatures.append([m_forge.hex(), int(R_forge.x()),
                           int(R_forge.y()), s_forge])

        await ws.send("submit")
        await ws.send(json.dumps(signatures, separators=(",", ":")))
        try:
            while True:
                print(await recv_text(ws), flush=True)
        except Exception:
            pass


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "wss://one-more.isfcr.xyz"
    asyncio.run(exploit(target))
