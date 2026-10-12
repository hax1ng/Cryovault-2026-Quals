#!/usr/bin/env python3
"""FROSTLANG assembler and thaw-ladder client.

The remote-driving path is intentionally not run automatically.  It first finds the
session's SEAL offset with a CONT/ATT gate oracle, then checks whether the 7.3 privileged
mode permits reads from the recorded-profile window.  The final attestation program is
also usable with an explicitly supplied profile (and is tested against frostbench 7.2).
"""

from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys
from dataclasses import dataclass, field


FUN = {
    "ADD": 0,
    "SUB": 1,
    "AND": 2,
    "OR": 3,
    "XOR": 4,
    "SHL": 5,
    "SHR": 6,
    "ROL": 7,
    "MUL": 8,
    "MULH": 9,
    "SLTU": 10,
}


def ins(op: int, a: int = 0, b: int = 0, c: int = 0, imm: int = 0) -> int:
    return ((op & 15) << 28) | ((a & 15) << 24) | ((b & 15) << 20) | ((c & 15) << 16) | (imm & 0xFFFF)


def ldi(a: int, imm: int) -> int:
    return ins(1, a=a, imm=imm)


def alu(a: int, b: int, c: int, fn: str) -> int:
    return ins(2, a=a, b=b, c=c, imm=FUN[fn])


def alui(a: int, b: int, fn: str, imm: int) -> int:
    return ins(3, a=a, b=b, c=FUN[fn], imm=imm)


def ldb(a: int, b: int, imm: int) -> int:
    return ins(4, a=a, b=b, imm=imm)


def ldw(a: int, b: int, imm: int) -> int:
    return ins(5, a=a, b=b, imm=imm)


def stb(a: int, b: int, imm: int) -> int:
    return ins(6, a=a, b=b, imm=imm)


def stw(a: int, b: int, imm: int) -> int:
    return ins(7, a=a, b=b, imm=imm)


def beq(a: int, b: int, rel: int) -> int:
    return ins(8, a=a, b=b, imm=rel)


def bne(a: int, b: int, rel: int) -> int:
    return ins(9, a=a, b=b, imm=rel)


def djnz(a: int, rel: int) -> int:
    return ins(0xB, a=a, imm=rel)


def seal(a: int) -> int:
    return ins(0xD, a=a)


def att(a: int, b: int, c: int) -> int:
    return ins(0xE, a=a, b=b, c=c)


HALT = 0


@dataclass
class Program:
    words: list[int] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)
    fixups: list[tuple[int, str, str, tuple[int, ...]]] = field(default_factory=list)

    def emit(self, word: int) -> int:
        self.words.append(word & 0xFFFFFFFF)
        return len(self.words) - 1

    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError(f"duplicate label {name}")
        self.labels[name] = len(self.words)

    def emit_djnz(self, a: int, target: str) -> None:
        self.fixups.append((self.emit(0), "djnz", target, (a,)))

    def patch(self) -> list[int]:
        out = self.words[:]
        for pc, kind, target, args in self.fixups:
            if target not in self.labels:
                raise ValueError(f"unknown label {target}")
            rel = self.labels[target] - (pc + 1)
            if not -0x8000 <= rel <= 0x7FFF:
                raise ValueError(f"branch out of range: {target}")
            if kind == "djnz":
                out[pc] = djnz(args[0], rel)
            else:
                raise AssertionError(kind)
        return out


def words_hex(words: list[int]) -> str:
    return "".join(f"{w:08x}" for w in words)


def gate_probe(offset: int, read_addr: int | None = None, bit: int = 0) -> list[int]:
    """Gate oracle, optionally followed by a privileged byte-read bit oracle.

    With no read address, SETTLED means SEAL opened the gate.  With read_addr, SETTLED
    means the privileged load succeeded and the selected bit was one; FAULT can mean
    either a zero bit or a forbidden controller read, so callers first probe a known bit.
    """
    p = Program()
    p.emit(ldi(1, offset))
    p.emit(seal(1))
    cont_ldi = p.emit(0)  # patched once the privileged target is known
    p.emit(stw(2, 0, 0x8200))
    p.emit(HALT)
    priv = len(p.words)
    if read_addr is None:
        p.emit(att(3, 0, 0))
        p.emit(HALT)
    else:
        p.emit(ldb(4, 0, read_addr))
        p.emit(alui(5, 4, "AND", 1 << bit))
        p.emit(bne(5, 0, 1))
        p.emit(ldb(6, 0, 0xA000))  # deliberate fault for a zero bit
        p.emit(HALT)
    p.words[cont_ldi] = ldi(2, 0x8000 | priv)
    return p.patch()


def thaw_program(offset: int, profile: bytes, profile_addr: int = 0x1000) -> list[int]:
    """Build a complete four-round ATT program using a supplied 32-byte profile."""
    if len(profile) != 32:
        raise ValueError("profile must contain exactly 32 bytes")
    p = Program()

    # Materialize K[0..15] in ordinary RAM while still unprivileged.
    for i in range(16):
        p.emit(ldi(1, int.from_bytes(profile[2 * i:2 * i + 2], "big")))
        p.emit(stw(1, 0, profile_addr + 2 * i))

    p.emit(ldi(1, offset))
    p.emit(seal(1))
    cont_ldi = p.emit(0)
    p.emit(stw(15, 0, 0x8200))
    p.emit(HALT)
    priv = len(p.words)

    # Persistent chain state and table bases.
    p.emit(ldw(1, 0, 0x8004))       # x
    p.emit(ldw(2, 0, 0x8006))       # y
    p.emit(ldi(8, 0x9E35))
    p.emit(ldi(11, profile_addr))
    p.emit(ldi(12, 0x8100))
    p.emit(att(10, 0, 0))           # draw N for round zero

    for rnd in range(4):
        p.emit(ldi(3, 0))            # t
        p.emit(ldi(9, 16))           # loop count
        loop = f"fold_{rnd}"
        p.label(loop)

        # j = (t + (y >> 12)) & 15; K[j]
        p.emit(alui(4, 2, "SHR", 12))
        p.emit(alu(4, 4, 3, "ADD"))
        p.emit(alui(4, 4, "AND", 15))
        p.emit(alui(4, 4, "SHL", 1))
        p.emit(alu(4, 4, 11, "ADD"))
        p.emit(ldw(5, 4, 0))

        # x = rol16(x ^ K[j], y) + N[t & 3]
        p.emit(alu(1, 1, 5, "XOR"))
        p.emit(alu(1, 1, 2, "ROL"))
        p.emit(alui(4, 3, "AND", 3))
        p.emit(alui(4, 4, "SHL", 1))
        p.emit(alu(4, 4, 12, "ADD"))
        p.emit(ldw(6, 4, 0))
        p.emit(alu(1, 1, 6, "ADD"))

        # y = y*0x9e35 + x + t; y ^= rol16(x, 7)
        p.emit(alu(2, 2, 8, "MUL"))
        p.emit(alu(2, 2, 1, "ADD"))
        p.emit(alu(2, 2, 3, "ADD"))
        p.emit(alui(13, 1, "ROL", 7))
        p.emit(alu(2, 2, 13, "XOR"))

        p.emit(alui(3, 3, "ADD", 1))
        p.emit_djnz(9, loop)
        p.emit(att(10, 1, 2))

    # Correct round four ends in THAWED inside ATT.  This HALT is defensive only.
    p.emit(HALT)
    p.words[cont_ldi] = ldi(15, 0x8000 | priv)
    out = p.patch()
    if len(out) > 1024:
        raise AssertionError(f"plan too long: {len(out)} words")
    return out


class Client:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=15)
        self.sock.settimeout(120)
        self.f = self.sock.makefile("rwb", buffering=0)
        self.banner = self.f.readline().decode("ascii", "replace").strip()
        if not re.fullmatch(r"thawd 7\.3 pod 07 session [0-9a-f]{16} meter \d+ ready", self.banner):
            raise RuntimeError(f"unexpected controller banner: {self.banner!r}")

    def plan(self, words: list[int]) -> str:
        self.f.write(("PLAN " + words_hex(words) + "\n").encode())
        line = self.f.readline().decode("ascii", "replace").strip()
        if not line:
            raise EOFError("controller closed the connection")
        return line


def local_selftest(bench_path: str) -> None:
    profile = bytes.fromhex("a1729f19f335a4e6c3e3c96a5d192d15abfbf4030595259e5e10130ff1fa60b5")
    words = thaw_program(0, profile)
    data = ("PLAN " + words_hex(words) + "\n").encode()
    cp = subprocess.run([sys.executable, bench_path], input=data, capture_output=True, check=True)
    lines = cp.stdout.decode().splitlines()
    print(f"selftest plan: {len(words)} words")
    print("\n".join(lines))
    if not any(line.startswith("THAWED ") for line in lines):
        raise SystemExit("bench self-test did not thaw")


def remote(host: str, port: int) -> None:
    c = Client(host, port)
    print(c.banner, flush=True)
    found = None
    for off in range(33):
        ans = c.plan(gate_probe(off))
        print(f"SEAL {off:2d}: {ans}", flush=True)
        if ans.startswith("SETTLED "):
            found = off
            break
    if found is None:
        raise RuntimeError("none of the documented 0..32 window offsets opened the gate")

    # 0x9000+found points at P if the field window uses the documented relationship.
    base = 0x9000 + found
    # The high bit of the known bench/field-independent first profile byte is not known;
    # probe all bits and treat an all-FAULT byte as a likely privilege-read denial.
    profile = bytearray()
    for i in range(32):
        v = 0
        for bit in range(8):
            ans = c.plan(gate_probe(found, base + i, bit))
            if ans.startswith("SETTLED "):
                v |= 1 << bit
            elif not ans.startswith("FAULT "):
                raise RuntimeError(f"unexpected read-oracle answer: {ans}")
        profile.append(v)
        print(f"profile[{i:02d}] = {v:02x}", flush=True)

    if profile == bytes(32):
        raise RuntimeError("privileged controller loads appear denied (all bit probes faulted)")
    print("profile", profile.hex(), flush=True)
    ans = c.plan(thaw_program(found, bytes(profile)))
    print(ans, flush=True)
    if not ans.startswith("THAWED "):
        raise RuntimeError("final attestation plan did not thaw")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bench", default="thaw-ladder/frostbench.py")
    ap.add_argument("--host", default="0.cloud.chals.io")
    ap.add_argument("--port", type=int, default=13929)
    args = ap.parse_args()
    if args.selftest:
        local_selftest(args.bench)
    else:
        remote(args.host, args.port)


if __name__ == "__main__":
    main()
