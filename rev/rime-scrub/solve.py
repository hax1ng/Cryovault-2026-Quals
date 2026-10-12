#!/usr/bin/env python3
import socket

HOST = "0.cloud.chals.io"
PORT = 10087


def recvn(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError(f"short read: {len(data)}/{size}")
        data += chunk
    return data


def command(sock, request):
    sock.sendall(request)
    return recvn(sock, 6)


def frozen_bit(address, bit):
    # Affine rime pattern inferred using known, readable bank words.
    # This expression is sufficient for physical data bits 0..31.
    return 1 ^ (address & 1) ^ (bit & 1)


with socket.create_connection((HOST, PORT), timeout=5) as sock:
    sock.settimeout(10)

    # A double error in the readable control word (address 0x30) is
    # miscorrected into logical bits 0, 2, and 8.  Bit 0 enables faulting
    # the otherwise protected words at 0x38..0x3f.
    assert command(sock, b"q" + bytes((0x30, 2)))[1] == 0
    assert command(sock, b"q" + bytes((0x30, 8)))[1] == 0
    assert command(sock, b"~")[1] == 0

    key = 0
    for word in range(4):
        for bit in range(32):
            low_address = 0x38 + word
            high_address = 0x3C + word
            high_bit = (bit + 13) & 31

            # The protected representation is
            #   low  = key XOR mask
            #   high = ROL32(mask, 13)
            # Probe matching low/mask bits in two distinct ECC words.  Each
            # mismatch is corrected independently, and response byte 2 is
            # the number of corrected words (0, 1, or 2).
            assert command(sock, b"q" + bytes((low_address, bit)))[1] == 0
            assert command(sock, b"q" + bytes((high_address, high_bit)))[1] == 0
            response = command(sock, b"~")
            assert response[1] == 0 and response[2] <= 2

            key_bit = ((response[2] & 1)
                       ^ frozen_bit(low_address, bit)
                       ^ frozen_bit(high_address, high_bit))
            key |= key_bit << (32 * word + bit)

    raw_key = key.to_bytes(16, "little")
    print(f"session key: {raw_key.hex()}")

    # Opcode 0x33 belongs to the outer vault rig, not scrubd.  It consumes
    # the raw 16-byte session key and then closes the connection.
    sock.sendall(b"\x33" + raw_key)
    result = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        result += chunk

    # A successful reply has a six-byte binary header followed by the flag.
    print(result[6:].decode().strip())
