#!/usr/bin/env python3
"""Join a PNG's IDAT chunks into one raw zlib/DEFLATE stream (stream.zlib)."""
import struct

png = open("mosaic_0417.png", "rb").read()
pos = 8                              # skip the 8-byte PNG signature
compressed = bytearray()

while pos < len(png):
    length = struct.unpack(">I", png[pos:pos + 4])[0]
    kind = png[pos + 4:pos + 8]
    data = png[pos + 8:pos + 8 + length]
    if kind == b"IDAT":
        compressed.extend(data)
    pos += 12 + length              # length(4) + type(4) + data + CRC(4)

open("stream.zlib", "wb").write(compressed)
print("wrote stream.zlib", len(compressed), "bytes")
