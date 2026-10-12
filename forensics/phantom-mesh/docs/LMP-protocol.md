# Lumeta Mesh Protocol (LMP) v1.3 — wire format

LMP rides directly on an IEEE 802.15.4 MAC data payload. Every PAN seen in
the capture is `0x1A2B`. The coordinator short address is `0x0000`.

Every LMP PDU starts with a 3-byte header:

```
+------+------+------+--------- ... ---------+
| 0x1C | 0x03 | cmd  |         body          |
+------+------+------+-----------------------+
  magic   ver   type
```

`cmd` identifies the command type. The commands used in this capture are:

| cmd  | name              | protected by        | direction            |
|------|-------------------|---------------------|----------------------|
| 0x11 | TRANSPORT_KEY     | TC Link Key         | coordinator → device |
| 0x12 | KEY_CONFIRM       | (plaintext)         | coordinator → device |
| 0x21 | SECURE_REPORT     | NWK Key             | any → coordinator    |
| 0x30 | BEACON            | (plaintext)         | coordinator → bcast  |

## Cryptography

Every protected LMP command uses **AES-CCM\*** with:

* key length: 128 bits
* nonce length: 13 bytes
* `M` (MIC length): 4 bytes
* `L` (length-field size): 2 bytes

The nonce is constructed as

```
nonce = src_eui64 (8 bytes, big-endian) || frame_counter (4 bytes, little-endian) || sec_ctl (1 byte)
```

Security control is always `0x05` (ENC-MIC-32).

The authenticated-but-not-encrypted header fed to CCM\* is

```
aad = sec_ctl (1) || frame_counter (4, little-endian) || src_eui64 (8, little-endian)
```

Note the byte-order mismatch between nonce and AAD representations of
`src_eui64`. It is intentional and matches the vendor's firmware.

## Command bodies

### 0x11 TRANSPORT_KEY (TC Link Key protected)

```
+-------+----------------+-----------------------+-----------+--------+
| 0x05  | frame_counter  |    src_eui64 (LE)     |  ct (16)  | mic(4) |
+-------+----------------+-----------------------+-----------+--------+
   1B           4B                   8B
```

The plaintext hidden under `ct` is a fresh 128-bit **Network Key** which is
installed by the receiving node as its active NWK key.

### 0x12 KEY_CONFIRM (plaintext)

```
+-------------- 16 bytes --------------+------- 8 bytes -------+
|              nonce                   |      confirm_tag      |
+--------------------------------------+-----------------------+
```

The receiver uses `confirm_tag` to verify that the sender possesses the
fleet-wide Trust Center link key. The exact construction is a one-call
AES-128 primitive — Lumeta's integration guide only specifies that
"`confirm_tag` is derived deterministically from `nonce` under the TC Link
Key, truncated to 8 octets". Devices refuse to install a Transport-Key that
is not immediately followed by a KEY_CONFIRM whose tag they can reproduce
locally.

### 0x21 SECURE_REPORT (NWK Key protected)

```
+-------+----------------+-----------------------+--------- ... ---------+--------+
| 0x05  | frame_counter  |    src_eui64 (LE)     |          ct           | mic(4) |
+-------+----------------+-----------------------+-----------------------+--------+
```

The hidden plaintext is a ZCL-like attribute report:

```
+----------- 2B ----------+----------- 2B ------------+------ 2B ------+-- vlen --+
|        cluster_id       |        attribute_id       |      vlen      |  value   |
+-------------------------+---------------------------+----------------+----------+
```

All multi-byte integer fields are little-endian. `value` is an opaque byte
string, up to 64 bytes, interpreted by the receiver according to
`cluster_id` / `attribute_id`.

### 0x30 BEACON (plaintext)

```
+---------- 4B ----------+---- 2B ----+---------- 10 bytes ---------+
|         epoch          |    PAN     |         fabric_name         |
+------------------------+------------+-----------------------------+
```

## Trust Center key hierarchy

Lumeta's cloud provisions every coordinator at the factory with a single
fleet-wide **TC Link Key**. It never leaves the device. The coordinator
uses it to:

1. protect `TRANSPORT_KEY` commands, and
2. produce the KEY_CONFIRM tag in step (1) above.

The NWK Key is rotated by the coordinator at install-time per site, so each
mesh has its own NWK Key, but the TC Link Key is the same across every
Lumeta coordinator in the world.
