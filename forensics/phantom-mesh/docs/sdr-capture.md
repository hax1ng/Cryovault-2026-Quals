# SDR capture notes

The operator rented a short-term bench RF probe to snoop on their own
coordinator (model `LM-COORD-24A`). This document is their lab notebook,
reproduced verbatim.

## Setup

* **DUT:** LM-COORD-24A, mains powered, running factory firmware 1.3.4.
* **RF tap:** Directional coupler on the antenna port, -20 dB tap into a
  USRP B210 at 2440 MHz (channel 15), 4 Ms/s, complex float32 (I+Q).
* **Trigger:** DUT exposes a header pin `JX2.6` that goes high just before
  the MAC layer calls `tx_start()` for an outbound frame. We routed that
  into the USRP PPS input so every record starts at the same point in
  the TX pipeline. Each record is 2500 samples long (~625 µs).
* **Scope:** Only the 2500 records captured while a `KEY_CONFIRM` was being
  transmitted are included here. We correlated against the TX FIFO snoop
  (JX2.7) to filter out other frame types.

## About the DUT

LM-COORD-24A uses a low-cost ARM SoC paired with an external PA. The
reference design review flagged a stability concern with the PA bias feed,
but the production board (ours included) ships without the recommended
decoupling cap. The vendor rated the resulting envelope stability as
"adequate for lighting but not for metrology". We have not pursued it
further on the bench.

The LMP crypto stack runs in software on the main core; we have not seen
Lumeta use the SoC's hardware AES peripheral.

## Alignment

Every I/Q record is aligned to the rising edge of the TX trigger within
±1 sample (the FPGA PPS logic occasionally slips one cycle). You should
not need to realign across records.

## File format

`traces/iq.npz` is a NumPy archive:

```python
import numpy as np
iq = np.load("traces/iq.npz")["iq"]   # shape (2500, 2500), complex64
```

`traces/nonces.csv` has two columns:

```
trace_index, nonce_hex
0, c99f...6a
1, 02d3...11
...
```

The nonce in each row is the exact 16-byte value that went on the air in
the KEY_CONFIRM frame transmitted while that I/Q record was being captured.
