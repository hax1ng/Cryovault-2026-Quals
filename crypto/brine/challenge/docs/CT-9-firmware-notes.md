# Kestrel CT-9 — firmware notes (2.4 SDK)

Engineering notes shipped with the 2.4 SDK drop.

## 3.1 Calibration profile

32 setpoints, strictly increasing, each an unsigned 32-bit integer in [1, 2^32 - 2],
derived at provisioning from the device key. The profile does not leave the device.

## 3.2 Round counter

An accepted `SOUND` advances the round counter by one. A `SOUND` that names any other
value is refused with `ESEQ`, which carries the current value.

## 4.1 Deltas

One value per pass, in nanoseconds.

## 5.1 Reprovisioning

Reprovisioning issues a fresh device key, and with it a fresh profile.
