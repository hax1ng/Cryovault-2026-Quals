RIME SCRUB

The vault's key bank sits behind a controller that will never read the key out.
Bench rig 2 is wired to your team's bank. You get the controller's firmware and
the image of a decommissioned bank. Open the vault.

  scrubd      controller firmware
  bench.img   the decommissioned bank

Your rig:      nc HOST PORT      (start your instance on the challenge page)
On the bench:  cat bench.img - | qemu-hexagon-static ./scrubd
