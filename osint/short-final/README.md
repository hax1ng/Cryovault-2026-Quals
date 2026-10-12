# short-final

**Category:** OSINT · **Points:** 446 · **Solves:** 10 · **Flag:** `isfcr{VT-ATE_USI}`

## Challenge

> Filmed in New Delhi on 6 October 2026 at 17:29 IST.
>
> Video: `https://files.catbox.moe/a9mxui.mp4` (4K HDR; plays in VLC)
>
> Flag: `isfcr{Part1_Part2}` — part 1 is the registration of the aircraft in the video, part 2 is the acronym of the institution whose grounds it was filmed from (any case). Example format: `isfcr{AB-XYZ_ABC}`.

Author: AJ. The only artifact is a 4K HDR video of an aircraft on final approach, plus a single precise timestamp.

## Initial Analysis

Two independent facts have to be recovered, and the only given data point is a timestamp:

- `2026-10-06 17:29 IST` = `2026-10-06 11:59 UTC`.

From the footage itself:

- A red-and-white Airbus A320-family jet, gear down, crossing the frame left-to-right on final approach into Delhi (VIDP / Indira Gandhi International).
- The camera is clearly on the ground, filming over a distinctive building facade in the foreground.

So the puzzle splits cleanly: **which aircraft** (needs flight history) and **where was the camera standing** (needs ground-level geolocation). The timestamp is the key that unlocks the first half.

## Vulnerability / Core Concept

This is a two-stage geolocation / flight-attribution problem. The "trick" is realizing that a single accurate timestamp plus a known approach corridor is enough to pin down one specific aircraft in historical ADS-B data — and that the foreground building, not the aircraft, is what you actually geolocate.

**Part 1 — aircraft registration via historical ADS-B.**
Querying the historical `planes_mercator` ADS-B dataset exposed by [adsb.exposed](https://adsb.exposed/) for the New Delhi approach corridor at 11:59 UTC on 2026-10-06 returns exactly one matching westbound arrival:

| Field | Value |
|---|---|
| Registration | `VT-ATE` |
| Type | `A20N` (Airbus A320neo) |
| Callsign | `AXB1824` (IX1824, Air India Express) |
| Track | ~271° (due west) |

A few representative track points (full set in [`vtate.jsonl`](vtate.jsonl)):

| UTC | Latitude | Longitude | Geom. alt |
|---|---:|---:|---:|
| 11:59:10 | 28.568756 | 77.166965 | 1525 ft |
| 11:59:20 | 28.568922 | 77.159460 | 1400 ft |
| 11:59:31 | 28.569108 | 77.150304 | 1250 ft |
| 11:59:33 | 28.569168 | 77.148690 | 1200 ft |

That gives **Part 1 = `VT-ATE`**.

**Part 2 — the camera location via geometry + facade matching.**
The aircraft is physically flying *west*, and in the upright video west maps to screen-right, so the camera must be **north of the approach path, looking roughly south/southwest**. A rough projection from the visible fuselage/wing foreshortening gave a line-of-sight component ratio of about `along:cross:vertical ≈ 0.34 : 0.75 : 0.57` — i.e. the camera sits a bit north of and below the flight path. Projecting that strip onto the 11:59:31–33 track positions lands it on the grounds of the **United Service Institution of India (USI)** on Rao Tula Ram Marg, around `28.571 N, 77.150 E`.

The decisive confirmation is the foreground facade, which has a very specific fingerprint:

- grouped circular vents at the roofline;
- dark balcony railings with diagonal / X motifs;
- projecting window shades and window AC units;
- tan/orange upper walls over dark-red lower walls;
- small cylindrical rooftop water tanks.

Every one of those features matches an exterior photo of **Residency Resorts**, the hospitality wing on the USI complex (`usiresidency.com`). The institution's acronym is **USI** (United Service Institution of India, `usiofindia.org`).

That gives **Part 2 = `USI`**.

## Exploitation

No code required — the solve is an OSINT chain:

1. Convert `17:29 IST` → `11:59 UTC`.
2. Query historical ADS-B (adsb.exposed `planes_mercator`) for arrivals into VIDP crossing the corridor at that minute; filter to the westbound A320neo on final → `VT-ATE` / `AXB1824`. Track points saved to [`vtate.jsonl`](vtate.jsonl).
3. Use the aircraft heading (west → screen-right) to fix the camera on the north side of the approach path, then project the line-of-sight onto the recovered track to narrow the ground location to the USI grounds near `28.571, 77.150`.
4. Match the distinctive foreground facade to Residency Resorts on the USI premises, confirming the institution as the **United Service Institution of India → USI**.
5. Assemble `isfcr{VT-ATE_USI}`.

## Flag

```
isfcr{VT-ATE_USI}
```

## Key Takeaways

- A single accurate timestamp + a known approach/departure corridor is often enough to attribute one specific aircraft in historical ADS-B data (adsb.exposed, ADSBExchange, etc.). Always convert the local time to UTC first.
- Aircraft heading is a free compass: in an upright shot, which way the plane crosses the frame tells you which side of the flight path the camera is on.
- Don't geolocate the obvious subject — geolocate the *foreground*. The building in frame (vents, railings, AC units, wall colors) is a far more specific fingerprint than the plane.
- Read the flag spec carefully: it explicitly wanted the *institution whose grounds it was filmed from*, not the airport or the aircraft operator.
