# short-final — solve notes

## Flag

```text
isfcr{VT-ATE_USI}
```

The flag was accepted by the official CTFd challenge endpoint.

## 1. Aircraft registration

The stated time converts as follows:

```text
2026-10-06 17:29 IST = 2026-10-06 11:59 UTC
```

The video shows a red-and-white Airbus A320-family aircraft, gear down, moving
screen-left to screen-right on final approach to Delhi.

I queried the historical `planes_mercator` ADS-B data exposed by
<https://adsb.exposed/> for the New Delhi approach corridor at 11:59 UTC. The
matching westbound arrival was:

| Field | Value |
|---|---|
| Registration | `VT-ATE` |
| Type | `A20N` (Airbus A320neo) |
| Callsign | `AXB1824` / IX1824 |
| Track | approximately 271 degrees |

Representative track points saved in `vtate.jsonl` and `/tmp/vtate2.jsonl`:

| UTC | Latitude | Longitude | Geometric altitude |
|---|---:|---:|---:|
| 11:59:10 | 28.568756 | 77.166965 | 1525 ft |
| 11:59:20 | 28.568922 | 77.159460 | 1400 ft |
| 11:59:31 | 28.569108 | 77.150304 | 1250 ft |
| 11:59:33 | 28.569168 | 77.148690 | 1200 ft |

This gives part 1: **VT-ATE**.

## 2. Camera-side geometry

The plane was physically flying west. Since west maps to screen-right in the
upright video, the camera was north of the approach path and looking generally
south/southwest. A projection estimate from the visible fuselage and wings gave
an approximate line-of-sight component ratio of:

```text
along-track : cross-track : vertical ~= 0.34 : 0.75 : 0.57
```

Thus the camera was about 1.3 times the aircraft's height above the camera to
the north of the flight path, and roughly 0.6 times that height east of the
aircraft. Applying those ratios to the full 17:29 minute is important: the
along-track geometry is nearly translation-invariant, so the video alone does
not justify stopping the search at 11:59:20.

Around 11:59:31–33, the resulting camera strip passes through the grounds of
the United Service Institution of India on Rao Tula Ram Marg, near roughly
28.571 N, 77.150 E.

## 3. Exact building match

The decisive clue is the foreground facade. It has:

- grouped circular vents at the roofline;
- dark balcony railings with diagonal/X motifs;
- projecting window shades and window AC units;
- tan/orange upper walls and dark red lower walls;
- small cylindrical rooftop tanks.

An exterior photograph of Residency Resorts on the USI premises matches all of
those features exactly, including the vent groupings and balcony layout:

<https://images.oyoroomscdn.com/uploads/hotel_image/9110/large/5b880d38d93d16ee.jpg>

The USI Residency site says that it manages the hospitality wing of USI in the
USI complex and describes the landscaped grounds:

<https://usiresidency.com/about-us.html>

The institution's official site uses **USI** for the United Service Institution
of India:

<https://www.usiofindia.org/?lang=en>

Therefore part 2 is **USI**.

## Final

```text
isfcr{VT-ATE_USI}
```
