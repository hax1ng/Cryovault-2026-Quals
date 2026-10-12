# The Wrong Landmark

**Category:** OSINT · **Points:** 212 · **Solves:** 49 · **Flag:** `isfcr{23.4279_88.3905}`

## Challenge

> The landmark is obvious. The location isn't.
>
> A traveler captured this photograph from a hotel overlooking something extraordinary. The photograph survived, but the details of where it was taken did not.
>
> Your task isn't to identify the monument. It's to find the hotel from which the photograph was captured.
>
> Find the hotel's geographical coordinates and round both latitude and longitude to exactly four decimal places.
>
> Flag format: `isfcr{latitude_longitude}` — Example: `isfcr{12.3456_78.9012}`

Author: AJ. Provided file: [`osint.jpg`](osint.jpg).

## Initial Analysis

`osint.jpg` is a 1152×1536 JPEG. `exiftool` reports **no camera, date, or GPS metadata** — so there's nothing to extract directly; the answer has to come from the visual content.

The image prominently shows a **turquoise/blue dome with gold ribs and star motifs, topped with a gold chakra and a flag**. The challenge text is explicit about the twist: identifying the monument is *not* the goal — the flag is the coordinates of the **hotel the photo was taken from**.

## Vulnerability / Core Concept

This is a classic "geolocate the viewpoint, not the subject" OSINT problem. The hard part is deliberately misdirected: the dome is instantly recognizable, but recognizing it earns you nothing. You have to:

1. Identify the landmark **only** as an anchor.
2. Figure out the vantage point (a hotel/guesthouse) that overlooks it.
3. Resolve that specific building to coordinates and round correctly.

**Step 1 — identify the landmark (the anchor).**
A reverse-image search (Yandex, Google Lens) plus architectural comparison identifies the dome as the **Temple of the Vedic Planetarium (TOVP)**, part of ISKCON Mayapur in West Bengal, India. The temple pin sits around `23.4251, 88.3895`. This tells us the general area but is explicitly *not* the answer.

**Step 2 — find the hotel overlooking it.**
Searching for accommodation near the TOVP surfaces many temple-view guesthouses and hotels. The decisive lead is **Gita Bhavan**:

- its official page identifies it as a guest house *inside the ISKCON compound*;
- an indexed room-tour video explicitly advertises a **temple-view AC room** at Gita Bhavan, inside the temple grounds — consistent with a photo shot *from a hotel overlooking the dome*.

**Step 3 — resolve coordinates.**
A direct Google Maps place search for `Gita Bhavan ISKCON Mayapur` resolves the building to:

```
23.4279212, 88.3905137
```

Rounded to exactly four decimals: `23.4279`, `88.3905`.

## Exploitation

The solve is a geolocation pivot, not code:

1. `exiftool osint.jpg` → no metadata, so work from pixels.
2. Reverse-image / Lens the dome → **Temple of the Vedic Planetarium, ISKCON Mayapur** (anchor only).
3. Enumerate nearby hotels/guesthouses with temple views; many were tested and rejected (SS Plaza, Hotel Shreesh, Jagannath Palace/Guest House, Narasimha Dev Guest House, Sudama Bhavan, Ishodyan Bhavan, Hotel AJ Plaza, Mayapur Iscon).
4. Land on **Gita Bhavan** — an official ISKCON guesthouse advertising a temple-view room inside the grounds.
5. Resolve `Gita Bhavan ISKCON Mayapur` on Google Maps → `23.4279212, 88.3905137`; round each to 4 decimals.

The attempt log in [`analysis.md`](analysis.md) shows this was a grind — ten wrong coordinate pairs were submitted before the correct one, because many temple-view hotels cluster within a few hundred metres and the scoring demands the *exact* 4-decimal rounding.

## Flag

```
isfcr{23.4279_88.3905}
```

## Key Takeaways

- Read the prompt literally: when a challenge says "not the monument, the viewpoint," the recognizable landmark is just an anchor — geolocate the *camera position*.
- For a specific building, Google Maps' place search gives the canonical coordinates; use those rather than a hand-dropped pin so the rounding is reproducible.
- Coordinate-format challenges are precision-sensitive: round to exactly the requested number of decimals, and expect several near-miss candidates when many similar hotels cluster around one landmark.
- Room-tour / booking listings and their videos are strong OSINT signals — they often state "temple view" and pin the exact property.
