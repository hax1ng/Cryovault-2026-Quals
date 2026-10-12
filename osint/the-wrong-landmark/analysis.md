# The Wrong Landmark — Analysis

## Challenge
Identify the hotel from which `osint.jpg` was captured and submit its latitude/longitude rounded to four decimals.

## Artifact triage
- Downloaded `osint.jpg` from the public challenge file URL.
- JPEG dimensions: 1152×1536.
- No EXIF/GPS metadata.
- The image shows a turquoise/blue and gold temple dome with star motifs, a gold chakra, and flag.

## Landmark identification
Yandex reverse-image matching and architectural comparison identify the landmark as the Temple of the Vedic Planetarium (TOVP), ISKCON Mayapur, West Bengal, India. The task explicitly asks for the hotel/viewpoint rather than the monument.

## Viewpoint research
- Temple map pin observed around 23.4250835, 88.389534.
- Hotel SS Plaza was an initial hypothesis because it advertises temple-view rooms. Both its Google Maps and alternate directory coordinates were submitted and rejected.
- Other nearby hotel/guesthouse pins tested and rejected: Hotel Shreesh Mayapur, Mayapur Iscon, Jagannath Palace, Narasimha Dev Guest House, Sudama Bhavan, Ishodyan Bhavan, Hotel AJ Plaza, and Jagannath Guest House.
- A stronger lead was Gita Bhavan, an official ISKCON Mayapur guesthouse. Its official page identifies it as a guest house in the ISKCON compound, while a video result explicitly advertises a temple-view AC room inside the temple grounds.
- A direct Google Maps place search resolved **Gita Bhavan** to **23.4279212, 88.3905137**.
- Rounding both components to exactly four decimal places gives **23.4279, 88.3905**.

## Attempt record
- `isfcr{23.4187_88.3847}` — incorrect
- `isfcr{23.4193_88.3851}` — incorrect
- `isfcr{23.4328_88.3872}` — incorrect
- `isfcr{23.4256_88.3882}` — incorrect
- `isfcr{23.4323_88.3888}` — incorrect
- `isfcr{23.4299_88.3887}` — incorrect
- `isfcr{23.4292_88.3906}` — incorrect
- `isfcr{23.4277_88.3920}` — incorrect
- `isfcr{23.4142_88.3835}` — incorrect
- `isfcr{23.4170_88.3836}` — incorrect
- `isfcr{23.4279_88.3905}` — **correct**

## Result
`isfcr{23.4279_88.3905}`
