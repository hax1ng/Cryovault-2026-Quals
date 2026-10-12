# The Alphabet That Wasn't There

**Category:** Forensics · **Points:** 104 · **Solves:** 67 · **Flag:** `isfcr{d7ef3d5dd98bd325c3b50114}`

## Challenge

> Decode the 16×16 symbol grid on the page of the document in `damaged.pdf` whose catalog carries the `/CaseID` bytes `9697624543591457a15dc6d9a4797c45`. In `reference.pdf` the n-th symbol from the left is the n-th hex digit of `8bd4e257f916c30a`. Reading order, in the page's default user space: rows top→bottom (descending baseline y), left→right within a row (ascending baseline x). A symbol drawn rotated is still the same symbol.
>
> Evidence fields, in order: the CaseID (32 lowercase hex), then the grid (256 lowercase hex, in reading order). Those two strings are fed through `scrypt` + `AES-GCM` (recipe supplied with the challenge) to produce the flag. Flag format: `isfcr{...}`.

Given: `reference.pdf` (the 16-symbol alphabet) and `damaged.pdf` (several PDF revisions ending in a damaged one).

## Initial Analysis

The task *sounds* like OCR, but it's really **PDF forensics**. `damaged.pdf` contains two complete revisions plus ~42 KB of trailing objects with **no final xref / `startxref`** — that missing final cross-reference is the damage.

```text
first startxref:  15118
second startxref: 22231   (/Prev 15118)
final file size:  64872   (trailing objects, no final xref)
```

Among the loose trailing objects: object stream `226` (the catalog with the requested `/CaseID`), object stream `225` (page object `3`), a new page tree `2`, and many fonts/forms for the final page. `mutool clean -d damaged.pdf recovered.pdf` reconstructs a usable file — but its scan-based repair makes one critical mistake.

## Vulnerability / Core Concept

**Trap 1 — a resurrected free object.** The last valid xref marks **object 10 as free** (`[0, 0, 1]`, type 0 = deleted). The damaged update never redefines it, so it should stay gone. But one new form XObject references `/Ov 10 0 R` and executes `/Ov Do`, and the *physical bytes* of old object 10 are still earlier in the file. A scan-based repair resurrects it — and object 10 is a decoy overlay that draws 14 white rectangles and re-draws glyphs over them. The page still looks plausible, 14 grid cells change, and the **AES-GCM tag rejects** the decoded grid. The fix: keep the live/free state of the last valid xref — leave object 10 unresolved (or strip the `/Ov Do`). *Physical presence ≠ live in the current revision.*

**Trap 2 — the "alphabet" is drawing programs, not characters.** The symbols are glyphs in **Type3 fonts**: each glyph is a mini PDF program that draws rectangles. Font names, glyph names, and character codes are all randomized, so text extraction yields garbage. You must compare **shapes**, not codes.

**Trap 3 — rotation and page rotation.** Glyphs may be drawn rotated (so canonicalize over 4 rotations), and the page has `/Rotate 90` — but the challenge wants **default user-space** coordinates, so the display rotation must be ignored when ordering.

## Exploitation

1. **Repair while respecting the xref.** `mutool clean` the damaged file, then ensure object 10 / the `/Ov Do` overlay is not applied, giving the correct target page.
2. **Build shape fingerprints.** For each Type3 glyph: decode its `CharProc`, collect `re` rectangle ops with their fill rule and the glyph `cm` transform, rasterize to unit cells, translate to origin, generate all 4 rotations, and take the lexicographically smallest as the fingerprint. Map the 16 reference fingerprints to the digits of `8bd4e257f916c30a`.
3. **Decode the grid.** Every live target glyph matches exactly one reference fingerprint. Order entries by `(-baseline_y, baseline_x)` and read off 256 hex digits. `glyph_decode.py` implements the full Type3 shape-matching decoder.
4. **Derive the flag.** Feed `[CaseID, grid]` through the supplied `scrypt` (n=131072, r=8, p=1) + `AES-GCM` recipe.

The recovered grid is:

```text
e7463684552dfb02 7076afdf977a1a94 bb89d9112b4ace4b c9207e7c18b3fbf5
5526ba3a9e437c7d 6c4a3ef3bf7e0dcd 4694f7288fc5d4c1 89be389bbbaadd51
4031b50de7eba382 0e5230915ddfa4bc c793d2b7aa7c880f 1900cd60b1caedd9
507009b6658d86d3 ce052d46f8f4c16d 13c9e5e6302733f3 906ff5e24f690ab6
```

`decrypt_flag.py` runs the final recipe against that grid:

```text
$ python3 decrypt_flag.py
FLAG: isfcr{d7ef3d5dd98bd325c3b50114}
```

A wrong (overlay-trapped) grid still decodes cleanly to 256 digits but fails the AES-GCM tag — the authentication check is what tells you the repair was correct.

## Flag

```
isfcr{d7ef3d5dd98bd325c3b50114}
```

## Key Takeaways

- A PDF can hold several historical revisions at once; objects after the last `%%EOF` may be a damaged final update.
- An xref `free` entry (type 0) means an object is deleted even if its bytes still sit in the file — scan-based repair tools happily resurrect it.
- Type3 fonts are drawing programs: compare glyph *shapes* (rotation-canonicalized) when codes/names are randomized.
- Page `/Rotate` is display-only; "default user space" ordering ignores it.
- AES-GCM authentication is the oracle — a plausible grid that fails the tag means you got the forensics wrong.

## Files

- `README.md` — this writeup
- `reference.pdf`, `damaged.pdf` — the challenge handout
- `glyph_decode.py` — Type3 glyph shape-matching grid decoder (run against the overlay-stripped/repaired target page; original of the solve, kept as reference)
- `decrypt_flag.py` — final `scrypt` + `AES-GCM` from the recovered grid → flag
