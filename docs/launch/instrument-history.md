# Instrument history

A generation's lifecycle is part of the instrument, so every change to it is recorded
here in the open. Rotation and retirement are **visible instrument changes**, never
silent attribute flips — that is the whole of the secrecy/verifiability resolution:
probes stay secret while ACTIVE, and disclosure happens *because* retirement happened,
on a date anyone can cite.

## gen-1-c4 — RETIRED 2026-09-10

- **Status:** `active` → `retired`
- **Date:** 2026-09-10
- **Reason:** Retired to permit disclosure. The generation faced a live system in the C4
  phase of 2026-08-22 and its purpose is complete; publishing the probes lets a third
  party verify the incident of record without trusting us. Approved by Core → Canary
  Response 011 §3; timing set by Response 012 §4.
- **Generation digest:** `e9cd77076c01a4b0f11a86d5d9051670c0ae96bb575be9818b2c60f9737a3806`
- **Cited by receipts:** `147af49464bbcab3…`, `1b3af5ef197fafaf…`, `f5b5b7c16bb8f10e…`
- **Consequence:** `gen-1-c4` may never probe a live system again.
  `assert_may_probe_live()` enforces this; there is no `unretire`.

## Generations still in service

`gen-2-c4` and `gen-3-c4` remain **ACTIVE**. Their probe text is not published and neither
is the seed that generated them; what is published is their identity and their digest,
which is the ACTIVE generations' public trace by design.

- **`gen-2-c4`** — ACTIVE, digest `76cd2afbc49f1b0d…` (truncated; see below)
- **`gen-3-c4`** — ACTIVE, digest `50230195e2b6ec7b…` (truncated; see below)

Naming them is deliberate. The secrecy this design protects is **probe text and the
generator, never the fact of rotation** — a monitor whose subjects know they are watched
by undisclosed probes is stronger than one that hides the patrol entirely.

**Publishing these digests is a commitment.** When `gen-2-c4` or `gen-3-c4` is eventually
retired and disclosed, its published text will have to hash to the digest recorded here —
a digest that has been public since this date, fixed long before the text it describes was
ever shown. That is the same proof the disclosure above rests on, with a longer fuse: the
check is handed to the reader before the thing being checked exists in public.

*The digests above are 16-hex prefixes, which is what the calibration runs recorded. The full values require the seed, which is held outside this repository; a seed-holder can complete this record offline at any time. The prefix is published rather than nothing, and labelled rather than padded.*
