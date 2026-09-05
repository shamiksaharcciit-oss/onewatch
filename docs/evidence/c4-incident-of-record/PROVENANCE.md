# The C4 incident of record — provenance and handling

This directory is the Detect pillar's launch deliverable: the complete frozen store from
the C4 live phase of **2026-08-22**. It is **RECEIVED data**. Every byte under `runs/`
came back from a live endpoint and is frozen exactly as it arrived.

## What the incident is

A baseline was sealed against `claude-sonnet-5`. Two further runs against the same model
produced no-change receipts. The configuration then switched to `claude-haiku-4-5`, the
provider served `claude-haiku-4-5-20251001`, and under the declared instrument
(refusal-sentinel v3) **not one probe changed verdict**.

So the receipts record two facts that never contradict each other: **the served model
changed, and the validated behaviour did not.** That is the incident — and a dashboard
cannot prove a negative.

The canary says *that* behaviour did not move, under a named instrument. It does not say
which stage of the vendor's system changed, and nothing in this directory should be read
as saying so; stage attribution is the forensics pillar's job.

## Custody

Copied — never moved — from `C:\tmp\c4live` on 2026-08-27 by
`scripts/secure_c4_store.py`, under Core → Canary Response 011 §2. That script digests
every file before the copy, digests the destination independently after it, asserts
per-file byte equality and set coverage in both directions, and contains no delete path
at all. It reported `74/74 files identical, 0 missing, 0 extra`.

The originals in `C:\tmp\c4live` are deleted by Shamik, never by tooling, and only after
the committed copy has been proven to re-derive. Until then both copies exist, which is
the point.

Before this copy the launch deliverable sat unpinned and unversioned in a scratch
directory beside a dozen throwaway stores from the same week. It survived by luck. That
was defect **F2**, self-reported in Note 007 §2.

## The pin, and why reformatting anything here is a defect

`c4-incident-of-record.SHA256` pins all 74 files by sha256 over exact bytes.
`tests/test_byte_discipline.py` checks every entry and checks that the pin has no holes.

A JSON file that has been parsed and written back out is a *different file* — key order,
separators, escaping and number rendering all move — and every result derived from it
becomes a result about something else. Re-derivation re-classifies verdicts **from the
raw reply bytes**, so a formatter run over `runs/*/bodies/` would not merely dirty the
diff; it would silently change what the instrument reads and could flip a verdict. This
directory is fenced `-text` in `.gitattributes` and excluded from every formatter.

**Nothing in this directory is ever edited.** Corrections go in `INTEGRITY.md` as sidecar
annotations, never into an archived artifact.

## Verification

Re-derivation reads this store alone and never re-queries any model. As of 2026-08-27,
from a cold clone of the committed copy:

- three receipts re-derive by the second route, 13 checks each, zero failed, zero
  unverifiable;
- the hash-chained ledger verifies, 3 rows, no chain problems;
- the RFC 6962 anchor root recomputes to
  `38ff95dbc6c4c31f6c55485fb1fdb71039db0cb8c671a02b4d95a33d60b956dd` — **bit-for-bit
  identical to the root recorded on the live day**.

Reproduce with `python scripts/rederive_incident.py`.

### Cloning this on Windows

Bodies are addressed `runs/<64-hex e_digest>/bodies/<64-hex body digest>` — 141
characters before any repository prefix, 177 as committed. On Windows that crosses
MAX_PATH (260) inside any clone root deeper than about 80 characters, and **`git clone`
then fails the checkout outright**:

```sh
git clone -c core.longpaths=true <url>      # required on Windows for deep clone roots
```

The digests are not shortened to fit. `canary/receipt/store.py` records the reason: a
content address truncated to suit a filesystem trades the property the whole design rests
on for a platform's convenience. The engine reads through the `\\?\\` long-path form
instead, and so does `scripts/rederive_incident.py`.

That checker did not, at first. In a deep clone it reported 59 of 74 files
**UNVERIFIABLE** while every one of them was present and byte-correct — defect F6,
self-caught by this very check. It was diagnosable only because the three-outcome rule
keeps *unverifiable* apart from *failed*: "could not check" and "checked, and wrong" point
at different suspects, and here the suspect was the checker.

## Instrument status — read before publishing anything from here

The generation exercised here is **`gen-1-c4`**, whose status in these artifacts is
`active`. Retirement and disclosure are **approved** (Core → Canary Response 011 §3) but
**not yet executed**, and the timing is launch week, with the rest of the packaging.

This repository is private, so committing the material here discloses nothing.
Publication is a separate act governed by four conditions: retirement recorded as a
visible instrument change with date and reason; the disclosed text pinned to its
ACTIVE-era digests; probes disclosed but generators never — `CANARY_GEN_SEED` and
anything permitting reconstruction of `gen-2-c4` or `gen-3-c4` stays secret; and the
timing set by the firing sequence.

`runs/*/suite.json` carries the full probe and document text. **Do not publish any file
from this directory until retirement has been executed and the leak check has run.**
