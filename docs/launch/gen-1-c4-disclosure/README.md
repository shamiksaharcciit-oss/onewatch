# gen-1-c4 — disclosed probe set

`gen-1-c4` was retired to permit this disclosure; see `docs/launch/instrument-history.md` for the dated record.

## What this is

`suite.json` is the probe set used against a live endpoint in the C4 phase of
2026-08-22 — the run that produced [the incident of record](../../evidence/c4-incident-of-record/):
the vendor served a different model, and the validated behaviour did not move.

## Why you can believe it is the same instrument

You do not have to believe it. Check it:

```sh
sha256sum suite.json
# e9cd77076c01a4b0f11a86d5d9051670c0ae96bb575be9818b2c60f9737a3806
```

That digest is `generation_digest` inside 3 receipts that were sealed,
hash-chained and Merkle-anchored **before these probes were ever published**. A
cleaned-up or reconstructed probe set would not reproduce it. The receipts commit to the
instrument; this file merely reveals it.

Re-derive the receipts themselves with `python scripts/rederive_incident.py` — it reads
frozen bytes and never queries a model.

## What is not here, and why

The **seed** that generated this set is not published, and neither is anything that would
let you rebuild the generations still in service. Probes are disclosed at retirement;
generators never are. That is the resolution the design rests on: the seed is the secret,
the digest is the public commitment, and rotation is a visible instrument change rather
than silent drift.

## The honest limit

This probe set is **retired**: it may never probe a live system again, and
`assert_may_probe_live()` enforces that. A system that has seen the probes can pass them
without behaving well, so a passing result from a published set proves nothing. That is
why disclosure follows retirement instead of preceding it.
