"""The receipt envelope: what a third party is handed.

Shaped on the vendored rederivable-manifest v3 envelope -- same discipline, same digest
primitives, same separation of manifest from evidence. It carries its own schema id
rather than `rederivable-manifest/1`, and the reason is worth stating: that schema's
verifier re-derives through a registry of *its* instrument specs, and the canary's
instrument is not in it. Emitting a manifest whose declared verifier cannot re-derive it
would fail with "unknown instrument", which reads like tampering. A distinct schema with
a verifier that genuinely re-derives is the honest version of the same idea.

WHAT THE RECEIPT CARRIES, AND WHY EACH PIECE
--------------------------------------------
    e_digest / baseline_e_digest   the two runs, content-addressed. *Did anything change*
    i_digest                       the instrument. A magnitude may not travel without it
    t_digest                       the trust set: what had to be believed
    v_digest                       the change verdict. *Did behaviour change*
    receipt_id                     digest over everything above
    anchor_ref                     filled in later, and only after re-verification (X-8)

**The seal question and the behaviour question are both present and never reconciled**
(Core -> Canary Response 004 §5). `seal.changed` can be true while `outcome` is
`UNCHANGED`: bytes moved, behaviour did not. One number would be a lie in both directions.

A NO-CHANGE RECEIPT IS THE PRODUCT
----------------------------------
`UNCHANGED` is not an empty result. *Behaviourally unchanged since validation, under this
named instrument, against this declared baseline, anchored, on schedule* is the thing a
regulated buyer needs and cannot otherwise get. The emitter treats it identically to a
change: same envelope, same chain, same anchor.
"""
from __future__ import annotations

import unicodedata
from datetime import datetime, timezone

from canary.acj import canon_datetime, canonical_bytes, digest_bytes, digest_obj
from canary.baseline.declare import Baseline
from canary.detector.compare import Comparison
from canary.freezer.freeze import FrozenRun

RECEIPT_SCHEMA = "canary/receipt/v1"


def build_receipt(baseline: Baseline, current: FrozenRun, comparison: Comparison,
                  trust: list[str] | None = None,
                  created_at: datetime | None = None) -> dict:
    """Assemble the envelope. Pure: no I/O, no clock unless one is not supplied.

    `created_at` is a parameter so a caller can produce a byte-identical receipt when
    re-deriving. A timestamp read from the clock inside this function would make every
    receipt unreproducible, which would defeat the entire point.
    """
    trust = sorted(trust or [])
    stamp = canon_datetime(created_at or datetime.now(timezone.utc))

    receipt = {
        "schema": RECEIPT_SCHEMA,
        "created_at": stamp,
        # Recorded because instrument operations that consult the Unicode Character
        # Database can differ between runtimes. The canary's classifier deliberately does
        # not casefold, so this should never matter -- and it is recorded anyway, so that
        # if it ever does, the mismatch is diagnosable rather than silent.
        "unicode_version": unicodedata.unidata_version,
        "baseline": {
            "baseline_id": baseline.baseline_id,
            "digest": baseline.digest,
            "prev_baseline_id": baseline.prev_baseline_id,
            "declared_by": baseline.declaration.declared_by,
            "declared_at": baseline.declaration.declared_at,
            "band": baseline.band.as_canonical(),
        },
        "evidence": {
            "baseline_ref": f"runs/{baseline.run.e_digest}",
            "current_ref": f"runs/{current.e_digest}",
        },
        "instrument": current.instrument_declaration(),
        "trust": {"set": trust},
        "verdict": comparison.as_canonical(),
        "target": current.target_declaration,
        "baseline_e_digest": baseline.run.e_digest,
        "e_digest": current.e_digest,
        "i_digest": current.i_digest,
        "t_digest": digest_obj(trust),
        "v_digest": comparison.v_digest,
        "anchor_ref": None,
    }
    receipt["receipt_id"] = digest_bytes(canonical_bytes(receipt))
    return receipt


def receipt_body(receipt: dict) -> dict:
    """The receipt minus its own id -- the preimage `receipt_id` commits to."""
    return {k: v for k, v in receipt.items() if k != "receipt_id"}


def check_receipt_id(receipt: dict) -> list[str]:
    """Recompute the id. A receipt whose id does not match its content is not a receipt."""
    recomputed = digest_bytes(canonical_bytes(receipt_body(receipt)))
    if recomputed != receipt.get("receipt_id"):
        return [f"receipt_id mismatch: recorded {receipt.get('receipt_id')}, "
                f"recomputed {recomputed}"]
    return []
