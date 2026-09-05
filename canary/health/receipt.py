"""The instrument-health receipt: a real receipt, in the same chain, under X-8.

Core → Canary Response 011 §4 ruled Q09, and the ruling turns on why a health measurement
qualifies at all:

    A health run **is** a run: responses frozen E10-verbatim, one quantise boundary,
    verdict a pure function of frozen bytes — therefore recomputable, therefore a receipt
    in the full post-amendment sense.

It carries a **distinct schema id** because it answers a different question. A change
receipt asks *did behaviour move against a baseline* and has the shape
`v = I(E_baseline, E_t)`. A health receipt asks *can this instrument still see anything*,
and has only one run in it. Emitting the second under the first's schema would hand a
verifier a receipt whose `baseline_e_digest` is meaningless and whose absence of a
comparison looks like a truncation.

It chains into the **same ledger** and anchors under the **same** X-8 rule. One ledger,
one anchor, one place a customer looks — an instrument-health record kept in a separate
chain would be the record nobody checks, and its whole purpose is being checked on a
schedule.

WHAT IT COMMITS TO
------------------
    h_digest    the headroom measurement: per-arm integers, totals, and the verdict
    e_digest    the run those numbers came from, content-addressed
    i_digest    the instrument whose sensitivity is being measured
    baseline    which baseline this family is maintained against
    receipt_id  a digest over everything above

`verdict` is `discriminating` or `saturated` and nothing else. **Saturation is surfaced as
an instrument-health state, never a silent fact** — that is the whole product claim here,
and a receipt that recorded it as a footnote would not be making it.
"""
from __future__ import annotations

import unicodedata
from datetime import datetime, timezone

from canary.acj import canon_datetime, canonical_bytes, digest_bytes, digest_obj
from canary.freezer.freeze import FrozenRun
from canary.health.headroom import Headroom

HEALTH_RECEIPT_SCHEMA = "canary/health-receipt/v1"


def build_health_receipt(headroom: Headroom, run: FrozenRun, baseline_id: str,
                         trust: list[str] | None = None,
                         created_at: datetime | None = None) -> dict:
    """Assemble the envelope. Pure: no I/O, and no clock unless one is not supplied.

    `created_at` is a parameter for the same reason it is one on the change receipt: a
    timestamp read from the clock inside this function would make every receipt
    unreproducible, and an unreproducible receipt is not a receipt.
    """
    trust = sorted(trust or [])
    receipt = {
        "schema": HEALTH_RECEIPT_SCHEMA,
        "created_at": canon_datetime(created_at or datetime.now(timezone.utc)),
        "unicode_version": unicodedata.unidata_version,
        "baseline_id": baseline_id,
        "evidence": {"run_ref": f"runs/{run.e_digest}"},
        "instrument": run.instrument_declaration(),
        "target": run.target_declaration,
        "headroom": headroom.as_canonical(),
        "trust": {"set": trust},
        "e_digest": run.e_digest,
        "i_digest": run.i_digest,
        "h_digest": headroom.digest,
        "t_digest": digest_obj(trust),
        "verdict": headroom.verdict.value,
        "anchor_ref": None,
    }
    receipt["receipt_id"] = digest_bytes(canonical_bytes(receipt))
    return receipt


def health_receipt_body(receipt: dict) -> dict:
    """The receipt minus its own id — the preimage `receipt_id` commits to."""
    return {k: v for k, v in receipt.items() if k != "receipt_id"}


def check_health_receipt_id(receipt: dict) -> list[str]:
    """Recompute the id. A receipt whose id does not match its content is not a receipt."""
    recomputed = digest_bytes(canonical_bytes(health_receipt_body(receipt)))
    if recomputed != receipt.get("receipt_id"):
        return [f"receipt_id mismatch: recorded {receipt.get('receipt_id')}, "
                f"recomputed {recomputed}"]
    return []
