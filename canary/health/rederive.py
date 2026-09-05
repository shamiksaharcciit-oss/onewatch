"""Re-derive a health receipt from the store alone. The second route, for instrument health.

A health receipt that could only be produced by the process that measured it would be a
claim about a process nobody else can run — precisely what this pillar refuses for change
receipts, and there is no reason instrument health gets an exemption. Sixty live calls once
produced a headroom number whose evidence is gone (F3); this module is the guarantee that
it cannot happen again in a way anyone would accept.

THE CHAIN OF RE-DERIVATION
--------------------------
1. The receipt's own id, over its canonical bytes.
2. Every stored body against the digest it is filed under.
3. Every reply's verdict, **re-classified from the raw bytes** by the declared instrument
   — not read back from the run file.
4. The headroom, **recomputed** from those verdicts by the same pure function.
5. `h_digest`, over the recomputed measurement.
6. The two-state verdict, which must follow from the recomputed totals.

Step 6 is the one worth naming. Reading `verdict` back and confirming it equals itself
proves nothing; a receipt that says `discriminating` over a run with zero failures is
either a bug or a lie, and it fails here either way.

THE THREE-OUTCOME RULE APPLIES TO THIS VERIFIER TOO
----------------------------------------------------
*Verified*, *failed* and *unverifiable* stay apart. A missing body is not a mismatch — it
is "we could not check", which points at the environment rather than at the evidence. That
distinction is not theoretical here: it is what stopped 59 present-and-correct files from
being read as a corrupted launch deliverable (N-C003).
"""
from __future__ import annotations

from pathlib import Path

from canary.health.headroom import HealthVerdict, measure
from canary.health.receipt import check_health_receipt_id
from canary.receipt.rederive import Rederivation, _rebuild_run
from canary.receipt.store import Store, StoreError


def rederive_health(store_root: Path, receipt_id: str) -> Rederivation:
    """Recompute a health receipt from bytes on disk. Never queries a target.

    The run is rebuilt by `canary.receipt.rederive._rebuild_run`, deliberately reusing the
    change receipt's path rather than carrying a second copy of it. That function already
    re-classifies every reply from its raw bytes, checks each body against its filed
    digest and its recorded length, and refuses a run whose counts or `e_digest` do not
    recompute. A parallel implementation here would start identical and drift, and the
    weaker of the two would be the one nobody noticed had stopped checking something.
    """
    result = Rederivation()
    store = Store(store_root)

    try:
        receipt = store.get_receipt(receipt_id)
    except (StoreError, OSError) as exc:
        result.unverifiable.append(f"receipt {receipt_id[:16]} not readable: {exc}")
        return result

    problems = check_health_receipt_id(receipt)
    if problems:
        result.failed.extend(problems)
    else:
        result.checked.append("receipt_id recomputes over the receipt's canonical bytes")

    run = _rebuild_run(store, receipt.get("e_digest", ""), result, "run")
    if run is None:
        return result

    recomputed = measure(run)
    if recomputed.digest != receipt.get("h_digest"):
        result.failed.append(
            f"h_digest mismatch: receipt cites {str(receipt.get('h_digest'))[:16]}, "
            f"re-measured headroom is {recomputed.digest[:16]}")
    else:
        result.checked.append("h_digest recomputes over the re-measured headroom")

    # The verdict must FOLLOW from the recomputed totals, not merely equal what was
    # recorded. Reading the field back and confirming it equals itself proves nothing; a
    # receipt claiming DISCRIMINATING over a run with zero failures is a lie its own
    # evidence refutes, and only recomputation catches it.
    implied = (HealthVerdict.SATURATED if recomputed.total_failures == 0
               else HealthVerdict.DISCRIMINATING)
    if receipt.get("verdict") != implied.value:
        result.failed.append(
            f"verdict {receipt.get('verdict')!r} does not follow from the evidence: "
            f"{recomputed.total_failures} failure(s) across {recomputed.total_probes} "
            f"probes implies {implied.value!r}")
    else:
        result.checked.append(
            f"verdict {implied.value!r} follows from {recomputed.total_failures} "
            f"failure(s) across {recomputed.total_probes} probes")

    return result
