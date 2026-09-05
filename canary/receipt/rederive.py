"""The second route: re-derive a receipt from disk alone.

**This module must not share state with the run that produced the receipt.** It takes a
store path and a receipt id. It reads bytes. It recomputes. Nothing is passed in from the
emitting process, and nothing here calls a target.

That constraint is the whole point. Route one is the engine computing a verdict while it
has the run in memory. Route two is a stranger with a directory. If the two agree, the
receipt means what it says; if only route one can produce the answer, the receipt is a
claim about a process nobody else can run.

THE CHAIN OF RE-DERIVATION, IN ORDER
------------------------------------
1. The receipt's own id, over its canonical bytes.
2. Every stored body against the digest it is filed under.
3. Every reply's verdict, **re-classified from the raw bytes** by the declared
   instrument version -- not read back from the run file.
4. The counts, recomputed from those verdicts.
5. `e_digest`, over the rebuilt run structure.
6. The comparison, re-run from the two rebuilt runs.
7. `v_digest`, over the recomputed comparison.

Step 3 is the one that matters most and the easiest to fake by accident: re-reading the
recorded verdict and confirming it equals itself proves nothing at all. The verdict is
recomputed from the evidence, so a receipt whose verdict does not follow from its bytes
fails here.

THE THREE-OUTCOME RULE APPLIES TO THIS VERIFIER
-----------------------------------------------
*Verified*, *failed*, and *unverifiable* are distinct. A missing body is unverifiable, not
a pass and not a mismatch; it is reported as its own kind of problem, because "we could not
check" and "we checked and it was wrong" call for different responses from a reader.
"""
from __future__ import annotations

import json
from pathlib import Path

from canary.acj import canonical_bytes, digest_bytes, digest_obj
from canary.baseline.band import VarianceBand
from canary.baseline.declare import Baseline, Declaration
from canary.detector.compare import compare
from canary.freezer.freeze import FrozenReply, FrozenRun
from canary.receipt.emit import check_receipt_id
from canary.receipt.store import Store, StoreError
from canary.suite.probe import Arm, Probe, ProbeSuite
from canary.suite.refusal import RefusalInstrument


class Rederivation:
    """The outcome of a second-route check. Problems are kept in three kinds."""

    def __init__(self) -> None:
        self.failed: list[str] = []          # checked, and wrong
        self.unverifiable: list[str] = []    # could not be checked at all
        self.checked: list[str] = []         # what was actually confirmed

    @property
    def ok(self) -> bool:
        return not self.failed and not self.unverifiable

    def report(self) -> str:
        lines = [f"checked: {len(self.checked)}"]
        for label, items in (("FAILED", self.failed), ("UNVERIFIABLE", self.unverifiable)):
            for item in items:
                lines.append(f"{label}: {item}")
        return "\n".join(lines)


def _rebuild_suite(store: Store, e_digest: str) -> ProbeSuite:
    raw = store.read_bytes(store.run_dir(e_digest) / "suite.json")
    d = json.loads(raw.decode("utf-8"))
    probes = tuple(
        Probe(probe_id=p["probe_id"], family=p["family"], arm=Arm(p["arm"]), query=p["query"])
        for p in d["probes"]
    )
    return ProbeSuite(suite_id=d["suite_id"], version=d["version"], probes=probes)


def _rebuild_run(store: Store, e_digest: str, result: Rederivation,
                 label: str) -> FrozenRun | None:
    """Rebuild a sealed run from disk, re-classifying every reply from its raw bytes."""
    try:
        run_json = store.get_run_json(e_digest)
        suite = _rebuild_suite(store, e_digest)
    except (StoreError, OSError, KeyError, ValueError) as e:
        result.unverifiable.append(f"{label}: cannot read stored run {e_digest[:16]}: {e}")
        return None

    declared_suite_digest = run_json["instrument"]["suite"]["digest"]
    if suite.digest != declared_suite_digest:
        result.failed.append(
            f"{label}: stored suite hashes to {suite.digest[:16]}, but the run declares "
            f"{declared_suite_digest[:16]}")
        return None
    result.checked.append(f"{label}: suite digest")

    version = run_json["instrument"]["detector"]["version"]
    instrument = RefusalInstrument(version)

    replies: list[FrozenReply] = []
    bodies: dict[tuple[str, str], bytes] = {}
    for row in run_json["replies"]:
        key = (row["probe_id"], row["arm"])
        try:
            body = store.get_body(e_digest, row["body_sha256"])
        except StoreError as e:
            result.unverifiable.append(f"{label}: {key[0]}::{key[1]}: {e}")
            return None

        if len(body) != row["n_bytes"]:
            result.failed.append(
                f"{label}: {key[0]}::{key[1]}: stored body is {len(body)} bytes, run "
                f"declares {row['n_bytes']}")
            return None

        # THE re-derivation: the verdict is recomputed from the bytes, never read back.
        try:
            recomputed = instrument.classify(body.decode("utf-8")).value
        except UnicodeDecodeError as e:
            result.unverifiable.append(
                f"{label}: {key[0]}::{key[1]}: body is not valid UTF-8 and cannot be "
                f"classified: {e}")
            return None

        if recomputed != row["verdict"]:
            result.failed.append(
                f"{label}: {key[0]}::{key[1]}: instrument {version} reads the stored bytes "
                f"as {recomputed}, but the run recorded {row['verdict']}")
            return None

        conforms = recomputed == row["expect"]
        if conforms != row["conforms"]:
            result.failed.append(
                f"{label}: {key[0]}::{key[1]}: conformance recomputes to {conforms}, "
                f"recorded {row['conforms']}")
            return None

        bodies[key] = body
        replies.append(FrozenReply(
            probe_id=row["probe_id"], arm=row["arm"], body_digest=row["body_sha256"],
            n_bytes=row["n_bytes"], provenance=row["provenance"],
            served_model=row["served_model"], verdict=recomputed, expect=row["expect"],
            conforms=conforms, source=row["source"],
        ))

    result.checked.append(f"{label}: {len(replies)} bodies re-classified from raw bytes")

    run = FrozenRun(
        run_id=run_json["run_id"], suite=suite, instrument=instrument,
        target_declaration=run_json["target"], replies=tuple(replies), bodies=bodies,
    )

    if run.e_digest != e_digest:
        result.failed.append(
            f"{label}: rebuilt run hashes to {run.e_digest[:16]}, filed as {e_digest[:16]}")
        return None
    result.checked.append(f"{label}: e_digest")

    if digest_obj(run.counts()) != digest_obj(run_json["counts"]):
        result.failed.append(f"{label}: recomputed counts differ from the sealed counts")
        return None
    result.checked.append(f"{label}: counts")
    return run


def _rebuild_baseline(receipt: dict, run: FrozenRun) -> Baseline:
    b = receipt["baseline"]
    band = VarianceBand(
        family=b["band"]["family"],
        instrument_version=b["band"]["instrument_version"],
        per_arm=dict(b["band"]["per_arm"]),
        calibrated_from=tuple(b["band"]["calibrated_from"]),
        method=b["band"]["method"],
    )
    return Baseline(
        baseline_id=b["baseline_id"], run=run, band=band,
        declaration=Declaration(
            declared_by=b["declared_by"], declared_at=b["declared_at"],
            reason="(re-derived from receipt)",
            supersedes_reason="(re-derived)" if b["prev_baseline_id"] else "",
        ),
        prev_baseline_id=b["prev_baseline_id"],
    )


def rederive(store_root: Path, receipt_id: str) -> Rederivation:
    """Re-derive one receipt from a store directory. Takes nothing else."""
    result = Rederivation()
    store = Store(Path(store_root))

    try:
        receipt = store.get_receipt(receipt_id)
    except (StoreError, json.JSONDecodeError) as e:
        result.unverifiable.append(f"receipt {receipt_id}: {e}")
        return result

    problems = check_receipt_id(receipt)
    if problems:
        result.failed.extend(problems)
        return result
    result.checked.append("receipt_id over canonical bytes")

    if receipt["schema"] != "canary/receipt/v1":
        result.unverifiable.append(f"unknown receipt schema: {receipt['schema']!r}")
        return result

    baseline_run = _rebuild_run(store, receipt["baseline_e_digest"], result, "baseline")
    current_run = _rebuild_run(store, receipt["e_digest"], result, "current")
    if baseline_run is None or current_run is None:
        return result

    if current_run.i_digest != receipt["i_digest"]:
        result.failed.append(
            f"i_digest mismatch: rebuilt instrument hashes to "
            f"{current_run.i_digest[:16]}, receipt declares {receipt['i_digest'][:16]}")
        return result
    result.checked.append("i_digest")

    if digest_obj(sorted(receipt["trust"]["set"])) != receipt["t_digest"]:
        result.failed.append("t_digest does not match the recorded trust set")
        return result
    result.checked.append("t_digest")

    baseline = _rebuild_baseline(receipt, baseline_run)
    recomputed = compare(baseline, current_run)

    if recomputed.v_digest != receipt["v_digest"]:
        result.failed.append(
            f"RE-DERIVATION FAILED: comparing the stored evidence produces v_digest "
            f"{recomputed.v_digest[:16]}, receipt declares {receipt['v_digest'][:16]}")
        return result
    result.checked.append("v_digest: the comparison re-derives from the stored evidence")

    if canonical_bytes(recomputed.as_canonical()) != canonical_bytes(receipt["verdict"]):
        result.failed.append(
            "the recomputed verdict digests equal but its canonical bytes differ; this "
            "should be impossible and indicates a digest collision or a defect")
        return result
    result.checked.append("verdict canonical bytes")

    expected_id = digest_bytes(canonical_bytes(
        {k: v for k, v in receipt.items() if k != "receipt_id"}))
    if expected_id != receipt["receipt_id"]:        # pragma: no cover - checked above
        result.failed.append("receipt_id drifted during re-derivation")
    return result
