"""The change detector: `v = I(E_baseline, E_t)`.

Pure, float-free, and **it never touches a target**. Everything it needs is in the two
sealed runs. That is what makes a verdict re-derivable by a third party who has the
receipt and the evidence but no access to the model, the pipeline, or the vendor.

TWO QUESTIONS, TWO ANSWERS, NEVER RECONCILED (Core -> Canary Response 004 §5)
----------------------------------------------------------------------------
    the SEAL     answers *did anything change*      -- bytes, `e_digest`
    the VERDICTS answer *did behaviour change*      -- counts under a named instrument

The detector answers the **behaviour** question, by declaration. The seal comparison
rides beside it and is reported, never folded in. The canonical case for why: a prompt
edit that makes a model explain its abstentions changes every byte of every refusal and
moves not one verdict under v3. One number would be a lie in both directions --
"unchanged" hides that the output is visibly different, "changed" implies a behavioural
regression that did not happen. Collapsing them into one number is what a dashboard does.

WHY PER-PROBE AND NOT PER-COUNT
-------------------------------
Aggregates cancel. Measured on this repository's own fixtures, under v1, a same-config
repeat moved nine individual probes -- five one way, four the other -- and the aggregate
showed `+2 / -1`. A detector comparing only totals would have reported two units of drift
where nine probes actually moved, and would have been blind entirely had they cancelled
exactly. So the comparison is per probe first; the triples are reported because they are
what a receipt cites, not because they are what was compared.

WHAT THIS NEVER SAYS
--------------------
Which stage caused it. The canary sees an endpoint. It reports *that* behaviour changed
and *where behaviourally* -- which probes, which arm, which direction. Stage attribution
belongs to a different instrument and inferring it from endpoint behaviour would be a
guess, which is worse in a receipt than an absence.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from canary.acj import digest_obj
from canary.baseline.declare import Baseline
from canary.freezer.freeze import FrozenRun

DETECTOR_SCHEMA = "canary/detector/v1"

#: arm -> the counts bucket that arm's failures land in.
ARM_BUCKET = {
    "answer_bearing": "wrong_abstention",
    "same_doc": "unsupported_answer_same_doc",
    "cross_doc": "unsupported_answer_cross_doc",
}


class Outcome(str, Enum):
    """Three outcomes, held apart. `INCOMPARABLE` is never quietly `UNCHANGED`.

    The three-outcome rule applied to detection: *no change*, *change*, and *this
    comparison could not be made*. A detector that reported "unchanged" when it could not
    compare would be a monitor that goes silent exactly when something structural moved.
    """

    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    INCOMPARABLE = "INCOMPARABLE"


@dataclass(frozen=True, slots=True)
class ProbeDelta:
    """One probe whose verdict moved."""

    probe_id: str
    arm: str
    baseline_verdict: str
    current_verdict: str
    expect: str
    #: True when the move is baseline-conforming -> current-failing.
    regressed: bool

    def as_canonical(self) -> dict:
        return {
            "probe_id": self.probe_id,
            "arm": self.arm,
            "baseline_verdict": self.baseline_verdict,
            "current_verdict": self.current_verdict,
            "expect": self.expect,
            "regressed": self.regressed,
        }


@dataclass(frozen=True, slots=True)
class Comparison:
    """`v`: the change verdict. Canonicalisable, float-free, and self-explaining."""

    outcome: Outcome
    reasons: tuple[str, ...]
    probe_deltas: tuple[ProbeDelta, ...]
    count_deltas: dict
    band_applied: dict
    #: Did the RECEIVED BYTES change? The seal question, independent of instrument.
    bytes_changed: bool
    #: Did the whole sealed run change? True whenever bytes OR the reading of them moved.
    seal_changed: bool
    baseline_e_digest: str
    current_e_digest: str
    baseline_bodies_digest: str
    current_bodies_digest: str
    i_digest: str

    def as_canonical(self) -> dict:
        return {
            "schema": DETECTOR_SCHEMA,
            "outcome": self.outcome.value,
            "reasons": list(self.reasons),
            "n_probe_deltas": len(self.probe_deltas),
            "probe_deltas": [d.as_canonical() for d in self.probe_deltas],
            "count_deltas": self.count_deltas,
            "band": self.band_applied,
            "seal": {
                "baseline_e_digest": self.baseline_e_digest,
                "current_e_digest": self.current_e_digest,
                "baseline_bodies_digest": self.baseline_bodies_digest,
                "current_bodies_digest": self.current_bodies_digest,
                "bytes_changed": self.bytes_changed,
                "changed": self.seal_changed,
            },
            "i_digest": self.i_digest,
        }

    @property
    def v_digest(self) -> str:
        return digest_obj(self.as_canonical())


def _incomparable(reason: str, baseline: Baseline, current: FrozenRun) -> Comparison:
    return Comparison(
        outcome=Outcome.INCOMPARABLE,
        reasons=(reason,),
        probe_deltas=(),
        count_deltas={},
        band_applied={},
        bytes_changed=baseline.run.bodies_digest != current.bodies_digest,
        seal_changed=baseline.run.e_digest != current.e_digest,
        baseline_e_digest=baseline.run.e_digest,
        current_e_digest=current.e_digest,
        baseline_bodies_digest=baseline.run.bodies_digest,
        current_bodies_digest=current.bodies_digest,
        i_digest=current.i_digest,
    )


def compare(baseline: Baseline, current: FrozenRun) -> Comparison:
    """Compare a sealed run against a declared baseline. Never re-queries anything."""

    # --- Comparability first. A comparison across instruments is not a strict comparison;
    # it is two different measurements subtracted, and its result means nothing.
    if current.i_digest != baseline.run.i_digest:
        return _incomparable(
            f"instrument digests differ: baseline {baseline.run.i_digest[:16]}, current "
            f"{current.i_digest[:16]}. These runs were scored by different instruments, "
            f"so any difference between them is partly the instrument and cannot be "
            f"attributed to the system. Re-score one under the other's instrument, or "
            f"declare a new baseline.",
            baseline, current)

    if current.suite.digest != baseline.run.suite.digest:
        return _incomparable(
            f"probe suites differ: baseline {baseline.run.suite.digest[:16]}, current "
            f"{current.suite.digest[:16]}. The instrument is the suite.",
            baseline, current)

    try:
        baseline.band.check_applicable(current.instrument.family, current.instrument.version)
    except Exception as e:                                  # BandViolation
        return _incomparable(str(e), baseline, current)

    # --- Per probe. This is the comparison; the counts below are reporting.
    base_by_key = {(r.probe_id, r.arm): r for r in baseline.run.replies}
    curr_by_key = {(r.probe_id, r.arm): r for r in current.replies}

    missing = sorted(set(base_by_key) - set(curr_by_key))
    extra = sorted(set(curr_by_key) - set(base_by_key))
    if missing or extra:
        return _incomparable(
            f"probe sets do not align despite equal suite digests: {len(missing)} missing "
            f"from the current run, {len(extra)} unexpected. This is a defect, not a "
            f"change: surfaced rather than compared over.",
            baseline, current)

    deltas: list[ProbeDelta] = []
    for key in sorted(base_by_key):
        b, c = base_by_key[key], curr_by_key[key]
        if b.verdict != c.verdict:
            deltas.append(ProbeDelta(
                probe_id=b.probe_id,
                arm=b.arm,
                baseline_verdict=b.verdict,
                current_verdict=c.verdict,
                expect=b.expect,
                regressed=b.conforms and not c.conforms,
            ))

    # --- Counts as triples, never scalars. Denominators legitimately move when probes
    # retire, so a triple is compared whole and a bare rate is never computed.
    base_counts, curr_counts = baseline.run.counts(), current.counts()
    count_deltas: dict[str, dict] = {}
    for bucket in sorted(base_counts):
        bt, ct = base_counts[bucket], curr_counts[bucket]
        count_deltas[bucket] = {
            "baseline": bt,
            "current": ct,
            "numerator_delta": ct["numerator"] - bt["numerator"],
            "denominator_changed": bt["denominator"] != ct["denominator"],
        }

    # --- The band, applied per arm, as whole probes.
    band_applied: dict[str, dict] = {}
    reasons: list[str] = []
    exceeded = False
    for arm, bucket in sorted(ARM_BUCKET.items()):
        width = baseline.band.width(arm)
        moved = abs(count_deltas[bucket]["numerator_delta"])
        within = moved <= width
        band_applied[arm] = {"width": width, "observed_movement": moved, "within_band": within}
        if not within:
            exceeded = True
            reasons.append(
                f"{arm}: {bucket} moved by {moved} probe(s), exceeding the declared "
                f"band of {width}")

    for bucket, d in sorted(count_deltas.items()):
        if d["denominator_changed"]:
            reasons.append(
                f"{bucket}: denominator moved {d['baseline']['denominator']} -> "
                f"{d['current']['denominator']}; counts are compared as triples, and this "
                f"one is not a rate change")

    # A probe can move while its arm's total stays put -- compensating flips. The band is
    # about aggregate movement, so per-probe movement inside a satisfied band is reported
    # explicitly rather than absorbed: it is the difference between "nothing happened" and
    # "things happened that happened to cancel".
    if deltas and not exceeded:
        reasons.append(
            f"{len(deltas)} probe(s) changed verdict while every arm stayed within its "
            f"declared band; movement that cancels in aggregate is still movement")

    if exceeded or deltas:
        outcome = Outcome.CHANGED
    else:
        outcome = Outcome.UNCHANGED
        reasons.append("no probe changed verdict and no arm moved outside its band")

    return Comparison(
        outcome=outcome,
        reasons=tuple(reasons),
        probe_deltas=tuple(deltas),
        count_deltas=count_deltas,
        band_applied=band_applied,
        bytes_changed=baseline.run.bodies_digest != current.bodies_digest,
        seal_changed=baseline.run.e_digest != current.e_digest,
        baseline_e_digest=baseline.run.e_digest,
        current_e_digest=current.e_digest,
        baseline_bodies_digest=baseline.run.bodies_digest,
        current_bodies_digest=current.bodies_digest,
        i_digest=current.i_digest,
    )
