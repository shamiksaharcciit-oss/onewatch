"""Instrument health: probe-family headroom, measured as a pure function over frozen bytes.

THE FINDING THIS EXISTS TO SERVE
--------------------------------
Paper-2 built the refusal-sentinel family when models produced 11–16 unsupported answers
per 30 on its shape. In 2026 three separately-designed generations of the same family each
produced **zero**. The family did not break. **The models improved, and took the
instrument's sensitivity to differences between them along with it.**

Core → Canary Response 008 §3 adopted the consequence: **probe-family headroom is a
maintained property, not a design-time decision.** A family calibrated against today's
models will silently stop discriminating, and the only way to find out is to re-measure
against the baseline and watch for saturation. This module is the canary for the canary.

THE TWO-STATE VOCABULARY, AND WHY IT IS NOT THREE
--------------------------------------------------
`DISCRIMINATING`  the baseline shows measurable room below the ceiling. A later run can
                  move in either direction, so the family can still detect a difference.
`SATURATED`       the baseline passes everything. There is no room below the ceiling for a
                  difference between two healthy models to appear in.

There is deliberately no `DEGRADED`, no `MARGINAL`, no score. A threshold between "enough
headroom" and "not quite enough" would be a number nobody measured, and the moment it
exists someone will tune it until a family they like passes. Whether the measured headroom
is *sufficient* is a judgement stated in a report by a person, not a comparison this
module performs.

**Saturation is a state to surface, never a silent fact.** A saturated family is not
broken — it is at maximum sensitivity to degradation and blind to differences above that
ceiling, which is a good property for a monitor and a poor one for a demo. What is
unacceptable is not knowing.

WHY THIS IS A PURE FUNCTION OVER A STORED RUN
----------------------------------------------
Defect F3: `calibrate_c4.py` measured headroom from a run it held in memory, printed the
number, and exited. Sixty live calls' worth of RECEIVED bytes were never written to disk
and are gone; the summary survives, and the evidence does not. Core → Canary Response 011
§4 put the lesson on the record as law:

    **Every live call's bytes are frozen from now on — calibration, health check,
    anything. A measurement whose bytes are gone is testimony about a measurement.**

So the acquisition of a run and the measurement over it are separated here. `measure()`
takes a `FrozenRun` and touches nothing else: it can be re-run from a store months later,
tested offline against recorded data, and re-derived by a third party. Nothing in this
module can reach a network, and nothing in it can decide to.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from canary.acj import digest_obj
from canary.freezer.freeze import FrozenRun


class HealthVerdict(str, Enum):
    """The two-state vocabulary. See the module docstring for why there is no third."""

    DISCRIMINATING = "discriminating"
    SATURATED = "saturated"


@dataclass(frozen=True, slots=True)
class Headroom:
    """One family's measured headroom against one baseline, and the verdict that follows.

    Everything here is an integer or a string. No rate is computed, stored or compared:
    denominators legitimately move when probes retire, which is exactly why comparing
    rates is a bug (E006's boundary, and the reason verdicts carry integer triples).
    """

    family: str
    instrument_version: str
    i_digest: str
    suite_digest: str
    baseline_model: str
    per_arm: dict[str, dict]
    total_failures: int
    total_probes: int
    verdict: HealthVerdict

    def as_canonical(self) -> dict:
        return {
            "baseline_model": self.baseline_model,
            "family": self.family,
            "i_digest": self.i_digest,
            "instrument_version": self.instrument_version,
            "per_arm": self.per_arm,
            "suite_digest": self.suite_digest,
            "total_failures": self.total_failures,
            "total_probes": self.total_probes,
            "verdict": self.verdict.value,
        }

    @property
    def digest(self) -> str:
        return digest_obj(self.as_canonical())

    @property
    def saturated(self) -> bool:
        return self.verdict is HealthVerdict.SATURATED

    def report(self) -> str:
        """The human-facing summary. States the finding; never states a judgement."""
        lines = [
            f"family       {self.family}@{self.instrument_version}  "
            f"suite={self.suite_digest[:16]}",
            f"baseline     {self.baseline_model}",
            f"{'arm':30} {'failures':>9} {'of':>4}",
        ]
        for arm in sorted(self.per_arm):
            counts = self.per_arm[arm]
            lines.append(f"{arm:30} {counts['numerator']:>9} {counts['denominator']:>4}")
        lines.append(f"headroom     {self.total_failures} failure(s) across "
                     f"{self.total_probes} probes")
        if self.saturated:
            lines.append(
                "SATURATED    the baseline passes everything; this family cannot detect a "
                "difference\n             between two healthy models. It remains at maximum "
                "sensitivity to\n             degradation. Whether that is acceptable is a "
                "judgement for a person.")
        else:
            lines.append(
                "DISCRIMINATING  the baseline has measurable room below the ceiling; a "
                "later run can\n                move in either direction.")
        return "\n".join(lines)


def measure(run: FrozenRun) -> Headroom:
    """Measure headroom from one frozen run. Pure: no I/O, no clock, no network.

    The run must be a **baseline-model** run. This function cannot check that — a
    `FrozenRun` records which model served it, not which model was *supposed* to — so the
    caller carries that obligation and `canary.health.check` enforces it. The reason the
    boundary matters is the one Response 007 §3 drew: a family tuned until a particular
    swap shows up is an instrument fitted to its finding, and consulting the switch model
    during a health measurement is the first step down that road.

    This does **not** tune toward a target. It measures, reports, and stops.
    """
    counts = run.counts()
    total_failures = sum(bucket["numerator"] for bucket in counts.values())
    total_probes = len(run.replies)
    if total_probes == 0:
        raise ValueError(
            "a run with no replies measures no headroom; reporting DISCRIMINATING or "
            "SATURATED over an empty run would be a verdict about nothing")

    verdict = (HealthVerdict.SATURATED if total_failures == 0
               else HealthVerdict.DISCRIMINATING)
    declaration = run.instrument_declaration()["detector"]
    return Headroom(
        family=declaration["family"],
        instrument_version=declaration["version"],
        i_digest=run.i_digest,
        suite_digest=run.suite.digest,
        baseline_model=run.target_declaration["served_model"],
        per_arm={name: {"numerator": bucket["numerator"],
                        "denominator": bucket["denominator"]}
                 for name, bucket in counts.items()},
        total_failures=total_failures,
        total_probes=total_probes,
        verdict=verdict,
    )
