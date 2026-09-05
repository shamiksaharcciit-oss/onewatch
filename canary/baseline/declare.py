"""Baselines: declared, content-addressed, chained.

**A baseline is a specific run, declared by a person, and never a rolling average.**

The distinction is the product. A rolling baseline adapts to what it sees, so a system
that degrades slowly is always compared against its recently degraded self and never
reports anything. It is a monitor that forgets, and forgetting is the failure this
category exists to prevent. A declared baseline is *the validated system as of date X*
and stays that until somebody, on the record, says otherwise.

Rebaselining is therefore an event, not an adjustment. It keeps the chain: every baseline
names its predecessor, so the sequence of declarations is itself auditable and a reader
can ask *when did we start accepting this?* and get an answer with a reason attached.
"""
from __future__ import annotations

from dataclasses import dataclass

from canary.acj import digest_obj
from canary.baseline.band import BandViolation, VarianceBand
from canary.freezer.freeze import FrozenRun

BASELINE_SCHEMA = "canary/baseline/v1"


@dataclass(frozen=True, slots=True)
class Declaration:
    """Who declared this baseline, when, and why. Required, never defaulted.

    A baseline whose declaration is optional is a baseline that can appear without anyone
    having decided anything -- which is a rolling average with extra steps.
    """

    declared_by: str
    declared_at: str          # RFC3339 UTC, canonicalised by the caller
    reason: str
    #: For a rebaseline: what changed such that the old baseline no longer applies.
    supersedes_reason: str = ""

    def __post_init__(self) -> None:
        for field_name in ("declared_by", "declared_at", "reason"):
            if not str(getattr(self, field_name)).strip():
                raise ValueError(f"declaration requires {field_name}")

    def as_canonical(self) -> dict:
        return {
            "declared_by": self.declared_by,
            "declared_at": self.declared_at,
            "reason": self.reason,
            "supersedes_reason": self.supersedes_reason,
        }


@dataclass(frozen=True, slots=True)
class Baseline:
    """A declared run, its band, and its link to the baseline it replaced."""

    baseline_id: str
    run: FrozenRun
    band: VarianceBand
    declaration: Declaration
    #: The `baseline_id` this one supersedes; None only for the first in a chain.
    prev_baseline_id: str | None = None

    def __post_init__(self) -> None:
        # The band must belong to this run's instrument. Checked at declaration time so a
        # mismatched pair can never be sealed, rather than at comparison time when the
        # mistake is already in the record.
        self.band.check_applicable(self.run.instrument.family, self.run.instrument.version)
        if self.prev_baseline_id is not None and not self.declaration.supersedes_reason:
            raise ValueError(
                "a rebaseline must say what changed such that the previous baseline no "
                "longer applies. Silently accepting change as the new normal is the "
                "failure a declared baseline exists to prevent.")

    @property
    def family(self) -> str:
        return self.run.instrument.family

    @property
    def instrument_version(self) -> str:
        return self.run.instrument.version

    def as_canonical(self) -> dict:
        return {
            "schema": BASELINE_SCHEMA,
            "baseline_id": self.baseline_id,
            "prev_baseline_id": self.prev_baseline_id,
            "declaration": self.declaration.as_canonical(),
            "band": self.band.as_canonical(),
            "run": {
                "run_id": self.run.run_id,
                "e_digest": self.run.e_digest,
                "i_digest": self.run.i_digest,
                "suite_digest": self.run.suite.digest,
                "counts": self.run.counts(),
                "target": self.run.target_declaration,
            },
        }

    @property
    def digest(self) -> str:
        return digest_obj(self.as_canonical())


def declare(baseline_id: str, run: FrozenRun, band: VarianceBand,
            declaration: Declaration, prev: Baseline | None = None) -> Baseline:
    """Declare a run as the baseline. This is the only way a baseline comes into being.

    There is deliberately no `from_recent_runs()`, no `rolling()`, no `auto()`. The
    absence is the design: an API that offers a computed baseline will have one used.
    """
    if prev is not None:
        if prev.family != run.instrument.family:
            raise BandViolation(
                f"cannot rebaseline across families: {prev.family} -> "
                f"{run.instrument.family}. That is a new instrument, not a new baseline.")
    return Baseline(
        baseline_id=baseline_id,
        run=run,
        band=band,
        declaration=declaration,
        prev_baseline_id=prev.baseline_id if prev is not None else None,
    )


def chain(baselines: list[Baseline]) -> list[str]:
    """Check a rebaselining chain. Returns problems; empty means intact.

    Returns rather than raises: a broken chain is a finding to report in a receipt, not
    an exception to swallow at the call site.
    """
    problems: list[str] = []
    if not baselines:
        return ["empty chain"]
    if baselines[0].prev_baseline_id is not None:
        problems.append(
            f"chain starts at {baselines[0].baseline_id}, which claims a predecessor "
            f"({baselines[0].prev_baseline_id}) that is not in the chain")
    seen: set[str] = set()
    for i, b in enumerate(baselines):
        if b.baseline_id in seen:
            problems.append(f"baseline_id repeats: {b.baseline_id}")
        seen.add(b.baseline_id)
        if i == 0:
            continue
        expected = baselines[i - 1].baseline_id
        if b.prev_baseline_id != expected:
            problems.append(
                f"{b.baseline_id} names predecessor {b.prev_baseline_id!r}, but follows "
                f"{expected!r} in the chain")
    return problems
