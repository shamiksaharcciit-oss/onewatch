"""The variance band: benign nondeterminism, measured once and then binding.

Ruled in Core -> Canary Response 004 §3. Three properties, and each closes a specific way
a monitor goes quietly useless:

1. **The band binds to the `(family, instrument_version)` pair.** A band measured under
   one instrument version is never carried to a run scored under another. This is not
   bookkeeping. Measured on this repository's own fixtures: across a same-config repeat,
   v1 shows nine per-probe verdict flips and v2/v3 show zero, and every one of the nine is
   a classifier defect rather than model variability. **The instrument does not measure
   the noise floor, it sets it.** A band calibrated under a defective instrument builds
   the defect in as expected noise, permanently -- and the un-tunability that protects the
   band from motivated widening would stand guard over the defect just as well.

2. **Measured zero is declared zero.** A non-zero band nobody measured is an alarm nobody
   will trust, and padding "for comfort" is motivated widening done pre-emptively. If the
   calibration runs show no movement, the band is zero and small real changes are visible.

3. **A band moves only through a rebaselining event**, with the full audit shape. It is
   inside `i_digest`, so a run under a widened band is a run under a different instrument
   and says so. There is no code path that adjusts a band after seeing a result.
"""
from __future__ import annotations

from dataclasses import dataclass

from canary.suite.probe import Arm


class BandViolation(ValueError):
    """A band used outside the pair it was calibrated for. Surfaced, never coerced."""


@dataclass(frozen=True, slots=True)
class VarianceBand:
    """Tolerated movement per arm, in whole probes, for one (family, version) pair.

    Integers, not rates. A band expressed as a fraction would need a denominator, and
    denominators legitimately move when probes retire -- so a fractional band silently
    changes width whenever the suite does.
    """

    family: str
    instrument_version: str
    #: arm value -> maximum tolerated absolute change in the failure numerator.
    per_arm: dict[str, int]
    #: `e_digest`s of the runs this band was measured from. Never a description.
    calibrated_from: tuple[str, ...]
    #: Free text: how it was measured, for the human reading the receipt.
    method: str

    def __post_init__(self) -> None:
        if not self.calibrated_from:
            raise ValueError(
                f"{self.family}@{self.instrument_version}: a band with no calibration runs "
                f"is an asserted band. Measure it or declare zero deliberately.")
        known = {a.value for a in Arm}
        unknown = set(self.per_arm) - known
        if unknown:
            raise ValueError(f"unknown arms in band: {sorted(unknown)}")
        for arm, width in self.per_arm.items():
            if not isinstance(width, int) or isinstance(width, bool):
                raise TypeError(
                    f"band width for {arm} must be an int (whole probes), got "
                    f"{type(width).__name__}. A fractional band changes width whenever "
                    f"the denominator does.")
            if width < 0:
                raise ValueError(f"band width for {arm} is negative: {width}")

    def width(self, arm: str) -> int:
        """Tolerated movement for an arm. Absent means zero: unmeasured is not permissive."""
        return self.per_arm.get(arm, 0)

    def check_applicable(self, family: str, instrument_version: str) -> None:
        """Refuse to apply this band outside the pair it was measured for (D2)."""
        if (family, instrument_version) != (self.family, self.instrument_version):
            raise BandViolation(
                f"band was calibrated for {self.family}@{self.instrument_version} and "
                f"cannot be applied to {family}@{instrument_version}. A band measured "
                f"under one instrument is not a band under another: the instrument sets "
                f"the noise floor it is measured against.")

    def as_canonical(self) -> dict:
        return {
            "family": self.family,
            "instrument_version": self.instrument_version,
            "per_arm": dict(sorted(self.per_arm.items())),
            "calibrated_from": list(self.calibrated_from),
            "method": self.method,
        }


def calibrate(family: str, instrument_version: str, runs, method: str) -> VarianceBand:
    """Measure a band from two or more runs of the SAME declared configuration.

    The band for each arm is the largest absolute movement observed in that arm's failure
    numerator across the calibration runs. With two runs of an unchanging system that is
    usually zero, and zero is what gets declared.

    This function is the *only* way a band is produced, and it takes evidence rather than
    a number, so there is no path by which a band is chosen instead of measured.
    """
    runs = list(runs)
    if len(runs) < 2:
        raise ValueError(
            "calibration needs at least two runs of the same declared configuration; "
            "one run measures nothing about variability")

    digests = {r.i_digest for r in runs}
    if len(digests) != 1:
        raise BandViolation(
            "calibration runs were scored under different instruments; a band measured "
            "across a mixed set would describe the instrument change, not the noise")

    versions = {r.instrument.version for r in runs}
    if versions != {instrument_version}:
        raise BandViolation(
            f"calibration runs are {sorted(versions)} but the band is declared for "
            f"{instrument_version}")

    buckets = {
        "answer_bearing": "wrong_abstention",
        "same_doc": "unsupported_answer_same_doc",
        "cross_doc": "unsupported_answer_cross_doc",
    }
    per_arm: dict[str, int] = {}
    for arm, bucket in buckets.items():
        numerators = [r.counts()[bucket]["numerator"] for r in runs]
        per_arm[arm] = max(numerators) - min(numerators)

    return VarianceBand(
        family=family,
        instrument_version=instrument_version,
        per_arm=per_arm,
        calibrated_from=tuple(r.e_digest for r in runs),
        method=method,
    )
