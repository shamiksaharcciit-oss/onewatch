"""Baselines and variance bands: declared, bound to an instrument, chained."""
from __future__ import annotations

import pytest

from canary.baseline import (
    BandViolation,
    Declaration,
    VarianceBand,
    calibrate,
    chain,
    declare,
)
from canary.freezer import freeze_run
from canary.suite.refusal import RefusalInstrument
from canary.target import Change, MockConfig, MockTarget, suite_from_cycle
from canary.target.mock import REPEAT_CYCLE

SUITE = suite_from_cycle()


def _run(run_id="r", cfg=None, version="v3", suite=SUITE):
    return freeze_run(run_id, suite, MockTarget(config=cfg or MockConfig()),
                      instrument=RefusalInstrument(version))


def _decl(**kw):
    base = dict(declared_by="tester", declared_at="2026-08-21T12:00:00Z",
                reason="the validated system as of this date")
    base.update(kw)
    return Declaration(**base)


# --------------------------------------------------------------- calibrating a band

def test_the_band_is_measured_from_runs_never_chosen():
    """`calibrate` takes evidence, not a number. There is no path to a picked band."""
    base = _run("a")
    repeat = freeze_run("b", suite_from_cycle(REPEAT_CYCLE),
                        MockTarget(config=MockConfig(repeat=True)),
                        instrument=RefusalInstrument("v3"))
    band = calibrate("refusal-sentinel", "v3", [base, repeat], method="repeat pair")
    assert band.calibrated_from == (base.e_digest, repeat.e_digest)


def test_measured_zero_is_declared_zero():
    """D2. Under v3 the same-config repeat moves nothing, so the band is zero.

    A non-zero band nobody measured is an alarm nobody will trust, and padding it "for
    comfort" is motivated widening done pre-emptively -- its only effect is to hide small
    real changes.
    """
    repeat = freeze_run("b", suite_from_cycle(REPEAT_CYCLE),
                        MockTarget(config=MockConfig(repeat=True)),
                        instrument=RefusalInstrument("v3"))
    band = calibrate("refusal-sentinel", "v3", [_run("a"), repeat], method="repeat pair")
    assert band.per_arm == {"answer_bearing": 0, "same_doc": 0, "cross_doc": 0}


def test_the_same_pair_under_v1_measures_a_wider_band():
    """The instrument sets the noise floor -- the reason D2 binds the band to a version.

    v1 misreads the trailing-period abstention, so a repeat of an unchanging system looks
    like movement. A band calibrated here would declare that defect to be expected noise,
    permanently, and would then be blind to a real change of the same size.
    """
    a = _run("a", version="v1")
    b = freeze_run("b", suite_from_cycle(REPEAT_CYCLE),
                   MockTarget(config=MockConfig(repeat=True)),
                   instrument=RefusalInstrument("v1"))
    band = calibrate("refusal-sentinel", "v1", [a, b], method="repeat pair")
    assert band.per_arm["same_doc"] > 0 or band.per_arm["cross_doc"] > 0, (
        "v1's repeat pair no longer shows movement; the finding behind D2 has changed")


def test_calibration_across_instruments_is_refused():
    with pytest.raises(BandViolation, match="different instruments"):
        calibrate("refusal-sentinel", "v3", [_run("a", version="v3"),
                                             _run("b", version="v1")], method="mixed")


def test_one_run_measures_nothing_about_variability():
    with pytest.raises(ValueError, match="at least two runs"):
        calibrate("refusal-sentinel", "v3", [_run("a")], method="single")


def test_a_band_with_no_calibration_runs_is_refused():
    with pytest.raises(ValueError, match="asserted band"):
        VarianceBand(family="f", instrument_version="v3", per_arm={},
                     calibrated_from=(), method="vibes")


def test_a_fractional_band_is_refused():
    """A band expressed as a fraction silently changes width when the suite does."""
    with pytest.raises(TypeError, match="whole probes"):
        VarianceBand(family="f", instrument_version="v3", per_arm={"same_doc": 0.1},
                     calibrated_from=("x",), method="m")


def test_an_unmeasured_arm_is_zero_not_permissive():
    band = VarianceBand(family="f", instrument_version="v3", per_arm={},
                        calibrated_from=("x",), method="m")
    assert band.width("same_doc") == 0


# ------------------------------------------------------- the band binds to the pair

def test_a_band_cannot_be_applied_to_another_instrument_version():
    """D2, the whole point: a band measured under one version is not a band under another."""
    band = VarianceBand(family="refusal-sentinel", instrument_version="v1",
                        per_arm={"same_doc": 2}, calibrated_from=("x",), method="m")
    with pytest.raises(BandViolation, match="cannot be applied"):
        band.check_applicable("refusal-sentinel", "v3")


def test_declaring_a_baseline_with_a_mismatched_band_fails_at_declaration_time():
    """Caught when the baseline is sealed, not when a comparison is attempted -- by then
    the mistake would already be in the record."""
    v1_band = VarianceBand(family="refusal-sentinel", instrument_version="v1",
                           per_arm={"same_doc": 2}, calibrated_from=("x",), method="m")
    with pytest.raises(BandViolation):
        declare("b1", _run(version="v3"), v1_band, _decl())


# ------------------------------------------------------------- declared, not learned

def test_there_is_no_api_that_computes_a_baseline_from_recent_runs():
    """The absence is the design: an API offering a rolling baseline will have one used.

    A monitor that silently accepts change as the new normal is a monitor that forgets.
    """
    import canary.baseline as mod
    offenders = [n for n in dir(mod)
                 if any(w in n.lower() for w in ("rolling", "auto", "recent", "average"))]
    assert not offenders, f"a computed-baseline API has appeared: {offenders}"


def test_a_declaration_requires_who_when_and_why():
    for missing in ("declared_by", "declared_at", "reason"):
        with pytest.raises(ValueError, match=missing):
            _decl(**{missing: "  "})


def test_a_rebaseline_must_say_what_changed():
    band = calibrate("refusal-sentinel", "v3",
                     [_run("a"), freeze_run("b", suite_from_cycle(REPEAT_CYCLE),
                                            MockTarget(config=MockConfig(repeat=True)),
                                            instrument=RefusalInstrument("v3"))],
                     method="repeat pair")
    first = declare("b1", _run("a"), band, _decl())
    with pytest.raises(ValueError, match="what changed"):
        declare("b2", _run("c", cfg=MockConfig(changes=(Change.MODEL_SWAP,))), band,
                _decl(), prev=first)


def test_a_rebaseline_with_a_reason_is_accepted_and_keeps_the_chain():
    band = calibrate("refusal-sentinel", "v3",
                     [_run("a"), freeze_run("b", suite_from_cycle(REPEAT_CYCLE),
                                            MockTarget(config=MockConfig(repeat=True)),
                                            instrument=RefusalInstrument("v3"))],
                     method="repeat pair")
    first = declare("b1", _run("a"), band, _decl())
    second = declare("b2", _run("c"), band,
                     _decl(supersedes_reason="model provider migration, signed off"),
                     prev=first)
    assert second.prev_baseline_id == "b1"
    assert chain([first, second]) == []


def test_a_broken_chain_is_reported_not_raised():
    """A broken chain is a finding a receipt should be able to state."""
    band = VarianceBand(family="refusal-sentinel", instrument_version="v3",
                        per_arm={}, calibrated_from=("x",), method="m")
    a = declare("b1", _run("a"), band, _decl())
    orphan = declare("b3", _run("c"), band,
                     _decl(supersedes_reason="r"),
                     prev=declare("b2", _run("b"), band, _decl()))
    problems = chain([a, orphan])
    assert problems and "predecessor" in problems[0]


def test_the_baseline_digest_covers_the_band_and_the_declaration():
    band_a = VarianceBand(family="refusal-sentinel", instrument_version="v3",
                          per_arm={"same_doc": 0}, calibrated_from=("x",), method="m")
    band_b = VarianceBand(family="refusal-sentinel", instrument_version="v3",
                          per_arm={"same_doc": 1}, calibrated_from=("x",), method="m")
    run = _run("a")
    assert declare("b1", run, band_a, _decl()).digest != \
           declare("b1", run, band_b, _decl()).digest
    assert declare("b1", run, band_a, _decl()).digest != \
           declare("b1", run, band_a, _decl(declared_by="somebody else")).digest
