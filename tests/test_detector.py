"""The change detector: comparability, per-probe comparison, and the two questions."""
from __future__ import annotations

import pytest

from canary.baseline import Declaration, VarianceBand, calibrate, declare
from canary.detector import Outcome, compare
from canary.freezer import freeze_run
from canary.suite.probe import ProbeSuite
from canary.suite.refusal import RefusalInstrument
from canary.target import Change, MockConfig, MockTarget, suite_from_cycle
from canary.target.mock import REPEAT_CYCLE

SUITE = suite_from_cycle()


def _run(run_id="r", cfg=None, version="v3", suite=SUITE):
    return freeze_run(run_id, suite, MockTarget(config=cfg or MockConfig()),
                      instrument=RefusalInstrument(version))


def _repeat(version="v3"):
    return freeze_run("repeat", suite_from_cycle(REPEAT_CYCLE),
                      MockTarget(config=MockConfig(repeat=True)),
                      instrument=RefusalInstrument(version))


def _baseline(version="v3", run=None):
    run = run or _run("base", version=version)
    band = calibrate("refusal-sentinel", version, [run, _repeat(version)],
                     method="same-config repeat pair")
    return declare("b1", run, band,
                   Declaration(declared_by="tester", declared_at="2026-08-21T12:00:00Z",
                               reason="validated system"))


# -------------------------------------------------------------------- comparability

def test_a_run_scored_by_a_different_instrument_is_incomparable_not_changed():
    """Not UNCHANGED, not CHANGED. Any difference would be partly the instrument, and a
    number that mixes the two cannot be attributed to the system at all."""
    c = compare(_baseline(version="v3"), _run("x", version="v1"))
    assert c.outcome is Outcome.INCOMPARABLE
    assert "different instruments" in " ".join(c.reasons)


def test_a_different_suite_is_incomparable():
    base = _baseline()
    smaller = ProbeSuite(suite_id=SUITE.suite_id, version=SUITE.version,
                         probes=SUITE.probes[:60])
    c = compare(base, _run("x", suite=smaller))
    assert c.outcome is Outcome.INCOMPARABLE


def test_incomparable_still_reports_the_seal_question():
    """Even when behaviour cannot be compared, whether the bytes moved is still knowable.

    And the two seal digests answer different questions, which this pins down. Scoring
    identical replies under a different instrument leaves `bytes_changed` FALSE -- the
    endpoint returned exactly what it returned before -- while `seal_changed` is TRUE,
    because the sealed run also records what we made of those bytes.

    Collapsing the pair would make "the model changed" and "we changed how we read the
    model" indistinguishable in a receipt, which is the §5 collapse one level down.
    """
    c = compare(_baseline(version="v3"), _run("x", version="v1"))
    assert c.outcome is Outcome.INCOMPARABLE
    assert c.bytes_changed is False, "the response bytes are identical; only the reading moved"
    assert c.seal_changed is True, "the sealed run covers the instrument, so it must move"
    assert c.baseline_bodies_digest == c.current_bodies_digest
    assert c.baseline_e_digest != c.current_e_digest


# ------------------------------------------------------------------- the two answers

def test_no_change_is_a_real_verdict_not_an_empty_one():
    """The no-change receipt is the product: behaviourally unchanged since validation."""
    base = _baseline()
    c = compare(base, _run("again"))
    assert c.outcome is Outcome.UNCHANGED
    assert c.probe_deltas == ()
    assert "no probe changed verdict" in " ".join(c.reasons)


def test_bytes_can_move_while_behaviour_does_not_and_both_are_reported():
    """§5 ruled: the seal answers *did anything change*, the verdicts answer *did
    behaviour change*, and the receipt carries both without reconciling them.

    The prompt edit makes the model explain its abstentions. It abstains on exactly the
    same probes. One number would be a lie in both directions.
    """
    base = _baseline()
    c = compare(base, _run("edited", cfg=MockConfig(changes=(Change.PROMPT_EDIT,))))
    assert c.bytes_changed is True, "the prompt edit changed no bytes; the fixture is wrong"
    assert c.seal_changed is True
    assert c.outcome is Outcome.UNCHANGED
    assert c.probe_deltas == ()


def test_a_real_behavioural_change_is_detected_and_located_behaviourally():
    base = _baseline()
    c = compare(base, _run("swapped", cfg=MockConfig(changes=(Change.MODEL_SWAP,))))
    assert c.outcome is Outcome.CHANGED
    assert c.probe_deltas, "the model swap moved no probe"
    # located behaviourally: which probes, which arm, which direction
    d = c.probe_deltas[0]
    assert d.probe_id and d.arm in ("answer_bearing", "same_doc", "cross_doc")
    assert d.baseline_verdict != d.current_verdict


def test_the_detector_never_says_which_stage():
    """The anti-overclaim line, asserted structurally rather than trusted to prose."""
    c = compare(_baseline(), _run("swapped", cfg=MockConfig(changes=(Change.MODEL_SWAP,))))
    blob = str(c.as_canonical()).lower()
    for word in ("retrieval", "ranking", "prompt assembly", "generation stage", "caused by"):
        assert word not in blob, f"the verdict speculates about stage: {word!r}"


# ------------------------------------------------------------------- per-probe first

def test_movement_that_cancels_in_aggregate_is_still_reported():
    """Aggregates cancel. Under v1 a same-config repeat moves nine probes and shows
    +2/-1 in the totals; a detector comparing only totals would have been blind had they
    cancelled exactly. So per-probe movement inside a satisfied band is stated, never
    absorbed."""
    base_run = _run("base", version="v1")
    # a deliberately generous band, so the arms stay inside it while probes move
    band = VarianceBand(family="refusal-sentinel", instrument_version="v1",
                        per_arm={"answer_bearing": 30, "same_doc": 30, "cross_doc": 30},
                        calibrated_from=("declared-wide-for-this-test",),
                        method="wide band, to isolate per-probe reporting")
    baseline = declare("b1", base_run, band,
                       Declaration(declared_by="t", declared_at="2026-08-21T12:00:00Z",
                                   reason="r"))
    c = compare(baseline, _repeat("v1"))
    assert c.outcome is Outcome.CHANGED
    assert c.probe_deltas, "the v1 repeat moved no probe; the finding has changed"
    assert all(b["within_band"] for b in c.band_applied.values())
    assert "cancels in aggregate is still movement" in " ".join(c.reasons)


def test_regression_direction_is_recorded_per_probe():
    c = compare(_baseline(), _run("swapped", cfg=MockConfig(changes=(Change.MODEL_SWAP,))))
    assert any(d.regressed for d in c.probe_deltas), "no regression flagged"
    for d in c.probe_deltas:
        expected = (d.baseline_verdict == d.expect) and (d.current_verdict != d.expect)
        assert d.regressed == expected


# ------------------------------------------------------------------ counts and bands

def test_counts_travel_as_triples_and_no_rate_is_computed():
    c = compare(_baseline(), _run("swapped", cfg=MockConfig(changes=(Change.MODEL_SWAP,))))
    for bucket, d in c.count_deltas.items():
        for side in ("baseline", "current"):
            assert set(d[side]) == {"numerator", "denominator", "probe_set_digest"}
            assert isinstance(d[side]["numerator"], int)
        assert isinstance(d["numerator_delta"], int)
    assert "rate" not in str(c.as_canonical())


def test_a_zero_band_makes_a_single_probe_visible():
    """The payoff for declaring measured zero: small real changes are not hidden."""
    base = _baseline()
    assert all(w == 0 for w in base.band.per_arm.values())
    c = compare(base, _run("drift", cfg=MockConfig(changes=(Change.FORMAT_DRIFT,))))
    assert c.outcome is Outcome.CHANGED
    assert any(not b["within_band"] for b in c.band_applied.values())


def test_the_verdict_is_canonicalisable_and_float_free():
    from canary.acj import canonical_bytes
    canonical_bytes(compare(_baseline(), _run("x")).as_canonical())


def test_the_v_digest_is_stable_and_sensitive():
    base = _baseline()
    a = compare(base, _run("x"))
    b = compare(base, _run("x"))
    assert a.v_digest == b.v_digest
    changed = compare(base, _run("y", cfg=MockConfig(changes=(Change.MODEL_SWAP,))))
    assert changed.v_digest != a.v_digest


def test_the_detector_never_touches_a_target():
    """Re-derivation replays the comparison; it never re-queries the model.

    A target that raises on `ask` is passed to nothing here -- the comparison takes two
    sealed runs, and this asserts the signature makes a target impossible to supply.
    """
    import inspect
    params = set(inspect.signature(compare).parameters)
    assert params == {"baseline", "current"}, params
