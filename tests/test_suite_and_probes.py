"""Probes and suites: immutability, content-addressing, and the digest's sensitivities."""
from __future__ import annotations

import dataclasses

import pytest

from canary.suite.probe import Arm, Expect, Probe, ProbeSuite


def _p(pid="p1", arm=Arm.SAME_DOC, family="refusal-sentinel", query="q") -> Probe:
    return Probe(probe_id=pid, family=family, arm=arm, query=query)


def _suite(*probes, suite_id="s", version="v1") -> ProbeSuite:
    return ProbeSuite(suite_id=suite_id, version=version, probes=tuple(probes))


# ------------------------------------------------------------------------ immutability

def test_a_probe_cannot_be_mutated_after_construction():
    with pytest.raises(dataclasses.FrozenInstanceError):
        _p().probe_id = "changed"


def test_a_probe_cannot_grow_an_attribute_the_digest_would_not_cover():
    """`slots=True`. An attribute outside the canonical form is a fact about the run
    that the digest does not attest, which is worse than not recording it.

    The guarantee is asserted structurally -- no instance `__dict__` -- rather than by
    exception type: a frozen slotted dataclass raises TypeError here, not the
    AttributeError a plain slotted class would, and pinning the wrong exception type
    would make this test a statement about CPython's dataclass internals instead of
    about the probe.
    """
    probe = _p()
    assert not hasattr(probe, "__dict__"), "Probe has instance storage outside its slots"
    assert Probe.__slots__
    with pytest.raises((AttributeError, TypeError)):
        probe.sneaky = "value"
    assert not hasattr(probe, "sneaky")


def test_a_suite_cannot_be_mutated():
    with pytest.raises(dataclasses.FrozenInstanceError):
        _suite(_p()).version = "v2"


# -------------------------------------------------------------------------- invariants

def test_an_empty_suite_is_refused():
    with pytest.raises(ValueError, match="measures nothing"):
        ProbeSuite(suite_id="s", version="v", probes=())


def test_a_duplicated_probe_is_refused_because_it_reweights_the_denominator():
    with pytest.raises(ValueError, match="duplicate probe"):
        _suite(_p("p1", Arm.SAME_DOC), _p("p1", Arm.SAME_DOC))


def test_the_same_probe_id_on_different_arms_is_not_a_duplicate():
    s = _suite(_p("p1", Arm.SAME_DOC), _p("p1", Arm.CROSS_DOC))
    assert len(s) == 2


def test_an_empty_probe_id_or_query_is_refused():
    with pytest.raises(ValueError, match="non-empty identifier"):
        _p(pid="   ")
    with pytest.raises(ValueError, match="query must not be empty"):
        _p(query="")


def test_an_arm_must_be_an_arm_not_a_string():
    with pytest.raises(TypeError, match="arm must be an Arm"):
        Probe(probe_id="p", family="f", arm="same_doc", query="q")


# ------------------------------------------------------------- expectation is derived

@pytest.mark.parametrize("arm,expect", [
    (Arm.ANSWER_BEARING, Expect.ANSWER),
    (Arm.SAME_DOC, Expect.REFUSAL),
    (Arm.CROSS_DOC, Expect.REFUSAL),
])
def test_expectation_is_derived_from_the_arm_never_stored(arm, expect):
    """One source of truth. A stored expectation could disagree with its arm, and no
    reader could tell which one the run actually used."""
    assert _p(arm=arm).expect is expect
    assert "expect" not in {f.name for f in dataclasses.fields(Probe)}


def test_both_directions_of_the_measurement_are_present():
    """A monitor checking only one direction is satisfiable by a system that refuses
    everything, or one that answers everything. Both failures are common."""
    expectations = {a: _p(arm=a).expect for a in Arm}
    assert Expect.ANSWER in expectations.values()
    assert Expect.REFUSAL in expectations.values()


# --------------------------------------------------------------- content addressing

def test_the_digest_is_stable_for_identical_content():
    assert _suite(_p("a"), _p("b")).digest == _suite(_p("a"), _p("b")).digest


@pytest.mark.parametrize("mutate", [
    lambda: _suite(_p("a"), _p("c")),                       # a probe id
    lambda: _suite(_p("a"), _p("b", query="different")),    # a query
    lambda: _suite(_p("a"), _p("b", family="other")),       # a family
    lambda: _suite(_p("a"), _p("b", arm=Arm.CROSS_DOC)),    # an arm
    lambda: _suite(_p("a"), _p("b"), version="v2"),         # the version
    lambda: _suite(_p("a"), _p("b"), suite_id="other"),     # the suite id
    lambda: _suite(_p("a")),                                # dropping a probe
])
def test_every_part_of_the_suite_moves_the_digest(mutate):
    """Changing a probe is a visible instrument change, never silent drift."""
    assert mutate().digest != _suite(_p("a"), _p("b")).digest


def test_probe_order_is_content():
    """Two suites holding the same probes in a different order are different
    instruments: a reader comparing them position-by-position compares different things."""
    assert _suite(_p("a"), _p("b")).digest != _suite(_p("b"), _p("a")).digest


def test_arm_counts_declare_the_denominators_before_any_run():
    s = _suite(_p("a", Arm.ANSWER_BEARING), _p("b", Arm.SAME_DOC), _p("c", Arm.SAME_DOC))
    assert s.arm_counts() == {"answer_bearing": 1, "same_doc": 2, "cross_doc": 0}


def test_families_are_reported_in_first_seen_order():
    s = _suite(_p("a", family="beta"), _p("b", family="alpha"), _p("c", family="beta"))
    assert s.families == ("beta", "alpha")


def test_the_canonical_form_is_json_safe_and_float_free():
    from canary.acj import canonical_bytes
    canonical_bytes(_suite(_p("a"), _p("b")).as_canonical())
