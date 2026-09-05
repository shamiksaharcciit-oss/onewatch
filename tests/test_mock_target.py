"""The deterministic mock and its four declared injectable changes."""
from __future__ import annotations

import pytest

from canary.suite.probe import Arm, Probe
from canary.target import BASELINE_CYCLE, REPEAT_CYCLE, Change, MockConfig, MockTarget
from canary.target.base import Provenance
from canary.target.mock import suite_from_cycle
from canary.suite.refusal import RefusalInstrument, Verdict

V1, V2, V3 = (RefusalInstrument(v) for v in ("v1", "v2", "v3"))
SUITE = suite_from_cycle()


def _ask_all(target: MockTarget, suite=SUITE) -> dict[tuple[str, str], bytes]:
    return {(p.probe_id, p.arm.value): target.ask(p).body for p in suite}


# ------------------------------------------------------------------------ determinism

def test_the_same_config_and_probe_give_the_same_bytes_every_time():
    """The mock's entire contract. A mock that varied would make every detector test
    unfalsifiable: a failure could always be the mock's fault."""
    t = MockTarget()
    first = _ask_all(t)
    assert first == _ask_all(t)
    assert first == _ask_all(MockTarget())      # and across instances


def test_two_targets_with_equal_configs_are_indistinguishable():
    assert _ask_all(MockTarget(config=MockConfig())) == \
           _ask_all(MockTarget(config=MockConfig(changes=())))


def test_asking_for_a_probe_the_fixtures_do_not_have_raises():
    """The mock never invents a reply. A suite that outruns its fixtures is an error."""
    ghost = Probe(probe_id="A-999-not-recorded", family="refusal-sentinel",
                  arm=Arm.SAME_DOC, query="A-999-not-recorded")
    with pytest.raises(KeyError, match="does not invent replies|no recorded reply"):
        MockTarget().ask(ghost)


# ------------------------------------------------------------------- recorded changes

def test_model_swap_replays_a_real_recorded_cycle_and_says_so():
    t = MockTarget(config=MockConfig(changes=(Change.MODEL_SWAP,)))
    r = t.ask(SUITE.probes[0])
    assert r.provenance is Provenance.RECORDED
    assert r.served_model == "claude-haiku-4-5-20251001"
    assert MockTarget().ask(SUITE.probes[0]).served_model == "claude-sonnet-5"


def test_model_swap_actually_changes_the_bytes():
    before = _ask_all(MockTarget())
    after = _ask_all(MockTarget(config=MockConfig(changes=(Change.MODEL_SWAP,))))
    changed = [k for k in before if before[k] != after.get(k)]
    assert changed, "the injected model swap changed nothing; the fixture is wrong"


def test_index_refresh_replays_the_corpus_release_cycle():
    t = MockTarget(config=MockConfig(changes=(Change.INDEX_REFRESH,)))
    r = t.ask(SUITE.probes[0])
    assert r.provenance is Provenance.RECORDED
    assert r.source["cycle"] == "telemetry_cycle4_after_release.json"
    # the corpus changed, not the model
    assert r.served_model == "claude-sonnet-5"


def test_two_recorded_changes_cannot_be_combined():
    """There is no cycle in which both happened, and manufacturing one would mean
    inventing model replies."""
    with pytest.raises(ValueError, match="cannot be combined"):
        MockConfig(changes=(Change.MODEL_SWAP, Change.INDEX_REFRESH))


def test_a_change_listed_twice_is_refused():
    with pytest.raises(ValueError, match="listed twice"):
        MockConfig(changes=(Change.PROMPT_EDIT, Change.PROMPT_EDIT))


# ------------------------------------------------------------------ synthetic changes

def test_synthetic_responses_are_labelled_synthetic():
    """The mock never presents a declared transformation as recorded model output."""
    for change in (Change.PROMPT_EDIT, Change.FORMAT_DRIFT):
        t = MockTarget(config=MockConfig(changes=(change,)))
        provenances = {t.ask(p).provenance for p in SUITE}
        assert provenances == {Provenance.SYNTHETIC}, change


def test_recorded_responses_are_labelled_recorded():
    assert {MockTarget().ask(p).provenance for p in SUITE} == {Provenance.RECORDED}


def test_prompt_edit_is_the_instrument_relativity_case():
    """One injected change, opposite verdicts, decided entirely by the instrument.

    The edited prompt asks the model to explain its abstentions, so a bare sentinel gains
    trailing prose. v3 still reads REFUSAL because the sentinel leads. v1 and v2 read
    ANSWER because the reply is no longer only the sentinel. Neither is wrong; they are
    different instruments, which is precisely why a magnitude may never travel without
    its `i_digest`.
    """
    t = MockTarget(config=MockConfig(changes=(Change.PROMPT_EDIT,)))
    flipped = []
    for p in SUITE:
        text = t.ask(p).text()
        if text.startswith("NOT FOUND. The provided context"):
            flipped.append(text)
            assert V3.classify(text) is Verdict.REFUSAL
            assert V2.classify(text) is Verdict.ANSWER
            assert V1.classify(text) is Verdict.ANSWER
    assert flipped, "the prompt edit transformed nothing"


def test_prompt_edit_leaves_answers_alone():
    """The edit asked for explained refusals; it did not touch answer-bearing replies."""
    base = MockTarget()
    edited = MockTarget(config=MockConfig(changes=(Change.PROMPT_EDIT,)))
    for p in SUITE:
        before, after = base.ask(p).text(), edited.ask(p).text()
        if before.strip() != "NOT FOUND":
            assert before == after, f"{p.probe_id}::{p.arm.value} was altered unexpectedly"


def test_format_drift_flips_every_arm_at_once():
    """Nothing about the model's behaviour changed -- only the bytes that reach us.

    A fence in front of the sentinel means the sentinel no longer leads, so no version
    reads a refusal. The uniformity is the signature: real behavioural change is rarely
    this tidy, and a detector that learns the difference has learned something useful.
    """
    t = MockTarget(config=MockConfig(changes=(Change.FORMAT_DRIFT,)))
    for p in SUITE:
        text = t.ask(p).text()
        assert text.startswith("```\n") and text.endswith("\n```")
        for inst in (V1, V2, V3):
            assert inst.classify(text) is Verdict.ANSWER, (inst.version, text[:40])


# ---------------------------------------------------------------- the repeat and decl

def test_the_repeat_cycle_is_a_different_run_of_the_same_declared_config():
    base = MockTarget()
    repeat = MockTarget(config=MockConfig(repeat=True))
    assert base.declaration()["served_model"] == repeat.declaration()["served_model"]
    assert _ask_all(base) != _ask_all(repeat), "the repeat is byte-identical; not a repeat"


def test_repeat_cannot_be_combined_with_a_recorded_change():
    with pytest.raises(ValueError, match="contradictory"):
        MockConfig(repeat=True, changes=(Change.MODEL_SWAP,))


def test_the_declaration_names_the_served_model_and_is_canonicalisable():
    from canary.acj import canonical_bytes
    d = MockTarget().declaration()
    assert d["served_model"] == "claude-sonnet-5"
    assert d["config"]["base_cycle"] == BASELINE_CYCLE
    canonical_bytes(d)          # raises on floats or non-canonical types


def test_suite_from_cycle_covers_every_probe_and_arm():
    s = suite_from_cycle(REPEAT_CYCLE)
    assert len(s) == 90
    assert s.arm_counts() == {"answer_bearing": 30, "same_doc": 30, "cross_doc": 30}
    assert "retired" in s.version, "the retirement caveat has left the suite version"
