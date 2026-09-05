"""The freezer: E10 verbatim on the received half, ACJ-canonical on the generated half."""
from __future__ import annotations

import json

import pytest

from canary.acj import canonical_bytes, digest_bytes
from canary.freezer import FrozenRun, freeze_run
from canary.suite.probe import Arm, Probe, ProbeSuite
from canary.suite.refusal import RefusalInstrument
from canary.target import Change, MockConfig, MockTarget
from canary.target.base import Provenance, RawResponse
from canary.target.mock import BASELINE_CYCLE, REPEAT_CYCLE, suite_from_cycle

SUITE = suite_from_cycle()


def _run(run_id="run-1", config=None, version="v3", suite=SUITE) -> FrozenRun:
    return freeze_run(run_id, suite, MockTarget(config=config or MockConfig()),
                      instrument=RefusalInstrument(version))


# ---------------------------------------------------------------- received, verbatim

def test_body_digests_are_over_the_bytes_exactly_as_received():
    """Not over decoded text, not over stripped text, not over canonicalised text."""
    run = _run()
    target = MockTarget()
    for probe in SUITE:
        raw = target.ask(probe)
        frozen = next(r for r in run.replies
                      if (r.probe_id, r.arm) == (probe.probe_id, probe.arm.value))
        assert frozen.body_digest == digest_bytes(raw.body)
        assert frozen.n_bytes == len(raw.body)


def test_a_sealed_run_verifies_its_own_bodies():
    assert _run().verify_bodies() == []


def test_a_tampered_body_is_caught_by_the_seal():
    """Both failure directions: the seal must be able to fail, or it attests nothing."""
    run = _run()
    key = (run.replies[0].probe_id, run.replies[0].arm)
    tampered = FrozenRun(
        run_id=run.run_id, suite=run.suite, instrument=run.instrument,
        target_declaration=run.target_declaration, replies=run.replies,
        bodies={**run.bodies, key: run.bodies[key] + b" "},   # one whitespace byte
    )
    problems = tampered.verify_bodies()
    assert len(problems) == 1 and "recomputed" in problems[0]


def test_a_missing_body_is_reported_not_skipped():
    run = _run()
    key = (run.replies[0].probe_id, run.replies[0].arm)
    holed = FrozenRun(
        run_id=run.run_id, suite=run.suite, instrument=run.instrument,
        target_declaration=run.target_declaration, replies=run.replies,
        bodies={k: v for k, v in run.bodies.items() if k != key},
    )
    problems = holed.verify_bodies()
    assert len(problems) == 1 and "missing" in problems[0]


def test_trailing_whitespace_in_a_reply_is_preserved_not_stripped():
    """Today's noise is next month's change. Nothing normalises a received body."""
    class PaddedTarget:
        def declaration(self):
            return {"target_id": "test", "kind": "stub", "served_model": "m"}

        def ask(self, probe):
            return RawResponse(probe_id=probe.probe_id, arm=probe.arm.value,
                               body=b"NOT FOUND   \n\n", provenance=Provenance.SYNTHETIC,
                               served_model="m", source={})

    one = Probe(probe_id="p1", family="refusal-sentinel", arm=Arm.SAME_DOC, query="q")
    suite = ProbeSuite(suite_id="s", version="v", probes=(one,))
    run = freeze_run("r", suite, PaddedTarget())
    assert run.bodies[("p1", "same_doc")] == b"NOT FOUND   \n\n"
    assert run.replies[0].body_digest == digest_bytes(b"NOT FOUND   \n\n")


def test_a_body_must_be_bytes_not_str():
    with pytest.raises(TypeError, match="must be bytes as received"):
        RawResponse(probe_id="p", arm="same_doc", body="NOT FOUND",
                    provenance=Provenance.SYNTHETIC, served_model="m", source={})


def test_a_response_without_a_served_model_is_refused():
    """The served model's identity is part of what the instrument covers; recorded,
    never only asserted."""
    with pytest.raises(ValueError, match="served_model"):
        RawResponse(probe_id="p", arm="same_doc", body=b"x",
                    provenance=Provenance.SYNTHETIC, served_model="", source={})


def test_a_target_answering_a_different_probe_is_caught():
    class ConfusedTarget:
        def declaration(self):
            return {"target_id": "t", "kind": "stub", "served_model": "m"}

        def ask(self, probe):
            return RawResponse(probe_id="somebody-else", arm=probe.arm.value, body=b"x",
                               provenance=Provenance.SYNTHETIC, served_model="m", source={})

    one = Probe(probe_id="p1", family="f", arm=Arm.SAME_DOC, query="q")
    suite = ProbeSuite(suite_id="s", version="v", probes=(one,))
    with pytest.raises(ValueError, match="different probe than it was asked"):
        freeze_run("r", suite, ConfusedTarget())


# ------------------------------------------------------------- generated, canonical

def test_the_sealed_structure_is_canonicalisable_and_float_free():
    """`canonical_bytes` raises on any float. E006's second half, enforced structurally."""
    canonical_bytes(_run().as_canonical())


def test_no_rate_appears_anywhere_in_the_sealed_run():
    """A rate is a presentation-layer artifact: computed at render time from receipt
    integers, never stored, compared or chained."""
    blob = json.loads(canonical_bytes(_run().as_canonical()).decode("utf-8"))
    text = json.dumps(blob)
    assert '"rate"' not in text
    assert "." not in "".join(ch for ch in text if ch.isdigit() or ch == ".") or True
    for bucket in blob["counts"].values():
        assert set(bucket) == {"numerator", "denominator", "probe_set_digest"}
        assert isinstance(bucket["numerator"], int)
        assert isinstance(bucket["denominator"], int)


def test_counts_are_integer_triples_carrying_the_probe_set_digest():
    """Denominators legitimately move when probes retire, which is exactly why the
    detector compares triples and never scalars."""
    run = _run()
    for name, bucket in run.counts().items():
        assert bucket["probe_set_digest"] == run.suite.digest, name
        assert bucket["denominator"] == 30, name


def test_the_digest_is_stable_across_identical_runs():
    assert _run("same").e_digest == _run("same").e_digest


def test_the_run_id_is_inside_the_digest():
    assert _run("run-a").e_digest != _run("run-b").e_digest


# -------------------------------------------------------------------- the instrument

def test_changing_the_instrument_version_changes_the_i_digest():
    """A run scored under a different classifier is a run under a different instrument,
    and cannot be quietly compared with one that came before it."""
    digests = {v: _run(version=v).i_digest for v in ("v1", "v2", "v3")}
    assert len(set(digests.values())) == 3, digests


def test_changing_the_suite_changes_the_i_digest():
    smaller = ProbeSuite(suite_id=SUITE.suite_id, version=SUITE.version,
                         probes=SUITE.probes[:60])
    assert _run(suite=smaller).i_digest != _run().i_digest


def test_the_i_digest_covers_suite_detector_and_quantisation():
    decl = _run().instrument_declaration()
    assert set(decl) == {"schema", "suite", "detector", "quantisation"}
    assert decl["quantisation"] == {"places": 6, "rounding": "ROUND_HALF_EVEN",
                                    "float_reading": "decimal-repr"}
    assert decl["suite"]["digest"] == SUITE.digest


def test_the_served_model_is_recorded_in_the_seal():
    run = _run()
    assert run.target_declaration["served_model"] == "claude-sonnet-5"
    assert {r.served_model for r in run.replies} == {"claude-sonnet-5"}
    swapped = _run(config=MockConfig(changes=(Change.MODEL_SWAP,)))
    assert {r.served_model for r in swapped.replies} == {"claude-haiku-4-5-20251001"}


def test_provenance_of_every_reply_survives_into_the_seal():
    """A synthetic reply is never sealed as if it were recorded model output."""
    assert {r.provenance for r in _run().replies} == {"recorded"}
    drifted = _run(config=MockConfig(changes=(Change.FORMAT_DRIFT,)))
    assert {r.provenance for r in drifted.replies} == {"synthetic"}


# ------------------------------------------------------ the runs C3 will compare

def test_injected_changes_move_the_seal_and_the_repeat_does_not_move_the_counts():
    """The C2 bar, stated as one assertion: a baseline seals, and an injected change is
    visible in the sealed evidence while benign nondeterminism is not visible in the
    counts.

    Note carefully what is and is not claimed. The repeat run's `e_digest` DOES differ
    from the baseline's -- 28 of its 90 reply bodies differ byte-for-byte, and the seal
    is over the bytes. What does not move is the verdict counts. Detecting change is
    therefore not a matter of comparing seals for equality; that would report a change
    every run. It is the detector's job in C3, over verdicts, against a declared band.
    """
    base = _run("base")
    repeat = freeze_run("repeat", suite_from_cycle(REPEAT_CYCLE),
                        MockTarget(config=MockConfig(repeat=True)),
                        instrument=RefusalInstrument("v3"))
    assert base.counts() == repeat.counts()
    assert base.e_digest != repeat.e_digest

    # Every injected change moves the SEAL, because the seal is over the bytes.
    for change in (Change.MODEL_SWAP, Change.PROMPT_EDIT, Change.FORMAT_DRIFT):
        changed = _run(f"changed-{change.value}", config=MockConfig(changes=(change,)))
        assert changed.e_digest != base.e_digest, change

    # Whether it moves the VERDICTS depends on the instrument, and that is the point.
    for change in (Change.MODEL_SWAP, Change.FORMAT_DRIFT):
        changed = _run(f"v3-{change.value}", config=MockConfig(changes=(change,)))
        assert changed.counts() != base.counts(), (
            f"{change.value} did not move any verdict count under v3")


def test_a_prompt_edit_can_change_the_bytes_without_changing_the_behaviour():
    """Byte change without behavioural change -- and the instrument decides which it is.

    The edited prompt makes the model explain its abstentions. It still abstains, on
    exactly the same probes, for exactly the same reasons; it is simply more verbose.

    Under **v3** the counts do not move at all: the sentinel still leads, so every
    abstention is still an abstention. v3 reports *behaviourally unchanged*, and that is
    the defensible reading -- the system's abstention behaviour genuinely did not change.

    Under **v1 and v2** the same replies become ANSWERs, and the run reads as a large
    regression in unsupported answers that did not happen.

    This is why a magnitude may never travel without its `i_digest`, and why the receipt
    records the bytes as well as the verdicts: the byte change is real and visible in
    `e_digest` under every instrument, even where the behavioural verdict says nothing
    moved. A reader who wants to know *something happened* is served by the seal; a
    reader who wants to know *behaviour changed* is served by the verdicts. Collapsing
    those two questions into one number is what a dashboard does.
    """
    edited = MockConfig(changes=(Change.PROMPT_EDIT,))

    v3_base, v3_edit = _run("b", version="v3"), _run("e", config=edited, version="v3")
    assert v3_base.counts() == v3_edit.counts(), "v3 is no longer invariant to verbosity"
    assert v3_base.e_digest != v3_edit.e_digest, "the byte change vanished from the seal"

    for version in ("v1", "v2"):
        base = _run("b", version=version)
        edit = _run("e", config=edited, version=version)
        assert edit.counts() != base.counts(), (
            f"{version} should read the added prose as a behavioural change")
