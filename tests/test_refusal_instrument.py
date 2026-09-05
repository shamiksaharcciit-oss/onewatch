"""The refusal-sentinel instrument: its three versions, and its refusals to guess.

The most important tests here are the last group: the reimplemented instrument is
checked against upstream's own published counts over upstream's own frozen replies.
A reimplementation that merely looks right is a reimplementation nobody has checked.
"""
from __future__ import annotations

import pytest

from canary.suite.probe import Expect
from canary.suite.refusal import (
    REFUSAL_INSTRUMENT_VERSIONS,
    SENTINEL,
    RefusalInstrument,
    Verdict,
)
from canary.target.mock import BASELINE_CYCLE, REPEAT_CYCLE, _index, _load_cycle

V1, V2, V3 = (RefusalInstrument(v) for v in ("v1", "v2", "v3"))


# ------------------------------------------------------------------- the declared form

@pytest.mark.parametrize("reply", [
    "NOT FOUND",
    "  NOT FOUND  ",
    "\nNOT FOUND\n",
])
def test_the_bare_sentinel_is_a_refusal_under_every_version(reply):
    for inst in (V1, V2, V3):
        assert inst.classify(reply) is Verdict.REFUSAL, inst.version


def test_v1_scores_the_trailing_period_as_an_answer():
    """v1's known defect, preserved deliberately. v1 is never modified.

    Upstream measured this happening 33 times across cycles 1-5, all in answerless
    slots, inflating the unsupported-answer count. It stays wrong here because v1 is the
    classifier of record for every published upstream number, and silently fixing it
    would retroactively restate results that were published under it.
    """
    assert V1.classify("NOT FOUND.") is Verdict.ANSWER
    assert V2.classify("NOT FOUND.") is Verdict.REFUSAL
    assert V3.classify("NOT FOUND.") is Verdict.REFUSAL


@pytest.mark.parametrize("reply", ["NOT FOUND.", "NOT FOUND!", "NOT FOUND;", "NOT FOUND:",
                                   "NOT FOUND,", "NOT FOUND...", "  NOT FOUND.  "])
def test_v2_forgives_trailing_punctuation_and_only_that(reply):
    assert V2.classify(reply) is Verdict.REFUSAL


def test_v3_accepts_a_sentinel_led_reply_with_prose_after_it():
    reply = "NOT FOUND. The provided context does not contain that information."
    assert V3.classify(reply) is Verdict.REFUSAL
    assert V2.classify(reply) is Verdict.ANSWER
    assert V1.classify(reply) is Verdict.ANSWER


# ------------------------------------------------------- the three refusals to guess

@pytest.mark.parametrize("reply", ["not found", "Not Found", "NOT found", "nOt FoUnD"])
def test_case_is_never_folded(reply):
    """A model that ignores the declared casing has not emitted the declared token.

    This also keeps `str.casefold` out of the instrument. Casefolding consults the
    Unicode Character Database, which would make a verdict depend on the runtime's UCD
    version -- the same class of defect as E14, and just as invisible.
    """
    for inst in (V1, V2, V3):
        assert inst.classify(reply) is Verdict.ANSWER, inst.version


@pytest.mark.parametrize("reply", [
    "The answer is NOT FOUND in the context.",
    "I searched but the value was NOT FOUND.",
    "Result: NOT FOUND",
])
def test_an_embedded_sentinel_is_never_a_refusal(reply):
    """The sentinel must LEAD. A reply that merely mentions the token has not opened
    with it, and substring search would make the classifier decide what counts as an
    abstention rather than recognise the form it declared."""
    for inst in (V1, V2, V3):
        assert inst.classify(reply) is Verdict.ANSWER, inst.version


@pytest.mark.parametrize("reply", ["NOT FOUNDATION", "NOT FOUNDATIONS are listed",
                                   "NOT FOUND2", "NOT FOUNDx"])
def test_a_word_boundary_is_required_after_the_token(reply):
    for inst in (V1, V2, V3):
        assert inst.classify(reply) is Verdict.ANSWER, inst.version


# ------------------------------------------------------------------- containment claim

def test_v3_contains_v2_contains_v1_over_every_frozen_reply():
    """`v3 ⊇ v2 ⊇ v1`, asserted over real data rather than trusted from the docstring."""
    replies = list(_index(_load_cycle(BASELINE_CYCLE)).values())
    replies += list(_index(_load_cycle(REPEAT_CYCLE)).values())
    assert replies
    for text in replies:
        r1 = V1.classify(text) is Verdict.REFUSAL
        r2 = V2.classify(text) is Verdict.REFUSAL
        r3 = V3.classify(text) is Verdict.REFUSAL
        assert not r1 or r2, f"v2 lost a refusal v1 found: {text[:60]!r}"
        assert not r2 or r3, f"v3 lost a refusal v2 found: {text[:60]!r}"


def test_every_declared_version_is_reachable_and_unknown_ones_are_refused():
    for v in REFUSAL_INSTRUMENT_VERSIONS:
        assert RefusalInstrument(v).classify(SENTINEL) is Verdict.REFUSAL
    with pytest.raises(ValueError, match="unknown refusal instrument version"):
        RefusalInstrument("v4")


def test_the_version_is_inside_the_instrument_declaration():
    """Two versions must not share a declaration, or they would share an i_digest."""
    decls = [RefusalInstrument(v).as_canonical() for v in REFUSAL_INSTRUMENT_VERSIONS]
    assert len({str(sorted(d.items())) for d in decls}) == len(decls)


def test_conforms_maps_both_failure_directions():
    assert V3.conforms("NOT FOUND", Expect.REFUSAL) is True
    assert V3.conforms("NOT FOUND", Expect.ANSWER) is False      # wrong abstention
    assert V3.conforms("Port 6565.", Expect.ANSWER) is True
    assert V3.conforms("Port 6565.", Expect.REFUSAL) is False    # unsupported answer


def test_residue_exposes_what_followed_the_sentinel():
    assert V3.residue("NOT FOUND. Because the context lacks it.") == "Because the context lacks it."
    assert V3.residue("NOT FOUND") == ""
    assert V3.residue("Port 6565.") == ""


def test_a_non_string_reply_is_a_type_error_not_a_verdict():
    with pytest.raises(TypeError):
        V3.classify(b"NOT FOUND")


# ------------------------------------------------ validation against upstream's numbers

#: Upstream's published counts, scored under v1 -- the classifier of record for them.
UPSTREAM_V1_COUNTS = {
    BASELINE_CYCLE: {"wrong_abstention": 0, "same_doc": 11, "cross_doc": 4},
    REPEAT_CYCLE: {"wrong_abstention": 0, "same_doc": 13, "cross_doc": 3},
}


@pytest.mark.parametrize("cycle_file", list(UPSTREAM_V1_COUNTS))
def test_v1_reproduces_upstream_published_counts_exactly(cycle_file):
    """The reimplementation is validated against upstream's own recorded results.

    This is the test that makes "reimplemented, not copied" a claim rather than a hope:
    the rule was rewritten in a different shape, and it produces upstream's published
    numbers to the unit over upstream's frozen replies.

    Scored under v1 because that is what upstream scored under. Comparing our v3 to
    their v1 would be comparing two instruments and calling the difference a defect.
    """
    cycle = _load_cycle(cycle_file)
    replies = _index(cycle)
    expected = UPSTREAM_V1_COUNTS[cycle_file]

    wrong_abstention = sum(
        1 for (pid, arm), t in replies.items()
        if arm == "answer_bearing" and V1.classify(t) is Verdict.REFUSAL)
    same_doc = sum(1 for (pid, arm), t in replies.items()
                   if arm == "same_doc" and V1.classify(t) is Verdict.ANSWER)
    cross_doc = sum(1 for (pid, arm), t in replies.items()
                    if arm == "cross_doc" and V1.classify(t) is Verdict.ANSWER)

    assert wrong_abstention == expected["wrong_abstention"]
    assert same_doc == expected["same_doc"]
    assert cross_doc == expected["cross_doc"]

    # And the file's own recorded counts agree, so the expectation above is not a
    # number this test invented.
    recorded = cycle["counts"]
    assert recorded["wrong_abstention"] == expected["wrong_abstention"]
    assert recorded["unsupported_answer"]["same_doc"] == expected["same_doc"]
    assert recorded["unsupported_answer"]["cross_doc"] == expected["cross_doc"]


def test_the_same_config_repeat_is_stable_under_v2_and_v3_but_not_under_v1():
    """The measured finding that shapes the variance band -- asserted, not remembered.

    Cycle 1 and cycle 2 are the same model, pipeline, corpus and probes. 28 of 90 reply
    slots differ byte-for-byte between them: the model's TEXT is nondeterministic. Its
    ABSTENTION BEHAVIOUR is not -- under v2 and v3, every one of the 90 slots classifies
    identically across the two runs.

    Under v1 nine slots flip, in both directions, and every flip is the trailing-period
    form. So the "benign nondeterminism" visible in the published v1 numbers is very
    largely v1's own defect, not the model's variability.

    Why this matters beyond bookkeeping: a variance band calibrated under v1 would
    declare roughly 2/30 per arm to be expected noise, and would then be unable to see a
    real change of that size. The instrument does not merely measure the noise floor --
    it sets it.
    """
    a = _index(_load_cycle(BASELINE_CYCLE))
    b = _index(_load_cycle(REPEAT_CYCLE))
    common = sorted(set(a) & set(b))
    assert len(common) == 90

    text_differs = [k for k in common if a[k] != b[k]]
    assert len(text_differs) == 28, "the fixtures' byte-level nondeterminism moved"

    flips = {v: [k for k in common
                 if RefusalInstrument(v).classify(a[k]) != RefusalInstrument(v).classify(b[k])]
             for v in ("v1", "v2", "v3")}

    assert len(flips["v1"]) == 9
    assert flips["v2"] == [], "v2 is no longer stable across the same-config repeat"
    assert flips["v3"] == [], "v3 is no longer stable across the same-config repeat"

    # every v1 flip is the trailing-punctuation form, not genuine behavioural movement
    for k in flips["v1"]:
        forms = {a[k].strip(), b[k].strip()}
        assert any(f.rstrip(".!;:,").strip() == SENTINEL for f in forms), (
            f"a v1 flip that is not the trailing-punctuation form: {forms!r}")
