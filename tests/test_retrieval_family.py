"""The retrieval-grounded family: seed pack, census gate, mock endpoint, detector.

Built to **calibration-ready** and not one step past it (Core → Canary Response 010 §2-C).
Everything here runs against the deterministic mock, which Q08 ruled in scope: the line is
the live endpoint, not testing, and the whole C2 pattern is fixtures first.

**Nothing in this file has been calibrated against a live model.** A band is measured from
a same-config repeat pair of *mock* runs, which proves the calibration path executes; it
says nothing about a real system's noise floor and is not presented as if it did.
"""
from __future__ import annotations

import pytest

from canary.baseline import Declaration, calibrate, declare
from canary.detector import compare
from canary.freezer import freeze_run
from canary.suite.corpus import SeedCorpus, SeedDocument, build_seed_corpus, statement_prefix
from canary.suite.probe import Arm
from canary.suite.refusal import RefusalInstrument
from canary.suite.retrieval import FAMILY, build_retrieval_generation
from canary.target.retrieval_mock import (RetrievalChange, RetrievalMockConfig,
                                          RetrievalMockTarget)

SEED = "test-seed-not-the-real-one"
STAMP = "2026-08-27T12:00:00Z"
V3 = RefusalInstrument("v3")


@pytest.fixture(scope="module")
def generation():
    return build_retrieval_generation("rg-test", SEED, n_documents=6, facts_per_document=2)


def frozen(generation, config=None, label="run"):
    target = RetrievalMockTarget(corpus=generation.corpus,
                                 config=config or RetrievalMockConfig())
    return freeze_run(f"rg-{label}", generation.suite, target, instrument=V3)


# ----------------------------------------------------------------- the seed pack


def test_the_corpus_rebuilds_byte_for_byte_from_its_seed():
    """The secrecy resolution: the seed is the secret, the digest is the public commitment.

    A verifier holding the seed rebuilds this corpus and confirms which sub-corpus a receipt
    was computed against. If the build were not reproducible the digest would identify
    nothing, and the whole disclosure-after-retirement mechanism would have nothing to pin.
    """
    a = build_seed_corpus("c", SEED, n_documents=4, facts_per_document=2)
    b = build_seed_corpus("c", SEED, n_documents=4, facts_per_document=2)
    assert a.digest == b.digest
    assert [d.text for d in a.documents] == [d.text for d in b.documents]


def test_a_different_seed_produces_a_different_corpus():
    """Otherwise the seed is decoration and every customer gets the same planted pack."""
    a = build_seed_corpus("c", SEED, n_documents=4, facts_per_document=2)
    b = build_seed_corpus("c", SEED + "x", n_documents=4, facts_per_document=2)
    assert a.digest != b.digest


def test_entities_are_unique_across_the_pack():
    """A construction constraint the cross-doc arm depends on.

    That arm places a decoy in a document where the entity never appears. An entity drawn
    into two documents would make it unsatisfiable while every test still passed.
    """
    corpus = build_seed_corpus("c", SEED, n_documents=6, facts_per_document=3)
    entities = [f.entity for f in corpus.facts]
    assert len(entities) == len(set(entities))
    for entity in entities:
        assert len(corpus.mentions_entity(entity)) == 1, f"{entity} appears in >1 document"


def test_a_one_document_pack_is_refused():
    """The cross-doc arm needs somewhere else to put the decoy."""
    with pytest.raises(ValueError, match="at least two documents"):
        build_seed_corpus("c", SEED, n_documents=1)


# ------------------------------------------------------------------- the census


def test_the_census_reads_statements_not_co_occurrence():
    """The defect this check was written against, kept as a test.

    A document holding two sentences about two entities contains both entity names and both
    attribute names. A two-substring test reports that it answers the crossed question --
    which it does not -- and would have justified answerless arms against documents that
    genuinely lacked the fact. Co-occurrence in a document is not a statement.
    """
    corpus = SeedCorpus(
        corpus_id="c",
        documents=(
            SeedDocument("d0", "The lattice shard uses a batch window of 31 milliseconds.\n"
                               "The lattice relay uses a lease duration of 13 minutes.\n"),
            SeedDocument("d1", "Unrelated note.\n"),
        ),
        facts=(),
    )
    assert corpus.census("lattice shard", "batch window") == ("d0",)
    assert corpus.census("lattice relay", "lease duration") == ("d0",)
    # The crossed pairs: both terms present in d0, neither pair asserted by it.
    assert corpus.census("lattice shard", "lease duration") == ()
    assert corpus.census("lattice relay", "batch window") == ()


def test_the_statement_prefix_is_what_the_documents_are_written_with():
    """The census and the generator must agree on the sentence form, or the gate is blind.

    If the writer's sentence and the reader's needle ever drift apart, `census` returns
    empty for every fact, every answer-bearing package is excluded, and the family
    silently degrades to answerless-only while reporting a clean build.
    """
    corpus = build_seed_corpus("c", SEED, n_documents=3, facts_per_document=2)
    for fact in corpus.facts:
        assert statement_prefix(fact.entity, fact.attribute) in fact.sentence
        assert corpus.census(fact.entity, fact.attribute) == (fact.doc_id,)


# -------------------------------------------------------------- the census gate


def test_the_gate_refuses_an_answerless_package_the_corpus_answers():
    """The gate's whole reason to exist, shown catching something.

    An answerless arm over a question the seed pack answers would score a **correct**
    answer as an unsupported one -- a monitor manufacturing an incident, which is the worst
    failure this product can have. The gate is proved capable of refusing, not merely
    present.
    """
    from canary.suite.retrieval import _answerless
    corpus = build_seed_corpus("c", SEED, n_documents=4, facts_per_document=2)
    fact = corpus.facts[0]
    decoy = next(f for f in corpus.facts if f.doc_id != fact.doc_id)

    # Ask for a fact the pack DOES assert, on an answerless arm.
    probe, cause = _answerless(corpus, fact.entity, fact.attribute, Arm.CROSS_DOC, decoy)
    assert probe is None
    assert "the seed pack answers this question" in cause
    assert fact.doc_id in cause, "the cause must name where the answer lives"

    # And the same call for a genuinely absent pair is allowed through.
    absent = next(a for a, _ in
                  [(x.attribute, None) for x in corpus.facts]
                  if not corpus.census(fact.entity, a))
    probe, cause = _answerless(corpus, fact.entity, absent, Arm.CROSS_DOC, decoy)
    assert cause == "" and probe is not None


def test_a_cross_doc_decoy_that_mentions_the_entity_is_refused():
    """Otherwise it is a same-doc probe wearing a cross-doc label.

    The two arms would stop measuring different things, and the arm counts -- which are the
    denominators -- would describe a split that does not exist.
    """
    from canary.suite.retrieval import _answerless
    corpus = build_seed_corpus("c", SEED, n_documents=4, facts_per_document=2)
    fact = corpus.facts[0]
    home = next(f for f in corpus.facts if f.doc_id == fact.doc_id and f.entity != fact.entity)
    absent = next(a for a in (x.attribute for x in corpus.facts)
                  if not corpus.census(fact.entity, a))
    probe, cause = _answerless(corpus, fact.entity, absent, Arm.CROSS_DOC, home)
    assert probe is None and "mislabelled as cross-doc" in cause


def test_exclusions_are_carried_and_enter_the_digest():
    """A builder that silently drops what it cannot justify reports a clean run over an
    unknown subset, and the denominator moves without anyone deciding it should."""
    generation = build_retrieval_generation("rg-x", SEED, n_documents=2,
                                            facts_per_document=1)
    assert generation.exclusions, "a two-document, one-fact pack cannot build every arm"
    for exclusion in generation.exclusions:
        assert len(exclusion.cause.split()) > 4, "a cause must be a sentence, not a code"
        assert exclusion.arm in {a.value for a in Arm}
        assert exclusion.entity, "an exclusion that does not say what was excluded"
    canonical = generation.as_canonical()
    assert canonical["n_excluded"] == len(generation.exclusions)
    assert canonical["exclusions"], "exclusions must enter the digest preimage"


def test_a_generation_whose_every_package_is_excluded_raises_with_its_causes(monkeypatch):
    """Refusing to hand back an empty instrument, and saying why it is empty.

    A suite of zero probes that still built successfully would be a monitor measuring
    nothing while reporting readiness. The census is forced to refuse everything -- by
    making it claim every fact lives in two documents at once, which fails the
    answer-bearing uniqueness check and makes every answerless question look answered.
    """
    import canary.suite.retrieval as retrieval

    monkeypatch.setattr(SeedCorpus, "census",
                        lambda self, entity, attribute: ("d0", "d1"))
    with pytest.raises(ValueError) as exc:
        retrieval.build_retrieval_generation("rg-doomed", SEED, n_documents=3,
                                             facts_per_document=2)
    message = str(exc.value)
    assert "excluded every candidate package" in message
    assert "answer_bearing" in message, "the raise must carry the causes, not just a count"


# ---------------------------------------------------------- the arms are provable


def test_every_answer_bearing_probe_is_grounded_in_exactly_one_document(generation):
    """The arm's claim, re-checked against the corpus rather than trusted."""
    for probe in generation.suite:
        if probe.arm is not Arm.ANSWER_BEARING:
            continue
        entity, attribute = _parse(probe.query)
        carriers = generation.corpus.census(entity, attribute)
        assert len(carriers) == 1, (
            f"{probe.probe_id}: grounded in {len(carriers)} documents, not one")


def test_every_answerless_probe_is_unanswerable_from_the_whole_pack(generation):
    """Not merely from one document -- from every planted document there is."""
    for probe in generation.suite:
        if probe.arm is Arm.ANSWER_BEARING:
            continue
        entity, attribute = _parse(probe.query)
        assert generation.corpus.census(entity, attribute) == (), (
            f"{probe.probe_id}: the seed pack answers this; the arm is wrong")


def test_the_family_states_its_anti_overclaim_boundary(generation):
    """It travels with the family everywhere, so it is asserted where the family lives."""
    note = generation.headroom_note()
    assert "seed documents" in note and "scoped to that" in note
    module = __import__("canary.suite.retrieval", fromlist=["x"]).__doc__
    assert "scoped to that" in module


# ------------------------------------------------------------------- the mock


def test_the_clean_mock_conforms_on_every_arm(generation):
    """A mock that fails its own probes would make every later signal unreadable."""
    run = frozen(generation, label="clean")
    counts = run.counts()
    assert all(c["numerator"] == 0 for c in counts.values()), counts


def test_index_refresh_produces_wrong_abstentions_and_nothing_else(generation):
    """The signal corpus-free families cannot produce.

    Nothing about the model changed and nothing about the prompt changed. A document
    stopped being retrievable, and the only visible trace from outside the endpoint is that
    questions it used to answer are now abstained on.
    """
    dropped = generation.corpus.documents[0].doc_id
    run = frozen(generation, RetrievalMockConfig(change=RetrievalChange.INDEX_REFRESH,
                                                 dropped_doc_id=dropped), "idx")
    counts = run.counts()
    assert counts["wrong_abstention"]["numerator"] > 0
    assert counts["unsupported_answer_same_doc"]["numerator"] == 0
    assert counts["unsupported_answer_cross_doc"]["numerator"] == 0


def test_grounding_drift_produces_unsupported_answers_and_nothing_else(generation):
    """The failure that looks like helpfulness: more answers, all of them ungrounded."""
    run = frozen(generation, RetrievalMockConfig(change=RetrievalChange.GROUNDING_DRIFT),
                 "drift")
    counts = run.counts()
    assert counts["wrong_abstention"]["numerator"] == 0
    assert counts["unsupported_answer_same_doc"]["numerator"] > 0
    assert counts["unsupported_answer_cross_doc"]["numerator"] > 0


def test_format_drift_moves_the_bytes_without_moving_the_verdicts(generation):
    """The instrument-relativity case, offline and free.

    Under v3 -- which reads a leading sentinel -- an explained abstention is still an
    abstention. Under v1 it is an answer, and every answerless arm flips. Same bytes,
    different instrument, opposite verdicts, and the receipt names which one ran.
    """
    clean = frozen(generation, label="c")
    drifted = frozen(generation, RetrievalMockConfig(change=RetrievalChange.FORMAT_DRIFT),
                     "f")
    assert clean.bodies_digest != drifted.bodies_digest, "the bytes must actually differ"
    assert drifted.counts()["unsupported_answer_same_doc"]["numerator"] == 0

    v1_run = freeze_run("rg-v1", generation.suite,
                        RetrievalMockTarget(corpus=generation.corpus,
                                            config=RetrievalMockConfig(
                                                change=RetrievalChange.FORMAT_DRIFT)),
                        instrument=RefusalInstrument("v1"))
    flipped = sum(c["numerator"] for c in v1_run.counts().values())
    assert flipped > 0, "v1 must misread the explained abstention; that is the whole point"


def test_the_declaration_is_identical_across_clean_and_every_variant(generation):
    """X-7: a fault perturbs behaviour, never its declaration.

    A change that announced itself in the target declaration would let a detector 'find' it
    by reading the declaration, which measures nothing about the evidence.
    """
    configs = [
        RetrievalMockConfig(),
        RetrievalMockConfig(change=RetrievalChange.INDEX_REFRESH,
                            dropped_doc_id=generation.corpus.documents[0].doc_id),
        RetrievalMockConfig(change=RetrievalChange.GROUNDING_DRIFT),
        RetrievalMockConfig(change=RetrievalChange.FORMAT_DRIFT),
    ]
    declarations = [RetrievalMockTarget(corpus=generation.corpus, config=c).declaration()
                    for c in configs]
    assert all(d == declarations[0] for d in declarations)
    runs = [frozen(generation, c, f"x{i}") for i, c in enumerate(configs)]
    assert len({r.i_digest for r in runs}) == 1, "i_digest moved across a fault"


def test_an_index_refresh_must_name_the_document_it_drops():
    """A declared change that does not say what it changed is not a declared change."""
    with pytest.raises(ValueError, match="must name the document"):
        RetrievalMockConfig(change=RetrievalChange.INDEX_REFRESH)


def test_a_dropped_document_on_a_non_refresh_config_is_refused():
    """The author expected something this configuration will not do."""
    with pytest.raises(ValueError, match="does not drop anything"):
        RetrievalMockConfig(change=RetrievalChange.NONE, dropped_doc_id="d0")


def test_the_mock_refuses_a_probe_it_cannot_parse(generation):
    """Silently treating an unparseable probe as answerless would report a catastrophic
    retrieval failure that is really a parser fault -- the F6 shape again, failing toward
    a confident wrong answer instead of a surfaced one."""
    from canary.suite.probe import Probe
    target = RetrievalMockTarget(corpus=generation.corpus)
    bad = Probe(probe_id="p", family=FAMILY, arm=Arm.ANSWER_BEARING, query="no question here")
    with pytest.raises(ValueError, match="could not parse"):
        target.ask(bad)


# ---------------------------------------------------------------- the detector


def test_the_detector_reports_unchanged_on_a_repeat_and_changed_on_each_fault(generation):
    """End to end on the mock: baseline sealed, faults injected, verdicts read.

    The band is measured from a same-config repeat pair of MOCK runs. That proves the
    calibration path executes; it is not a claim about any live system's noise floor.
    """
    b1 = frozen(generation, label="b1")
    b2 = frozen(generation, label="b2")
    band = calibrate("refusal-sentinel", "v3", [b1, b2],
                     "same-config repeat pair, measured at baseline")
    baseline = declare("rg-baseline", b1, band,
                       Declaration(declared_by="tests", declared_at=STAMP,
                                   reason="mock dry run"))

    repeat = compare(baseline, frozen(generation, label="r")).as_canonical()
    assert repeat["outcome"] == "UNCHANGED" and repeat["n_probe_deltas"] == 0

    dropped = generation.corpus.documents[0].doc_id
    idx = compare(baseline, frozen(generation, RetrievalMockConfig(
        change=RetrievalChange.INDEX_REFRESH, dropped_doc_id=dropped), "i")).as_canonical()
    assert idx["outcome"] == "CHANGED"
    assert any("answer_bearing" in r for r in idx["reasons"])

    drift = compare(baseline, frozen(generation, RetrievalMockConfig(
        change=RetrievalChange.GROUNDING_DRIFT), "d")).as_canonical()
    assert drift["outcome"] == "CHANGED"

    fmt = compare(baseline, frozen(generation, RetrievalMockConfig(
        change=RetrievalChange.FORMAT_DRIFT), "f")).as_canonical()
    assert fmt["outcome"] == "UNCHANGED", (
        "under v3 an explained abstention is still an abstention; reporting CHANGED here "
        "would be the v1 mistake the re-scoring table exists to illustrate")


# ------------------------------------------------------- the stopping line

def test_nothing_in_this_family_can_reach_a_network():
    """Calibration-ready stops at the live endpoint. Asserted, not intended."""
    import pathlib
    banned = ("import requests", "import httpx", "import urllib.request",
              "from requests", "from httpx", "anthropic")
    root = pathlib.Path(__file__).resolve().parent.parent / "canary"
    for name in ("suite/corpus.py", "suite/retrieval.py", "target/retrieval_mock.py"):
        text = (root / name).read_text(encoding="utf-8")
        for marker in banned:
            assert marker not in text, f"{name} reaches for {marker}"


def _parse(query: str) -> tuple[str, str]:
    import re
    m = re.search(r"Question: What is the (.+?) of the (.+?)\?", query)
    assert m, f"could not parse a question from {query!r}"
    return m.group(2), m.group(1)
