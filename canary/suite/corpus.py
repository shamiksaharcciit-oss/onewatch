"""The seed pack: a sub-corpus the canary owns, and the provenance computation over it.

WHAT THIS BUYS, AND WHAT IT COSTS
---------------------------------
Corpus-free families (refusal-sentinel, format) ask questions and read the shape of the
answer. They can tell you behaviour changed. They cannot tell you the system *stopped
finding what it used to find*, because they have no way to know what was findable.

A retrieval probe needs ground truth about the index, and there are only three ways to get
it. Two are bad. **(c)** ask the customer for question/answer pairs — the ground truth
becomes an assertion, and "provable property of the input" was the whole differentiator.
**(b)** give up and stay corpus-free. **(a)** plant a small set of documents at onboarding
that the canary owns outright, and compute ground truth over *those*.

Core → Canary Response 001 §2 ruled **(a)**, and amended the charter sentence to say so:

    "endpoint-level at run time, zero pipeline integration; at most a one-time
    seed-document onboarding act — content placed in the corpus, never code placed
    in the pipeline."

That is the cost, stated plainly: one onboarding act. No SDK, no hook, no deploy, no change
to the customer's code path — documents into a corpus, and nothing else, ever.

THE ANTI-OVERCLAIM BOUNDARY, WHICH TRAVELS WITH THIS FAMILY EVERYWHERE
----------------------------------------------------------------------
**Seed-grounded probes prove properties of the *seed documents'* retrieval, and the claim
is scoped to that.** If the seed documents stop being retrieved, this family says so. It
does **not** license any statement about the rest of the corpus, and a system that
regressed on customer documents while still serving the seed pack correctly would pass.
That is a real limit, it is not fixable from outside the endpoint, and every artifact that
mentions this family states it.

WHY GROUND TRUTH IS COMPUTED AND NEVER DECLARED
-----------------------------------------------
The temptation is to build a document, write down "this document answers Q", and move on.
Then an edit to the generator changes the document, the note stays, and the probe is
quietly measuring something else — the ground truth having become an assertion again, by
drift rather than by design.

So the corpus carries no hand-written answer key. `census()` reads the documents and
reports which of them contain a fact, and every probe's arm is justified by that reading at
construction time. A package that the census cannot justify is **excluded with its cause
recorded**, never silently dropped: a corpus builder that discards what it cannot explain
reports a clean run over an unknown subset.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterator

from canary.acj import digest_obj

#: Vocabulary for synthetic entities. Deliberately drab and technical: seed documents sit
#: in a customer's real corpus, so they must be inert, unmemorable, and impossible to
#: mistake for genuine content — while still being distinctive enough that a retrieval
#: system has something to match on.
_ADJS = ("marlin", "isolde", "kestrel", "pergola", "tundra", "vellum", "quartz",
         "orrery", "basalt", "cinder", "juniper", "lattice", "meridian", "nocturne")
_NOUNS = ("cache", "planner", "shard", "ledger", "relay", "digest", "warden",
          "conduit", "beacon", "harbour", "gantry", "trellis")

#: Attributes an entity may carry. Each is a (name, unit) pair; the value is a number, so
#: a grounded answer is checkable by a reader without interpretation.
_ATTRS = (("eviction high-water mark", "percent"), ("retry ceiling", "attempts"),
          ("shard fan-out", "partitions"), ("flush interval", "seconds"),
          ("queue depth limit", "entries"), ("lease duration", "minutes"),
          ("compaction threshold", "percent"), ("batch window", "milliseconds"))


def _stream(seed: str, salt: str) -> Iterator[int]:
    """A deterministic byte stream. `hashlib`, not `random`.

    Identical in construction and in reason to `canary.suite.generation._rng_stream`:
    `random.Random(seed)` is reproducible only for a given CPython implementation of the
    Mersenne generator, while SHA-256 is specified. A seed corpus must rebuild
    byte-for-byte on any runtime, or the digest a receipt cites means nothing off this
    machine.
    """
    counter = 0
    while True:
        for byte in hashlib.sha256(f"{seed}|{salt}|{counter}".encode("utf-8")).digest():
            yield byte
        counter += 1


def _pick(stream: Iterator[int], options: tuple):
    return options[next(stream) % len(options)]


def _number(stream: Iterator[int], lo: int, hi: int) -> int:
    return lo + ((next(stream) << 8 | next(stream)) % (hi - lo + 1))


def statement_prefix(entity: str, attribute: str) -> str:
    """The exact opening of the sentence that asserts (entity, attribute).

    The census matches on this rather than on the entity and attribute separately, and the
    difference is not cosmetic. A document holding

        The lattice shard uses a batch window of 31 milliseconds.
        The lattice relay uses a lease duration of 13 minutes.

    contains "lattice shard" and contains "lease duration", so a two-substring test reports
    that it answers "what is the lease duration of the lattice shard?" -- which it does not.
    The first version of `census` did exactly that, and it would have justified answerless
    arms against a document that genuinely lacked the fact, producing probes whose expected
    behaviour was wrong. Co-occurrence in a document is not a statement.
    """
    return f"The {entity} uses a {attribute} of"


@dataclass(frozen=True, slots=True)
class Fact:
    """One (entity, attribute) → value statement, and the document that carries it.

    The unit of provenance. Ground truth in this family is always "which document contains
    this fact", never "what is the answer to this question" — the second is a claim about
    the world, the first is a claim about bytes we planted and can re-read.
    """

    entity: str
    attribute: str
    value: int
    unit: str
    doc_id: str

    @property
    def question(self) -> str:
        return f"What is the {self.attribute} of the {self.entity}?"

    @property
    def sentence(self) -> str:
        return f"{statement_prefix(self.entity, self.attribute)} {self.value} {self.unit}."

    def as_canonical(self) -> dict:
        return {"attribute": self.attribute, "doc_id": self.doc_id, "entity": self.entity,
                "unit": self.unit, "value": self.value}


@dataclass(frozen=True, slots=True)
class SeedDocument:
    """One planted document. Content-addressed; its text is its identity.

    `text` is what goes into the customer's corpus verbatim. Nothing derived from it is
    stored alongside it — a cached fact list would be a second source of truth about a
    document, and the two would eventually disagree.
    """

    doc_id: str
    text: str

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    def as_canonical(self) -> dict:
        return {"doc_id": self.doc_id, "text": self.text}


@dataclass(frozen=True, slots=True)
class SeedCorpus:
    """The planted sub-corpus, its facts, and the provenance computation over both.

    `facts` is not an answer key. It is the record of what the builder *wrote*, and
    `census()` independently re-reads the documents to confirm it — so a generator change
    that moved a fact out of a document is caught rather than inherited.
    """

    corpus_id: str
    documents: tuple[SeedDocument, ...]
    facts: tuple[Fact, ...]

    def __post_init__(self) -> None:
        if not self.documents:
            raise ValueError(f"{self.corpus_id}: an empty seed pack grounds nothing")
        ids = [d.doc_id for d in self.documents]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{self.corpus_id}: duplicate doc_id in the seed pack")
        known = set(ids)
        for fact in self.facts:
            if fact.doc_id not in known:
                raise ValueError(
                    f"{self.corpus_id}: fact for {fact.entity!r} cites unknown document "
                    f"{fact.doc_id!r}")

    def document(self, doc_id: str) -> SeedDocument:
        for doc in self.documents:
            if doc.doc_id == doc_id:
                return doc
        raise KeyError(doc_id)

    def census(self, entity: str, attribute: str) -> tuple[str, ...]:
        """Which planted documents actually contain this (entity, attribute) statement.

        **This re-reads the document text.** It does not consult `facts`, which is exactly
        the point: `facts` records what the builder intended to write and the census
        records what is there. Where they disagree, the census wins and the package is
        excluded — the alternative is a probe whose arm was justified by a note rather than
        by the corpus it claims to be grounded in.

        Returns doc_ids in declared order, so the result is stable across runs.
        """
        needle = statement_prefix(entity, attribute).lower()
        return tuple(doc.doc_id for doc in self.documents
                     if needle in doc.text.lower())

    def mentions_entity(self, entity: str) -> tuple[str, ...]:
        """Documents naming the entity at all, whatever they say about it.

        Used by the cross-doc arm, whose decoy must live somewhere the entity does *not*
        appear — otherwise the probe is not testing what its arm claims.
        """
        needle = entity.lower()
        return tuple(doc.doc_id for doc in self.documents if needle in doc.text.lower())

    def as_canonical(self) -> dict:
        return {
            "corpus_id": self.corpus_id,
            "n_documents": len(self.documents),
            "documents": [d.as_canonical() for d in self.documents],
            "facts": [f.as_canonical() for f in self.facts],
        }

    @property
    def digest(self) -> str:
        """The corpus's content address. Enters the instrument digest with the suite.

        A seed pack that changed — a document edited, a fact moved, one more planted — is a
        different instrument, and this digest is what makes that visible rather than
        arguable.
        """
        return digest_obj(self.as_canonical())


def build_seed_corpus(corpus_id: str, seed: str, n_documents: int = 6,
                      facts_per_document: int = 2) -> SeedCorpus:
    """Build a seed pack deterministically from a secret seed.

    Same secrecy resolution as the probe generations: **the seed is the secret, the digest
    is the public commitment.** A verifier holding the seed rebuilds this corpus
    byte-for-byte and confirms which sub-corpus a receipt was computed against; a verifier
    without it sees only the digest. The seed is supplied from outside the repository and
    appears in no artifact.

    Entities are unique across the pack. That is a construction constraint rather than a
    stylistic one: the cross-doc arm needs entities that appear in exactly one document,
    and an entity drawn twice would silently break the arm it was drawn for.
    """
    if n_documents < 2:
        raise ValueError(
            "a seed pack needs at least two documents: the cross-doc arm places a decoy "
            "in a document the entity does not appear in, and one document cannot do that")
    capacity = len(_ADJS) * len(_NOUNS)
    wanted = n_documents * facts_per_document
    if wanted > capacity:
        raise ValueError(
            f"{wanted} entities requested but only {capacity} distinct names exist; widen "
            f"_ADJS/_NOUNS rather than allowing a collision, which would break the "
            f"cross-doc arm silently")
    if facts_per_document < 1:
        raise ValueError("a document with no facts grounds nothing")

    stream = _stream(seed, corpus_id)
    used_entities: set[str] = set()
    documents: list[SeedDocument] = []
    facts: list[Fact] = []

    for doc_index in range(n_documents):
        doc_id = f"{corpus_id}-doc-{doc_index:02d}"
        lines = [f"Reference note {doc_index:02d}. Operational parameters, current cycle."]
        for _ in range(facts_per_document):
            entity = _draw_unique(
                stream, lambda: f"{_pick(stream, _ADJS)} {_pick(stream, _NOUNS)}",
                used_entities,
                "entity names exhausted; widen _ADJS/_NOUNS")
            attribute, unit = _pick(stream, _ATTRS)
            value = _number(stream, 10, 99)
            fact = Fact(entity=entity, attribute=attribute, value=value, unit=unit,
                        doc_id=doc_id)
            facts.append(fact)
            lines.append(fact.sentence)
        documents.append(SeedDocument(doc_id=doc_id, text="\n".join(lines) + "\n"))

    return SeedCorpus(corpus_id=corpus_id, documents=tuple(documents),
                      facts=tuple(facts))


def _draw_unique(stream, draw, used: set[str], exhausted: str, attempts: int = 4096) -> str:
    """Draw until the value is new, then record it. Bounded, and loud when it fails.

    An unbounded retry loop on a deterministic stream is an infinite loop waiting for a
    parameter change; a silent give-up produces a duplicate that breaks the cross-doc arm
    without breaking any test. Neither is acceptable, so this raises.
    """
    for _ in range(attempts):
        candidate = draw()
        if candidate not in used:
            used.add(candidate)
            return candidate
    raise ValueError(exhausted)
