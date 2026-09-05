"""A deterministic mock RAG endpoint, with declared changes the canary is meant to catch.

Fixtures first, live later — the pattern C2 established and Q08 confirmed for this family:
*"the mock is offline and free; calibration-ready draws its line at the live endpoint, not
at testing."* Everything here runs offline, costs nothing, and is reproducible byte-for-byte.

WHAT THIS MOCK IS AND IS NOT
----------------------------
It is a **declared deterministic transformation**, and every reply it produces is frozen
with `Provenance.SYNTHETIC`. It is not a language model and it is not recorded model
output; presenting its replies as either would be fabrication. What it faithfully
reproduces is the *shape* of a retrieval-augmented system as seen from outside the wall:
a question goes in, some documents are or are not retrieved, and an answer or an
abstention comes back.

That is enough to test the instrument, because the instrument only ever sees the reply.

THE CHANGES, AND WHY EACH ONE MATTERS
-------------------------------------
`INDEX_REFRESH`   one seed document silently stops being retrievable. Its answer-bearing
                  probes begin abstaining. **This is the event corpus-free families cannot
                  see** — nothing about the model changed, nothing about the prompt changed,
                  and the system now cannot find what it could find yesterday.

`GROUNDING_DRIFT` the system starts answering from an adjacent fact when it cannot find the
                  one asked for. Answer-bearing probes are unaffected; the answerless arms
                  begin producing unsupported answers. This is the failure that looks like
                  an improvement in every metric that counts answers rather than checking
                  them.

`FORMAT_DRIFT`    the abstention stops being a bare sentinel. Under refusal-sentinel `v3`
                  this is *not* a behavioural change — v3 reads a leading sentinel — while
                  under `v1` it would flip every abstention to an answer. The mock carries
                  it so the instrument-relativity case can be exercised offline, on demand,
                  without spending anything.

X-7 APPLIES HERE
----------------
**A fault perturbs behaviour, never its declaration.** The clean mock and every variant
above return the identical `declaration()`, so `i_digest` is unchanged across them. A
change that announced itself in the instrument declaration would be trivially detectable
and would prove nothing about the detector.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from canary.suite.corpus import SeedCorpus, statement_prefix
from canary.suite.probe import Probe
from canary.target.base import Provenance, RawResponse

SENTINEL = "NOT FOUND"

#: Parses the question this family generates. Anchored and specific: a loose parser that
#: silently failed to match would make every probe look answerless, and the mock would
#: report a catastrophic retrieval failure that was really a regex bug.
_QUESTION = re.compile(r"Question: What is the (?P<attribute>.+?) of the (?P<entity>.+?)\?")


class RetrievalChange(str, Enum):
    """Declared changes a run may inject. `NONE` is the clean configuration."""

    NONE = "none"
    #: One seed document drops out of the index. The retrieval-loss signal.
    INDEX_REFRESH = "index_refresh"
    #: Answers get drawn from adjacent facts when the asked-for one is missing.
    GROUNDING_DRIFT = "grounding_drift"
    #: Abstentions stop being bare sentinels.
    FORMAT_DRIFT = "format_drift"


@dataclass(frozen=True, slots=True)
class RetrievalMockConfig:
    """What the mock does. Frozen, and declared in full.

    `dropped_doc_id` is required by `INDEX_REFRESH` and forbidden otherwise, because a
    change that does not say *what* it changed is a change nobody can reason about — and a
    dropped document specified on a run that is not refreshing the index is a
    configuration whose author expected something the mock will not do.
    """

    change: RetrievalChange = RetrievalChange.NONE
    dropped_doc_id: str = ""
    served_model: str = "mock-rag-1"

    def __post_init__(self) -> None:
        if self.change is RetrievalChange.INDEX_REFRESH and not self.dropped_doc_id:
            raise ValueError(
                "INDEX_REFRESH must name the document that left the index; a retrieval "
                "loss nobody can point at is not a declared change")
        if self.change is not RetrievalChange.INDEX_REFRESH and self.dropped_doc_id:
            raise ValueError(
                f"dropped_doc_id={self.dropped_doc_id!r} is set but change is "
                f"{self.change.value}; this configuration does not drop anything and the "
                f"author expected it to")


@dataclass(frozen=True, slots=True)
class RetrievalMockTarget:
    """The endpoint. Two methods, exactly as the Target protocol requires.

    It deliberately exposes **no** view of what was retrieved. A target that offered its
    retrieval internals would tempt the engine into stage attribution, which is the
    forensics pillar's job and the line this pillar does not cross. The canary sees the
    reply, the same as any customer would.
    """

    corpus: SeedCorpus
    config: RetrievalMockConfig = field(default_factory=RetrievalMockConfig)

    def declaration(self) -> dict:
        """What the receipt records. **Identical across clean and every variant (X-7).**

        The injected change is deliberately absent. A declaration that named the fault
        would let the detector 'detect' it by reading the declaration, which measures
        nothing about the evidence.
        """
        return {
            "kind": "mock-retrieval",
            "target_id": "mock://retrieval",
            "served_model": self.config.served_model,
            "corpus_digest": self.corpus.digest,
            "n_documents": len(self.corpus.documents),
        }

    def _retrievable(self) -> tuple[str, ...]:
        if self.config.change is RetrievalChange.INDEX_REFRESH:
            return tuple(d.doc_id for d in self.corpus.documents
                         if d.doc_id != self.config.dropped_doc_id)
        return tuple(d.doc_id for d in self.corpus.documents)

    def _abstain(self) -> str:
        if self.config.change is RetrievalChange.FORMAT_DRIFT:
            # Still an abstention, and still leads with the sentinel. Under v3 this is not
            # a behavioural change; under v1 it would flip. That difference is the point.
            return f"{SENTINEL} — the available documents do not contain this information."
        return SENTINEL

    def ask(self, probe: Probe) -> RawResponse:
        """Answer from the retrievable seed documents, or abstain. No model involved."""
        match = _QUESTION.search(probe.query)
        if match is None:
            raise ValueError(
                f"{probe.probe_id}: the mock could not parse a question from this probe. "
                f"Silently treating it as answerless would report a retrieval failure that "
                f"is really a parser fault.")
        entity = match.group("entity")
        attribute = match.group("attribute")

        retrievable = self._retrievable()
        needle = statement_prefix(entity, attribute).lower()
        answer_value = None
        for doc in self.corpus.documents:
            if doc.doc_id not in retrievable:
                continue
            for line in doc.text.splitlines():
                if needle in line.lower():
                    answer_value = line.strip()
                    break
            if answer_value:
                break

        if answer_value is not None:
            body = f"{answer_value}"
        elif self.config.change is RetrievalChange.GROUNDING_DRIFT:
            # The failure that looks like helpfulness: no exact match, so answer from
            # whatever adjacent statement mentions the entity at all.
            adjacent = self._adjacent_statement(entity, retrievable)
            body = adjacent if adjacent is not None else self._abstain()
        else:
            body = self._abstain()

        return RawResponse(
            probe_id=probe.probe_id,
            arm=probe.arm.value,
            body=body.encode("utf-8"),
            provenance=Provenance.SYNTHETIC,
            served_model=self.config.served_model,
            source={"kind": "mock-retrieval", "change": self.config.change.value,
                    "n_retrievable": len(retrievable)},
        )

    def _adjacent_statement(self, entity: str, retrievable: tuple[str, ...]) -> str | None:
        """Any statement about this entity, whatever it actually says. The drift."""
        needle = f"the {entity.lower()} uses"
        for doc in self.corpus.documents:
            if doc.doc_id not in retrievable:
                continue
            for line in doc.text.splitlines():
                if needle in line.lower():
                    return line.strip()
        return None
