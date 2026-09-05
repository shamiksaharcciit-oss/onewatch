"""The retrieval-grounded probe family: packages, the census gate, and exclusion-with-cause.

This is the family Q01(a) ratified. It reuses the refusal-sentinel instrument unchanged and
adds nothing to the classifier, because the seed pack's advantage is not a better reader of
replies — it is **provenance-verified ground truth for the arms**. In a corpus-free family,
"this question is answerless" is a design assumption. Here it is a computation over
documents we planted and can re-read.

THE THREE ARMS, AND WHY EACH IS PROVABLE HERE
---------------------------------------------
`ANSWER_BEARING`  the fact is in a seed document. Refusing is a **wrong abstention** —
                  and, in this family specifically, evidence that the document stopped
                  being retrieved. This is the "it stopped finding what it used to find"
                  signal that corpus-free families cannot produce.

`SAME_DOC`        answerless, with a decoy attribute for the *same entity* in the document.
                  The document talks about the entity and does not answer the question.
                  Answering is an **unsupported answer** drawn from an adjacent fact.

`CROSS_DOC`       answerless, with the decoy in a document where the entity never appears.
                  Answering means the system stitched two documents together.

Every one of those three claims is checked by `SeedCorpus.census()` against the document
text before the package is allowed to exist. A package the census cannot justify is
**excluded, with its cause recorded** — never silently dropped.

WHY EXCLUSIONS ARE A DELIVERABLE AND NOT A LOG LINE
----------------------------------------------------
A builder that quietly discards what it cannot justify produces a clean run over an unknown
subset, and the denominator moves without anyone deciding it should. So exclusions are
returned with the generation, carried into the declaration, and covered by the digest: the
reader sees both what was built and what was refused, and can tell the difference between
"thirty probes because thirty were wanted" and "thirty probes because eleven were thrown
away".

WHAT THIS FAMILY DOES NOT CLAIM
-------------------------------
**Seed-grounded probes prove properties of the seed documents' retrieval, and the claim is
scoped to that.** A system that regressed on the customer's own documents while still
serving the seed pack correctly passes this family completely. That limit is inherent to
probing from outside the endpoint and is stated wherever the family appears.
"""
from __future__ import annotations

from dataclasses import dataclass

from canary.acj import digest_obj
from canary.suite.corpus import Fact, SeedCorpus, build_seed_corpus
from canary.suite.probe import Arm, Probe, ProbeSuite

FAMILY = "retrieval-grounded"

#: The instruction wrapper. Identical in shape to the corpus-free families' framing so the
#: refusal-sentinel instrument reads these replies under exactly the rules it was
#: calibrated on -- a probe family that quietly changed the answer format would be
#: measuring the format change instead of the retrieval change.
_TEMPLATE = (
    "Answer the question using ONLY the documents available to you. Do not use outside "
    "knowledge.\nIf the documents do not contain the answer, reply with exactly: NOT FOUND"
    "\n\nQuestion: {question}"
)


@dataclass(frozen=True, slots=True)
class Exclusion:
    """One package the census refused, and why.

    `cause` is a sentence, not a code. The reader of a generation declaration is a human
    deciding whether to trust a denominator, and "excluded: E07" tells them nothing they
    can act on.
    """

    entity: str
    attribute: str
    arm: str
    cause: str

    def as_canonical(self) -> dict:
        return {"arm": self.arm, "attribute": self.attribute, "cause": self.cause,
                "entity": self.entity}


@dataclass(frozen=True, slots=True)
class RetrievalGeneration:
    """A built retrieval family: the corpus, the suite, and what was refused.

    The corpus digest is carried separately from the suite digest and both enter the
    declaration. They answer different questions: the suite digest says which questions were
    asked, the corpus digest says which documents made those questions answerable. A run
    where the suite held still and the seed pack was edited is a different instrument, and
    only the corpus digest makes that visible.
    """

    generation_id: str
    corpus: SeedCorpus
    suite: ProbeSuite
    exclusions: tuple[Exclusion, ...]

    def as_canonical(self) -> dict:
        return {
            "corpus_digest": self.corpus.digest,
            "exclusions": [e.as_canonical() for e in self.exclusions],
            "family": FAMILY,
            "generation_id": self.generation_id,
            "n_excluded": len(self.exclusions),
            "n_probes": len(self.suite),
            "suite_digest": self.suite.digest,
        }

    @property
    def digest(self) -> str:
        return digest_obj(self.as_canonical())

    def headroom_note(self) -> str:
        """The sentence a report must carry beside any result from this family."""
        return ("Seed-grounded probes prove properties of the seed documents' retrieval; "
                "the claim is scoped to that and says nothing about the rest of the corpus.")


def _answer_bearing(corpus: SeedCorpus, fact: Fact) -> tuple[Probe | None, str]:
    """The fact is planted. Census must find it in exactly the document that claims it."""
    carriers = corpus.census(fact.entity, fact.attribute)
    if fact.doc_id not in carriers:
        return None, (f"census could not find the statement in {fact.doc_id}, which the "
                      f"fact record claims carries it; the corpus and its record disagree")
    if len(carriers) != 1:
        return None, (f"the statement appears in {len(carriers)} documents {carriers}; an "
                      f"answer-bearing probe must be grounded in exactly one, or a "
                      f"retrieval failure on one document is masked by the other")
    return Probe(probe_id=f"{fact.doc_id}::{_slug(fact.entity)}::answer",
                 family=FAMILY, arm=Arm.ANSWER_BEARING,
                 query=_TEMPLATE.format(question=fact.question)), ""


def _answerless(corpus: SeedCorpus, entity: str, attribute: str, arm: Arm,
                decoy: Fact) -> tuple[Probe | None, str]:
    """The question must be unanswerable from the WHOLE seed pack, not merely from one doc.

    This is the census gate doing the work the family exists for. If any planted document
    answers the question, the probe's arm is wrong and the probe would punish a system for
    behaving correctly -- the worst failure a monitor can have, because it manufactures an
    incident.
    """
    carriers = corpus.census(entity, attribute)
    if carriers:
        return None, (f"the seed pack answers this question in {carriers}; an answerless "
                      f"arm here would score a correct answer as an unsupported one")

    if arm is Arm.CROSS_DOC:
        # The decoy must sit where the entity never appears, or the probe is a same-doc
        # probe wearing a cross-doc label and the two arms stop measuring different things.
        if entity.lower() in corpus.document(decoy.doc_id).text.lower():
            return None, (f"the decoy document {decoy.doc_id} mentions {entity!r}, so this "
                          f"is a same-doc probe mislabelled as cross-doc")
    else:
        if decoy.doc_id not in corpus.mentions_entity(entity):
            return None, (f"the decoy document {decoy.doc_id} does not mention {entity!r}, "
                          f"so this is a cross-doc probe mislabelled as same-doc")

    question = f"What is the {attribute} of the {entity}?"
    return Probe(probe_id=f"{decoy.doc_id}::{_slug(entity)}::{arm.value}",
                 family=FAMILY, arm=arm,
                 query=_TEMPLATE.format(question=question)), ""


def build_retrieval_generation(generation_id: str, seed: str, n_documents: int = 6,
                               facts_per_document: int = 2) -> RetrievalGeneration:
    """Build the family: seed the corpus, construct packages, gate every one on the census.

    Deterministic from the seed, like every other generation here. The seed is the secret
    and the digests are the public commitment; `CANARY_GEN_SEED` is supplied from outside
    the repository and appears in no artifact.
    """
    corpus = build_seed_corpus(f"{generation_id}-corpus", seed,
                              n_documents=n_documents,
                              facts_per_document=facts_per_document)
    probes: list[Probe] = []
    exclusions: list[Exclusion] = []

    def consider(probe_and_cause, entity: str, attribute: str, arm: Arm) -> None:
        probe, cause = probe_and_cause
        if probe is None:
            exclusions.append(Exclusion(entity=entity, attribute=attribute,
                                        arm=arm.value, cause=cause))
        else:
            probes.append(probe)

    facts = list(corpus.facts)
    by_doc: dict[str, list[Fact]] = {}
    for fact in facts:
        by_doc.setdefault(fact.doc_id, []).append(fact)

    for fact in facts:
        consider(_answer_bearing(corpus, fact), fact.entity, fact.attribute,
                 Arm.ANSWER_BEARING)

        # SAME_DOC: ask this entity about an attribute carried by a SIBLING in the same
        # document. The document names the entity and holds a plausible-looking number for
        # a different question -- the strongest available pull toward an unsupported answer.
        # A decoy whose attribute is the target entity's OWN attribute would make the
        # question answerable, and the census would (correctly) refuse the package. Filter
        # those out here so exclusions record structural shortages rather than avoidable
        # self-collisions -- while leaving the census as the backstop that decides.
        siblings = [f for f in by_doc[fact.doc_id]
                    if f.entity != fact.entity and f.attribute != fact.attribute]
        if not siblings:
            exclusions.append(Exclusion(
                entity=fact.entity, attribute="(no sibling)", arm=Arm.SAME_DOC.value,
                cause=f"{fact.doc_id} offers no sibling fact with a different attribute, "
                      f"so no same-document decoy exists; raise facts_per_document or "
                      f"widen the attribute vocabulary to build this arm"))
        else:
            decoy = siblings[0]
            consider(_answerless(corpus, fact.entity, decoy.attribute, Arm.SAME_DOC, decoy),
                     fact.entity, decoy.attribute, Arm.SAME_DOC)

        # CROSS_DOC: ask this entity about an attribute that exists only in a document
        # where the entity is never named. Answering means two documents were stitched.
        elsewhere = [f for f in facts
                     if f.doc_id != fact.doc_id
                     and f.attribute != fact.attribute
                     and fact.entity.lower() not in corpus.document(f.doc_id).text.lower()]
        if not elsewhere:
            exclusions.append(Exclusion(
                entity=fact.entity, attribute="(no remote decoy)", arm=Arm.CROSS_DOC.value,
                cause="no document lacks this entity while carrying a usable decoy; the "
                      "seed pack is too small for a cross-document arm"))
        else:
            decoy = elsewhere[0]
            consider(_answerless(corpus, fact.entity, decoy.attribute, Arm.CROSS_DOC, decoy),
                     fact.entity, decoy.attribute, Arm.CROSS_DOC)

    if not probes:
        raise ValueError(
            f"{generation_id}: the census excluded every candidate package. Causes:\n" +
            "\n".join(f"  {e.arm} {e.entity}/{e.attribute}: {e.cause}" for e in exclusions))

    suite = ProbeSuite(suite_id=generation_id, version=generation_id,
                       probes=tuple(probes))
    return RetrievalGeneration(generation_id=generation_id, corpus=corpus, suite=suite,
                               exclusions=tuple(exclusions))


def _slug(text: str) -> str:
    return text.replace(" ", "-").lower()
