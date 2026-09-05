"""Probes and suites: frozen, content-addressed, and hostile to silent edits.

A probe set that can be edited between runs is not an instrument, it is a moving
target. Everything here is immutable at the type level and content-addressed at the
digest level, so that "the suite changed" is a fact the receipt states rather than a
possibility the reader has to rule out.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterator

from canary.acj import digest_obj


class Arm(str, Enum):
    """Which direction of the two-direction measurement a probe tests.

    The pair is the point. A monitor that only checks whether a system refuses when it
    should can be satisfied by a system that refuses everything; a monitor that only
    checks whether it answers when it should can be satisfied by one that answers
    everything. Both failures are common and neither is visible from one direction.
    """

    #: The corpus contains the answer. Refusing here is a WRONG ABSTENTION.
    ANSWER_BEARING = "answer_bearing"
    #: Answerless, with a decoy in the same document. Answering is an UNSUPPORTED ANSWER.
    SAME_DOC = "same_doc"
    #: Answerless, with the decoy in a different document. Answering is unsupported.
    CROSS_DOC = "cross_doc"


class Expect(str, Enum):
    """What a conforming system does with this probe."""

    ANSWER = "ANSWER"
    REFUSAL = "REFUSAL"


#: Which expectation each arm carries. Declared once, here, rather than recomputed at
#: every call site — an arm whose expectation varies by caller is not an arm.
ARM_EXPECTATION = {
    Arm.ANSWER_BEARING: Expect.ANSWER,
    Arm.SAME_DOC: Expect.REFUSAL,
    Arm.CROSS_DOC: Expect.REFUSAL,
}


@dataclass(frozen=True, slots=True)
class Probe:
    """One question put to the target, with the answer the arm requires.

    Frozen and slotted: a probe cannot be mutated after the suite is sealed, and
    cannot grow an attribute that the digest would not cover.
    """

    probe_id: str
    family: str
    arm: Arm
    query: str

    def __post_init__(self) -> None:
        if not self.probe_id or not self.probe_id.strip():
            raise ValueError("probe_id must be a non-empty identifier")
        if not self.query:
            raise ValueError(f"{self.probe_id}: query must not be empty")
        if not isinstance(self.arm, Arm):
            raise TypeError(f"{self.probe_id}: arm must be an Arm, got {type(self.arm).__name__}")

    @property
    def expect(self) -> Expect:
        """Derived from the arm, never stored.

        A stored expectation could disagree with its arm — two sources of truth for one
        fact, and no way for a reader to tell which one the run actually used.
        """
        return ARM_EXPECTATION[self.arm]

    def as_canonical(self) -> dict:
        """The probe as it enters a digest preimage. Enum values render as their strings."""
        return {
            "probe_id": self.probe_id,
            "family": self.family,
            "arm": self.arm.value,
            "query": self.query,
            "expect": self.expect.value,
        }


@dataclass(frozen=True, slots=True)
class ProbeSuite:
    """A frozen, versioned, content-addressed probe set.

    `suite_id` and `version` name the generation; `digest` identifies its exact content.
    Both are needed and neither substitutes for the other: the name is what a human
    schedules a run against, the digest is what a verifier checks. A suite whose name
    stayed the same while its content moved is precisely the silent drift this design
    exists to make impossible.
    """

    suite_id: str
    version: str
    probes: tuple[Probe, ...]

    def __post_init__(self) -> None:
        if not self.probes:
            raise ValueError(f"{self.suite_id}: a suite with no probes measures nothing")
        seen: dict[str, Probe] = {}
        for p in self.probes:
            key = f"{p.probe_id}::{p.arm.value}"
            if key in seen:
                raise ValueError(
                    f"{self.suite_id}: duplicate probe {key}. A duplicated probe is "
                    f"counted twice, which silently reweights the denominator.")
            seen[key] = p

    def __iter__(self) -> Iterator[Probe]:
        return iter(self.probes)

    def __len__(self) -> int:
        return len(self.probes)

    @property
    def families(self) -> tuple[str, ...]:
        """Distinct families present, in first-seen order."""
        out: list[str] = []
        for p in self.probes:
            if p.family not in out:
                out.append(p.family)
        return tuple(out)

    def arm_counts(self) -> dict[str, int]:
        """Probes per arm. The denominators, declared before any run touches them."""
        counts = {a.value: 0 for a in Arm}
        for p in self.probes:
            counts[p.arm.value] += 1
        return counts

    def as_canonical(self) -> dict:
        """The suite as it enters the instrument digest.

        Probes are canonicalised **in declared order, not sorted**. Order is content
        here: two suites holding the same probes in a different order are different
        instruments, because a reader comparing them position-by-position would be
        comparing different things.
        """
        return {
            "suite_id": self.suite_id,
            "version": self.version,
            "n_probes": len(self.probes),
            "arm_counts": self.arm_counts(),
            "probes": [p.as_canonical() for p in self.probes],
        }

    @property
    def digest(self) -> str:
        """SHA-256 over the suite's canonical bytes. This is what the receipt cites."""
        return digest_obj(self.as_canonical())
