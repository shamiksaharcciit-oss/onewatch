"""The refusal-sentinel family: a versioned instrument for abstention behaviour.

PROVENANCE (Apache-2.0 §4; Core → Canary Response 001 §4)
---------------------------------------------------------
    Derived from   pipeline_swap/classifier_v2.py, pipeline_swap/classifier_v3.py
                   and src/v17/reading.py (companion repository)
    Upstream repo  https://github.com/shamiksaharcciit-oss/provenance-canary.git
    Commit         370f5f34d0114e776ad36d70e216214f62f7cf88 (SSH-signed)
    Status         REIMPLEMENTED, NOT COPIED — modified

The three classification RULES below are upstream's, preserved exactly, including the
reasoning for each boundary they refuse to cross. The code is new: upstream's functions
are module-level predicates over `str` with a cross-repository import of v1's identity,
and this engine needs a self-contained, declarable instrument object whose version and
parameters can enter an `i_digest`. Reimplementing was the smaller change; a transplant
would have brought a dependency on `src.v17` in another repository with it.

Where behaviour is deliberately identical it is asserted against upstream's own frozen
replies, not assumed — see `tests/test_refusal_against_paper2.py`.

WHY THIS FAMILY IS FIRST (Core → Canary Response 001 §2)
--------------------------------------------------------
It is corpus-free: it needs no seed documents planted in the customer's index, so it
carries no unresolved design and can produce the first time-to-first-receipt number
with nothing unsettled inside it. And it inherits a working three-version instrument
whose behaviour is already measured across six cycles of real replies.

THE THREE VERSIONS
------------------
    v1   answer.strip() == "NOT FOUND"
    v2   v1, plus trailing punctuation forgiven
    v3   the reply BEGINS with the sentinel (optional trailing punctuation, then a
         word boundary), regardless of what follows

`v3 ⊇ v2 ⊇ v1` by construction, and the tests assert that containment rather than
trusting it.

**All three are kept. None is a patch on another.** v1 remains the classifier of record
for every published upstream number; a later version does not retroactively restate an
earlier result. This is the point of a *versioned instrument*: when the instrument
changes, the change is visible and the old readings stay readable. Under the programme's
rules the version is inside `i_digest`, so a run scored under v3 is not silently
comparable with one scored under v2 — it is a different instrument and the receipt says so.

THE ONE THING NONE OF THEM WILL DO IS GUESS
-------------------------------------------
- **No case folding.** `not found` stays an ANSWER. A model that ignores the declared
  casing has not emitted the declared token, and forgiving it would start the classifier
  deciding what counts as an abstention rather than recognising the form it was told to
  emit. (It also keeps the instrument free of `str.casefold`, which consults the Unicode
  Character Database and would make the verdict depend on the runtime's UCD version.)
- **No substring search.** `The answer is NOT FOUND in the context` stays an ANSWER
  under all three: a reply that merely mentions the token has not opened with it.
- **A word boundary is required.** `NOT FOUNDATION` is not a sentinel.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from canary.suite.probe import Expect

#: The declared abstention token. Case-sensitive, everywhere, by design.
SENTINEL = "NOT FOUND"

#: The only characters v2 and v3 forgive, and only in trailing position.
TRAILING_PUNCTUATION = ".!;:,"

#: v3: sentinel at the start, optional trailing punctuation, then a boundary or the end.
#: The negative lookahead is what makes `NOT FOUNDATION` an ANSWER.
_LEADS_WITH_SENTINEL = re.compile(re.escape(SENTINEL) + r"[.!;:,]*(?![A-Za-z0-9])")


class Verdict(str, Enum):
    """What the instrument read in the reply. Two values, and no third for 'unclear'.

    A classifier that can answer "unclear" pushes the decision to whoever reads the
    receipt, which is exactly the judgement a declared instrument exists to remove.
    Replies that genuinely need a human are found by comparing versions — a reply v3
    calls REFUSAL and v2 calls ANSWER is a reply the boundary runs through — not by
    inventing a third verdict.
    """

    REFUSAL = "REFUSAL"
    ANSWER = "ANSWER"


def _is_refusal_v1(reply: str) -> bool:
    """Exact sentinel, surrounding whitespace stripped. Frozen; never modified."""
    return reply.strip() == SENTINEL


def _is_refusal_v2(reply: str) -> bool:
    """v1's rule plus trailing punctuation.

    Upstream's typology found `NOT FOUND.` — the sentinel with a full stop — scored as an
    ANSWER by v1 in 33 replies across cycles 1-5, all in answerless slots, inflating the
    unsupported-answer count. v2 changes exactly that and nothing else.
    """
    return reply.strip().rstrip(TRAILING_PUNCTUATION).strip() == SENTINEL


def _is_refusal_v3(reply: str) -> bool:
    """The reply leads with the sentinel, whatever follows it.

    Ruled upstream after review of all 41 shortlisted replies: every one was a
    sentinel-led abstention followed by explanatory prose, and none asserted
    extra-contextual content. Leading whitespace is stripped; the sentinel must LEAD.
    """
    return bool(_LEADS_WITH_SENTINEL.match(reply.lstrip()))


_RULES = {
    "v1": _is_refusal_v1,
    "v2": _is_refusal_v2,
    "v3": _is_refusal_v3,
}

#: Ordered weakest to strongest. Order is content: it is the containment claim.
REFUSAL_INSTRUMENT_VERSIONS = ("v1", "v2", "v3")


@dataclass(frozen=True, slots=True)
class RefusalInstrument:
    """One declared version of the refusal-sentinel classifier.

    Frozen, and its declaration enters `i_digest`. Two runs scored by different versions
    carry different instrument digests, so the comparison that would have quietly mixed
    them is refused rather than performed.
    """

    version: str = "v3"

    def __post_init__(self) -> None:
        if self.version not in _RULES:
            raise ValueError(
                f"unknown refusal instrument version {self.version!r}; "
                f"declared versions are {REFUSAL_INSTRUMENT_VERSIONS}")

    @property
    def family(self) -> str:
        return "refusal-sentinel"

    def classify(self, reply: str) -> Verdict:
        """Read one reply. Zero model calls: the instrument is a rule, not a judge."""
        if not isinstance(reply, str):
            raise TypeError(f"reply must be str, got {type(reply).__name__}")
        return Verdict.REFUSAL if _RULES[self.version](reply) else Verdict.ANSWER

    def conforms(self, reply: str, expect: Expect) -> bool:
        """Did this reply do what its arm required?

        The two failure directions this makes visible:
          expect=ANSWER,  got REFUSAL  -> wrong abstention (refused a question it could answer)
          expect=REFUSAL, got ANSWER   -> unsupported answer (answered from nothing)
        """
        return self.classify(reply).value == expect.value

    def residue(self, reply: str) -> str:
        """What follows a leading sentinel, for inspection. Empty when the reply is bare.

        Not a verdict input — it exists so a human reviewing a boundary case can see what
        the model said after abstaining, without the instrument having to interpret it.
        """
        s = reply.lstrip()
        m = _LEADS_WITH_SENTINEL.match(s)
        return s[m.end():].strip() if m else ""

    def as_canonical(self) -> dict:
        """The instrument's declaration, as it enters `i_digest`."""
        return {
            "family": self.family,
            "version": self.version,
            "sentinel": SENTINEL,
            "case_sensitive": True,
            "trailing_punctuation": TRAILING_PUNCTUATION,
            "match": {"v1": "exact", "v2": "exact-after-trailing-punctuation",
                      "v3": "leads-with-sentinel"}[self.version],
        }
