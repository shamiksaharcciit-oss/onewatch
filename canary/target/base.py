"""What a probed system looks like from the canary's side of the wall.

The target is *the world*. It lives in `T`, it is probed from outside on a schedule,
and — this is the part that matters at verify time — **it is never re-run**. A receipt
is re-derived by replaying the comparison over frozen evidence, never by asking the
model again. If verification required the target, verification would require the
target's owner's cooperation, its continued existence, and its unchanged behaviour;
the first is a negotiation and the last is the very thing in dispute.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from canary.suite.probe import Probe


class Provenance(str, Enum):
    """Where a response's bytes actually came from. Never inferred, always carried.

    The distinction exists because this repository ships a mock whose replies are, in
    part, real recorded model output and, in part, declared synthetic transformations.
    Presenting the second as the first would be fabrication — so every response says
    which it is, and the freezer records it.
    """

    #: Real model output, recorded in a paper-2 cycle and replayed byte-for-byte.
    RECORDED = "recorded"
    #: Produced by a declared, deterministic transformation. Not a real model reply.
    SYNTHETIC = "synthetic"
    #: Received from a live endpoint during this run.
    LIVE = "live"


@dataclass(frozen=True, slots=True)
class RawResponse:
    """One reply, as RECEIVED. The bytes are evidence and are never touched.

    `body` is `bytes`, not `str`, deliberately. A `str` has already been through a
    decoder, and a decoder is a transformation: it picks an encoding, may substitute
    replacement characters, and silently discards what it could not read. The freezer
    must be able to record what actually arrived, including the case where what arrived
    was not valid UTF-8 — which is itself a behavioural change worth detecting.
    """

    probe_id: str
    arm: str
    body: bytes
    provenance: Provenance
    served_model: str
    #: Free-form, canonicalisable detail about how this response came to exist.
    source: dict

    def __post_init__(self) -> None:
        if not isinstance(self.body, bytes):
            raise TypeError(
                f"{self.probe_id}: response body must be bytes as received, got "
                f"{type(self.body).__name__}. Decoding before freezing loses the "
                f"evidence of what actually arrived.")
        if not isinstance(self.provenance, Provenance):
            raise TypeError(f"{self.probe_id}: provenance must be a Provenance")
        if not self.served_model:
            raise ValueError(
                f"{self.probe_id}: served_model must not be empty. The served model's "
                f"identity is part of what the instrument digest covers; it is recorded, "
                f"never only asserted.")

    def text(self, errors: str = "strict") -> str:
        """Decode for classification. The decode happens HERE, never before freezing.

        Default `errors='strict'`: a body that is not valid UTF-8 raises rather than
        being silently repaired into something classifiable. A reply the instrument
        cannot read is a fact about the run, not a gap to paper over.
        """
        return self.body.decode("utf-8", errors=errors)


@runtime_checkable
class Target(Protocol):
    """The whole interface. Endpoint-level, zero pipeline integration.

    Two methods, because there are exactly two things the engine needs: ask a probe,
    and record what was probed. A target that also exposed retrieval internals would
    tempt the engine into stage attribution, which is the forensics pillar's job and
    the line this pillar does not cross.
    """

    def declaration(self) -> dict:
        """What the receipt records about this target. Canonicalisable; no floats."""
        ...

    def ask(self, probe: Probe) -> RawResponse:
        """Put one probe to the system and return what came back, unmodified."""
        ...
