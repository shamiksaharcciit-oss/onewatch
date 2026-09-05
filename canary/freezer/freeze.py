"""The freezer: seal one run as `E_t`.

A run's evidence is frozen the moment it is received and never touched again. What gets
sealed is not a summary of what happened — it is what happened: the response bytes, the
instrument that read them, and the verdicts that reading produced, content-addressed so
that a third party can recompute every one of them without asking the model anything.

THE TWO DISCIPLINES, SIDE BY SIDE IN ONE FILE
---------------------------------------------
This module is where E10's two halves meet, so the split is made explicit rather than
left to the reader:

    RECEIVED   response bodies      frozen verbatim, digested as raw bytes,
                                    never decoded before digesting, never normalised
    GENERATED  the sealed structure canonicalised (ACJ v2), digested over canonical bytes

A response body is digested as `sha256(bytes)`. It is *not* canonicalised, not decoded,
not stripped, not NFC-normalised. If the endpoint returned trailing whitespace, the
receipt says it returned trailing whitespace, because next month that whitespace may be
the change.

WHAT IS NOT HERE
----------------
No rate is computed, stored, or chained. Verdict counts travel as
`(numerator, denominator, probe-set digest)` triples and a rate is a presentation-layer
artifact computed at render time (Core → Canary Response 001 §5). Denominators
legitimately move when probes retire, which is exactly why comparing two rates is a bug
and comparing two triples is not.

No comparison either: `E_t` is one run, sealed on its own terms. Comparison is the
detector's job in C3, and it operates on two sealed `E`s without ever touching a target.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from canary.acj import canonical_bytes, digest_bytes, digest_obj
from canary.quantise import QUANTISATION
from canary.suite.probe import Expect, Probe, ProbeSuite
from canary.suite.refusal import RefusalInstrument, Verdict
from canary.target.base import RawResponse, Target

#: Envelope version for the sealed structure. Bumping it is an instrument change.
FROZEN_SCHEMA = "canary/frozen-run/v1"


@dataclass(frozen=True, slots=True)
class FrozenReply:
    """One response, frozen. `body_digest` is over the bytes exactly as received."""

    probe_id: str
    arm: str
    body_digest: str
    n_bytes: int
    provenance: str
    served_model: str
    verdict: str
    expect: str
    conforms: bool
    source: dict

    def as_canonical(self) -> dict:
        return {
            "probe_id": self.probe_id,
            "arm": self.arm,
            "body_sha256": self.body_digest,
            "n_bytes": self.n_bytes,
            "provenance": self.provenance,
            "served_model": self.served_model,
            "verdict": self.verdict,
            "expect": self.expect,
            "conforms": self.conforms,
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class FrozenRun:
    """`E_t`: one sealed run.

    `bodies` holds the verbatim response bytes keyed by `(probe_id, arm)`. They are kept
    beside the sealed structure rather than inside it: the structure is canonical JSON
    and carries digests, and the bytes are evidence files addressed by those digests —
    the same separation the manifest layer makes between a manifest and the evidence it
    references.
    """

    run_id: str
    suite: ProbeSuite
    instrument: RefusalInstrument
    target_declaration: dict
    replies: tuple[FrozenReply, ...]
    bodies: dict[tuple[str, str], bytes]

    # ------------------------------------------------------------------ the instrument

    @property
    def i_digest(self) -> str:
        """The instrument digest: suite + detector config + quantisation parameters.

        This is the number that makes a magnitude citable. A detection claim is citable
        only with its instrument named, because the same frozen replies read as
        different changes under different instruments — that is not a hypothetical, it
        is what the paper-2 record shows.
        """
        return digest_obj(self.instrument_declaration())

    def instrument_declaration(self) -> dict:
        return {
            "schema": FROZEN_SCHEMA,
            "suite": {
                "suite_id": self.suite.suite_id,
                "version": self.suite.version,
                "digest": self.suite.digest,
                "n_probes": len(self.suite),
                "arm_counts": self.suite.arm_counts(),
            },
            "detector": self.instrument.as_canonical(),
            "quantisation": QUANTISATION,
        }

    # ---------------------------------------------------------------------- the counts

    def counts(self) -> dict:
        """Verdict counts as integer triples. No rate is computed here, or anywhere.

        Two named failure directions, kept apart because they are different faults:
          `wrong_abstention`   refused a question the corpus could answer
          `unsupported_answer` answered a question the corpus could not
        """
        suite_digest = self.suite.digest
        buckets = {
            "wrong_abstention": {"arms": ("answer_bearing",), "expect": Expect.ANSWER},
            "unsupported_answer_same_doc": {"arms": ("same_doc",), "expect": Expect.REFUSAL},
            "unsupported_answer_cross_doc": {"arms": ("cross_doc",), "expect": Expect.REFUSAL},
        }
        out: dict[str, dict] = {}
        for name, spec in buckets.items():
            arms = spec["arms"]
            considered = [r for r in self.replies if r.arm in arms]
            failures = [r for r in considered if not r.conforms]
            out[name] = {
                "numerator": len(failures),
                "denominator": len(considered),
                "probe_set_digest": suite_digest,
            }
        return out

    # ----------------------------------------------------------------------- the seal

    @property
    def bodies_digest(self) -> str:
        """A digest over the RECEIVED bytes alone -- no verdicts, no instrument.

        This is what answers *did anything change* about the world. `e_digest` cannot:
        it covers the whole sealed run, including the instrument's reading of the bytes,
        so re-scoring identical replies under a different classifier moves it. Both
        digests are needed and they answer different questions:

            bodies_digest   what the endpoint returned
            e_digest        what the endpoint returned AND what we made of it

        Conflating them would make "the bytes changed" and "we changed how we read the
        bytes" indistinguishable in a receipt -- which is the same collapse §5 forbids
        between the seal and the verdicts, one level down.
        """
        rows = sorted(
            ({"probe_id": r.probe_id, "arm": r.arm,
              "body_sha256": r.body_digest, "n_bytes": r.n_bytes} for r in self.replies),
            key=lambda d: (d["probe_id"], d["arm"]),
        )
        return digest_obj({"schema": "canary/bodies/v1", "bodies": rows})

    def as_canonical(self) -> dict:
        """The sealed structure. GENERATED data: canonicalised, float-free."""
        return {
            "schema": FROZEN_SCHEMA,
            "run_id": self.run_id,
            "instrument": self.instrument_declaration(),
            "i_digest": self.i_digest,
            "bodies_digest": self.bodies_digest,
            "target": self.target_declaration,
            "counts": self.counts(),
            "replies": [r.as_canonical() for r in self.replies],
        }

    @property
    def e_digest(self) -> str:
        """`E_t`'s content address: sha256 over the sealed structure's canonical bytes."""
        return digest_obj(self.as_canonical())

    def evidence_digests(self) -> dict[str, str]:
        """Every frozen body, addressed by digest. The evidence side of the seal."""
        return {f"{r.probe_id}::{r.arm}": r.body_digest for r in self.replies}

    def verify_bodies(self) -> list[str]:
        """Recompute every body digest against the bytes held. Returns mismatches.

        The freezer checking its own seal. A sealed run whose bodies no longer hash to
        their recorded digests is not a run with a discrepancy to note — it is not
        evidence at all, and this is how that gets found rather than assumed away.
        """
        bad = []
        for r in self.replies:
            body = self.bodies.get((r.probe_id, r.arm))
            if body is None:
                bad.append(f"{r.probe_id}::{r.arm}: body missing from the sealed run")
                continue
            got = digest_bytes(body)
            if got != r.body_digest:
                bad.append(f"{r.probe_id}::{r.arm}: sealed {r.body_digest}, recomputed {got}")
        return bad


def freeze_run(run_id: str, suite: ProbeSuite, target: Target,
               instrument: RefusalInstrument | None = None,
               probes: Sequence[Probe] | None = None) -> FrozenRun:
    """Probe the target once and seal the result as `E_t`.

    The order is the discipline: **receive, freeze, then classify.** The body is digested
    from the bytes as they arrived, before anything decodes them, so the evidence is
    fixed before any interpretation of it happens. Classification then reads the frozen
    bytes — never a separately-held copy that could have drifted from them.
    """
    instrument = instrument or RefusalInstrument()
    to_ask = list(probes if probes is not None else suite)

    frozen: list[FrozenReply] = []
    bodies: dict[tuple[str, str], bytes] = {}

    for probe in to_ask:
        response: RawResponse = target.ask(probe)

        if response.probe_id != probe.probe_id or response.arm != probe.arm.value:
            raise ValueError(
                f"target answered a different probe than it was asked: asked "
                f"{probe.probe_id}::{probe.arm.value}, got "
                f"{response.probe_id}::{response.arm}")

        key = (probe.probe_id, probe.arm.value)
        bodies[key] = response.body
        body_digest = digest_bytes(response.body)      # RECEIVED bytes, undecoded

        verdict = instrument.classify(response.text())  # decode happens after freezing
        frozen.append(FrozenReply(
            probe_id=probe.probe_id,
            arm=probe.arm.value,
            body_digest=body_digest,
            n_bytes=len(response.body),
            provenance=response.provenance.value,
            served_model=response.served_model,
            verdict=verdict.value,
            expect=probe.expect.value,
            conforms=verdict.value == probe.expect.value,
            source=response.source,
        ))

    run = FrozenRun(
        run_id=run_id,
        suite=suite,
        instrument=instrument,
        target_declaration=target.declaration(),
        replies=tuple(frozen),
        bodies=bodies,
    )

    # X-8 in miniature: verify before sealing is claimed, not after it is relied on.
    mismatches = run.verify_bodies()
    if mismatches:                                       # pragma: no cover - defensive
        raise RuntimeError("freezer sealed a run it cannot verify:\n" + "\n".join(mismatches))
    canonical_bytes(run.as_canonical())                  # raises on any float that got in
    return run


__all__ = ["FROZEN_SCHEMA", "FrozenReply", "FrozenRun", "Verdict", "freeze_run"]
