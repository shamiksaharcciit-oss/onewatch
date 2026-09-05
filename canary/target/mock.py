"""A deterministic mock target with four declared, injectable changes.

WHY A MOCK AT ALL
-----------------
Fixtures first, live later — the forensics pattern. A change detector tested only
against a live endpoint is tested against something that changes for reasons nobody
recorded, so a failing test could always be the endpoint's fault. Here the changes are
declared: the test knows exactly what was injected and can assert exactly what should
be detected. Live probing also costs money and creates external records, and is barred
until core rules and Shamik supplies an endpoint.

DETERMINISM IS THE WHOLE CONTRACT
---------------------------------
Same config plus same probe gives the same bytes, always. No clock, no randomness, no
network, no filesystem writes. Benign nondeterminism is a real phenomenon this engine
must handle, but it is *modelled* here (by replaying cycle 2, which recorded it) rather
than *simulated* with a random number generator. A mock that generated its own noise
would be testing the detector against our idea of noise instead of the real thing.

THE FOUR CHANGES, AND WHICH ARE REAL
------------------------------------
    change          backed by                              provenance
    ------------------------------------------------------------------------
    model_swap      cycle 3: sonnet-5 -> haiku-4-5         RECORDED
    index_refresh   cycle 4: corpus release, spans migrated RECORDED
    prompt_edit     declared transformation                 SYNTHETIC
    format_drift    declared transformation                 SYNTHETIC

Two are real recorded model behaviour under a real change. Two are declared
transformations, because no paper-2 cycle recorded a prompt edit or a format change.
**The mock never presents a synthetic reply as a recorded one** — every response carries
its provenance, and the freezer records it into the receipt.

WHAT THE SYNTHETIC TWO DO, AND WHY THOSE SHAPES
-----------------------------------------------
Both were chosen because they are behaviourally interesting to a refusal-sentinel
instrument, not because they were easy to write.

**prompt_edit** — the system prompt now asks the model to explain its abstentions. A
bare `NOT FOUND` becomes `NOT FOUND. The provided context does not contain ...`. This is
the instrument-relativity case in miniature: under v3 the reply is still a REFUSAL (the
sentinel leads), under v1 and v2 it becomes an ANSWER (the reply is no longer *only* the
sentinel). One injected change, two opposite verdicts, decided entirely by which
instrument was declared. This is exactly the phenomenon that makes `i_digest` necessary
rather than tidy.

**format_drift** — a rendering layer now wraps replies in a fenced code block. Nothing
about the model's behaviour changed; the bytes did. A refusal becomes
```` ```\\nNOT FOUND\\n``` ````, which no version classifies as a REFUSAL, because the
sentinel no longer leads. Every arm flips at once — and that uniformity is the signature
worth learning, since real behavioural change is rarely so tidy.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path

from canary.suite.probe import Arm, Probe
from canary.target.base import Provenance, RawResponse

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures" / "paper2"


class Change(str, Enum):
    """The four declared injectable changes."""

    MODEL_SWAP = "model_swap"
    INDEX_REFRESH = "index_refresh"
    PROMPT_EDIT = "prompt_edit"
    FORMAT_DRIFT = "format_drift"


#: Which recorded cycle backs each configuration. `None` means "cycle 1, transformed".
_RECORDED_CYCLE = {
    Change.MODEL_SWAP: "telemetry_cycle3_model_swap.json",
    Change.INDEX_REFRESH: "telemetry_cycle4_after_release.json",
}

#: The baseline cycle, and the same-config repeat that measures benign nondeterminism.
BASELINE_CYCLE = "telemetry_cycle1_baseline.json"
REPEAT_CYCLE = "telemetry_cycle2_stability.json"

#: The prose a prompt edit appends after the sentinel. Declared, fixed, not generated.
_PROMPT_EDIT_RESIDUE = (
    ". The provided context does not contain information answering this question."
)


@lru_cache(maxsize=None)
def _load_cycle(filename: str) -> dict:
    """Read one frozen cycle. Cached because it is immutable and read many times.

    Read-only, always. These files are RECEIVED data (see fixtures/paper2/PROVENANCE.md)
    and nothing in this engine writes to them.
    """
    path = FIXTURES / filename
    if not path.exists():                                # pragma: no cover - install error
        raise FileNotFoundError(
            f"fixture {filename} not found at {path}. The mock target has no fallback: "
            f"a mock that invented replies when its fixtures were missing would produce "
            f"confident output from nothing.")
    return json.loads(path.read_bytes().decode("utf-8"))


def _index(cycle: dict) -> dict[tuple[str, str], str]:
    """(probe_id, arm) -> recorded reply text, for one cycle."""
    out: dict[tuple[str, str], str] = {}
    for probe in cycle.get("probes", []):
        qid = probe["query_id"]
        for arm, reply in probe.get("replies", {}).items():
            out[(qid, arm)] = reply["text"]
    return out


def _served_model(cycle: dict) -> str:
    served = cycle.get("model_served") or []
    if isinstance(served, list):
        if len(served) != 1:
            # More than one served model in a cycle means the run itself was not
            # single-instrument. Surfaced, never averaged away.
            raise ValueError(f"cycle served {len(served)} models: {served!r}")
        return served[0]
    return str(served)


@dataclass(frozen=True, slots=True)
class MockConfig:
    """A declared configuration of the mock system under test.

    Frozen: a config that changed mid-run would make the run's own declaration false.
    """

    #: Injected changes, applied in the order listed here (recorded first, then synthetic).
    changes: tuple[Change, ...] = ()
    #: Replay the same-config repeat instead of the baseline. Same declared config,
    #: different recorded replies -- this is benign nondeterminism, not a change.
    repeat: bool = False

    def __post_init__(self) -> None:
        if len(set(self.changes)) != len(self.changes):
            raise ValueError(f"a change is listed twice: {self.changes!r}")
        recorded = [c for c in self.changes if c in _RECORDED_CYCLE]
        if len(recorded) > 1:
            raise ValueError(
                f"{[c.value for c in recorded]} are each backed by a different recorded "
                f"cycle and cannot be combined: there is no cycle in which both happened, "
                f"and manufacturing one would mean inventing model replies.")
        if self.repeat and recorded:
            raise ValueError(
                "repeat replays the same-config repeat cycle, which by definition has no "
                "change injected; combining it with a recorded change is contradictory.")

    @property
    def base_cycle(self) -> str:
        for c in self.changes:
            if c in _RECORDED_CYCLE:
                return _RECORDED_CYCLE[c]
        return REPEAT_CYCLE if self.repeat else BASELINE_CYCLE

    @property
    def synthetic_changes(self) -> tuple[Change, ...]:
        return tuple(c for c in self.changes
                     if c in (Change.PROMPT_EDIT, Change.FORMAT_DRIFT))

    def as_canonical(self) -> dict:
        return {
            "changes": [c.value for c in self.changes],
            "repeat": self.repeat,
            "base_cycle": self.base_cycle,
        }


@dataclass(frozen=True, slots=True)
class MockTarget:
    """A deterministic, offline stand-in for a probed LLM/RAG system."""

    config: MockConfig = field(default_factory=MockConfig)
    target_id: str = "mock://paper2"

    # -------------------------------------------------------------- declared behaviour

    def declaration(self) -> dict:
        """What the receipt records about this target.

        Includes the served model, which is part of what `i_digest` covers: a run whose
        endpoint quietly started serving a different model is a run against a different
        system, and the receipt must be able to say so rather than assert continuity.
        """
        cycle = _load_cycle(self.config.base_cycle)
        return {
            "target_id": self.target_id,
            "kind": "deterministic-mock",
            "served_model": _served_model(cycle),
            "config": self.config.as_canonical(),
            "fixture_provenance": "fixtures/paper2 (upstream 370f5f3, verbatim)",
        }

    # ------------------------------------------------------------------------- probing

    def ask(self, probe: Probe) -> RawResponse:
        """Put one probe to the mock. Pure: no clock, no randomness, no network."""
        cycle_name = self.config.base_cycle
        cycle = _load_cycle(cycle_name)
        replies = _index(cycle)

        key = (probe.probe_id, probe.arm.value)
        if key not in replies:
            raise KeyError(
                f"no recorded reply for {probe.probe_id} arm {probe.arm.value} in "
                f"{cycle_name}. The mock does not invent replies for probes it has no "
                f"record of; a suite that outruns its fixtures is a configuration error, "
                f"surfaced here rather than filled in.")

        text = replies[key]
        provenance = Provenance.RECORDED
        applied: list[str] = []

        for change in self.config.synthetic_changes:
            text = _apply_synthetic(change, text)
            provenance = Provenance.SYNTHETIC
            applied.append(change.value)

        return RawResponse(
            probe_id=probe.probe_id,
            arm=probe.arm.value,
            body=text.encode("utf-8"),
            provenance=provenance,
            served_model=_served_model(cycle),
            source={
                "cycle": cycle_name,
                "recorded_upstream": True,
                "synthetic_transforms": applied,
            },
        )


def _apply_synthetic(change: Change, text: str) -> str:
    """The declared transformations. Deterministic, total, and documented above."""
    if change is Change.PROMPT_EDIT:
        # Only abstentions gain prose: the edit asked the model to explain refusals.
        # A bare sentinel becomes sentinel-plus-explanation; an answer is unaffected.
        if text.strip() == "NOT FOUND":
            return "NOT FOUND" + _PROMPT_EDIT_RESIDUE
        return text
    if change is Change.FORMAT_DRIFT:
        # A rendering layer wraps every reply, regardless of content. Nothing about the
        # model's behaviour changed -- only the bytes that reach the canary.
        return "```\n" + text + "\n```"
    raise ValueError(f"not a synthetic change: {change!r}")   # pragma: no cover


def baseline_probe_ids(cycle: str = BASELINE_CYCLE) -> tuple[str, ...]:
    """Probe ids present in a recorded cycle, in file order."""
    return tuple(p["query_id"] for p in _load_cycle(cycle).get("probes", []))


def suite_from_cycle(cycle: str = BASELINE_CYCLE, *,
                     suite_id: str = "paper2-refusal-sentinel",
                     version: str = "gen-0-retired") -> "ProbeSuite":  # noqa: F821
    """Build a probe suite covering every probe and arm recorded in a cycle.

    The version string says `retired` on purpose. This generation is a fixture, a demo
    and a worked example -- never a live canary for any system whose training data or
    index may have seen it. The name carries the caveat so it cannot be separated from
    the suite by a reader in a hurry.

    The query text upstream recorded is the query *id*, not the prompt: the prompts
    live in the companion repository's corpus, which this repository does not vendor.
    The id is what identifies the probe and what the digest covers, so the suite is
    complete for comparison purposes and explicitly not a re-runnable prompt set.
    """
    from canary.suite.probe import ProbeSuite

    data = _load_cycle(cycle)
    probes = []
    for entry in data.get("probes", []):
        qid = entry["query_id"]
        for arm_name in entry.get("replies", {}):
            probes.append(Probe(
                probe_id=qid,
                family="refusal-sentinel",
                arm=Arm(arm_name),
                query=qid,
            ))
    return ProbeSuite(suite_id=suite_id, version=version, probes=tuple(probes))
