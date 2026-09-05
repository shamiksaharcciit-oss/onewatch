"""The live target: a real Anthropic endpoint, probed from outside.

FOUR CONDITIONS, ENFORCED HERE (Core → Canary Response 005 §3)
--------------------------------------------------------------
1. **Fresh generation only.** `generation.assert_may_probe_live()` runs before the first
   call. A retired generation raises; it is never a warning, because a published probe
   set that has faced a live system produces a result that cannot be trusted and cannot
   be re-taken.
2. **Declared ceiling.** `require_ceiling` refuses a missing ledger, and the ledger is
   checked *before* each call. No ceiling, no call.
3. The demo sequence lives in `scripts/demo_c4.py`; this module is what it drives.
4. **The key never enters the repository.** It is read from the environment at call time,
   never stored on the instance, never passed as an argument, never logged, and never
   written into a config, a receipt, or a memo. `declaration()` records the *model served*
   and deliberately has no field a credential could occupy.

WHY THE SDK IS A HARD REQUIREMENT OF THIS PATH ONLY
---------------------------------------------------
The engine has no runtime dependencies, and that property is load-bearing: a receipt must
be re-derivable by a third party who resolves nothing. **Re-derivation never runs this
module.** It replays a comparison over frozen bytes; it does not call an endpoint. So the
official `anthropic` SDK is required for *collection* and absent from *verification*, and
the split is exactly where it should be.

X-6 says an alarm dependency is a hard requirement, never an optional extra — meaning it
must never degrade quietly. That is honoured: a missing SDK raises at construction with an
instruction, and there is no fallback to a mock, no skip, and no "live mode unavailable,
continuing" path. Install it or do not probe.

THE SERVED MODEL IS RECORDED, NEVER ASSERTED
--------------------------------------------
The response carries the model that actually answered, and that is what the receipt keeps
— not the model that was requested. A provider silently serving a different model is
precisely the incident this pillar exists to catch, so believing our own request would
blind the instrument to its own subject.

**This is not hypothetical, and it does not require anything to go wrong.** Measured
against the live endpoint on 2026-08-22, before any probe was sent:

    requested  claude-haiku-4-5     ->  served  claude-haiku-4-5-20251001
    requested  claude-sonnet-5      ->  served  claude-sonnet-5

An alias resolves to a dated snapshot. The two fields already disagree on a perfectly
healthy call, which is why they are two fields. A receipt recording only what was asked
for would say `claude-haiku-4-5` on the day the alias silently began resolving somewhere
else, and would look identical to the day before. (Upstream's cycle-3 telemetry recorded
the same dated form under `model_served`, which is how the pattern was inherited.)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from canary.spend import SpendLedger, require_ceiling
from canary.suite.generation import Generation
from canary.suite.probe import Probe
from canary.target.base import Provenance, RawResponse

#: The environment variable the key is read from. Never a config field, never a CLI flag:
#: a flag lands in shell history and a config field lands in the repository.
API_KEY_ENV = "ANTHROPIC_API_KEY"

#: The generation seed's variable. Read at build time only, exactly like the key:
#: never a flag (shell history), never a config field (the repository), never logged,
#: never in a receipt. The generation digest is the only public trace it leaves.
SEED_ENV = "CANARY_GEN_SEED"

#: Enough for a sentinel plus a sentence of explanation. Deliberately small: this is a
#: refusal probe, not a generation task, and a large cap turns a runaway reply into spend.
MAX_TOKENS = 512


class MissingKey(RuntimeError):
    """No API key in the environment. Never falls back to anything."""


class SDKUnavailable(RuntimeError):
    """The `anthropic` SDK is not installed. A hard failure, never a degraded mode."""


def _client():
    """Build the SDK client. Imported lazily so the engine imports without the SDK.

    The client resolves credentials from the environment itself; no key is passed in, so
    no key is held by this module even momentarily.
    """
    try:
        import anthropic
    except ImportError as e:                              # pragma: no cover - env dependent
        raise SDKUnavailable(
            "the `anthropic` SDK is required for live probing and is not installed. "
            "Install it with `pip install 'canary[live]'`. There is deliberately no "
            "fallback: a live phase that quietly ran against a mock would produce "
            "receipts that look real and prove nothing."
        ) from e

    if not os.environ.get(API_KEY_ENV):
        raise MissingKey(
            f"{API_KEY_ENV} is not set. The key is read from the environment and only "
            f"from the environment — it never enters config, logs, receipts, memos, or "
            f"this repository. Export it in the shell that runs the phase.")
    return anthropic.Anthropic()


@dataclass(frozen=True, slots=True)
class LiveTarget:
    """A real endpoint, probed at arm's length.

    Endpoint-level, zero pipeline integration: the probe supplies its own context inline,
    so nothing is planted in anyone's index and no code sits in anyone's request path.
    """

    #: The model to ask for. What is *served* may differ, and that is the point.
    model_requested: str
    generation: Generation
    ledger: SpendLedger
    target_id: str = "live://anthropic"
    #: Set once the first response names a model; used to detect a mid-run swap.
    _seen_models: set = field(default_factory=set, compare=False)

    def __post_init__(self) -> None:
        require_ceiling(self.ledger)
        self.generation.assert_may_probe_live()
        if not self.model_requested:
            raise ValueError("model_requested must name a model")

    # -------------------------------------------------------------------- declaration

    def declaration(self) -> dict:
        """What the receipt records about this target.

        Note what is absent: there is no key field, no header dump, no client config. A
        structure that *could* hold a credential eventually will, so the shape refuses it.
        """
        return {
            "target_id": self.target_id,
            "kind": "live-endpoint",
            "provider": "anthropic",
            "model_requested": self.model_requested,
            "served_model": sorted(self._seen_models)[0] if self._seen_models else "",
            "models_seen": sorted(self._seen_models),
            "generation": self.generation.as_canonical(),
            "spend": self.ledger.as_canonical(),
            "max_tokens": MAX_TOKENS,
        }

    # ------------------------------------------------------------------------ probing

    def ask(self, probe: Probe) -> RawResponse:
        """Put one probe to the live endpoint. Counts against the declared ceiling."""
        self.generation.assert_may_probe_live()
        self.ledger.check(1)                      # BEFORE the call, never after
        client = _client()

        message = client.messages.create(
            model=self.model_requested,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": probe.query}],
        )

        served = message.model
        if not served:                            # pragma: no cover - provider contract
            raise RuntimeError(
                "the response carried no model identity. The served model is part of what "
                "the receipt attests; recording the requested model instead would let a "
                "silent provider swap pass as continuity, which is the incident this "
                "instrument exists to catch.")

        usage = message.usage
        self.ledger.record(served, usage.input_tokens, usage.output_tokens)
        self._seen_models.add(served)

        text = "".join(b.text for b in message.content if b.type == "text")

        return RawResponse(
            probe_id=probe.probe_id,
            arm=probe.arm.value,
            # RECEIVED: encoded once here and never touched again. This is the earliest
            # point at which bytes exist, because the SDK hands back decoded text.
            body=text.encode("utf-8"),
            provenance=Provenance.LIVE,
            served_model=served,
            source={
                "provider": "anthropic",
                "model_requested": self.model_requested,
                "stop_reason": message.stop_reason or "",
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "generation_id": self.generation.generation_id,
            },
        )


#: Substrings that must never appear in anything this repository writes out. Checked by
#: `tests/test_live_guards.py` against configs, receipts, ledgers and memos.
KEY_MARKERS = ("sk-ant-", "ANTHROPIC_API_KEY=", "x-api-key",
               "CANARY_GEN_SEED=")


def scan_for_key_material(text: str) -> list[str]:
    """Return any credential markers found. Used by the guards, and by the demo script.

    Deliberately crude and deliberately broad: the cost of a false positive is a moment's
    inspection, and the cost of a false negative is a key in a published artifact.
    """
    return [m for m in KEY_MARKERS if m in text]
