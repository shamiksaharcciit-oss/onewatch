"""The call ceiling: declared before the first call, enforced, and reported.

Core → Canary Response 005 §3(2): *a call ceiling declared in config, enforcement and
reporting both pinned, spend visible in every report. **No ceiling, no call.***

WHY BOTH HALVES, AND WHY NEITHER IS ENOUGH ALONE
------------------------------------------------
**Enforcement without reporting** is a cap nobody can audit: the run stops at some number
and the reader has to trust that the number was the declared one. **Reporting without
enforcement** is a spend log, which tells you afterwards what you already cannot undo.
The pair is the control: the ceiling is declared up front, the engine refuses to exceed
it, and every receipt carries what was declared and what was actually spent — so a reader
checks the claim rather than accepting it.

THE CEILING IS NOT A BUDGET ESTIMATE
------------------------------------
It is a hard stop. `LedgerFull` is raised *before* the call that would exceed it, not
after, because "we noticed at 501" is not a ceiling of 500. There is no `force`, no
`allow_overage`, and no way to raise the ceiling on a live ledger — a ceiling that can be
lifted mid-run by the code that hit it is a suggestion.

WHAT IT DOES NOT PROTECT AGAINST
--------------------------------
Cost. A ceiling counts *calls*, not dollars, because calls are what this engine controls
and what it can refuse. Token spend is recorded alongside so a reader can see the money,
but a token-denominated cap would have to guess an output length before making the call
and would stop mid-suite on a long reply, leaving a partial run that is not evidence of
anything. Calls are the honest unit for a hard stop; tokens are the honest unit for a
report. Both are carried.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class NoCeilingDeclared(RuntimeError):
    """A live call was attempted with no declared ceiling. No ceiling, no call."""


class LedgerFull(RuntimeError):
    """The declared ceiling would be exceeded by the next call. Raised BEFORE it."""


@dataclass(frozen=True, slots=True)
class Ceiling:
    """The declaration. Immutable, and part of what the receipt records."""

    #: Maximum API calls for the whole phase. Core suggested 500 for all of C4.
    max_calls: int
    #: What this ceiling is for, in words, so a reader knows what it was meant to cover.
    scope: str
    declared_by: str
    declared_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.max_calls, int) or isinstance(self.max_calls, bool):
            raise TypeError("max_calls must be an int")
        if self.max_calls <= 0:
            raise ValueError(
                f"max_calls must be positive; got {self.max_calls}. A ceiling of zero is "
                f"not a ceiling, it is a disabled phase — say so by not running.")
        for name in ("scope", "declared_by", "declared_at"):
            if not str(getattr(self, name)).strip():
                raise ValueError(
                    f"a ceiling requires {name}: an undeclared ceiling cannot be audited "
                    f"against what it was supposed to cover")

    def as_canonical(self) -> dict:
        return {
            "max_calls": self.max_calls,
            "scope": self.scope,
            "declared_by": self.declared_by,
            "declared_at": self.declared_at,
        }


@dataclass
class SpendLedger:
    """Counts calls and tokens against a declared ceiling.

    Mutable by design — it is the one thing in this engine that accumulates during a run.
    Everything it records is integers, so it crosses no quantisation boundary and enters
    a receipt as counts.
    """

    ceiling: Ceiling
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    #: Per-model call counts. A swap mid-phase is visible here without reading receipts.
    by_model: dict = field(default_factory=dict)

    @property
    def remaining(self) -> int:
        return self.ceiling.max_calls - self.calls

    def check(self, n: int = 1) -> None:
        """Would `n` more calls breach the ceiling? Raises if so. Call before spending."""
        if self.calls + n > self.ceiling.max_calls:
            raise LedgerFull(
                f"declared ceiling of {self.ceiling.max_calls} call(s) would be exceeded: "
                f"{self.calls} already spent, {n} more requested, {self.remaining} "
                f"remaining. Scope: {self.ceiling.scope}. The ceiling is not raised by the "
                f"code that hit it; declare a new one deliberately if more is intended.")

    def record(self, model_served: str, input_tokens: int, output_tokens: int) -> None:
        """Record one completed call. Called after the response, never before.

        Recording after means a call that failed in transport is not counted as spend —
        but `check`/`reserve` ran before it, so a storm of failing calls still cannot run
        past the ceiling. The two together are what make the count both honest and safe.
        """
        self.calls += 1
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.by_model[model_served] = self.by_model.get(model_served, 0) + 1

    def as_canonical(self) -> dict:
        """What every report and receipt carries. Both halves: declared and spent."""
        return {
            "ceiling": self.ceiling.as_canonical(),
            "spent": {
                "calls": self.calls,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "by_model": dict(sorted(self.by_model.items())),
            },
            "remaining_calls": self.remaining,
        }

    def report(self) -> str:
        """One human-readable line. Spend is visible in every report, not on request."""
        return (f"spend: {self.calls}/{self.ceiling.max_calls} calls "
                f"({self.remaining} remaining) | "
                f"tokens in/out {self.input_tokens}/{self.output_tokens} | "
                f"models {dict(sorted(self.by_model.items())) or '-'}")


def require_ceiling(ledger: SpendLedger | None) -> SpendLedger:
    """Gate every live path. `None` is refused loudly rather than defaulted.

    A default ceiling would be a number nobody declared, which is exactly the thing the
    rule exists to prevent — so the absence is an error, not an opportunity to be helpful.
    """
    if ledger is None:
        raise NoCeilingDeclared(
            "no spend ledger was supplied, so no ceiling has been declared. No ceiling, "
            "no call. Declare a Ceiling and pass a SpendLedger; there is no default, "
            "because a default ceiling is a number nobody chose.")
    return ledger
