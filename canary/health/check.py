"""Running a health check: acquire a run, freeze it, measure, emit, chain, anchor.

**The acquisition and the measurement are separate on purpose.** Defect F3 was a
calibration path that measured from a run held in memory, printed the number, and exited;
sixty live calls' worth of RECEIVED bytes were never written and are gone. The law that
followed (Core -> Canary Response 011 §4):

    Every live call's bytes are frozen from now on -- calibration, health check, anything.
    A measurement whose bytes are gone is testimony about a measurement.

So `run_health_check` **persists the run before it measures**. Not after, and not
conditionally: the store write happens first, so a crash between acquisition and
measurement loses the number and keeps the evidence, which is the survivable direction.

THE BASELINE-ONLY BOUNDARY, CARRIED FORWARD VERBATIM
-----------------------------------------------------
Core -> Canary Response 007 §3: a health measurement may consult the baseline model and
nothing else. There is no `--switch-model`, no comparison model, no second target. A
family measured against the model whose change you are hoping to detect is an instrument
fitted to its finding, with the fitting done one step earlier -- and the surest way to
never do it is to have no parameter for it.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from canary.freezer.freeze import FrozenRun
from canary.health.headroom import Headroom, measure
from canary.health.receipt import build_health_receipt
from canary.receipt import ledger
from canary.receipt.store import Store


class BaselineOnlyViolation(RuntimeError):
    """A health check was pointed at something other than the declared baseline model."""


def assert_baseline_only(served_model: str, baseline_model: str) -> None:
    """Refuse any model but the declared baseline. The boundary, enforced rather than meant.

    Checked against what was **served**, not what was requested: a provider quietly serving
    a different model is exactly the event this pillar exists to catch, and believing our
    own request would blind the check to its own subject.
    """
    if served_model != baseline_model:
        raise BaselineOnlyViolation(
            f"health check served {served_model!r} but the declared baseline model is "
            f"{baseline_model!r}. A family measured against anything but its baseline is "
            f"an instrument fitted to its finding.")


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    """What one scheduled check produced. The receipt is the deliverable."""

    headroom: Headroom
    receipt: dict
    run_path: Path
    row: ledger.Row


def run_health_check(store_root: Path, run: FrozenRun, baseline_id: str,
                     baseline_model: str, created_at: datetime | None = None,
                     trust: list[str] | None = None) -> HealthCheckResult:
    """Persist, measure, emit, chain. In that order, and the order is the discipline."""
    assert_baseline_only(run.target_declaration["served_model"], baseline_model)

    store = Store(store_root)
    run_path = store.put_run(run)          # evidence first -- see the module docstring

    headroom = measure(run)
    receipt = build_health_receipt(headroom, run, baseline_id=baseline_id,
                                   trust=trust, created_at=created_at)
    store.put_receipt(receipt)
    row = ledger.append(store.ledger_path(), receipt, headroom.verdict.value)
    return HealthCheckResult(headroom=headroom, receipt=receipt, run_path=run_path,
                             row=row)
