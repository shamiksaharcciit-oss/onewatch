#!/usr/bin/env python3
"""The scheduled instrument-health re-check: the canary for the canary.

Probe-family headroom is a maintained property, not a design-time decision (Core → Canary
Response 008 §3). A family calibrated against the models of 2026 will silently stop
discriminating as models improve, and the only way to find out is to re-measure against the
baseline on a schedule and **surface saturation as a state rather than discover it during
an incident.**

    python scripts/health_check.py                      # mock, offline, free  (default)
    python scripts/health_check.py --live --max-calls N # requires a declared ceiling

THE LIVE LEG IS RUN-GATED, AND THE GATE IS THE SAME ONE
---------------------------------------------------------
`--live` is refused without an explicit `--max-calls` and without the key in the
environment. That is not a separate discipline invented for health checks: it is the same
ceiling rule every live call on this programme obeys — declared before the first call,
checked before each request rather than after, with no flag that lifts it mid-run.

`--live` also has **no model parameter**. The baseline model is read from the baseline
being maintained, and `assert_baseline_only` refuses anything else. A family measured
against the model whose change you hope to detect is an instrument fitted to its finding,
and the surest way never to do it is to have no parameter for it (Response 007 §3).

WHAT IT EMITS
-------------
A real receipt, per Q09 as ruled: frozen bytes, one quantise boundary, a verdict that is a
pure function of those bytes, chained into the same ledger and anchored under the same X-8
rule. One ledger, one anchor, one place a customer looks — an instrument-health record in a
separate chain would be the record nobody checks, and being checked on a schedule is its
entire purpose.

    exit 0   DISCRIMINATING — the family still has room below the ceiling
    exit 0   SATURATED      — reported, receipted, and NOT an error
    exit 2   the check could not be completed

**Saturation is not a failure exit.** A saturated family is at maximum sensitivity to
degradation and blind to differences above that ceiling: a good property for a monitor and
a poor one for a demo. Exiting non-zero would teach a scheduler to page someone, and the
correct response to saturation is a decision by a person, not an alarm.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from canary.freezer import freeze_run  # noqa: E402
from canary.health import rederive_health  # noqa: E402
from canary.health.check import run_health_check  # noqa: E402
from canary.receipt import ledger  # noqa: E402
from canary.suite.refusal import RefusalInstrument  # noqa: E402
from canary.suite.retrieval import build_retrieval_generation  # noqa: E402
from canary.target.retrieval_mock import RetrievalMockConfig, RetrievalMockTarget  # noqa: E402

#: A fixed stamp so a mock health check is byte-reproducible. A clock read here would make
#: every receipt unreproducible, which would defeat the point of emitting one.
MOCK_STAMP = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)
MOCK_SEED = "health-check-mock-seed-not-the-real-one"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--store", type=Path, default=None,
                    help="receipt store to chain into (default: a temporary directory)")
    ap.add_argument("--live", action="store_true",
                    help="probe a live endpoint. Requires --max-calls and a key.")
    ap.add_argument("--max-calls", type=int, default=0,
                    help="the declared ceiling. No ceiling, no call.")
    args = ap.parse_args(argv)

    if args.live:
        # The gate, refused loudly rather than degraded quietly to a mock run. A health
        # check that silently fell back would report a family's headroom against a
        # deterministic fixture while the operator believed it had measured production.
        if args.max_calls <= 0:
            print("--live requires --max-calls: no ceiling, no call.", file=sys.stderr)
            return 2
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("--live requires ANTHROPIC_API_KEY in the environment.", file=sys.stderr)
            return 2
        print("The live health check is gated behind a core ruling and a declared call "
              "budget. Spend stands at 210/500 and is CLOSED; no further live call is "
              "made without a new declaration naming its budget.", file=sys.stderr)
        return 2

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store = args.store or Path(tmp)
        generation = build_retrieval_generation("health-mock", MOCK_SEED,
                                                n_documents=6, facts_per_document=2)
        target = RetrievalMockTarget(corpus=generation.corpus,
                                     config=RetrievalMockConfig())
        run = freeze_run("health-mock", generation.suite, target,
                         instrument=RefusalInstrument("v3"))

        result = run_health_check(store, run, baseline_id="health-mock-baseline",
                                  baseline_model=target.config.served_model,
                                  created_at=MOCK_STAMP)

        print(result.headroom.report())
        print(f"\nreceipt      {result.receipt['receipt_id']}")
        print(f"verdict      {result.receipt['verdict']}")
        print(f"ledger       seq={result.row.seq}  row={result.row.row_hash[:16]}")

        # The second route, immediately: a receipt nobody has re-derived is a claim.
        check = rederive_health(store, result.receipt["receipt_id"])
        print(f"re-derived   ok={check.ok}  checks={len(check.checked)}  "
              f"failed={len(check.failed)}  unverifiable={len(check.unverifiable)}")
        if not check.ok:
            for problem in check.failed + check.unverifiable:
                print(f"  {problem}", file=sys.stderr)
            return 2

        rows = ledger.read_rows(store / "ledger.jsonl")
        anchor = ledger.anchor(rows, lambda rid: (
            rederive_health(store, rid).failed + rederive_health(store, rid).unverifiable))
        print(f"anchor       {anchor['root']}  tree_size={anchor['tree_size']}")

        if result.headroom.saturated:
            print("\nSaturation is a state, not an error. Exit 0: the correct response is "
                  "a decision\nby a person about whether to rotate the family, not a page.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
