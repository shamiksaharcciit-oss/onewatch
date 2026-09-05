#!/usr/bin/env python3
"""Calibrate a probe generation against the BASELINE MODEL ONLY.

Core -> Canary Response 007 §3: calibration may consult the baseline model and nothing
else. The switch model is never queried, scored, or glanced at during generation design.

WHY THE BOUNDARY IS THE WHOLE POINT
-----------------------------------
A probe set tuned until *this particular swap* shows up is an instrument fitted to its
finding — it would prove only that we kept adjusting until we got the answer we wanted.
A set calibrated to be non-saturated **on the baseline alone** is an instrument made
capable of finding anything, and then the swap measurement means what it says.

So this script takes one model. There is no `--switch-model` flag to forget to leave
off, and `assert_baseline_only()` refuses any model that is not the declared baseline —
the boundary is enforced by the code rather than by my remembering it.

WHAT "CALIBRATED" MEANS
-----------------------
The set is known-discriminating when the baseline shows **measurable headroom**: a
non-trivial failure rate, the paper-2 shape. Saturation (30/30 conforming) is what
`gen-1` had, and a set every model passes cannot detect change between models, because
there is no room below the ceiling for a difference to appear in.

This does NOT tune toward a target number. It measures, reports, and stops. Whether the
headroom is enough is a judgement stated in the report, not a threshold the script
optimises against — a script that iterated until a number came out right would be the
fitting this boundary exists to prevent.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from canary.freezer import freeze_run  # noqa: E402
from canary.receipt.store import Store  # noqa: E402
from canary.spend import Ceiling, SpendLedger  # noqa: E402
from canary.suite.generation import Status, build_hard_generation  # noqa: E402
from canary.suite.multihop import build_multihop_generation  # noqa: E402
from canary.suite.refusal import RefusalInstrument  # noqa: E402
from canary.target.live import SEED_ENV, LiveTarget  # noqa: E402

STAMP = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)

#: The ruled baseline (Core -> Canary Response 006 §3). Calibration sees this and only
#: this. The switch model is deliberately not named anywhere in this file.
BASELINE_MODEL = "claude-sonnet-5"


def assert_baseline_only(model: str) -> None:
    """Refuse any model but the declared baseline. The boundary, enforced."""
    if model != BASELINE_MODEL:
        raise SystemExit(
            f"calibration may consult the baseline model only, and the baseline is "
            f"{BASELINE_MODEL!r}; refusing {model!r}. Core -> Canary Response 007 §3: a "
            f"set tuned until a particular swap shows up would be an instrument fitted "
            f"to its finding.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Calibrate a generation on the baseline model.")
    ap.add_argument("--generation-id", default="gen-2-c4")
    ap.add_argument("--shape", default="hard", choices=("hard", "multihop"),
                    help="probe shape: string-matching-under-distraction, "
                         "or two-hop derivation")
    ap.add_argument("--entities", type=int, default=10)
    ap.add_argument("--package-size", type=int, default=9)
    ap.add_argument("--max-calls", type=int, default=150)
    ap.add_argument("--store", type=Path, required=True,
                    help="where the frozen run is written. Required: a live call "
                         "whose bytes are not persisted is defect F3 repeating.")
    ap.add_argument("--model", default=BASELINE_MODEL,
                    help="must be the declared baseline; anything else is refused")
    args = ap.parse_args(argv)

    assert_baseline_only(args.model)

    seed = os.environ.get(SEED_ENV, "")
    if not seed:
        raise SystemExit(f"{SEED_ENV} is not set; the generation seed comes from the "
                         f"environment only.")

    builder = {"hard": build_hard_generation,
               "multihop": build_multihop_generation}[args.shape]
    gen = builder(
        generation_id=args.generation_id, seed=seed,
        created_at=STAMP.strftime("%Y-%m-%d"),
        provenance=("C4 calibrated generation. gen-1-c4 saturated: both models scored "
                    "30/30, and a probe set every model passes cannot detect change "
                    "between models. Harder by dilution, near-miss sibling entities, and "
                    "the asked-for attribute present for the sibling — never by "
                    "ambiguity, which would measure the scorer rather than the system."),
        n_entities=args.entities, package_size=args.package_size, status=Status.ACTIVE)

    spend = SpendLedger(Ceiling(
        max_calls=args.max_calls,
        scope=f"C4 calibration of {args.generation_id} against the baseline model only",
        declared_by="canary build session",
        declared_at=STAMP.strftime("%Y-%m-%dT%H:%M:%SZ")))

    print(f"generation   {gen.generation_id}  digest={gen.digest[:16]}  "
          f"probes={len(gen.suite)}  package_size={args.package_size}  "
          f"shape={args.shape}")
    print(f"model        {args.model}   (baseline only; the switch model is not queried)")
    print(f"ceiling      {spend.report()}")

    target = LiveTarget(model_requested=args.model, generation=gen, ledger=spend)
    run = freeze_run(f"calib-{args.generation_id}", gen.suite, target,
                     instrument=RefusalInstrument("v3"))

    # THE EVIDENCE IS WRITTEN BEFORE THE NUMBER IS COMPUTED. Defect F3: this script used
    # to measure from a run held in memory, print the headroom, and exit -- and 60 live
    # calls' worth of RECEIVED bytes for gen-2-c4 and gen-3-c4 were lost that way. Only
    # the summaries survive, so those generations can publish a truncated digest and
    # nothing more (Note 010 §1).
    #
    # Core -> Canary Response 011 §4 made the lesson law: **every live call's bytes are
    # frozen from now on -- calibration, health check, anything. A measurement whose bytes
    # are gone is testimony about a measurement.** The store write happens first, so a
    # crash between acquisition and measurement loses the number and keeps the evidence,
    # which is the survivable direction.
    store = Store(args.store)
    run_path = store.put_run(run)
    print(f"evidence     frozen to {run_path}")

    counts = run.counts()
    print(f"\nserved       {run.target_declaration['served_model']}")
    print(f"{spend.report()}\n")

    total_fail = 0
    print(f"{'arm':16} {'failures':>10} {'of':>4}   what a failure means")
    meanings = {
        "wrong_abstention": ("answer_bearing", "refused a question the package answers"),
        "unsupported_answer_same_doc": ("same_doc", "answered from the sibling's value"),
        "unsupported_answer_cross_doc": ("cross_doc", "answered though the entity is absent"),
    }
    for bucket, (arm, meaning) in meanings.items():
        n = counts[bucket]["numerator"]
        d = counts[bucket]["denominator"]
        total_fail += n
        print(f"{arm:16} {n:>10} {d:>4}   {meaning}")

    print(f"\nheadroom     {total_fail} failure(s) across {len(run.replies)} probes")
    if total_fail == 0:
        print("SATURATED    the baseline passes everything; this set cannot detect a "
              "difference between models. Do not run the swap against it.")
        return 2
    print("HEADROOM     the baseline has measurable room below the ceiling; a swap "
          "measured against this set can move in either direction.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
