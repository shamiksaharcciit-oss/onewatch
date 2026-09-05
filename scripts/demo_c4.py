#!/usr/bin/env python3
"""The Detect leg: baseline, silence, a provider swap, and what the receipts actually say.

    run 1   baseline against model A          -> sealed, declared
    run 2   model A again                     -> receipt
    run 3   model A again                     -> receipt
    run 4   config switches to model B        -> receipt, instrument named

**What the receipts say is measured, not scripted.** This header used to promise a
CHANGED receipt at run 4. On the live run of 2026-08-22 it did not happen, and the
summary line — which had the outcome hard-coded — cheerfully reported one that did not
exist. The lesson kept: *a demo whose narration is fixed before the measurement will
narrate a result it did not get.*

WHAT THE LIVE RUN FOUND (Core -> Canary Response 008 closes C4 on it)
---------------------------------------------------------------------
The baseline served `claude-sonnet-5`; the switch served
`claude-haiku-4-5-20251001`. The swap is recorded in `served_model`. Behaviour, under
v3, did not move: haiku refused every answerless probe, merely explaining four of them,
and both models scored 30/30. So the receipt says two things that never contradict each
other — **the served model changed, and its validated behaviour did not.**

That is the incident. "The vendor changed the model underneath you, and here is proof
your behaviour didn't move" is the most common real incident this product will meet, and
**a dashboard cannot prove a negative.**

The silence is not filler either. A monitor that only ever speaks when something breaks
is indistinguishable from a monitor that is broken.

The switch is a **real provider-side difference injected by declaration**: the config
names a different model, the endpoint serves it, and the receipt records what was served
rather than what was asked for.

USAGE

    # against the deterministic mock — offline, free, and what CI runs
    python scripts/demo_c4.py --mock

    # against live endpoints — requires ANTHROPIC_API_KEY in the environment
    python scripts/demo_c4.py --baseline-model claude-opus-5 \\
                             --switch-model claude-haiku-4-5 \\
                             --max-calls 500      # seed read from CANARY_GEN_SEED

Both secrets are read from the environment and nowhere else — `ANTHROPIC_API_KEY` by the
SDK, `CANARY_GEN_SEED` at generation-build time. Neither is ever a flag: a flag lands in
shell history. Neither is ever logged, written to a receipt, or relayed in a memo — the
generation digest is the only public trace the seed leaves.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from canary.acj import verify_inclusion  # noqa: E402
from canary.baseline import Declaration, calibrate, declare  # noqa: E402
from canary.detector import Outcome, compare  # noqa: E402
from canary.freezer import freeze_run  # noqa: E402
from canary.receipt import Store, build_receipt, ledger, rederive  # noqa: E402
from canary.spend import Ceiling, SpendLedger  # noqa: E402
from canary.suite.generation import Status, build_generation  # noqa: E402
from canary.suite.refusal import RefusalInstrument  # noqa: E402
from canary.target import Change, MockConfig, MockTarget, suite_from_cycle  # noqa: E402
from canary.target.live import (  # noqa: E402
    SEED_ENV,
    LiveTarget,
    scan_for_key_material,
)

STAMP = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)


def banner(text: str) -> None:
    print(f"\n{'=' * 74}\n{text}\n{'=' * 74}")


def build_targets(args, spend):
    """Return (generation, baseline_target_factory, switch_target_factory, instrument).

    The mock path exists so this script is runnable, testable and demonstrable with no
    key, no spend, and no network. It runs the *same* sequence through the *same* engine;
    only the target differs.
    """
    instrument = RefusalInstrument(args.instrument)

    if args.mock:
        suite = suite_from_cycle()
        gen = None
        return (gen, suite,
                lambda: MockTarget(),
                lambda: MockTarget(config=MockConfig(changes=(Change.MODEL_SWAP,))),
                instrument)

    seed = os.environ.get(SEED_ENV, "")
    if not seed:
        raise SystemExit(
            f"{SEED_ENV} is not set. A live run needs a generation seed, and it enters "
            f"through the environment ONLY - never a command-line flag, which would land "
            f"in shell history, and never a config file, which would land in the "
            f"repository. Generate one with a cryptographic RNG on the machine that will "
            f"run the phase; nobody else should ever see it, because a seed that has been "
            f"relayed is a seed that has been published.\n"
            f"  python -c \"import secrets; print(secrets.token_hex(32))\"")

    gen = build_generation(
        generation_id=args.generation_id, seed=seed,
        created_at=STAMP.strftime("%Y-%m-%d"),
        provenance=("C4 live phase. Fresh generation, mandated by Core → Canary "
                    "Response 005 §3(1): gen-0-paper2 is published and permanently "
                    "retired, so it may not face a live system."),
        n_entities=args.entities, status=Status.ACTIVE)
    gen.assert_may_probe_live()

    return (gen, gen.suite,
            lambda: LiveTarget(model_requested=args.baseline_model, generation=gen,
                               ledger=spend),
            lambda: LiveTarget(model_requested=args.switch_model, generation=gen,
                               ledger=spend),
            instrument)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mock", action="store_true",
                    help="run offline against the deterministic mock (no key, no spend)")
    # Defaults ARE the ruling (Core -> Canary Response 006 §3): baseline
    # claude-sonnet-5, switch claude-haiku-4-5 — the same provider-swap shape paper-2
    # caught in the wild. A default that differed from the ruling would let a bare
    # invocation probe an unruled model, and no substitution is permitted without one.
    ap.add_argument("--baseline-model", default="claude-sonnet-5")
    ap.add_argument("--switch-model", default="claude-haiku-4-5")
    ap.add_argument("--generation-id", default="gen-1-c4")
    ap.add_argument("--entities", type=int, default=10,
                    help="entities per generation; each contributes 3 probes")
    ap.add_argument("--instrument", default="v3", choices=("v1", "v2", "v3"))
    ap.add_argument("--max-calls", type=int, default=500,
                    help="declared call ceiling for the whole phase")
    ap.add_argument("--store", default="C:/tmp/canary-c4" if sys.platform == "win32"
                    else "/tmp/canary-c4")
    ap.add_argument("--keep", action="store_true", help="do not wipe the store first")
    args = ap.parse_args(argv)

    # ---------------------------------------------------------------- the ceiling first
    spend = SpendLedger(Ceiling(
        max_calls=args.max_calls,
        scope=("C4 live phase: baseline, two repeat runs, one model-swap run, "
               "against a fresh refusal-sentinel generation"),
        declared_by="canary build session",
        declared_at=STAMP.strftime("%Y-%m-%dT%H:%M:%SZ")))
    banner(f"CEILING DECLARED - {spend.report()}")

    gen, suite, make_baseline_target, make_switch_target, instrument = \
        build_targets(args, spend)

    root = Path(args.store)
    if root.exists() and not args.keep:
        shutil.rmtree(root)
    store = Store(root)

    if gen is not None:
        print(f"generation   {gen.generation_id}  status={gen.status.value}  "
              f"digest={gen.digest[:16]}  probes={len(suite)}")
        print(f"provenance   {gen.provenance}")
    else:
        print(f"generation   (mock: retired gen-0 fixtures, offline only)  probes={len(suite)}")

    # ---------------------------------------------------------------- run 1: baseline
    banner("RUN 1 - BASELINE")
    base_run = freeze_run("c4-run-001-baseline", suite, make_baseline_target(),
                          instrument=instrument)
    store.put_run(base_run)

    calib = freeze_run("c4-run-001b-calibration", suite,
                       MockTarget(config=MockConfig(repeat=True)) if args.mock
                       else make_baseline_target(), instrument=instrument)
    store.put_run(calib)

    band = calibrate("refusal-sentinel", args.instrument, [base_run, calib],
                     method="same-config repeat pair, measured at baseline")
    baseline = declare("c4-baseline", base_run, band,
                       Declaration(declared_by="canary build session",
                                   declared_at=STAMP.strftime("%Y-%m-%dT%H:%M:%SZ"),
                                   reason="the validated system as of this date"))
    store.put_baseline(baseline)
    print(f"  e_digest   {base_run.e_digest}")
    print(f"  i_digest   {base_run.i_digest}")
    print(f"  served     {base_run.target_declaration.get('served_model', '-')}")
    print(f"  band       {band.per_arm}")
    print(f"  {spend.report()}")

    # ------------------------------------------------------- runs 2-3: the silence
    receipts = []
    for n in (2, 3):
        banner(f"RUN {n} - NOTHING CHANGED (the no-change receipt IS the product)")
        run = freeze_run(f"c4-run-{n:03d}", suite, make_baseline_target(),
                         instrument=instrument)
        store.put_run(run)
        cmp_ = compare(baseline, run)
        rec = build_receipt(baseline, run, cmp_,
                            trust=["anthropic-endpoint"] if not args.mock else ["mock"],
                            created_at=STAMP)
        store.put_receipt(rec)
        row = ledger.append(store.ledger_path(), rec, cmp_.outcome.value)
        receipts.append((rec, cmp_, row))
        print(f"  outcome    {cmp_.outcome.value}")
        print(f"  bytes      changed={cmp_.bytes_changed}   probes moved={len(cmp_.probe_deltas)}")
        print(f"  receipt    {rec['receipt_id']}")
        print(f"  {spend.report()}")

    # ------------------------------------------------------------ run 4: the change
    banner("RUN 4 - MODEL SWITCHED")
    changed_run = freeze_run("c4-run-004-switched", suite, make_switch_target(),
                             instrument=instrument)
    store.put_run(changed_run)
    cmp4 = compare(baseline, changed_run)
    rec4 = build_receipt(baseline, changed_run, cmp4,
                         trust=["anthropic-endpoint"] if not args.mock else ["mock"],
                         created_at=STAMP)
    store.put_receipt(rec4)
    row4 = ledger.append(store.ledger_path(), rec4, cmp4.outcome.value)
    receipts.append((rec4, cmp4, row4))

    print(f"  outcome    {cmp4.outcome.value}")
    print(f"  instrument {rec4['instrument']['detector']['family']}@"
          f"{rec4['instrument']['detector']['version']}  i_digest={rec4['i_digest'][:16]}")
    print(f"  served     {changed_run.target_declaration.get('served_model', '-')}")
    print(f"  probes     {len(cmp4.probe_deltas)} moved")
    for reason in cmp4.reasons[:3]:
        print(f"  reason     {reason}")
    print(f"  receipt    {rec4['receipt_id']}")
    print(f"  {spend.report()}")

    # ------------------------------------------------------------- verify everything
    banner("SECOND ROUTE - re-derive every receipt from the store alone")
    for rec, cmp_, _ in receipts:
        res = rederive(root, rec["receipt_id"])
        print(f"  {cmp_.outcome.value:12} {rec['receipt_id'][:16]}  ok={res.ok}  "
              f"checks={len(res.checked)}")
        if not res.ok:
            print(res.report())
            return 1

    rows = ledger.read_rows(store.ledger_path())
    problems = ledger.verify_chain(rows)
    print(f"\n  ledger     {len(rows)} rows, chain problems: {problems or 'none'}")
    anchor = ledger.anchor(rows, reverify=lambda rid: (
        lambda r: r.failed + r.unverifiable)(rederive(root, rid)))
    print(f"  anchor     {anchor['root']}  tree_size={anchor['tree_size']}")
    proof = ledger.prove_inclusion(anchor, rows[-1].row_hash)
    ok = verify_inclusion(proof["leaf"], proof["index"], proof["tree_size"],
                          proof["path"], proof["root"])
    print(f"  inclusion  proof for the CHANGED receipt verifies alone: {ok}")

    # ------------------------------------------------- condition (4), checked not assumed
    banner("KEY HYGIENE - nothing written carries credential material")
    leaked = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            try:
                found = scan_for_key_material(path.read_bytes().decode("utf-8", "replace"))
            except OSError:                                # pragma: no cover
                continue
            if found:
                leaked.append(f"{path}: {found}")
    print(f"  scanned    {sum(1 for p in root.rglob('*') if p.is_file())} files")
    print(f"  leaks      {leaked or 'none'}")
    if leaked:
        return 1

    banner("SUMMARY")
    # COUNT the outcomes; never narrate them from the plan.
    #
    # This line used to read "N no-change receipt(s), 1 changed receipt" with the 1
    # hard-coded, because the script assumed a model swap must change behaviour. On the
    # first live run it did not, and the summary cheerfully reported a changed receipt
    # that did not exist. A demo whose narration is fixed in advance will narrate a
    # result it did not get — the same family as a guard that cannot fail.
    tally = {}
    for _, c, _ in receipts:
        tally[c.outcome.value] = tally.get(c.outcome.value, 0) + 1
    changed = tally.get("CHANGED", 0)
    unchanged = tally.get("UNCHANGED", 0)
    print(f"  baseline sealed, {unchanged} no-change receipt(s), "
          f"{changed} changed receipt(s), all re-derived")
    if changed == 0:
        print("  NOTE: the injected switch produced NO behavioural change under "
              f"{args.instrument}. That is a finding about the probe set and the two "
              "models, not a failure of the run — and it is reported as measured.")
    print(f"  {spend.report()}")
    print(f"  store      {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
