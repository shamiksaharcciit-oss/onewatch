#!/usr/bin/env python3
"""Re-score the C4 incident's frozen bytes under refusal-sentinel v1, v2 and v3.

This is the **(c) instrument-relativity demonstration**: the same evidence, three
instruments, opposite verdicts. It is a demonstration and never a receipt of record —
v1 and v2 are superseded instruments, and a run scored under one of them is not a run
this product would report. The label travels with the table.

WHY THIS COMMAND EXISTS (F4)
----------------------------
The table lived in `README.md` with no tool that produced it. The numbers were right —
they were checked by hand against the frozen bytes — but a table with no regenerating
command is transcription with extra steps: the next person to touch it has nothing to
re-run, and X-11 asks for digests and figures computed into documents by tooling rather
than retyped. Now the command exists and the table cites it.

WHAT IT COSTS
-------------
Nothing. Every reply was frozen on 2026-08-22 and re-scoring reads bytes off disk. No
model is queried, and no model *can* be queried: this module imports no network client
and the target is never constructed. Changing the instrument does not change the world,
which is the entire reason instrument versions live inside `i_digest`.

READ THE TABLE THIS WAY
-----------------------
"verdict flips" counts arms whose verdict differs between the baseline run and the run
after the provider swap. It is the number that decides UNCHANGED versus CHANGED — not
the raw failure counts, which can coincide while the underlying arms differ.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from canary.receipt.store import _long_path  # noqa: E402
from canary.suite.probe import Expect  # noqa: E402
from canary.suite.refusal import REFUSAL_INSTRUMENT_VERSIONS, RefusalInstrument  # noqa: E402

DEFAULT_STORE = REPO / "docs" / "evidence" / "c4-incident-of-record"

#: The baseline run (`claude-sonnet-5`) and the run after the configuration switched
#: (`claude-haiku-4-5-20251001` served). Both are e_digests, addressed under `runs/`.
BASELINE_E = "6706b01a078ee442796cd7acf1ab282df73769f8c866d2aba78572df6b3dfda7"
SWAP_E = "c5d0ff3825a7f7340bcca8681ecf662dd7eebd8c32a33b37ed1c32977006f18d"

#: The instrument the receipts of record actually declare. The others are shown beside it
#: precisely because they are NOT what ran.
OF_RECORD = "v3"


def verdicts(store: Path, e_digest: str, version: str) -> dict[tuple[str, str], bool]:
    """Re-classify every reply from its raw bytes under one instrument version.

    Keyed by `(probe_id, arm)` and not by `probe_id` alone: each probe carries three arms
    and a probe-keyed dict silently collapses thirty replies into ten, which reads as a
    denominator of 10 and is wrong in a way that still looks plausible.
    """
    run_path = store / "runs" / e_digest / "run.json"
    run = json.loads(open(_long_path(run_path), "rb").read())
    instrument = RefusalInstrument(version=version)

    out: dict[tuple[str, str], bool] = {}
    for reply in run["replies"]:
        key = (reply["probe_id"], reply["arm"])
        assert key not in out, f"duplicate arm key {key} -- the run file is malformed"
        body_path = store / "runs" / e_digest / "bodies" / reply["body_sha256"]
        body = open(_long_path(body_path), "rb").read().decode("utf-8")
        out[key] = instrument.conforms(body, Expect(reply["expect"]))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--store", type=Path, default=DEFAULT_STORE)
    ap.add_argument("--markdown", action="store_true",
                    help="emit the table as markdown, for pasting beside its label")
    args = ap.parse_args(argv)

    rows = []
    for version in REFUSAL_INSTRUMENT_VERSIONS:
        base = verdicts(args.store, BASELINE_E, version)
        swap = verdicts(args.store, SWAP_E, version)
        assert set(base) == set(swap), "the two runs do not cover the same arms"
        base_fail = sum(1 for k in base if not base[k])
        swap_fail = sum(1 for k in swap if not swap[k])
        flips = sum(1 for k in base if base[k] != swap[k])
        rows.append((version, base_fail, swap_fail, flips, len(base),
                     "UNCHANGED" if flips == 0 else "CHANGED"))

    if args.markdown:
        print("| instrument | baseline failures | after the swap | verdict flips | "
              "would report |")
        print("|---|---|---|---|---|")
        for v, bf, sf, fl, n, verdict in rows:
            bold = "**" if v == OF_RECORD else ""
            print(f"| {bold}{v}{bold}{' (default)' if v == OF_RECORD else ''} | "
                  f"{bf} / {n} | {sf} / {n} | {fl} | {bold}{verdict}{bold} |")
    else:
        print(f"{'instrument':12} {'baseline':>10} {'after swap':>12} {'flips':>7}  "
              f"would report")
        for v, bf, sf, fl, n, verdict in rows:
            mark = "  <- of record" if v == OF_RECORD else ""
            print(f"{v:12} {f'{bf} / {n}':>10} {f'{sf} / {n}':>12} {fl:>7}  "
                  f"{verdict}{mark}")

    print("\nA re-scoring demonstration over frozen bytes, never a receipt of record.",
          file=sys.stderr)
    print("v1 and v2 would have reported a regression that did not happen: they misread "
          "a sentinel-with-explanation as an answer.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
