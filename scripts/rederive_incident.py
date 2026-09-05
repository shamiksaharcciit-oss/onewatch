#!/usr/bin/env python3
"""Re-derive the C4 incident of record from the committed store, by the second route.

This is the product's own claim performed on its own evidence: a stranger with a
directory recomputes the verdicts, the chain and the anchor, and never queries a model.
It reads `docs/evidence/c4-incident-of-record/` and nothing else.

WHAT "SECOND ROUTE" MEANS, AND WHY IT IS NOT CIRCULAR
-----------------------------------------------------
Route one is the engine computing a verdict while it still holds the run in memory.
Route two is this: bytes off disk, verdicts **re-classified from the raw reply bodies**
by the declared instrument version rather than read back from the run file. Confirming
that a recorded verdict equals itself proves nothing; recomputing it from the evidence
is the whole point, and a receipt whose verdict does not follow from its bytes fails here.

THE THREE-OUTCOME RULE
----------------------
*Verified*, *failed* and *unverifiable* are held apart, all the way to the exit code. A
missing body is not a pass and not a mismatch — it is "we could not check", which calls
for a different response from a reader than "we checked and it was wrong".

    exit 0   every receipt re-derived, chain clean, anchor recomputed
    exit 2   something FAILED   -- checked, and wrong
    exit 3   something was UNVERIFIABLE -- could not be checked at all
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from canary.receipt import ledger  # noqa: E402
from canary.receipt.rederive import rederive  # noqa: E402
from canary.receipt.store import _long_path  # noqa: E402

DEFAULT_STORE = REPO / "docs" / "evidence" / "c4-incident-of-record"
MANIFEST_NAME = "c4-incident-of-record.SHA256"

#: The root recorded by the live run of 2026-08-22, in `docs/evidence/c4_live_run_2026-08-22.log`.
#: Pinned here so that "the anchor still matches" is a checked assertion and not a thing
#: someone eyeballs across two screens.
RECORDED_ANCHOR_ROOT = "38ff95dbc6c4c31f6c55485fb1fdb71039db0cb8c671a02b4d95a33d60b956dd"


def _exists(path: Path) -> bool:
    """Windows-safe existence check. See `_read` for why this cannot be `Path.is_file`."""
    return os.path.exists(_long_path(path))


def _read(path: Path) -> bytes:
    r"""Read bytes through the engine's long-path form, exactly as the Store does.

    The store addresses bodies as `runs/<64-hex e_digest>/bodies/<64-hex body digest>`,
    which is 141 characters before the repository prefix. On Windows that crosses
    MAX_PATH inside any reasonably deep clone, and `Path.is_file()` then answers *False*
    for a file that is present and intact. `canary.receipt.store` already solved this
    with the `\?\` prefix, and recorded why it refused the alternative: truncating a
    content address to fit a filesystem trades the property the design rests on for a
    platform's convenience.

    The first version of this checker used plain paths and reported 59 of 74 files
    UNVERIFIABLE in a deep clone whose files were all present and correct. It was caught
    because the three-outcome rule kept *unverifiable* apart from *failed*: the checker
    said "could not check", not "checked and wrong", and those call for very different
    conclusions. Collapsed into one outcome it would have read as a corrupted launch
    deliverable.
    """
    with open(_long_path(path), "rb") as fh:
        return fh.read()


def check_pin(store: Path) -> tuple[list[str], list[str]]:
    """Every pinned file present and byte-identical; and no file present but unpinned.

    Returns (failed, unverifiable). A pinned file that is missing is *unverifiable*; a
    pinned file whose bytes moved is *failed*. Holding those apart is the point.
    """
    manifest = store / MANIFEST_NAME
    if not manifest.is_file():
        return [], [f"digest manifest absent: {manifest}"]

    failed: list[str] = []
    unverifiable: list[str] = []
    pinned: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        want, _, rel = line.partition("  ")
        pinned.add(rel)
        path = store / rel
        if not _exists(path):
            unverifiable.append(f"pinned file missing: {rel}")
            continue
        got = hashlib.sha256(_read(path)).hexdigest()
        if got != want:
            failed.append(f"bytes moved: {rel} pinned {want}, computed {got}")

    on_disk = set()
    for dirpath, _dirnames, filenames in os.walk(_long_path(store)):
        for name in filenames:
            full = Path(dirpath) / name
            on_disk.add(full.relative_to(Path(os.path.abspath(_long_path(store)))).as_posix())
    unpinned = on_disk - pinned - {MANIFEST_NAME, "PROVENANCE.md"}
    # A pin with a hole reads as full coverage while attesting nothing about the gap.
    failed += [f"present but unpinned: {rel}" for rel in sorted(unpinned)]
    return failed, unverifiable


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--store", type=Path, default=DEFAULT_STORE)
    args = ap.parse_args(argv)
    store = args.store

    if not store.is_dir():
        print(f"store not found: {store}", file=sys.stderr)
        return 3

    print(f"store        {store}")
    all_failed: list[str] = []
    all_unverifiable: list[str] = []

    # --- layer 3 of the byte discipline: the pin, checked before anything is derived
    # from the bytes it governs. Deriving first and checking afterwards would report a
    # verdict computed from bytes we had not yet established were the right ones.
    failed, unverifiable = check_pin(store)
    all_failed += failed
    all_unverifiable += unverifiable
    n_pinned = len((store / MANIFEST_NAME).read_text(encoding="utf-8").strip().splitlines()) \
        if (store / MANIFEST_NAME).is_file() else 0
    print(f"digest pin   {n_pinned} files pinned, "
          f"{len(failed)} failed, {len(unverifiable)} unverifiable")

    # --- the receipts, re-derived
    rows = ledger.read_rows(store / "ledger.jsonl")
    print(f"\n{'receipt':18} {'re-derives':>11} {'checks':>7} {'failed':>7} {'unverif':>8}")
    for row in rows:
        res = rederive(store, row.receipt_id)
        print(f"{row.receipt_id[:16]:18} {str(res.ok):>11} {len(res.checked):>7} "
              f"{len(res.failed):>7} {len(res.unverifiable):>8}")
        all_failed += [f"{row.receipt_id[:16]}: {p}" for p in res.failed]
        all_unverifiable += [f"{row.receipt_id[:16]}: {p}" for p in res.unverifiable]

    # --- the chain
    chain_problems = ledger.verify_chain(rows)
    all_failed += chain_problems
    print(f"\nledger       {len(rows)} rows, chain problems: {chain_problems or 'none'}")

    # --- the anchor, under X-8: reverify returns a LIST OF PROBLEMS, empty for a receipt
    # that re-derives. Anchoring is an assertion that these were real; asserting it over
    # an unread document is the failure the rule exists to prevent.
    def reverify(receipt_id: str) -> list[str]:
        res = rederive(store, receipt_id)
        return res.failed + res.unverifiable

    if chain_problems:
        all_unverifiable.append("anchor not attempted: the chain is broken")
        print("anchor       not attempted -- refusing to anchor a broken chain")
    else:
        anchor = ledger.anchor(rows, reverify)
        print(f"anchor       {anchor['root']}  tree_size={anchor['tree_size']}")
        print(f"recorded     {RECORDED_ANCHOR_ROOT}  (live day, 2026-08-22)")
        if anchor["root"] == RECORDED_ANCHOR_ROOT:
            print("             MATCH -- bit-for-bit identical to the live-day root")
        else:
            all_failed.append(
                f"anchor root {anchor['root']} != recorded {RECORDED_ANCHOR_ROOT}")

    # --- the three outcomes, held apart to the exit code
    if all_failed:
        print(f"\nFAILED       {len(all_failed)} problem(s) -- checked, and wrong",
              file=sys.stderr)
        for p in all_failed:
            print(f"  {p}", file=sys.stderr)
        return 2
    if all_unverifiable:
        print(f"\nUNVERIFIABLE {len(all_unverifiable)} item(s) -- could not be checked",
              file=sys.stderr)
        for p in all_unverifiable:
            print(f"  {p}", file=sys.stderr)
        return 3
    print("\nVERIFIED     every receipt re-derived, chain clean, anchor matches the "
          "live-day root")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
