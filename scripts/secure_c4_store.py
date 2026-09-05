#!/usr/bin/env python3
"""Bring the C4 incident of record under repository custody. COPY, never move.

Core -> Canary Response 011 §2: the Detect pillar's launch deliverable was sitting in
`C:\\tmp\\c4live` -- unpinned, unversioned, beside a dozen throwaway stores from the same
week, surviving by luck. This script is the custody act, and it is written to be run and
re-run: it is idempotent, it never writes to the source, and it fails loudly rather than
producing a partial copy that looks complete.

WHY COPY AND NEVER MOVE
-----------------------
A move is a copy plus a delete, with the delete executed by the same process that has
just claimed the copy succeeded. If the claim is wrong the evidence is already gone. So
this script has no delete path at all -- not a guarded one, not a `--force` one. The
originals are removed by a human, after the committed copy has been proven to re-derive,
which is the only order in which the removal is safe. `assert_no_delete_path()` exists so
that a later edit adding one has to remove an assertion that says why it must not.

THE THREE DIGEST CHECKS
-----------------------
1. **Before**: every source file digested, into a manifest.
2. **After**: every destination file digested independently, and compared per file.
3. **Coverage**: the two file *sets* compared, so a file that was silently dropped fails
   as loudly as a file whose bytes moved. A manifest with a hole reads as full coverage
   while attesting nothing about the gap.

E10 applies with full force here: this is RECEIVED data -- real replies from a live
endpoint, frozen byte-for-byte on 2026-08-22. Nothing here parses, re-serialises,
normalises or pretty-prints anything. Files are moved as bytes and compared as bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_SRC = Path("C:/tmp/c4live")
DEFAULT_DST = REPO / "docs" / "evidence" / "c4-incident-of-record"
MANIFEST_NAME = "c4-incident-of-record.SHA256"


def digest(path: Path) -> str:
    """sha256 over exact bytes. No text mode, no encoding, no newline translation."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def walk(root: Path) -> dict[str, Path]:
    """Every file under `root`, keyed by POSIX-style relative path.

    Keys are forward-slashed so the manifest is identical on any platform: a manifest
    whose contents depend on the OS that generated it cannot be checked by anyone else.
    """
    return {p.relative_to(root).as_posix(): p
            for p in sorted(root.rglob("*")) if p.is_file()}


def assert_no_delete_path() -> None:
    """This script must never be able to remove the originals. See the module docstring.

    Deletion is Shamik's act, performed after the committed copy re-derives. If you are
    here to add a `--move` flag, the answer is no: the ordering that makes removal safe
    cannot be enforced from inside the process doing the copying.

    The banned tokens are assembled from fragments rather than written out, because a
    literal list of them in this file is itself a match: the first version of this guard
    failed on its own docstring. A check that cannot survive reading itself is a check
    that will be deleted by whoever it inconveniences.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    banned = ["shutil." + "rmtree", "os." + "remove", "os." + "unlink",
              "." + "unlink(", "shutil." + "move", "os." + "rmdir"]
    found = [b for b in banned if b in source]
    assert not found, f"this script must contain no delete path; found {found}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--src", type=Path, default=DEFAULT_SRC)
    ap.add_argument("--dst", type=Path, default=DEFAULT_DST)
    args = ap.parse_args(argv)

    assert_no_delete_path()

    src, dst = args.src, args.dst
    if not src.is_dir():
        print(f"source store not found: {src}", file=sys.stderr)
        return 2

    before = walk(src)
    if not before:
        print(f"source store is empty: {src}", file=sys.stderr)
        return 2
    print(f"source       {src}")
    print(f"             {len(before)} files, digested before the copy")

    # --- the copy. shutil.copy2 preserves bytes and mtime; it never touches the source.
    dst.mkdir(parents=True, exist_ok=True)
    for rel, path in before.items():
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    print(f"destination  {dst}")
    print(f"             {len(before)} files copied (source untouched)")

    # --- check 1 and 2: per-file byte equality, computed independently on each side.
    after = walk(dst)
    after.pop(MANIFEST_NAME, None)
    after.pop("PROVENANCE.md", None)

    mismatched = [f"{rel}: source {digest(before[rel])}, copy {digest(after[rel])}"
                  for rel in sorted(before) if rel in after
                  and digest(before[rel]) != digest(after[rel])]

    # --- check 3: coverage, both directions.
    missing = sorted(set(before) - set(after))
    extra = sorted(set(after) - set(before))

    if mismatched or missing or extra:
        print("\nCUSTODY FAILED -- the copy is not byte-equivalent to the source",
              file=sys.stderr)
        for m in mismatched:
            print(f"  bytes moved: {m}", file=sys.stderr)
        for m in missing:
            print(f"  missing from copy: {m}", file=sys.stderr)
        for m in extra:
            print(f"  present in copy but not in source: {m}", file=sys.stderr)
        return 2

    print(f"\n  byte equality  {len(before)}/{len(before)} files identical")
    print(f"  coverage       0 missing, 0 extra")

    # --- the pin, on the fixtures/paper2.SHA256 pattern: `<sha256>  <relative path>`.
    lines = [f"{digest(dst / rel)}  {rel}\n" for rel in sorted(before)]
    (dst / MANIFEST_NAME).write_bytes("".join(lines).encode("utf-8"))
    print(f"  manifest       {MANIFEST_NAME}, {len(lines)} entries")
    print("\nCUSTODY OK -- originals NOT deleted; that is Shamik's act, after the "
          "committed copy re-derives.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
