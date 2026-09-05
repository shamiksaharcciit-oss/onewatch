#!/usr/bin/env python3
"""Memo integrity footer: verify and seal.

THE PROTOCOL (CLAUDE.md, verbatim)
----------------------------------
Every memo carries a final line::

    Integrity: sha256(body) = <hex>

**body** = every byte of the file strictly before the line beginning ``Integrity:``,
trailing whitespace stripped, plus exactly one LF, UTF-8.

**Exactly one line of a memo may begin with** ``Integrity:`` -- a producer obligation
(quotations are indented or kept mid-line). A verifier encountering more than one such
line MUST reject the file as malformed; ambiguity is an error to surface, never a tie
to resolve.

THE THREE-OUTCOME RULE
----------------------
*absent*, *unverifiable* and *failed* are held apart and never collapsed::

    OK            0   footer present, well-formed, and the digest matches
    FAILED        2   footer present and well-formed, digest DOES NOT match
    UNVERIFIABLE  3   footer present but the file cannot be checked (two footers,
                      malformed footer, footer not final, undecodable bytes)
    ABSENT        4   no line begins with ``Integrity:``
    ERROR         5   the file could not be read at all

Unverifiable and malformed are failures to surface, never skips.

TWO INTERPRETATIONS, DECLARED
-----------------------------
1. *"trailing whitespace stripped"* is implemented as a **byte-level** strip of the
   ASCII whitespace set ``b" \\t\\n\\r\\f\\v"``, not ``str.rstrip()``. ``str.rstrip()``
   consults the Unicode database, which would make the preimage depend on the
   runtime's UCD version -- the defect the manifest layer closed as E14 (ACJ v2: no
   Unicode normalisation in a hash preimage). A digest that moves with a Python
   upgrade is not a digest.
2. *"a final line"* is enforced: bytes after the footer line's terminating LF must be
   empty. A footer with content after it is UNVERIFIABLE, not OK -- the footer would
   not cover those bytes, and the file would carry unattested content under a passing
   check.

Both are recorded as questions for core rather than settled here.

RECEIVED-DATA DISCIPLINE (E10)
------------------------------
This module reads bytes and never rewrites them. ``--seal`` appends a footer to a file
that has none (or replaces an existing footer line, leaving every other byte
untouched); it normalises nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

MARKER = b"Integrity:"
#: ``Integrity: sha256(body) = <64 lowercase hex>`` -- exactly one space after the
#: colon and either side of ``=``. Narrow by design: a footer we cannot parse is
#: unverifiable, never quietly re-read under a looser rule.
FOOTER_RE = re.compile(rb"^Integrity: sha256\(body\) = ([0-9a-f]{64})$")
#: ASCII whitespace only; see "TWO INTERPRETATIONS" above.
ASCII_WS = b" \t\n\r\f\v"

OK, FAILED, UNVERIFIABLE, ABSENT, ERROR = 0, 2, 3, 4, 5
OUTCOME_NAMES = {OK: "OK", FAILED: "FAILED", UNVERIFIABLE: "UNVERIFIABLE",
                 ABSENT: "ABSENT", ERROR: "ERROR"}


class Result:
    """One verdict. ``outcome`` is the exit code; ``reason`` says why, always."""

    def __init__(self, outcome: int, reason: str, computed: str = "", declared: str = ""):
        self.outcome = outcome
        self.reason = reason
        self.computed = computed
        self.declared = declared

    @property
    def name(self) -> str:
        return OUTCOME_NAMES[self.outcome]

    def __repr__(self) -> str:                              # pragma: no cover - debug aid
        return f"<Result {self.name}: {self.reason}>"


def _split_lines_keepends(data: bytes) -> list[bytes]:
    """Split on LF only, keeping ends.

    ``bytes.splitlines()`` also splits on CR, FF, VT and friends; a memo line is
    LF-terminated and nothing else decides where a line begins.
    """
    out, start = [], 0
    while True:
        i = data.find(b"\n", start)
        if i == -1:
            if start < len(data):
                out.append(data[start:])
            return out
        out.append(data[start:i + 1])
        start = i + 1


def body_bytes(preceding: bytes) -> bytes:
    """The canonical preimage: everything before the footer, ASCII-rstripped, plus one LF."""
    return preceding.rstrip(ASCII_WS) + b"\n"


def compute_digest(preceding: bytes) -> str:
    return hashlib.sha256(body_bytes(preceding)).hexdigest()


def footer_line(digest: str) -> str:
    return f"Integrity: sha256(body) = {digest}"


def verify_bytes(data: bytes) -> Result:
    """Verify raw file bytes. Never raises for content reasons; every path returns a Result."""
    lines = _split_lines_keepends(data)
    hits = [i for i, ln in enumerate(lines) if ln.startswith(MARKER)]

    if not hits:
        return Result(ABSENT, "no line begins with 'Integrity:'")
    if len(hits) > 1:
        at = ", ".join(str(i + 1) for i in hits)
        return Result(UNVERIFIABLE,
                      f"{len(hits)} lines begin with 'Integrity:' (lines {at}); the protocol "
                      f"permits exactly one -- ambiguity is surfaced, not resolved")

    idx = hits[0]
    stripped = lines[idx].rstrip(b"\n")
    m = FOOTER_RE.match(stripped)
    if not m:
        return Result(UNVERIFIABLE,
                      f"footer on line {idx + 1} does not match "
                      f"'Integrity: sha256(body) = <64 lowercase hex>': {stripped[:120]!r}")

    trailing = b"".join(lines[idx + 1:])
    if trailing:
        return Result(UNVERIFIABLE,
                      f"{len(trailing)} byte(s) follow the footer; the footer must be the "
                      f"final line, and bytes after it are not covered by the digest")

    preceding = b"".join(lines[:idx])
    try:
        preceding.decode("utf-8")
    except UnicodeDecodeError as e:
        return Result(UNVERIFIABLE, f"body is not valid UTF-8: {e}")

    declared = m.group(1).decode("ascii")
    computed = compute_digest(preceding)
    if computed != declared:
        return Result(FAILED, "digest mismatch", computed=computed, declared=declared)
    return Result(OK, "footer verified", computed=computed, declared=declared)


def verify_file(path: Path) -> Result:
    try:
        data = path.read_bytes()
    except OSError as e:
        return Result(ERROR, f"cannot read {path}: {e}")
    return verify_bytes(data)


def seal_bytes(data: bytes) -> bytes:
    """Return `data` with a correct footer. Raises ValueError if the file is ambiguous.

    X-11: the digest is computed in, never transcribed. An existing footer line is
    replaced; no other byte is touched.
    """
    lines = _split_lines_keepends(data)
    hits = [i for i, ln in enumerate(lines) if ln.startswith(MARKER)]
    if len(hits) > 1:
        raise ValueError(f"{len(hits)} lines begin with 'Integrity:'; refusing to seal an "
                         f"ambiguous file")
    if hits:
        idx = hits[0]
        if b"".join(lines[idx + 1:]):
            raise ValueError("content follows the existing footer; refusing to seal")
        preceding = b"".join(lines[:idx])
    else:
        preceding = data
    body = body_bytes(preceding)
    return body + footer_line(compute_digest(preceding)).encode("utf-8") + b"\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Verify (or seal) memo integrity footers.")
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--seal", action="store_true",
                    help="compute and write the footer instead of verifying")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="print nothing for files that verify")
    args = ap.parse_args(argv)

    worst = OK
    for p in args.paths:
        if args.seal:
            try:
                out = seal_bytes(p.read_bytes())
            except (OSError, ValueError) as e:
                print(f"ERROR        {p}: {e}", file=sys.stderr)
                worst = max(worst, ERROR)
                continue
            p.write_bytes(out)
            r = verify_file(p)                              # seal, then prove the seal
            print(f"SEALED       {p}: {r.name} {r.computed}")
            worst = max(worst, r.outcome)
            continue

        r = verify_file(p)
        if r.outcome != OK or not args.quiet:
            stream = sys.stdout if r.outcome == OK else sys.stderr
            detail = r.reason
            if r.outcome == FAILED:
                detail = f"{r.reason}: declared {r.declared}, computed {r.computed}"
            print(f"{r.name:<12} {p}: {detail}", file=stream)
        worst = max(worst, r.outcome)
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
