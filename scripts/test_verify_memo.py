"""Tests for the memo integrity footer verifier.

Both failure directions are tested, as the charter requires: a correctly sealed memo
verifies (a verifier that always rejects is useless), and a memo altered by one byte
fails (a verifier that always accepts is worse than useless).

The three-outcome rule gets its own tests: *absent*, *unverifiable* and *failed* are
distinct outcomes with distinct exit codes, and none of them is a skip.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from verify_memo import (  # noqa: E402
    ABSENT, ERROR, FAILED, OK, UNVERIFIABLE,
    body_bytes, compute_digest, footer_line, main, seal_bytes, verify_bytes, verify_file,
)

SCRIPT = Path(__file__).resolve().parent / "verify_memo.py"
BODY = "Progress report 001\n\nTests are green.\n"


def sealed(body: str = BODY) -> bytes:
    return seal_bytes(body.encode("utf-8"))


# ------------------------------------------------------------------ the preimage rule

def test_body_is_rstripped_plus_exactly_one_lf():
    assert body_bytes(b"a\n\n\n   \n") == b"a\n"
    assert body_bytes(b"a") == b"a\n"
    assert body_bytes(b"") == b"\n"


def test_digest_is_sha256_of_that_preimage_and_nothing_else():
    assert compute_digest(b"a\n\n") == hashlib.sha256(b"a\n").hexdigest()


def test_trailing_whitespace_variants_share_a_digest():
    """The strip is what makes the footer stable against editors adding blank lines."""
    d = compute_digest(BODY.encode())
    for tail in ("", "\n", "\n\n\n", "   \n\t\n"):
        assert compute_digest((BODY + tail).encode()) == d


def test_rstrip_is_ascii_only_not_unicode(tmp_path):
    """U+00A0 is whitespace to str.rstrip() and not to us: the preimage must not depend
    on the runtime's Unicode database (the E14 lesson)."""
    nbsp = "body\n "
    assert compute_digest(nbsp.encode("utf-8")) != compute_digest(b"body\n")
    assert nbsp.rstrip() == "body"          # what str.rstrip() would have done


# ------------------------------------------------------- direction 1: a good memo verifies

def test_a_sealed_memo_verifies():
    r = verify_bytes(sealed())
    assert r.outcome == OK, r.reason


def test_seal_is_idempotent():
    once = sealed()
    assert seal_bytes(once) == once


def test_seal_replaces_an_existing_footer_rather_than_appending():
    stale = BODY.encode() + footer_line("0" * 64).encode() + b"\n"
    out = seal_bytes(stale)
    assert out.count(b"Integrity:") == 1
    assert verify_bytes(out).outcome == OK


def test_footer_digest_is_over_the_body_not_the_whole_file():
    out = sealed()
    declared = out.decode().rstrip("\n").rsplit(" ", 1)[1]
    assert declared == hashlib.sha256(BODY.encode()).hexdigest()


# --------------------------------------------------- direction 2: a bad memo is rejected

def test_one_altered_byte_in_the_body_fails():
    out = sealed().replace(b"green", b"greeN")
    r = verify_bytes(out)
    assert r.outcome == FAILED
    assert r.declared != r.computed


def test_an_altered_digit_in_the_footer_fails():
    out = bytearray(sealed())
    out[-5] = ord("0") if out[-5] != ord("0") else ord("1")
    r = verify_bytes(bytes(out))
    assert r.outcome == FAILED


def test_appended_content_after_the_footer_is_not_silently_accepted():
    r = verify_bytes(sealed() + b"PS: smuggled.\n")
    assert r.outcome == UNVERIFIABLE
    assert "final line" in r.reason


# -------------------------------------------------------------- the three-outcome rule

def test_absent_is_its_own_outcome():
    r = verify_bytes(BODY.encode())
    assert r.outcome == ABSENT
    assert r.outcome not in (OK, FAILED, UNVERIFIABLE)


def test_two_footers_are_unverifiable_not_a_tie_to_resolve():
    """The producer obligation is one footer; a verifier must reject, never pick one."""
    good = sealed()
    r = verify_bytes(good + good)
    assert r.outcome == UNVERIFIABLE
    assert "exactly one" in r.reason or "permits exactly one" in r.reason


def test_a_second_footer_whose_digest_is_correct_is_still_unverifiable():
    """Ambiguity is malformed even when one of the candidates would have passed."""
    body = BODY.encode()
    two = body + footer_line(compute_digest(body)).encode() + b"\n" \
        + footer_line(compute_digest(body)).encode() + b"\n"
    assert verify_bytes(two).outcome == UNVERIFIABLE


@pytest.mark.parametrize("line", [
    b"Integrity: sha256(body) = deadbeef",                    # too short
    b"Integrity: sha256(body) = " + b"A" * 64,                # uppercase hex
    b"Integrity: sha256(body)=" + b"a" * 64,                  # spacing
    b"Integrity: md5(body) = " + b"a" * 64,                   # wrong algorithm
    b"Integrity: " + b"a" * 64,                               # no algorithm
])
def test_malformed_footers_are_unverifiable_never_absent(line):
    r = verify_bytes(BODY.encode() + line + b"\n")
    assert r.outcome == UNVERIFIABLE, r.reason


def test_a_footer_without_a_trailing_newline_still_verifies():
    """The ratified missing-LF case: a file ending at the digest's final hex character,
    with no LF at all, is WELL-FORMED.

    Ratified in Core -> Forensics Response 017; confirmed to this session in Core ->
    Canary Response 002 §3, after both other channels diverged permissively on Forward
    003 clause 2 and the closure surfaced this residual case. The clause in full: *the
    file ends at the footer line with at most one terminating LF; a missing final LF is
    tolerated; any byte after that LF, whitespace included, is malformed.*

    This assertion predates the ruling -- it was written under this session's own strict
    Q03 reading, which the ruling confirms -- so it is annotated rather than added. A
    test that already held the ratified behaviour is evidence, and it should say which
    ruling it now answers to.
    """
    out = sealed()
    assert verify_bytes(out.rstrip(b"\n")).outcome == OK
    # The byte-level detail the clause turns on: nothing at all follows the hex.
    assert out.rstrip(b"\n")[-1:] in b"0123456789abcdef"


@pytest.mark.parametrize("tail", [
    b"\n",       # a second LF -- "at most one terminating LF"
    b" ",        # a single space
    b"   ",      # several spaces
    b"\t",       # a tab
    b"\r",       # a lone CR: the CRLF tail this repo's `* -text` exists to prevent
    b"\n\n",     # a blank line
    b" \n",      # space then LF
])
def test_whitespace_after_the_terminating_lf_is_malformed(tail):
    """"Any byte after that LF, WHITESPACE INCLUDED, is malformed."

    This is the half of the clause the permissive divergence turned on, and the half
    with no test before this one: trailing content was covered only by visible text
    (`PS: smuggled.`). Whitespace is the dangerous case precisely because it is
    invisible in an editor -- a reviewer cannot see the byte a permissive verifier
    would forgive, so the digest would attest less than the file contains while every
    human check looked clean.
    """
    r = verify_bytes(sealed() + tail)
    assert r.outcome == UNVERIFIABLE, f"tail {tail!r} was not rejected: {r.reason}"
    assert r.outcome not in (OK, FAILED)


def test_undecodable_body_is_unverifiable_not_a_crash():
    bad = b"\xff\xfe not utf-8\n"
    r = verify_bytes(bad + footer_line(compute_digest(bad)).encode() + b"\n")
    assert r.outcome == UNVERIFIABLE
    assert "UTF-8" in r.reason


def test_an_indented_quotation_of_a_footer_does_not_count_as_a_footer():
    """CLAUDE.md's producer rule: quotations are indented or kept mid-line."""
    quoting = "The memo ended:\n\n    Integrity: sha256(body) = " + "b" * 64 + "\n\nSo it did.\n"
    assert verify_bytes(seal_bytes(quoting.encode())).outcome == OK


def test_missing_file_is_an_error_outcome(tmp_path):
    assert verify_file(tmp_path / "nope.md").outcome == ERROR


def test_seal_refuses_an_ambiguous_file():
    with pytest.raises(ValueError, match="ambiguous"):
        seal_bytes(sealed() + sealed())


# ----------------------------------------------------------------------- the CLI surface

def test_cli_exit_codes_match_the_outcomes(tmp_path):
    good, bad, none = tmp_path / "g.md", tmp_path / "b.md", tmp_path / "n.md"
    good.write_bytes(sealed())
    bad.write_bytes(sealed().replace(b"green", b"greeN"))
    none.write_text(BODY, encoding="utf-8", newline="")
    assert main([str(good)]) == OK
    assert main([str(bad)]) == FAILED
    assert main([str(none)]) == ABSENT


def test_cli_reports_the_worst_outcome_over_several_files(tmp_path):
    good, bad = tmp_path / "g.md", tmp_path / "b.md"
    good.write_bytes(sealed())
    bad.write_bytes(sealed() + sealed())
    assert main([str(good), str(bad)]) == UNVERIFIABLE


def test_cli_seal_then_verify_roundtrip(tmp_path):
    p = tmp_path / "memo.md"
    p.write_text(BODY, encoding="utf-8", newline="")
    assert main(["--seal", str(p)]) == OK
    assert main([str(p)]) == OK


def test_invoked_as_a_subprocess_the_way_ci_will(tmp_path):
    """Gate-verbatim: the CI gate runs the script, so the script is what is tested."""
    p = tmp_path / "memo.md"
    p.write_bytes(sealed())
    r = subprocess.run([sys.executable, str(SCRIPT), str(p)], capture_output=True)
    assert r.returncode == OK, r.stderr.decode()
    p.write_bytes(sealed().replace(b"green", b"greeN"))
    r = subprocess.run([sys.executable, str(SCRIPT), str(p)], capture_output=True)
    assert r.returncode == FAILED
    assert b"FAILED" in r.stderr
