"""E10 layer 3 of 3: digest tests over received and vendored data.

The three layers of the received-data discipline, and where each lives:

1. **`.gitattributes`** — `* -text`, so no git checkout rewrites a byte. Layer 1
   prevents the corruption.
2. **Exclusion lists** — `pyproject.toml` keeps every formatter, linter and
   auto-fixer out of the received-data paths. Layer 2 prevents a *tool* from
   rewriting a byte.
3. **These tests** — layer 3 assumes layers 1 and 2 have already failed and asks
   the only question that survives that assumption: *are the bytes still the
   bytes?* A preventive control that cannot be observed failing is not a control.

Every assertion here is over bytes read from disk. Nothing is normalised on the way
in, because normalising on the way in is the defect being tested for.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
VENDOR = REPO / "vendor" / "rederivable-manifest"
PIN = REPO / "vendor" / "rederivable-manifest.SHA256"

sys.path.insert(0, str(REPO / "scripts"))

from verify_memo import OK, verify_file  # noqa: E402

sys.path.insert(0, str(REPO))
from canary.receipt.store import _long_path  # noqa: E402

#: Paths whose bytes are RECEIVED data: frozen verbatim, never normalised. Every one of
#: these must be excluded from every byte-rewriting tool.
RECEIVED_DIRS = ("docs/from_core", "docs/to_core", "vendor", "fixtures", "docs/evidence")

#: Paths where CR-ABSENCE is a meaningful corruption signal, because every file in them
#: arrived LF-only. `fixtures` is deliberately NOT here, and the reason matters:
#:
#: The upstream telemetry artifacts are CRLF files. Verbatim copies of them contain 2844
#: carriage returns, and that is *correct* — those bytes are the evidence. A blanket
#: "no CR in received data" rule would fail on faithful copies and could only be
#: satisfied by stripping them, which is exactly the corruption the rule exists to
#: prevent. The rule would have demanded the defect.
#:
#: So: **CR-absence is a proxy, not the invariant. The invariant is byte-identity.**
#: Where a digest pin exists (`vendor`, `fixtures`) the pin is the real check and it is
#: tested directly. The CR check is retained only where it detects something the pin
#: cannot: `docs/*` carries no pin, only `Integrity:` footers, and a CRLF checkout there
#: breaks verification in a way that looks like a content dispute rather than a
#: transport fault.
LF_ONLY_DIRS = ("docs/from_core", "docs/to_core", "vendor")

FIXTURES = REPO / "fixtures" / "paper2"
FIXTURE_PIN = REPO / "fixtures" / "paper2.SHA256"

#: The C4 incident of record -- the Detect pillar's launch deliverable. Brought under
#: repository custody on 2026-08-27 (Core -> Canary Response 011 §2) from a scratch
#: directory where it had been sitting unpinned and unversioned. Defect F2, self-reported.
INCIDENT = REPO / "docs" / "evidence" / "c4-incident-of-record"
INCIDENT_PIN = INCIDENT / "c4-incident-of-record.SHA256"


def tracked_files() -> list[str]:
    """Ask git what it tracks. A hard-coded list would rot; this cannot."""
    p = subprocess.run(["git", "-C", str(REPO), "ls-files"],
                       capture_output=True, text=True, check=True)
    files = p.stdout.split("\n")
    files = [f for f in files if f.strip()]
    assert files, "git ls-files returned nothing; refusing to pass vacuously"
    return files


def _pin_entries() -> dict[str, str]:
    entries = {}
    for line in PIN.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split(None, 1)
            entries[name.strip()] = digest
    assert entries, "pin file parsed to nothing"
    return entries


# ------------------------------------------------------------------ the vendored pin

def test_every_vendored_file_matches_its_pinned_digest():
    """The pin is the whole reason a vendored copy is trustworthy."""
    entries = _pin_entries()
    mismatched = []
    for name, want in entries.items():
        path = VENDOR / name
        assert path.exists(), f"pinned file missing from the vendored tree: {name}"
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if got != want:
            mismatched.append(f"{name}: pinned {want}, computed {got}")
    assert not mismatched, "vendored bytes have moved:\n" + "\n".join(mismatched)


def test_the_pin_covers_every_file_in_the_vendored_tree():
    """A pin with a hole in it is worse than no pin: it reads as full coverage.

    An unpinned file could be added to the vendored tree and every digest check
    would still pass, because nothing would ever look at it.
    """
    on_disk = {
        str(p.relative_to(VENDOR)).replace("\\", "/")
        for p in VENDOR.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    assert on_disk, "vendored tree is empty"
    unpinned = on_disk - set(_pin_entries())
    assert not unpinned, f"files present in vendor/ but absent from the pin: {sorted(unpinned)}"


def test_vendored_selftest_contract():
    """The CONTRACT, never the count -- R-C001.

    The vendored README's "20 checks" is stale (v3 emits more). This test asserts
    what the self-test actually promises -- reports its checks, ALL PASS, exit 0 --
    and would not need editing if the count moved again. Asserting the number here
    would reproduce, inside our own test suite, the exact defect the erratum records.

    Invoked via `sys.executable`, never the name `python3`: that name may resolve to
    something other than an interpreter, and it is not this suite's job to find out
    which (N-C001). The OUTPUT is asserted, not merely the status, because the output
    contract is the only thing that travels with the work.
    """
    p = subprocess.run([sys.executable, "validate.py", "--selftest"],
                       cwd=VENDOR, capture_output=True, text=True)
    out = p.stdout + p.stderr
    assert p.returncode == 0, f"self-test exited {p.returncode}:\n{out}"
    assert out.strip().splitlines()[-1] == "ALL PASS", f"final line was not ALL PASS:\n{out}"
    assert out.count("[PASS]") > 0, "self-test reported no checks at all"


def _working_bash() -> str | None:
    """Return the path of a bash that actually runs, or None.

    Probed rather than assumed: a name on PATH is a claim, and this file exists because
    claims about what a command does are worth less than what it does when run.
    """
    candidates = [shutil.which("bash"),
                  r"C:\Program Files\Git\bin\bash.exe",
                  r"C:\Program Files\Git\usr\bin\bash.exe",
                  "/bin/bash", "/usr/bin/bash"]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            p = subprocess.run([candidate, "-c", "echo ok"],
                               capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode == 0 and p.stdout.strip() == "ok":
            return candidate
    return None


def test_a_bare_dollar_question_after_a_pipeline_reports_the_wrong_command():
    """N-C001, corrected: the mechanism is the pipe, not any particular interpreter.

    THIS TEST REPLACES ONE THAT ASSERTED A FALSE PREMISE. The earlier version claimed
    the Store `python3` alias "exits 0 while running nothing" and skipped whenever the
    alias happened to work -- so on a host where the alias resolved, it asserted nothing
    at all, which is precisely the shape of defect it was written to guard against.

    The alias in fact fails loudly (exit 49). The false green came from reading `$?`
    after a pipeline, where it holds the LAST command's status -- `tail`'s -- and the
    gate's status has already been discarded. That needs no Windows alias and no
    missing interpreter. It needs a pipe, and nearly every gate anyone runs is piped.

    So the mechanism is asserted here with a command whose failure is certain, making
    the test independent of what any interpreter name resolves to on any host.
    """
    fail = [sys.executable, "-c", "import sys; sys.exit(49)"]

    direct = subprocess.run(fail, capture_output=True, text=True)
    assert direct.returncode == 49, "the control command did not fail as constructed"

    # A real shell, so the assertion is about real shell semantics rather than a Python
    # emulation of them. `bash` specifically: PIPESTATUS is a bash array, not POSIX sh.
    # Both spellings run the SAME failing command through the SAME pipe.
    #
    # The shell is located by PROBING, not by name. Invoking bare "bash" on this Windows
    # host reaches System32's WSL relay, which cannot execute anything here and fails
    # with a message about /bin/bash -- a name resolving to the wrong program, which is
    # the same class of fault as N-C001 itself. So each candidate is run with a control
    # command and only a shell that actually answers is used.
    bash = _working_bash()
    if bash is None:                                     # pragma: no cover - host dep
        pytest.skip(
            "no working bash found; the pipe mechanism is a shell property and cannot "
            "be demonstrated without one. CI runs this job on ubuntu-latest, where a "
            "real bash always exists, so the assertion is never skipped everywhere.")

    # Single quotes and forward slashes: inside bash double quotes a Windows path's
    # backslashes are escape characters, which silently mangles the command into
    # something that exits 127 rather than 49 -- a broken control masquerading as a
    # result. Single-quoting makes every character literal.
    exe = sys.executable.replace("\\", "/")
    quoted = f"'{exe}' -c 'import sys; sys.exit(49)'"

    def _bash(script: str) -> str:
        p = subprocess.run([bash, "-c", script], capture_output=True, text=True)
        assert p.returncode == 0, f"bash itself failed: {p.stderr}"
        return p.stdout.strip()

    # The control, through the same shell: if this is not 49, nothing below means
    # anything, and the failure should say so rather than look like a masking result.
    assert _bash(f"{quoted}; echo $?") == "49", (
        "the control command did not return 49 through bash; the shell invocation is "
        "broken and no conclusion about pipelines can be drawn from it")

    masked = _bash(f"{quoted} 2>&1 | tail -1 >/dev/null; echo $?")
    recovered = _bash(f"{quoted} 2>&1 | tail -1 >/dev/null; echo ${{PIPESTATUS[0]}}")
    pipefail = _bash(f"set -o pipefail; {quoted} 2>&1 | tail -1 >/dev/null; echo $?")

    assert masked == "0", (
        f"`$?` after the pipeline reported {masked!r}, not 0. If this shell propagates "
        f"pipeline failure by default the masking cannot be demonstrated here, but the "
        f"rule stands: take PIPESTATUS[0] or set -o pipefail.")
    assert recovered == "49", f"PIPESTATUS[0] reported {recovered!r}, not the gate's 49"
    assert pipefail == "49", f"under pipefail the shell reported {pipefail!r}, not 49"


def test_this_repository_never_branches_on_a_bare_status_after_a_pipe():
    """The third consequence, enforced rather than remembered.

    A CI step that pipes a gate and then trusts `$?` would report success over a failed
    gate. Grep is the right instrument here: the property is about text we author, and
    an authored `| ... $?` sequence is exactly what must not appear.
    """
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    offenders = []
    for i, line in enumerate(ci.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "$?" in stripped and "PIPESTATUS" not in stripped:
            offenders.append(f"ci.yml:{i}: {stripped}")
    assert not offenders, (
        "a bare `$?` appears in CI; after a pipeline it reports the wrong command's "
        "status (N-C001):\n" + "\n".join(offenders))


# ------------------------------------------------------------------- the fixture pin

def _fixture_pin() -> dict[str, str]:
    entries = {}
    for line in FIXTURE_PIN.read_text(encoding="utf-8").splitlines():
        if line.strip():
            digest, name = line.split(None, 1)
            entries[name.strip()] = digest
    assert entries, "fixture pin parsed to nothing"
    return entries


def test_every_paper2_fixture_matches_its_pinned_digest():
    """The frozen replies are RECEIVED data: byte-for-byte copies of upstream artifacts.

    A JSON file that has been parsed and written back out is a different file -- key
    order, separators, escaping and number rendering all move -- and every result
    derived from it becomes a result about something else. The pin is what makes
    "verbatim" checkable rather than merely intended.
    """
    mismatched = []
    for name, want in _fixture_pin().items():
        path = FIXTURES / name
        assert path.exists(), f"pinned fixture missing: {name}"
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if got != want:
            mismatched.append(f"{name}: pinned {want}, computed {got}")
    assert not mismatched, "fixture bytes have moved:\n" + "\n".join(mismatched)


def test_the_fixture_pin_covers_every_fixture_present():
    """A pin with a hole reads as full coverage while attesting nothing about the gap."""
    on_disk = {p.name for p in FIXTURES.glob("*.json")}
    assert on_disk, "no fixtures found"
    unpinned = on_disk - set(_fixture_pin())
    assert not unpinned, f"fixtures present but unpinned: {sorted(unpinned)}"


def test_the_fixtures_carry_their_provenance_and_their_caveat():
    """§7.4's retirement line must not drift out of the file that governs its use."""
    text = (FIXTURES / "PROVENANCE.md").read_text(encoding="utf-8")
    assert "370f5f34d0114e776ad36d70e216214f62f7cf88" in text
    assert "permanently retired generation" in text
    assert "never a live canary" in text


# ------------------------------------------------------- received bytes are unrewritten

@pytest.mark.parametrize("directory", LF_ONLY_DIRS)
def test_no_lf_only_file_contains_a_carriage_return(directory):
    """The autocrlf failure, asserted so it can never return silently.

    Measured 2026-08-21: with `core.autocrlf=true` (Git for Windows' own default) and
    no `.gitattributes`, a cold clone injected 140 CR bytes into an 8533-byte memo and
    the verifier returned UNVERIFIABLE. The blob was correct; the checkout was not.
    That is the failure mode this repository cannot have -- clean to its author,
    broken for its verifier -- so it is asserted, not trusted to a config setting.
    """
    offenders = []
    for rel in tracked_files():
        if not rel.startswith(directory + "/") or rel.endswith(".zip"):
            continue
        data = (REPO / rel).read_bytes()
        if b"\r" in data:
            offenders.append(f"{rel}: {data.count(b'\r')} CR byte(s)")
    assert not offenders, (
        "carriage returns in received data -- line-ending translation has been "
        "reintroduced somewhere:\n" + "\n".join(offenders))


def test_every_archived_memo_still_verifies():
    """A memo whose footer stops verifying is a memo whose bytes moved."""
    memos = [REPO / f for f in tracked_files()
             if f.startswith(("docs/from_core/", "docs/to_core/")) and f.endswith(".md")]
    assert memos, "no archived memos found; refusing to pass vacuously"
    broken = []
    for m in memos:
        r = verify_file(m)
        if r.outcome != OK:
            broken.append(f"{m.relative_to(REPO)}: {r.name} -- {r.reason}")
    assert not broken, "archived memos no longer verify:\n" + "\n".join(broken)


def test_gitattributes_still_disables_eol_translation():
    """Layer 1, asserted. Deleting `* -text` must break a test, not just a habit."""
    text = (REPO / ".gitattributes").read_text(encoding="utf-8")
    directives = [
        ln.split()[0:2] for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    assert ["*", "-text"] in directives, (
        "the global `* -text` rule is gone from .gitattributes; every received-data "
        "path is exposed to end-of-line translation again")


def test_received_paths_are_excluded_from_every_formatter():
    """Layer 2, asserted: a formatter added later must not silently inherit these paths."""
    cfg = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    for directory in RECEIVED_DIRS:
        assert directory in cfg, (
            f"{directory} is not named in pyproject.toml; a byte-rewriting tool "
            f"configured there would be free to reach received data")


def test_the_fixtures_really_do_carry_carriage_returns():
    """The exclusion above is load-bearing, so it is asserted rather than assumed.

    If upstream's artifacts were ever replaced with LF-only files, `LF_ONLY_DIRS` should
    grow to include `fixtures` and this test should be the thing that says so. An
    exclusion nobody re-checks becomes a hole nobody remembers opening.
    """
    CR = bytes([13])
    total = sum((FIXTURES / name).read_bytes().count(CR) for name in _fixture_pin())
    assert total == 2844, (
        f"expected 2844 CR bytes across the pinned fixtures, found {total}. If they "
        f"were re-copied from an LF-only source, add 'fixtures' back to LF_ONLY_DIRS; "
        f"if they were stripped in place, that is the corruption this file exists to "
        f"catch and the pin test above will say so too.")


# ------------------------------------------------- the C4 incident of record, layer 3


def _incident_pin() -> dict[str, str]:
    entries = {}
    for line in INCIDENT_PIN.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        want, _, rel = line.partition("  ")
        entries[rel] = want
    assert entries, "incident pin parsed to nothing"
    return entries


def test_every_incident_file_matches_its_pinned_digest():
    """The launch deliverable's bytes, pinned.

    Re-derivation re-classifies every verdict FROM THESE RAW BYTES rather than reading a
    recorded verdict back. So a byte that moves here does not merely dirty a diff -- it
    changes what the instrument reads, and can flip the verdict in the artifact this
    pillar ships. The pin is what makes "frozen" checkable rather than merely intended.
    """
    mismatched = []
    for rel, want in _incident_pin().items():
        path = INCIDENT / rel
        # Long-path form, exactly as the engine's Store reads these: the body addresses
        # run to 177 characters and plain `Path.exists()` answers False past MAX_PATH on
        # Windows for a file that is present and intact. This test passed in the shallow
        # working tree and failed only from a deep cold clone -- the same defect as F6,
        # in the test that was meant to catch it. Cold-clone verification is why it
        # surfaced at all.
        assert os.path.exists(_long_path(path)), f"pinned incident file missing: {rel}"
        with open(_long_path(path), "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        if got != want:
            mismatched.append(f"{rel}: pinned {want}, computed {got}")
    assert not mismatched, "incident bytes have moved:\n" + "\n".join(mismatched)


def test_the_incident_pin_covers_every_file_present():
    """A pin with a hole reads as full coverage while attesting nothing about the gap."""
    root = Path(os.path.abspath(_long_path(INCIDENT)))
    on_disk = {(Path(d) / n).relative_to(root).as_posix()
               for d, _sub, names in os.walk(_long_path(INCIDENT)) for n in names}
    unpinned = on_disk - set(_incident_pin()) - {INCIDENT_PIN.name, "PROVENANCE.md"}
    assert not unpinned, f"incident files present but unpinned: {sorted(unpinned)}"


def test_the_incident_still_rederives_and_the_anchor_still_matches():
    """The product's own claim, asserted as a test rather than performed in a demo.

    Three receipts re-derived from bytes on disk, the chain verified, and the Merkle root
    recomputed against the root recorded on the live day of 2026-08-22. If this ever goes
    red, the launch deliverable has stopped being evidence and the receipts are the first
    thing to stop trusting -- which is why it runs on every commit rather than by hand.
    """
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "rederive_incident.py")],
                       capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, (
        f"re-derivation of the incident of record did not verify "
        f"(exit {r.returncode}):\n{r.stdout}\n{r.stderr}")
    assert "MATCH -- bit-for-bit identical to the live-day root" in r.stdout, (
        f"anchor root no longer matches the live-day root:\n{r.stdout}")


def test_the_incident_carries_its_provenance_and_its_publication_caveat():
    """gen-1-c4 is ACTIVE until retirement is executed; the caveat must not drift away.

    Retirement and disclosure are approved (Response 011 §3) but timed to launch week.
    Until then `runs/*/suite.json` carries full probe text that must not be published,
    and the file that says so lives beside the bytes it governs.
    """
    text = (INCIDENT / "PROVENANCE.md").read_text(encoding="utf-8")
    assert "RECEIVED data" in text
    assert "gen-1-c4" in text
    assert "not yet executed" in text
    assert "Do not publish" in text
    assert "CANARY_GEN_SEED" in text


def test_the_custody_script_has_no_delete_path():
    """Copy, never move. The originals are removed by a human, after this copy verifies.

    A move is a copy plus a delete performed by the same process that just claimed the
    copy succeeded; if the claim is wrong the evidence is already gone. The script
    asserts this about itself -- this test asserts that the assertion is still there.
    """
    sys.path.insert(0, str(REPO / "scripts"))
    import secure_c4_store
    secure_c4_store.assert_no_delete_path()


def test_the_rescoring_table_in_the_readme_is_what_the_command_produces():
    """F4: a table with no regenerating command is transcription with extra steps.

    The numbers were right, and being right by hand is not the property X-11 asks for --
    it asks that figures be computed into documents by tooling. This test binds the
    published table to its generator, so the two cannot drift apart silently: if either
    moves without the other, this goes red.
    """
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "rescore_incident.py"),
                        "--markdown"], capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, f"re-scoring failed:{chr(10)}{r.stdout}{chr(10)}{r.stderr}"
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    for line in r.stdout.strip().splitlines():
        assert line in readme, (
            f"the README table no longer matches its generator. Missing row:{chr(10)}"
            f"  {line}{chr(10)}Regenerate with: "
            f"python scripts/rescore_incident.py --markdown")
    assert "scripts/rescore_incident.py" in readme, (
        "the table must cite the command that produces it")


def test_the_rescoring_demonstration_keeps_its_label():
    """The (c) artefact is a demonstration; unlabelled it becomes a receipt of record.

    v1 and v2 are superseded instruments. A table showing them reporting CHANGED, shorn
    of its label, reads as evidence that the behaviour changed -- the exact overclaim the
    incident of record exists to refuse.
    """
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "never as a receipt of record" in readme
    source = (REPO / "scripts" / "rescore_incident.py").read_text(encoding="utf-8")
    assert "never a receipt of record" in source, (
        "the generator must print the label alongside the table it emits")


def test_the_coverage_scan_finds_a_file_whose_path_is_too_long(tmp_path):
    """F6, the grave half: a hole in the hole-finder fails toward reassurance.

    Core -> Canary Response 012 §2 requires this test by name: the scan is shown a
    too-long path and is required to FIND it. The original used `rglob`, which simply
    does not enumerate past MAX_PATH on Windows -- so an unpinned file hiding at a long
    path never entered the on-disk set and was never reported. The check whose entire job
    is finding holes had one, and it failed in the direction of reassurance, which is the
    only direction this programme genuinely fears.

    Constructed rather than recorded: a store is built here with one pinned file and one
    unpinned intruder placed deliberately past MAX_PATH. The intruder must be reported.
    """
    sys.path.insert(0, str(REPO / "scripts"))
    import rederive_incident

    # A store root deep enough that `runs/<64>/bodies/<64>` crosses MAX_PATH.
    deep = tmp_path
    while len(str(deep)) < 150:
        deep = deep / "nested-directory-padding"
    store = deep / "store"
    bodies = store / "runs" / ("a" * 64) / "bodies"
    os.makedirs(_long_path(bodies), exist_ok=True)

    pinned_body = bodies / ("b" * 64)
    intruder = bodies / ("c" * 64)
    for path, content in ((pinned_body, b"pinned"), (intruder, b"unpinned intruder")):
        with open(_long_path(path), "wb") as fh:
            fh.write(content)
    assert len(str(intruder)) > 260, (
        f"the intruder path is only {len(str(intruder))} chars; this test proves nothing "
        f"unless it actually crosses MAX_PATH")
    # Sanity: the intruder is genuinely invisible to the naive call the bug used.
    assert not intruder.is_file(), (
        "Path.is_file() can see the intruder here, so this platform does not reproduce "
        "the condition and the test would pass vacuously")

    rel = f"runs/{'a' * 64}/bodies/{'b' * 64}"
    digest = hashlib.sha256(b"pinned").hexdigest()
    with open(_long_path(store / rederive_incident.MANIFEST_NAME), "wb") as fh:
        fh.write(f"{digest}  {rel}".encode("utf-8") + b"\n")

    failed, unverifiable = rederive_incident.check_pin(store)

    assert not unverifiable, f"the pinned file should have been readable: {unverifiable}"
    assert any("present but unpinned" in f and "c" * 64 in f for f in failed), (
        f"the coverage scan did not find the too-long intruder. This is the failing-open "
        f"defect F6, returned: {failed}")
