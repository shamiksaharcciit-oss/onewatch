"""The gen-1-c4 disclosure package: staged now, fired at the firing sequence.

Every check here has both directions. A staging script that can only succeed is a
staging script that has not been shown to check anything -- and the thing it is checking
is whether we are about to publish an ACTIVE instrument's probes, or publish a text that
is not the instrument the receipts were computed against. Both would be worse than not
publishing at all.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO))

import stage_disclosure  # noqa: E402
from canary.suite.generation import Status  # noqa: E402

INCIDENT = REPO / "docs" / "evidence" / "c4-incident-of-record"


# ------------------------------------------------------------------ condition 2


def test_the_published_suite_hashes_to_the_digest_the_receipts_cite():
    """Condition 2, the demonstration the whole disclosure rests on.

    Anyone can publish a file and call it the probe set. The claim worth making is that
    THIS text is what those receipts were computed against -- checkable without trusting
    us, because the digest was sealed into the receipts, chained and Merkle-anchored,
    before the text was ever disclosed. The disclosure does not ask to be believed.
    """
    digest, receipts = stage_disclosure.cited_generation_digest()
    assert len(receipts) == 3, f"expected all three receipts to cite it, got {receipts}"
    suite = stage_disclosure._read(
        INCIDENT / "runs" / stage_disclosure.SUITE_SOURCE_E / "suite.json")
    assert hashlib.sha256(suite).hexdigest() == digest


def test_every_run_of_the_generation_carries_the_same_suite_bytes():
    """The published suite must not be one run's private copy.

    If two runs of `gen-1-c4` disagreed on their suite bytes, the generation would not be
    one instrument and `generation_digest` would be citing something that does not exist.
    Publishing any single run's copy would then be a choice among candidates -- which is
    exactly the ambiguity X-12 says a reconstruction must never resolve on its own.
    """
    seen = {}
    for run_dir in (INCIDENT / "runs").iterdir():
        suite_path = run_dir / "suite.json"
        raw = stage_disclosure._read(suite_path)
        if json.loads(raw)["suite_id"] != stage_disclosure.GENERATION_ID:
            continue
        seen.setdefault(hashlib.sha256(raw).hexdigest(), []).append(run_dir.name)
    assert len(seen) == 1, (
        f"runs of {stage_disclosure.GENERATION_ID} disagree on their suite bytes: {seen}")


def test_staging_refuses_a_text_that_is_not_the_cited_instrument(monkeypatch, tmp_path):
    """Direction two: a suite that does NOT hash to the cited digest is refused.

    This is the "cleaned-up cousin" case -- a probe set tidied, reformatted or partially
    reconstructed before publication. It would still look like a probe set. It would not
    be the instrument, and the receipts would not vouch for it.
    """
    fake_run = tmp_path / "runs" / ("f" * 64)
    fake_run.mkdir(parents=True)
    (fake_run / "suite.json").write_bytes(b'{"suite_id": "gen-1-c4", "probes": []}')
    monkeypatch.setattr(stage_disclosure, "INCIDENT", tmp_path)
    monkeypatch.setattr(stage_disclosure, "SUITE_SOURCE_E", "f" * 64)
    monkeypatch.setattr(stage_disclosure, "cited_generation_digest",
                        lambda: ("0" * 64, ["receipt"]))
    monkeypatch.setattr(stage_disclosure, "STAGING", tmp_path / "staging")
    assert stage_disclosure.main([]) == 2, "staging accepted a text that is not the instrument"


# ------------------------------------------------------------------ condition 3


def test_the_staged_package_leaks_no_generator_and_no_seed():
    """Condition 3: probes are disclosed, generators never.

    The seed is the secret and the digest is the public commitment. A package that also
    shipped the generator -- or merely named the still-ACTIVE generations it can build --
    would hand a reader the means to reconstruct instruments still in service.
    """
    files = [p for p in stage_disclosure.STAGING.rglob("*") if p.is_file()]
    assert files, "nothing staged; run `python scripts/stage_disclosure.py` first"
    assert not stage_disclosure.check_no_generator_leak(files)


def test_the_leak_check_actually_finds_a_planted_secret(tmp_path, monkeypatch):
    """Direction two, and the one that matters: the check must be able to fail.

    A leak check that has never caught anything is indistinguishable from a leak check
    that cannot. Each forbidden marker is planted in turn and required to be found --
    per marker, because a check that catches one and silently ignores the rest passes a
    single-marker test while leaving six holes.
    """
    monkeypatch.setattr(stage_disclosure, "STAGING", tmp_path)
    for marker in stage_disclosure.SECRET_MARKERS:
        planted = tmp_path / "leaky.md"
        planted.write_text(f"harmless text\n{marker}=deadbeef\nmore text\n",
                           encoding="utf-8")
        problems = stage_disclosure.check_no_generator_leak([planted])
        assert problems and marker in problems[0], (
            f"the leak check did not find planted marker {marker!r}")
    planted.write_text("nothing forbidden here\n", encoding="utf-8")
    assert not stage_disclosure.check_no_generator_leak([planted])


def test_the_secret_markers_cover_the_seed_the_key_and_the_generators():
    """The marker list is the check's whole reach, so its contents are asserted.

    A marker quietly dropped from this tuple would silently widen what may be published,
    and nothing else in the suite would notice.
    """
    markers = set(stage_disclosure.SECRET_MARKERS)
    assert {"CANARY_GEN_SEED", "ANTHROPIC_API_KEY"} <= markers, "the secrets must be covered"
    assert {"_rng_stream", "build_generation"} <= markers, "the generators must be covered"


def test_generation_names_are_allowed_explicitly_and_not_by_omission():
    """Response 013 §3: the secrecy protected is probe text and the generator, never
    the fact of rotation.

    The names live on an explicit allow-list rather than merely being absent from
    SECRET_MARKERS, because "allowed by omission" and "allowed on purpose" look identical
    in a source file and are very different claims. Whoever adds a generation later has to
    decide which list it belongs on.
    """
    allowed = set(stage_disclosure.ALLOWED_GENERATION_NAMES)
    assert {"gen-1-c4", "gen-2-c4", "gen-3-c4"} <= allowed
    assert not allowed & set(stage_disclosure.SECRET_MARKERS), (
        "a name cannot be both allowed and secret; the two lists have drifted")
    source = (REPO / "scripts" / "stage_disclosure.py").read_text(encoding="utf-8")
    rationale = " ".join(source.lower().replace("*", "").split())
    assert "a generation name is not a probe set" in rationale, (
        "the rationale must be recorded in the check itself, not only in a memo")


def test_probe_text_confinement_catches_a_quoted_probe(tmp_path):
    """The positive half of condition 3, shown failing and then passing.

    SECRET_MARKERS only catches things somebody thought to name. This catches the
    accident nobody named: a README that quotes a probe to illustrate a point. The
    fragment is taken from the suite itself, so the check needs no foresight.
    """
    fragment = "Answer the question using ONLY the context below, and do not guess."
    suite = {"suite_id": "gen-x", "probes": [{"probe_id": "p0", "query": fragment}]}
    (tmp_path / "suite.json").write_text(json.dumps(suite), encoding="utf-8")

    leaky = tmp_path / "README.md"
    leaky.write_text(f"For example, one probe asks:\n\n> {fragment}\n",
                     encoding="utf-8")
    problems = stage_disclosure.check_probe_text_confined(tmp_path)
    assert problems and "README.md" in problems[0], (
        f"a quoted probe was not caught: {problems}")

    leaky.write_text("This package contains one probe set.\n", encoding="utf-8")
    assert not stage_disclosure.check_probe_text_confined(tmp_path)


def test_probe_text_confinement_refuses_to_pass_on_an_empty_search(tmp_path):
    """A confinement claim built from zero fragments is a claim about nothing.

    If the suite yields no searchable probe text, the honest answer is a problem, not a
    clean bill of health -- the same failing-open shape as F6's coverage scan.
    """
    (tmp_path / "suite.json").write_text('{"suite_id": "gen-x", "probes": []}',
                                         encoding="utf-8")
    problems = stage_disclosure.check_probe_text_confined(tmp_path)
    assert problems and "empty search" in problems[0]

    problems = stage_disclosure.check_probe_text_confined(tmp_path / "nonexistent")
    assert problems and "cannot be checked" in problems[0]


# ------------------------------------------------------------- conditions 1 and 4


def test_gen_1_c4_was_retired_at_the_firing_sequence():
    """Condition 4, after the switch: a visible, dated instrument change.

    Until 2026-09-10 this was `test_gen_1_c4_is_not_retired_yet` and asserted the absence
    of an instrument-history record. It changed in the same commit as the retirement,
    deliberately and visibly, exactly as its own failure message instructed. The frozen
    receipts still read ACTIVE -- they were sealed before the switch, and that is the
    point: the disclosure is checkable against evidence that predates it.
    """
    assert stage_disclosure.HISTORY.exists(), (
        "the retirement record is missing: gen-1-c4 was retired on 2026-09-10 and "
        "docs/launch/instrument-history.md is the dated record of it.")
    record = stage_disclosure.HISTORY.read_text(encoding="utf-8")
    assert "2026-09-10" in record
    digest, _ = stage_disclosure.cited_generation_digest()
    assert digest in record
    receipt = json.loads(stage_disclosure._read(
        next((INCIDENT / "receipts").iterdir())))
    assert receipt["target"]["generation"]["status"] == Status.ACTIVE.value
    assert receipt["target"]["generation"]["disclosed_at"] == ""


def test_the_disclosed_package_names_its_retirement():
    """After the switch, the package's front page points at the dated record.

    While ACTIVE this was `test_the_staged_package_says_it_must_not_be_published` and
    asserted the refusal banner. A staged artifact must say it is not for publication; a
    disclosed one must say what permitted its publication.
    """
    readme = (stage_disclosure.STAGING / "README.md").read_text(encoding="utf-8")
    assert "NOT FOR PUBLICATION" not in readme
    assert "retired to permit this disclosure" in readme
    assert "instrument-history.md" in readme


def test_firing_twice_is_refused(tmp_path, monkeypatch):
    """Retirement is one-way and is recorded once.

    A retirement with two dates is a retirement nobody can cite -- and re-dating one
    silently would turn the visible instrument change into a moving target.
    """
    monkeypatch.setattr(stage_disclosure, "HISTORY", tmp_path / "instrument-history.md")
    stage_disclosure.fire("2026-09-01")
    assert stage_disclosure.HISTORY.exists()
    with pytest.raises(SystemExit) as exc:
        stage_disclosure.fire("2026-09-02")
    assert "one-way" in str(exc.value)


def test_the_retirement_record_names_date_reason_and_digest(tmp_path, monkeypatch):
    """Condition 1: a visible instrument change, not a quietly flipped attribute."""
    monkeypatch.setattr(stage_disclosure, "HISTORY", tmp_path / "instrument-history.md")
    stage_disclosure.fire("2026-09-01")
    record = stage_disclosure.HISTORY.read_text(encoding="utf-8")
    digest, _ = stage_disclosure.cited_generation_digest()
    assert "2026-09-01" in record
    assert digest in record
    assert "Reason:" in record
    assert "may never probe a live system again" in record
    assert "gen-2-c4` and `gen-3-c4` remain **ACTIVE**" in record


def test_there_is_no_unretire_anywhere():
    """The one-way property is asserted, not merely intended.

    `canary.suite.generation` says there is deliberately no `unretire`. Saying so in a
    docstring is not the same as it being true a year from now.
    """
    from canary.suite import generation
    assert not hasattr(generation, "unretire")
    assert "unretire" not in dir(generation.Generation)
    source = (REPO / "scripts" / "stage_disclosure.py").read_text(encoding="utf-8")
    assert "def unretire" not in source


# ------------------------------------------------------------------ the narration


def test_the_narration_matches_a_fresh_build_from_the_frozen_record():
    """B3: narration never outruns what the frozen record already proves.

    The demo header records what happens otherwise -- a summary line with the outcome
    hard-coded reported a CHANGED receipt the live run never produced. A launch document
    has a larger audience and the same failure mode, so the committed narration is
    required to equal a fresh build from the store rather than merely to have been
    generated once.
    """
    import subprocess
    r = subprocess.run([sys.executable, str(REPO / "scripts" / "build_narration.py"),
                        "--check"], capture_output=True, text=True, cwd=REPO)
    assert r.returncode == 0, f"{r.stdout}{r.stderr}"


def test_the_narration_states_the_anti_overclaim_boundary():
    """The canary says THAT behaviour moved, never WHICH STAGE caused it.

    This is the line the whole pillar's honesty rests on, and it is in a document written
    to persuade. Asserting it means a future edit that trims the caveats for punchiness
    fails a test instead of shipping.
    """
    raw = (REPO / "docs" / "launch" / "incident-narration.md").read_text(encoding="utf-8")
    # Collapsed, because these sentences are line-wrapped in the document and an
    # assertion that breaks when a paragraph re-flows tests the typesetting, not the claim.
    text = " ".join(raw.split())
    assert "does **not** say which stage" in text
    assert "Stage attribution is a different instrument's job" in text
    assert "aged out as a discriminator" in text, (
        "the saturation limit must travel with the result it qualifies")
    assert "never a receipt of record" in text, (
        "the re-scoring table must keep its (c) label inside the narration too")


def test_the_narration_carries_no_probe_text():
    """gen-1-c4 is ACTIVE until the firing sequence; the narration publishes before then.

    The narration is written to be read early -- by core, by the launch sequence -- while
    the probes are still secret. It quotes digests and counts, never probe or corpus text.
    """
    text = (REPO / "docs" / "launch" / "incident-narration.md").read_text(encoding="utf-8")
    for marker in ("Answer the question using ONLY", "[doc-1]", "CANARY_GEN_SEED"):
        assert marker not in text, f"the narration leaks {marker!r}"


def test_the_narration_builder_reverifies_before_it_anchors():
    """X-8, asserted against a regression I actually wrote.

    The first version anchored with `lambda rid: []` and a comment explaining that CI had
    already re-derived the rows. That is the precise shape X-8 exists to refuse: an anchor
    asserted over an unread document because somebody else is believed to have read it.
    """
    source = (REPO / "scripts" / "build_narration.py").read_text(encoding="utf-8")
    # Comments are stripped first: the file deliberately QUOTES the bad line while
    # explaining why it is gone, and a naive substring search would flag the explanation.
    # A check that cannot tell code from the commentary about it is a check that punishes
    # writing the reason down.
    code = "\n".join(line for line in source.splitlines()
                     if not line.lstrip().startswith("#"))
    assert "lambda rid: []" not in code, "the narration anchors without re-verifying"
    assert "rederive(INCIDENT, receipt_id)" in code


def test_the_history_publishes_the_active_digests_as_a_commitment(tmp_path, monkeypatch):
    """Response 013 §3 refinement 2: publishing the ACTIVE digests is a commitment.

    When gen-2-c4 or gen-3-c4 is one day retired, its published text must hash to a digest
    that has been public since launch week -- condition 2's proof with a longer fuse, where
    the check reaches the reader before the thing being checked exists in public. A record
    that published the names but withheld the digests would be announcing a patrol without
    committing to anything.
    """
    monkeypatch.setattr(stage_disclosure, "HISTORY", tmp_path / "instrument-history.md")
    stage_disclosure.fire("2026-09-01")
    record = stage_disclosure.HISTORY.read_text(encoding="utf-8")

    active = stage_disclosure.active_generation_digests()
    assert set(active) >= {"gen-2-c4", "gen-3-c4"}, f"digests not recovered: {active}"
    for generation_id, digest in active.items():
        if generation_id == stage_disclosure.GENERATION_ID:
            continue
        assert generation_id in record, f"{generation_id} is not named in the history"
        assert digest in record, f"{generation_id}'s digest is not published"
    assert "is a commitment" in record


def test_the_history_labels_the_truncated_digests_rather_than_padding_them(tmp_path,
                                                                          monkeypatch):
    """F3's shadow, stated rather than hidden.

    The full digests are unrecoverable here: `calibrate_c4.py` froze its runs in memory and
    exited without persisting them, and rebuilding requires the seed. A 16-hex prefix is a
    weaker commitment than a full digest. Publishing it unlabelled -- or worse, padding it
    to look like a full one -- would be claiming more than was measured, which is the
    single thing this repository exists not to do.
    """
    monkeypatch.setattr(stage_disclosure, "HISTORY", tmp_path / "instrument-history.md")
    stage_disclosure.fire("2026-09-01")
    record = stage_disclosure.HISTORY.read_text(encoding="utf-8")
    assert "truncated" in record
    assert "require the seed" in record
    for digest in stage_disclosure.active_generation_digests().values():
        assert len(digest) < 64, "an ACTIVE digest is full-length; update the caveat"


def test_the_active_digests_are_parsed_from_the_logs_not_typed_into_the_source():
    """X-11 at file scope: a digest in a document is generated by the tool that measured it.

    If someone pastes a digest into the source and the log then disagrees, the published
    commitment would be to a number nobody measured.
    """
    source = (REPO / "scripts" / "stage_disclosure.py").read_text(encoding="utf-8")
    for digest in stage_disclosure.active_generation_digests().values():
        assert digest not in source, (
            f"digest {digest} is hard-coded in stage_disclosure.py; it must be read from "
            f"the calibration log that recorded it")


def test_confinement_catches_a_leak_whose_line_endings_were_translated(tmp_path):
    """F9, direction one: the hole that made the check fail OPEN.

    The first version compared LF-bearing fragments against file text carrying CRLF,
    because writing a file translates newlines on Windows. A multi-line probe rendered onto
    a page therefore went unreported -- a leak check silently passing, which is the only
    direction this programme genuinely fears. Found by writing the sabotage test rather
    than by reasoning about the code.
    """
    fragment = ("Answer the question using ONLY the context below, and do not guess."
                + chr(10) + "If the context does not contain the answer, say NOT FOUND.")
    suite = {"suite_id": "gen-x", "probes": [{"probe_id": "p0", "query": fragment}]}
    (tmp_path / "suite.json").write_text(json.dumps(suite), encoding="utf-8")

    leaky = tmp_path / "page.html"
    leaky.write_bytes(("<p>" + fragment.replace(chr(10), chr(13) + chr(10))
                       + "</p>").encode("utf-8"))
    problems = stage_disclosure.check_probe_text_confined(tmp_path)
    assert problems and "page.html" in problems[0], (
        f"a CRLF-translated leak was not caught -- the check is failing open: {problems}")


def test_confinement_searches_the_distinctive_part_not_only_a_shared_preamble(tmp_path):
    """F9, direction two: thirty probes collapsing to one fragment.

    Every probe in a generation shares its instruction preamble, so taking `value[:120]`
    and deduplicating searched for the one thing the probes have in COMMON -- and would
    have missed a leak of the part that actually identifies them.
    """
    preamble = "Answer the question using ONLY the context below. Do not use outside knowledge."
    suite = {"suite_id": "gen-x", "probes": [
        {"probe_id": f"p{i}",
         "query": preamble + chr(10) + f"What is the flush interval of the marlin cache {i}?"}
        for i in range(5)]}
    (tmp_path / "suite.json").write_text(json.dumps(suite), encoding="utf-8")

    fragments = stage_disclosure._fragments(suite)
    assert len(fragments) > 1, (
        f"the fragment set collapsed to {len(fragments)}; it is searching only for what "
        f"every probe shares")

    # A leak of ONLY the distinctive tail, with no preamble anywhere near it.
    leaky = tmp_path / "page.html"
    leaky.write_text("<p>What is the flush interval of the marlin cache 3?</p>",
                     encoding="utf-8")
    problems = stage_disclosure.check_probe_text_confined(tmp_path)
    assert problems, "a leak of the distinctive question text was not caught"
