"""Instrument health: headroom, the two-state verdict, the receipt, and its second route.

**All offline.** The SATURATED branch is tested against *recorded* evidence — the gen-1-c4
baseline run inside the committed incident of record, which is genuinely saturated at 0
failures of 30. The DISCRIMINATING branch has no recorded example, because the only two
non-saturated live runs this project ever had were the ones whose bytes F3 lost. It is
therefore tested against **constructed** fixtures, and this docstring says so rather than
letting a reader assume both branches carry equal evidential weight.

That asymmetry is itself the argument for the law F3 produced: every live call's bytes are
frozen from now on, because a measurement whose bytes are gone is testimony about a
measurement.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from canary.freezer import freeze_run
from canary.health import (HEALTH_RECEIPT_SCHEMA, HealthVerdict, build_health_receipt,
                           check_health_receipt_id, measure, rederive_health)
from canary.health.check import BaselineOnlyViolation, assert_baseline_only, run_health_check
from canary.receipt import ledger
from canary.receipt.store import Store
from canary.suite.refusal import RefusalInstrument
from canary.suite.retrieval import build_retrieval_generation
from canary.target.retrieval_mock import (RetrievalChange, RetrievalMockConfig,
                                          RetrievalMockTarget)

REPO = Path(__file__).resolve().parent.parent
INCIDENT = REPO / "docs" / "evidence" / "c4-incident-of-record"
#: The gen-1-c4 baseline run: real recorded model output, 0 failures of 30. Saturated.
RECORDED_BASELINE_E = "6706b01a078ee442796cd7acf1ab282df73769f8c866d2aba78572df6b3dfda7"

SEED = "health-test-seed-not-the-real-one"
STAMP = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)
V3 = RefusalInstrument("v3")


@pytest.fixture(scope="module")
def generation():
    return build_retrieval_generation("h-test", SEED, n_documents=6, facts_per_document=2)


def mock_run(generation, change=None, label="r"):
    config = (RetrievalMockConfig(change=change) if change else RetrievalMockConfig())
    return freeze_run(f"h-{label}", generation.suite,
                      RetrievalMockTarget(corpus=generation.corpus, config=config),
                      instrument=V3)


# --------------------------------------------------- the measurement, on recorded data


def test_saturation_is_measured_from_the_recorded_gen_1_run():
    """The SATURATED branch, against real recorded model output.

    This is the run that produced the finding the whole module serves: paper-2 built this
    family when models failed 11-16 of 30 on its shape, and in 2026 the baseline failed
    none. The family did not break; the models improved and took the instrument's
    sensitivity with them.
    """
    from canary.receipt.rederive import Rederivation, _rebuild_run
    result = Rederivation()
    run = _rebuild_run(Store(INCIDENT), RECORDED_BASELINE_E, result, "recorded")
    assert run is not None, f"could not rebuild the recorded run: {result.unverifiable}"

    headroom = measure(run)
    assert headroom.verdict is HealthVerdict.SATURATED
    assert headroom.total_failures == 0
    assert headroom.total_probes == 30
    assert headroom.family == "refusal-sentinel"
    assert headroom.baseline_model == "claude-sonnet-5"


def test_the_discriminating_branch_on_a_constructed_fixture(generation):
    """The other branch. **Constructed, not recorded** -- see the module docstring.

    The only non-saturated live runs this project ever had were gen-2-c4's and gen-3-c4's
    calibration runs, and F3 lost their bytes. A fixture is what remains, and it is labelled
    as one rather than presented as evidence of a model's behaviour.
    """
    run = mock_run(generation, RetrievalChange.GROUNDING_DRIFT, "drift")
    headroom = measure(run)
    assert headroom.verdict is HealthVerdict.DISCRIMINATING
    assert headroom.total_failures > 0
    assert not headroom.saturated


def test_the_verdict_is_two_state_and_has_no_threshold():
    """No DEGRADED, no MARGINAL, no score.

    A threshold between "enough headroom" and "not quite enough" would be a number nobody
    measured, and the moment it exists someone tunes it until a family they like passes.
    Whether measured headroom is *sufficient* is a judgement for a person.
    """
    assert {v.value for v in HealthVerdict} == {"discriminating", "saturated"}
    source = (REPO / "canary" / "health" / "headroom.py").read_text(encoding="utf-8")
    code = "\n".join(line for line in source.splitlines()
                     if not line.lstrip().startswith("#"))
    for word in ("threshold =", "THRESHOLD", "min_failures", "> 0.0"):
        assert word not in code, f"a tunable threshold appeared in the health module: {word}"


def test_measure_refuses_an_empty_run(generation):
    """A verdict over zero probes is a verdict about nothing."""
    from canary.freezer.freeze import FrozenRun
    empty = FrozenRun(run_id="e", suite=generation.suite, instrument=V3, replies=(),
                      target_declaration={"served_model": "mock-rag-1"}, bodies={})
    with pytest.raises(ValueError, match="measures no headroom"):
        measure(empty)


def test_headroom_carries_integers_and_never_a_rate(generation):
    """E006's boundary: denominators legitimately move, so comparing rates is a bug."""
    headroom = measure(mock_run(generation, label="ints"))
    payload = json.dumps(headroom.as_canonical())
    assert "." not in payload.replace("refusal-sentinel", "").replace("mock-rag", ""), (
        "a float reached the headroom measurement")
    for arm in headroom.per_arm.values():
        assert isinstance(arm["numerator"], int) and isinstance(arm["denominator"], int)


# ------------------------------------------------------------- the baseline boundary


def test_a_health_check_refuses_a_model_that_is_not_the_baseline():
    """Response 007 §3, carried forward verbatim.

    A family measured against the model whose change you hope to detect is an instrument
    fitted to its finding, with the fitting done one step earlier.
    """
    with pytest.raises(BaselineOnlyViolation, match="fitted to its finding"):
        assert_baseline_only("claude-haiku-4-5-20251001", "claude-sonnet-5")
    assert_baseline_only("claude-sonnet-5", "claude-sonnet-5")   # and the allowed case


def test_the_boundary_is_checked_against_what_was_served(generation, tmp_path):
    """Not against what was requested. A provider quietly serving a different model is the
    event this pillar exists to catch, and believing our own request would blind the check
    to its own subject."""
    run = mock_run(generation, label="served")
    with pytest.raises(BaselineOnlyViolation):
        run_health_check(tmp_path, run, baseline_id="b",
                         baseline_model="some-other-model", created_at=STAMP)


def test_the_health_check_has_no_switch_model_parameter():
    """The surest way never to consult the switch model is to have no parameter for it."""
    # Comments and docstrings are stripped first: both files deliberately EXPLAIN that no
    # such parameter exists, and a naive substring search would flag the explanation. A
    # check that cannot tell code from the commentary about it punishes writing the reason
    # down -- the same trap as F7's regression test.
    for path in (REPO / "canary" / "health" / "check.py",
                 REPO / "scripts" / "health_check.py"):
        code = _code_only(path.read_text(encoding="utf-8"))
        for forbidden in ("switch_model", "switch-model", "comparison_model"):
            assert forbidden not in code, f"{path.name} offers a {forbidden} parameter"
        assert 'add_argument("--model"' not in code, (
            f"{path.name} takes a model parameter; the baseline model is read from the "
            f"baseline being maintained, never passed in")


# ----------------------------------------------------------------- the receipt


def test_the_health_receipt_carries_its_own_schema(generation, tmp_path):
    """A health receipt emitted under the change receipt's schema would hand a verifier a
    receipt whose baseline_e_digest is meaningless and whose missing comparison looks like
    a truncation."""
    run = mock_run(generation, label="schema")
    result = run_health_check(tmp_path, run, baseline_id="b",
                              baseline_model="mock-rag-1", created_at=STAMP)
    assert result.receipt["schema"] == HEALTH_RECEIPT_SCHEMA
    assert result.receipt["schema"] != "canary/receipt/v1"
    assert "h_digest" in result.receipt and "v_digest" not in result.receipt


def test_the_receipt_id_commits_to_the_whole_receipt(generation, tmp_path):
    run = mock_run(generation, label="id")
    result = run_health_check(tmp_path, run, baseline_id="b",
                              baseline_model="mock-rag-1", created_at=STAMP)
    assert check_health_receipt_id(result.receipt) == []
    tampered = dict(result.receipt)
    tampered["verdict"] = "discriminating"
    assert check_health_receipt_id(tampered), "a tampered receipt must fail its own id"


def test_the_receipt_is_reproducible_for_a_given_stamp(generation, tmp_path):
    """A clock read inside the emitter would make every receipt unreproducible."""
    run = mock_run(generation, label="repro")
    a = build_health_receipt(measure(run), run, baseline_id="b", created_at=STAMP)
    b = build_health_receipt(measure(run), run, baseline_id="b", created_at=STAMP)
    assert a == b


def test_the_health_receipt_chains_into_the_same_ledger(generation, tmp_path):
    """One ledger, one anchor, one place a customer looks.

    A health record in a separate chain would be the record nobody checks, and being
    checked on a schedule is its entire purpose.
    """
    for i, change in enumerate((None, RetrievalChange.GROUNDING_DRIFT)):
        run = mock_run(generation, change, f"chain{i}")
        run_health_check(tmp_path, run, baseline_id="b", baseline_model="mock-rag-1",
                         created_at=STAMP)
    rows = ledger.read_rows(tmp_path / "ledger.jsonl")
    assert len(rows) == 2
    assert ledger.verify_chain(rows) == []
    assert {r.outcome for r in rows} == {"saturated", "discriminating"}


def test_the_ledger_refuses_a_schema_it_does_not_know():
    """The chain does not guess which field carries a verdict digest.

    A ledger that chained a receipt shape it did not understand would commit to a structure
    nobody had checked, and every row's meaning is the chain's whole value.
    """
    with pytest.raises(ledger.LedgerError, match="unknown receipt schema"):
        ledger.verdict_digest_field("some/other/schema")
    assert ledger.verdict_digest_field("canary/receipt/v1") == "v_digest"
    assert ledger.verdict_digest_field("canary/health-receipt/v1") == "h_digest"


def test_extending_the_ledger_did_not_move_the_incident_of_records_anchor():
    """The regression this change most needed.

    Making the ledger accept health receipts must not alter the row preimage, because the
    C4 incident's Merkle root is a published launch claim. A field renamed for tidiness
    would have moved every row_hash and broken it silently.
    """
    rows = ledger.read_rows(INCIDENT / "ledger.jsonl")
    anchor = ledger.anchor(rows, lambda rid: [])
    assert anchor["root"] == (
        "38ff95dbc6c4c31f6c55485fb1fdb71039db0cb8c671a02b4d95a33d60b956dd")


# ------------------------------------------------------------- the second route


def test_a_health_receipt_re_derives_from_the_store_alone(generation, tmp_path):
    """A receipt only its own emitter can produce is a claim about a process nobody can run."""
    run = mock_run(generation, label="rd")
    result = run_health_check(tmp_path, run, baseline_id="b",
                              baseline_model="mock-rag-1", created_at=STAMP)
    check = rederive_health(tmp_path, result.receipt["receipt_id"])
    assert check.ok, f"failed={check.failed} unverifiable={check.unverifiable}"
    assert len(check.checked) >= 5


def test_re_derivation_catches_a_verdict_that_does_not_follow(generation, tmp_path):
    """The step that matters, shown catching something.

    Reading `verdict` back and confirming it equals itself proves nothing. A receipt
    claiming DISCRIMINATING over a run with zero failures is a lie its own evidence
    refutes, and only recomputation catches it.
    """
    run = mock_run(generation, label="lie")
    result = run_health_check(tmp_path, run, baseline_id="b",
                              baseline_model="mock-rag-1", created_at=STAMP)
    assert result.receipt["verdict"] == "saturated"

    # Rewrite the stored receipt so its verdict contradicts its evidence, and re-id it so
    # the forgery is internally consistent -- otherwise the id check would catch it first
    # and this would not be testing the verdict recomputation at all.
    from canary.acj import canonical_bytes, digest_bytes
    from canary.health.receipt import health_receipt_body
    forged = dict(result.receipt)
    forged["verdict"] = "discriminating"
    forged["receipt_id"] = digest_bytes(canonical_bytes(health_receipt_body(forged)))
    path = tmp_path / "receipts" / f"{result.receipt['receipt_id']}.json"
    path.write_bytes(canonical_bytes(forged))

    check = rederive_health(tmp_path, result.receipt["receipt_id"])
    assert not check.ok
    assert any("does not follow from the evidence" in p for p in check.failed), check.failed


def test_re_derivation_holds_unverifiable_apart_from_failed(tmp_path):
    """A receipt that is not there is 'could not check', never 'checked and wrong'."""
    check = rederive_health(tmp_path, "0" * 64)
    assert check.unverifiable and not check.failed


def test_a_tampered_body_fails_rather_than_going_unnoticed(generation, tmp_path):
    """The verdict is recomputed from the bytes, so moving the bytes must be visible."""
    run = mock_run(generation, label="tamper")
    result = run_health_check(tmp_path, run, baseline_id="b",
                              baseline_model="mock-rag-1", created_at=STAMP)
    bodies = list((tmp_path / "runs" / run.e_digest / "bodies").iterdir())
    bodies[0].write_bytes(b"tampered")
    check = rederive_health(tmp_path, result.receipt["receipt_id"])
    assert not check.ok


# ------------------------------------------------------------- F3 closed at source


def test_the_calibration_script_persists_before_it_measures():
    """F3, closed where it happened.

    The script used to measure from a run held in memory, print the number and exit; sixty
    live calls' worth of RECEIVED bytes are gone because of it. The store write now happens
    first, so a crash between acquisition and measurement loses the number and keeps the
    evidence -- the survivable direction.
    """
    source = (REPO / "scripts" / "calibrate_c4.py").read_text(encoding="utf-8")
    assert "--store" in source, "calibration must name where its evidence is written"
    assert "required=True" in source, "a store that can be omitted will be omitted"
    put = source.index("store.put_run(run)")
    counts = source.index("counts = run.counts()")
    assert put < counts, "the evidence must be written before the number is computed"


def test_the_scheduled_check_refuses_a_live_run_without_a_ceiling():
    """No ceiling, no call -- the same gate every live path on this programme obeys.

    And it refuses rather than falling back to the mock: a health check that silently
    degraded would report a family's headroom against a deterministic fixture while the
    operator believed it had measured production.
    """
    import subprocess
    import sys as _sys
    result = subprocess.run([_sys.executable, str(REPO / "scripts" / "health_check.py"),
                             "--live"], capture_output=True, text=True, cwd=REPO)
    assert result.returncode == 2
    assert "no ceiling, no call" in result.stdout + result.stderr


def test_saturation_is_not_a_failure_exit():
    """Exiting non-zero on saturation would teach a scheduler to page someone.

    The correct response to a saturated family is a decision by a person about whether to
    rotate it -- not an alarm, and certainly not one that fires every scheduled run until
    somebody silences the check.
    """
    import subprocess
    import sys as _sys
    result = subprocess.run([_sys.executable, str(REPO / "scripts" / "health_check.py")],
                            capture_output=True, text=True, cwd=REPO)
    assert result.returncode == 0
    assert "SATURATED" in result.stdout
    assert "not an error" in result.stdout


def _code_only(source: str) -> str:
    """Source with comments and docstrings removed, via the tokenizer rather than by eye.

    A regex would mistake a `#` inside a string for a comment. `tokenize` knows the
    difference, and the whole point of this helper is telling code apart from the prose
    about it.
    """
    import io
    import token
    import tokenize
    out = []
    previous = token.INDENT
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and previous in (token.INDENT, token.NEWLINE,
                                                        tokenize.NL, token.DEDENT):
            continue                      # a bare string statement: a docstring
        out.append(tok.string)
        if tok.type not in (tokenize.NL, tokenize.COMMENT):
            previous = tok.type
    return " ".join(out)
