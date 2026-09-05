"""The receipt: envelope, store, ledger, anchor, and the second-route re-derivation.

C3's bar in one file: baseline sealed, change injected, receipt emitted, receipt
re-derived by a second route.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from canary.baseline import Declaration, calibrate, declare
from canary.detector import Outcome, compare
from canary.freezer import freeze_run
from canary.receipt import Store, StoreError, build_receipt, rederive
from canary.receipt import ledger
from canary.receipt.emit import check_receipt_id
from canary.suite.probe import ProbeSuite
from canary.suite.refusal import RefusalInstrument
from canary.target import Change, MockConfig, MockTarget, suite_from_cycle

REPO_ROOT = Path(__file__).resolve().parent.parent

FULL = suite_from_cycle()
STAMP = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)
V3 = RefusalInstrument("v3")

#: A 12-probe subset (4 probe ids x 3 arms) for the structural tests.
#:
#: Sizing is a real cost here, not fussiness: every stored run writes one file per reply
#: body, and the full 90-probe suite made this file take two minutes -- long enough that
#: someone would eventually stop running it, which is how a suite quietly dies. The
#: end-to-end bar below still runs the full suite, because that is the claim being made.
SUITE = ProbeSuite(suite_id=FULL.suite_id, version=FULL.version, probes=FULL.probes[:12])


def _run(run_id="r", cfg=None, suite=SUITE):
    return freeze_run(run_id, suite, MockTarget(config=cfg or MockConfig()), instrument=V3)


def _repeat_run(run_id="repeat", suite=SUITE):
    """The same declared configuration, a different recorded run: the calibration pair."""
    return freeze_run(run_id, suite, MockTarget(config=MockConfig(repeat=True)),
                      instrument=V3)


def _build_sealed(root):
    """A store holding a declared baseline and one changed run, with a receipt."""
    store = Store(root)
    base_run = _run("run-001")
    repeat = _repeat_run("run-001b")
    store.put_run(base_run)
    store.put_run(repeat)

    band = calibrate("refusal-sentinel", "v3", [base_run, repeat],
                     method="same-config repeat pair")
    baseline = declare("baseline-1", base_run, band,
                       Declaration(declared_by="tester",
                                   declared_at="2026-08-21T12:00:00Z",
                                   reason="validated system as of this date"))
    store.put_baseline(baseline)

    current = _run("run-002", cfg=MockConfig(changes=(Change.MODEL_SWAP,)))
    store.put_run(current)
    comparison = compare(baseline, current)
    receipt = build_receipt(baseline, current, comparison, trust=["mock", "fixtures"],
                            created_at=STAMP)
    store.put_receipt(receipt)
    return store, baseline, current, comparison, receipt


@pytest.fixture
def sealed(tmp_path):
    """A private store, for tests that tamper with what is on disk."""
    return _build_sealed(tmp_path)


@pytest.fixture(scope="module")
def sealed_ro(tmp_path_factory):
    """A store shared by tests that only READ it.

    Built once because file IO on some hosts is startlingly expensive -- measured on this
    development machine at ~24 ms per small write and ~70 ms per read, which is real-time
    antivirus scanning rather than anything in this code. Tests that mutate the store take
    the function-scoped `sealed` above; sharing a store between a mutating test and a
    reading one would make failures depend on execution order, which is worse than slow.
    """
    return _build_sealed(tmp_path_factory.mktemp("sealed_ro"))


# ------------------------------------------------------------------- C3's bar itself

def test_the_full_path_baseline_change_receipt_rederived(sealed, tmp_path):
    """Baseline sealed, change injected, receipt emitted, re-derived by a second route."""
    store, baseline, current, comparison, receipt = sealed
    assert comparison.outcome is Outcome.CHANGED

    result = rederive(tmp_path, receipt["receipt_id"])
    assert result.ok, result.report()
    # the checks that matter are named, so this cannot pass by checking nothing
    joined = " ".join(result.checked)
    assert "re-classified from raw bytes" in joined
    assert "v_digest" in joined
    assert "e_digest" in joined


def test_the_bar_holds_on_the_full_ninety_probe_suite(tmp_path):
    """The same path, on the real suite rather than the 12-probe subset.

    The subset above keeps the structural tests fast; this one keeps the *claim* honest.
    "Baseline sealed, change injected, receipt emitted, re-derived" is a claim about the
    instrument this repository actually ships, and a bar demonstrated only on a trimmed
    suite would be a bar quietly lowered to fit the test budget.
    """
    store = Store(tmp_path)
    base_run = _run("full-001", suite=FULL)
    repeat = _repeat_run("full-001b", suite=FULL)
    store.put_run(base_run)
    store.put_run(repeat)

    band = calibrate("refusal-sentinel", "v3", [base_run, repeat],
                     method="same-config repeat pair, 90 probes")
    assert band.per_arm == {"answer_bearing": 0, "same_doc": 0, "cross_doc": 0}

    baseline = declare("full-baseline", base_run, band,
                       Declaration(declared_by="tester",
                                   declared_at="2026-08-21T12:00:00Z",
                                   reason="paper-2 cycle 1, full suite"))
    store.put_baseline(baseline)

    current = _run("full-002", cfg=MockConfig(changes=(Change.MODEL_SWAP,)), suite=FULL)
    store.put_run(current)
    comparison = compare(baseline, current)
    assert comparison.outcome is Outcome.CHANGED
    assert len(comparison.probe_deltas) >= 1

    receipt = build_receipt(baseline, current, comparison, created_at=STAMP)
    store.put_receipt(receipt)
    row = ledger.append(store.ledger_path(), receipt, comparison.outcome.value)

    result = rederive(tmp_path, receipt["receipt_id"])
    assert result.ok, result.report()
    assert f"{len(FULL)} bodies re-classified from raw bytes" in " ".join(result.checked)

    # and the anchor, under X-8, over a re-verified chain
    anchor_obj = ledger.anchor(
        ledger.read_rows(store.ledger_path()),
        reverify=lambda rid: (lambda r: r.failed + r.unverifiable)(rederive(tmp_path, rid)))
    assert anchor_obj["tree_size"] == 1
    proof = ledger.prove_inclusion(anchor_obj, row.row_hash)
    from canary.acj import verify_inclusion
    assert verify_inclusion(proof["leaf"], proof["index"], proof["tree_size"],
                            proof["path"], proof["root"])


def test_the_second_route_shares_no_state_with_the_first():
    """`rederive` takes a directory and a receipt id, and nothing else.

    If it accepted a run, a baseline, or a comparison, it would be route one wearing a
    different hat: a receipt only means something if a stranger with the files can
    reproduce it.
    """
    import inspect
    assert set(inspect.signature(rederive).parameters) == {"store_root", "receipt_id"}


def test_a_no_change_receipt_is_emitted_and_rederives(tmp_path):
    """The no-change receipt is a product in itself, and takes the identical path."""
    store = Store(tmp_path)
    base_run = _run("run-001")
    repeat = _repeat_run("run-001b")
    store.put_run(base_run)
    store.put_run(repeat)
    band = calibrate("refusal-sentinel", "v3", [base_run, repeat], method="repeat pair")
    baseline = declare("b1", base_run, band,
                       Declaration(declared_by="t", declared_at="2026-08-21T12:00:00Z",
                                   reason="r"))
    again = _run("run-002")
    store.put_run(again)
    c = compare(baseline, again)
    assert c.outcome is Outcome.UNCHANGED

    receipt = build_receipt(baseline, again, c, created_at=STAMP)
    store.put_receipt(receipt)
    assert rederive(tmp_path, receipt["receipt_id"]).ok


# ----------------------------------------------------------------- the envelope

def test_the_receipt_id_covers_every_field(sealed_ro):
    _, _, _, _, receipt = sealed_ro
    assert check_receipt_id(receipt) == []
    for field in ("e_digest", "i_digest", "v_digest", "t_digest", "created_at"):
        tampered = {**receipt, field: "x" * 64}
        assert check_receipt_id(tampered), f"{field} is outside the receipt id"


def test_the_receipt_is_reproducible_given_the_same_timestamp(sealed_ro):
    """`created_at` is a parameter, not a clock read inside the emitter -- otherwise no
    receipt could ever be reproduced, which would defeat the entire point."""
    _, baseline, current, comparison, receipt = sealed_ro
    again = build_receipt(baseline, current, comparison, trust=["mock", "fixtures"],
                          created_at=STAMP)
    assert again["receipt_id"] == receipt["receipt_id"]


def test_the_receipt_carries_both_questions_unreconciled(sealed_ro):
    _, _, _, _, receipt = sealed_ro
    seal = receipt["verdict"]["seal"]
    assert set(seal) >= {"bytes_changed", "changed", "baseline_bodies_digest"}
    assert "outcome" in receipt["verdict"]
    # no field claims to summarise the pair
    assert "overall" not in receipt and "summary" not in receipt


def test_the_receipt_names_its_instrument_and_its_band(sealed_ro):
    _, _, _, _, receipt = sealed_ro
    assert receipt["instrument"]["detector"]["version"] == "v3"
    assert receipt["baseline"]["band"]["instrument_version"] == "v3"
    assert receipt["i_digest"]


def test_the_receipt_is_float_free(sealed_ro):
    from canary.acj import canonical_bytes
    _, _, _, _, receipt = sealed_ro
    canonical_bytes(receipt)


# ------------------------------------------------------------------------- the store

def test_bodies_are_stored_raw_and_addressed_by_their_own_digest(sealed_ro):
    store, _, current, _, _ = sealed_ro
    for (probe_id, arm), body in current.bodies.items():
        from canary.acj import digest_bytes
        stored = store.get_body(current.e_digest, digest_bytes(body))
        assert stored == body, "a stored body is not byte-identical to what was frozen"


def test_a_body_altered_on_disk_is_caught_on_read(sealed, tmp_path):
    store, _, current, _, _ = sealed
    bodies_dir = store.run_dir(current.e_digest) / "bodies"
    victim = sorted(bodies_dir.iterdir())[0]
    victim.write_bytes(victim.read_bytes() + b" ")
    with pytest.raises(StoreError, match="modified since it was written"):
        store.get_body(current.e_digest, victim.name)


def test_a_content_addressed_path_is_never_overwritten_with_different_content(sealed_ro):
    store, _, current, _, _ = sealed_ro
    path = store.run_dir(current.e_digest) / "run.json"
    with pytest.raises(StoreError, match="different content"):
        store._write_bytes(path, b"not the run")


def test_storing_a_run_that_does_not_verify_is_refused(tmp_path):
    from canary.freezer import FrozenRun
    store = Store(tmp_path)
    run = _run("r")
    key = (run.replies[0].probe_id, run.replies[0].arm)
    broken = FrozenRun(run_id=run.run_id, suite=run.suite, instrument=run.instrument,
                       target_declaration=run.target_declaration, replies=run.replies,
                       bodies={**run.bodies, key: b"tampered"})
    with pytest.raises(StoreError, match="does not verify"):
        store.put_run(broken)


# ---------------------------------------------------- re-derivation must be able to fail

def test_a_tampered_body_breaks_rederivation(sealed, tmp_path):
    """The check that matters: the verdict is recomputed FROM the bytes.

    Re-reading a recorded verdict and confirming it equals itself would prove nothing, so
    a body that no longer supports its verdict must fail here.
    """
    store, _, current, _, receipt = sealed
    bodies_dir = store.run_dir(current.e_digest) / "bodies"
    victim = sorted(bodies_dir.iterdir())[0]
    victim.write_bytes(b"NOT FOUND")
    result = rederive(tmp_path, receipt["receipt_id"])
    assert not result.ok
    assert result.unverifiable or result.failed


def test_the_verdict_is_recomputed_from_the_bytes_not_read_back(sealed, tmp_path):
    """The load-bearing property of the whole second route, isolated so it can fail.

    WHY THIS EXISTS: mutation-testing C3 found that replacing the re-classification with
    `recomputed = row["verdict"]` -- reading the recorded verdict back and confirming it
    equals itself -- broke NO test. The tamper test above was catching corruption through
    the body-digest check, which would still pass on a store whose verdicts were pure
    fiction. The strongest claim in the design had no test that could distinguish it from
    a much weaker one.

    So: leave every body untouched and byte-perfect, and flip a VERDICT recorded in
    run.json. The digest checks all pass. Only an implementation that actually re-reads
    the bytes through the instrument can notice, and the failure must name that mismatch
    rather than surface as some downstream digest confusion.
    """
    store, _, current, _, receipt = sealed
    run_path = store.run_dir(current.e_digest) / "run.json"
    doctored = json.loads(run_path.read_bytes().decode("utf-8"))

    victim = next(r for r in doctored["replies"] if r["verdict"] == "REFUSAL")
    victim["verdict"] = "ANSWER"
    victim["conforms"] = (victim["verdict"] == victim["expect"])
    run_path.write_bytes(json.dumps(doctored).encode("utf-8"))

    result = rederive(tmp_path, receipt["receipt_id"])
    assert not result.ok
    assert any("reads the stored bytes as" in f for f in result.failed), (
        "re-derivation did not catch a verdict that its own evidence contradicts; it is "
        "reading recorded verdicts back rather than recomputing them:\n" + result.report())


def test_a_missing_body_is_unverifiable_not_failed(sealed, tmp_path):
    """The three-outcome rule: *could not check* and *checked and wrong* are different
    findings and call for different responses."""
    store, _, current, _, receipt = sealed
    victim = sorted((store.run_dir(current.e_digest) / "bodies").iterdir())[0]
    victim.unlink()
    result = rederive(tmp_path, receipt["receipt_id"])
    assert result.unverifiable and not result.failed
    assert "missing" in " ".join(result.unverifiable)


def test_an_edited_verdict_in_the_receipt_is_caught(sealed, tmp_path):
    store, _, _, _, receipt = sealed
    path = store.receipts_dir() / f"{receipt['receipt_id']}.json"
    doctored = json.loads(path.read_bytes().decode("utf-8"))
    doctored["verdict"]["outcome"] = "UNCHANGED"
    path.write_bytes(json.dumps(doctored).encode("utf-8"))
    result = rederive(tmp_path, receipt["receipt_id"])
    assert not result.ok
    assert any("receipt_id mismatch" in f for f in result.failed)


def test_an_unknown_receipt_is_unverifiable(tmp_path):
    result = rederive(tmp_path, "0" * 64)
    assert result.unverifiable and not result.failed


# ------------------------------------------------------------------ ledger and anchor

def test_the_ledger_chains_and_verifies(sealed, tmp_path):
    store, _, _, comparison, receipt = sealed
    row = ledger.append(store.ledger_path(), receipt, comparison.outcome.value)
    assert row.seq == 0 and row.prev_hash == ledger.GENESIS
    rows = ledger.read_rows(store.ledger_path())
    assert ledger.verify_chain(rows) == []


def test_a_removed_row_breaks_the_chain(sealed, tmp_path):
    store, baseline, _, _, _ = sealed
    for i in range(3):
        run = _run(f"extra-{i}", cfg=MockConfig(changes=(Change.FORMAT_DRIFT,)) if i else None)
        store.put_run(run)
        c = compare(baseline, run)
        r = build_receipt(baseline, run, c, created_at=STAMP)
        store.put_receipt(r)
        ledger.append(store.ledger_path(), r, c.outcome.value)

    lines = store.ledger_path().read_bytes().splitlines()
    store.ledger_path().write_bytes(b"\n".join(lines[:1] + lines[2:]) + b"\n")
    problems = ledger.verify_chain(ledger.read_rows(store.ledger_path()))
    assert problems, "removing a row did not break the chain"
    assert any("removed" in p or "seq" in p for p in problems)


def test_an_altered_row_is_caught_when_read(sealed):
    store, _, _, comparison, receipt = sealed
    ledger.append(store.ledger_path(), receipt, comparison.outcome.value)
    raw = json.loads(store.ledger_path().read_bytes().decode("utf-8").strip())
    raw["outcome"] = "UNCHANGED"
    store.ledger_path().write_bytes((json.dumps(raw) + "\n").encode("utf-8"))
    with pytest.raises(ledger.LedgerError, match="row_hash does not match"):
        ledger.read_rows(store.ledger_path())


def test_x8_anchoring_refuses_receipts_that_do_not_reverify(sealed, tmp_path):
    """X-8: anchor only what you have re-verified.

    An anchor is a public assertion that these receipts were real. Publishing one over a
    receipt nobody re-checked puts the programme's signature on an unread document.
    """
    store, _, current, comparison, receipt = sealed
    ledger.append(store.ledger_path(), receipt, comparison.outcome.value)
    rows = ledger.read_rows(store.ledger_path())

    # honest path first
    anchor_obj = ledger.anchor(rows, reverify=lambda rid: (lambda r: r.failed + r.unverifiable)(
        rederive(tmp_path, rid)))
    assert anchor_obj["root"] and anchor_obj["reverified"] is True

    # now break the evidence and try again
    victim = sorted((store.run_dir(current.e_digest) / "bodies").iterdir())[0]
    victim.unlink()
    with pytest.raises(ledger.LedgerError, match="X-8"):
        ledger.anchor(rows, reverify=lambda rid: (lambda r: r.failed + r.unverifiable)(
            rederive(tmp_path, rid)))


def test_reverify_has_no_default(sealed):
    """A default would let a caller anchor without re-verifying by not thinking about it,
    and X-8 exists precisely for the moments nobody is thinking about it."""
    import inspect
    sig = inspect.signature(ledger.anchor)
    assert sig.parameters["reverify"].default is inspect.Parameter.empty


def test_an_inclusion_proof_lets_one_receipt_be_checked_alone(sealed, tmp_path):
    """A third party given one receipt verifies it and its path to the root, without
    needing the other receipts -- which may be somebody else's and none of their business.
    """
    from canary.acj import verify_inclusion
    store, baseline, _, comparison, receipt = sealed
    ledger.append(store.ledger_path(), receipt, comparison.outcome.value)
    for i in range(2):
        run = _run(f"more-{i}", cfg=MockConfig(changes=(Change.FORMAT_DRIFT,)))
        store.put_run(run)
        c = compare(baseline, run)
        r = build_receipt(baseline, run, c, created_at=STAMP)
        r["created_at"] = STAMP.strftime("%Y-%m-%dT%H:%M:%SZ")
        store.put_receipt(r)
        ledger.append(store.ledger_path(), r, c.outcome.value)

    rows = ledger.read_rows(store.ledger_path())
    anchor_obj = ledger.anchor(rows, reverify=lambda rid: [])
    proof = ledger.prove_inclusion(anchor_obj, rows[0].row_hash)
    assert verify_inclusion(proof["leaf"], proof["index"], proof["tree_size"],
                            proof["path"], proof["root"])
    assert not verify_inclusion("f" * 64, proof["index"], proof["tree_size"],
                                proof["path"], proof["root"])


def test_appending_to_a_broken_chain_is_refused(sealed):
    store, _, _, comparison, receipt = sealed
    ledger.append(store.ledger_path(), receipt, comparison.outcome.value)
    raw = json.loads(store.ledger_path().read_bytes().decode("utf-8").strip())
    raw["prev_hash"] = "f" * 64
    raw["row_hash"] = ledger.Row(
        seq=raw["seq"], prev_hash=raw["prev_hash"], receipt_id=raw["receipt_id"],
        e_digest=raw["e_digest"], i_digest=raw["i_digest"], v_digest=raw["v_digest"],
        outcome=raw["outcome"], created_at=raw["created_at"]).row_hash
    store.ledger_path().write_bytes((json.dumps(raw) + "\n").encode("utf-8"))
    with pytest.raises(ledger.LedgerError, match="broken chain"):
        ledger.append(store.ledger_path(), receipt, comparison.outcome.value)

# ------------------------------------------------ F5: the reverify contract is enforced


def _two_rows(tmp_path):
    """A minimal two-row ledger, so anchoring has something real to refuse."""
    from canary.receipt import ledger as _ledger
    path = tmp_path / "ledger.jsonl"
    rows = []
    for i in range(2):
        receipt = {"schema": "canary/receipt/v1",
                   "receipt_id": f"{i:064x}", "e_digest": f"{i:064x}",
                   "i_digest": f"{i:064x}", "v_digest": f"{i:064x}",
                   "created_at": "2026-08-27T00:00:00Z"}
        rows.append(_ledger.append(path, receipt, "UNCHANGED"))
    return rows


def test_anchor_refuses_a_reverify_that_returns_a_bool(tmp_path):
    """Direction one: the wrong TYPE is refused, and the error names the real mistake.

    `True` is the natural thing to return from a function called `reverify` -- and it is
    the dangerous one, because it means "problems present" to `anchor` and "it verified"
    to whoever wrote it. Those are opposite claims. Before this check the bool sailed
    into the failure branch and died inside the error formatter with a TypeError, which
    accused the receipts for a defect in the caller.
    """
    from canary.receipt import ledger as _ledger
    rows = _two_rows(tmp_path)
    with pytest.raises(_ledger.LedgerError) as exc:
        _ledger.anchor(rows, lambda rid: True)
    message = str(exc.value)
    assert "reverify must return a list of problems" in message
    assert "bool" in message, "the error must name the type actually returned"
    assert "TypeError" not in message


def test_anchor_refuses_a_reverify_that_reports_problems(tmp_path):
    """Direction two: a CORRECTLY-typed non-empty result still refuses the anchor.

    X-8: anchor only what you have re-verified. A checker that can only fail on bad input
    and never on a bad receipt would be enforcing a type, not a rule.
    """
    from canary.receipt import ledger as _ledger
    rows = _two_rows(tmp_path)
    with pytest.raises(_ledger.LedgerError) as exc:
        _ledger.anchor(rows, lambda rid: ["body 3baec1fa missing"])
    message = str(exc.value)
    assert "X-8" in message
    assert "body 3baec1fa missing" in message, (
        "the refusal must carry the problem it refused on, or a reader cannot act on it")


def test_anchor_accepts_the_documented_contract(tmp_path):
    """And the empty list -- the documented success form -- anchors.

    Without this the two refusals above are satisfied by a function that refuses
    everything, which is not the same as a function that checks anything.
    """
    from canary.receipt import ledger as _ledger
    rows = _two_rows(tmp_path)
    anchor = _ledger.anchor(rows, lambda rid: [])
    assert anchor["reverified"] is True
    assert anchor["tree_size"] == 2
    assert len(anchor["root"]) == 64


def test_the_composed_reverifier_catches_a_known_bad_row(tmp_path):
    """F7's closing test, ruled by Core -> Canary Response 013 §2.

    THE LAW THIS CLOSES
    -------------------
    F5's enforcement makes `anchor` refuse a caller returning the WRONG TYPE. It cannot
    refuse a caller returning the RIGHT TYPE dishonestly -- `lambda rid: []` is a perfectly
    typed list of zero problems, and it is a lie. **A right-typed lie passes every type
    check; only a test that lies to the verifier proves the verifier reads.**

    So this test does not inspect a signature. It feeds the composed path a receipt id that
    genuinely does not re-derive and requires the anchor to refuse. If someone re-introduces
    an empty-list lambda -- or wires the reverifier to a stub, or catches its exceptions and
    returns success -- the row below stops being caught and this goes red.
    """
    from canary.receipt import ledger as _ledger
    from canary.receipt.rederive import rederive

    store = tmp_path / "store"
    (store / "receipts").mkdir(parents=True)
    rows = _two_rows(tmp_path)          # a valid two-row chain
    # ...whose receipts are absent from the store entirely, so re-derivation cannot
    # succeed for either of them. Nothing is faked in the checker; the evidence is
    # genuinely missing, which is precisely the condition X-8 forbids anchoring over.

    def reverify(receipt_id: str) -> list[str]:
        result = rederive(store, receipt_id)
        return result.failed + result.unverifiable

    problems = reverify(rows[0].receipt_id)
    assert problems, (
        "the reverifier reported no problems for a receipt that is not in the store. It "
        "is not reading the evidence, and every anchor built on it is an X-8 violation.")

    with pytest.raises(_ledger.LedgerError) as exc:
        _ledger.anchor(rows, reverify)
    assert "X-8" in str(exc.value)


def test_the_shipped_reverifiers_are_the_composed_kind(tmp_path):
    """Every script that anchors must re-derive in the same call that anchors.

    Named individually rather than grep-for-a-pattern, so adding a new anchoring script
    without a reverifier is a decision someone has to make about this list.
    """
    for name in ("rederive_incident.py", "build_narration.py"):
        source = (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines()
                         if not line.lstrip().startswith("#"))
        if "ledger.anchor(" not in code:
            continue
        assert "rederive(" in code, f"{name} anchors without re-deriving"
        assert "lambda rid: []" not in code, f"{name} anchors over an unread document"


def test_the_ledger_refuses_a_receipt_with_no_schema(tmp_path):
    """Malformed, not a default case.

    Surfaced as a LedgerError rather than a KeyError from a dict lookup: "which field
    carries the verdict" is a question about the receipt, and a stack trace naming a
    missing key sends the reader hunting a bug in the ledger instead of the malformed
    receipt in front of them. Unverifiable and malformed are failures to surface.
    """
    from canary.receipt import ledger as _ledger
    with pytest.raises(_ledger.LedgerError, match="declares no schema"):
        _ledger.append(tmp_path / "l.jsonl",
                       {"receipt_id": "a" * 64, "e_digest": "b" * 64,
                        "i_digest": "c" * 64, "v_digest": "d" * 64,
                        "created_at": "2026-08-27T00:00:00Z"}, "UNCHANGED")


def test_the_ledger_refuses_a_receipt_that_disagrees_with_its_own_schema(tmp_path):
    """A receipt declaring one shape and carrying another is refused, not coerced."""
    from canary.receipt import ledger as _ledger
    with pytest.raises(_ledger.LedgerError, match="disagree"):
        _ledger.append(tmp_path / "l.jsonl",
                       {"schema": "canary/health-receipt/v1", "receipt_id": "a" * 64,
                        "e_digest": "b" * 64, "i_digest": "c" * 64,
                        "v_digest": "d" * 64,      # v_digest, but the schema wants h_digest
                        "created_at": "2026-08-27T00:00:00Z"}, "saturated")
