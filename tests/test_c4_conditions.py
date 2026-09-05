"""C4's four conditions, each asserted rather than documented.

Core → Canary Response 005 §3:
  (1) fresh probe generation, mandatory — §7.4 operational
  (2) declared ceiling before the first call — no ceiling, no call
  (3) the demo script: baseline, silence, change, receipt
  (4) the key never enters the repository
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from canary.spend import Ceiling, LedgerFull, NoCeilingDeclared, SpendLedger, require_ceiling
from canary.suite.generation import (
    RetiredGenerationError,
    Status,
    build_generation,
    gen0_paper2,
    generation_digest,
    render_prompt,
    retire,
    rotate,
    validate_generation,
)
from canary.suite.probe import Arm
from canary.target.live import (
    API_KEY_ENV,
    KEY_MARKERS,
    SEED_ENV,
    LiveTarget,
    scan_for_key_material,
)
from canary.target.mock import suite_from_cycle

REPO = Path(__file__).resolve().parent.parent
SEED = "test-seed-not-a-real-generation-seed"


def _gen(gid="gen-1-test", seed=SEED, n=6, status=Status.ACTIVE):
    return build_generation(gid, seed, "2026-08-21", "test generation", n_entities=n,
                            status=status)


def _ceiling(max_calls=10):
    return Ceiling(max_calls=max_calls, scope="test", declared_by="tester",
                   declared_at="2026-08-21T12:00:00Z")


# ------------------------------------------------- (1) fresh generation, mandatory

def test_the_paper2_generation_is_retired_and_may_never_probe_live():
    """§7.4, operational. Not a warning: the harm cannot be undone or re-taken."""
    gen0 = gen0_paper2(suite_from_cycle())
    assert gen0.status is Status.RETIRED
    with pytest.raises(RetiredGenerationError, match="RETIRED"):
        gen0.assert_may_probe_live()


def test_a_live_target_refuses_a_retired_generation_at_construction(monkeypatch):
    """The gate is at construction, before any key is read or any call is made."""
    monkeypatch.setenv(API_KEY_ENV, "sk-ant-not-a-real-key")
    with pytest.raises(RetiredGenerationError):
        LiveTarget(model_requested="claude-opus-5",
                   generation=gen0_paper2(suite_from_cycle()),
                   ledger=SpendLedger(_ceiling()))


def test_a_superseded_generation_takes_no_new_runs():
    old, new = rotate(_gen("gen-1"), _gen("gen-2", seed=SEED + "-2"))
    assert old.status is Status.SUPERSEDED and old.superseded_by == "gen-2"
    with pytest.raises(RetiredGenerationError, match="SUPERSEDED"):
        old.assert_may_probe_live()
    new.assert_may_probe_live()          # the successor is fine


def test_rotation_changes_the_instrument_digest():
    """Rotation is a visible instrument change, never silent drift."""
    assert _gen("gen-1").digest != _gen("gen-2", seed=SEED + "-2").digest


def test_retirement_requires_a_disclosure_date_and_is_one_way():
    with pytest.raises(ValueError, match="disclosure date"):
        retire(_gen(), "")
    retired = retire(_gen(), "2026-12-01")
    assert retired.status is Status.RETIRED
    import canary.suite.generation as mod
    assert not hasattr(mod, "unretire"), (
        "an unretire() exists; once probes are public no later decision makes them "
        "private again, and an API implying otherwise will be believed")


def test_a_generation_rebuilds_byte_for_byte_from_its_seed():
    """The secrecy resolution: the seed is the secret, the digest is the commitment."""
    assert _gen().digest == _gen().digest
    assert generation_digest(SEED, "gen-1-test", "2026-08-21", n_entities=6) == _gen().digest
    assert _gen(seed="different").digest != _gen().digest


def test_the_receipt_records_the_generation_but_never_its_probes():
    """An active generation's probes are private; the digest is what travels."""
    gen = _gen()
    blob = str(gen.as_canonical())
    assert gen.digest in blob
    assert "specs" not in gen.as_canonical()
    for probe in gen.suite:
        assert probe.query not in blob, "probe text leaked into the receipt payload"


@pytest.mark.parametrize("seed", ["a", "b", "c", "seed-1", "seed-2", "zzz"])
def test_every_generated_arm_is_what_it_claims(seed):
    """The generator's own gate. An 'answerless' arm that contains the answer scores a
    correct refusal as a wrong abstention, and nothing downstream can detect it."""
    assert validate_generation(_gen(seed=seed, n=12)) == []


def test_an_impossible_pool_fails_fast_instead_of_hanging():
    """A rejection loop that cannot be satisfied must FAIL, not spin.

    This test found the bug it now guards. With a single attribute in the pool, the
    withheld attribute can never differ from the asked-for one, and the original
    `while True` never returned — the suite simply stopped, which reads as a slow test
    rather than a defect. A generator that cannot produce a sound probe set has to say so.
    """
    import canary.suite.generation as mod
    saved = mod._ATTRS
    try:
        mod._ATTRS = (("listen port", "", (1, 2)),)
        with pytest.raises(ValueError, match="at least two attributes|could not draw"):
            mod.build_generation("gen-x", SEED, "2026-08-21", "p", n_entities=2)
    finally:
        mod._ATTRS = saved


def test_more_entities_than_names_is_refused():
    import canary.suite.generation as mod
    with pytest.raises(ValueError, match="only .* names exist"):
        mod.build_generation("gen-x", SEED, "2026-08-21", "p",
                             n_entities=len(mod._ADJS) * len(mod._NOUNS) + 1)


def test_the_prompt_template_survives_braces_in_the_package():
    """`str.format` would raise or interpolate; the package is model-facing text."""
    out = render_prompt("a {weird} package with {braces}", "q?")
    assert "{weird}" in out and "Question: q?" in out


def test_generated_probes_carry_both_measurement_directions():
    gen = _gen()
    assert gen.suite.arm_counts() == {"answer_bearing": 6, "same_doc": 6, "cross_doc": 6}
    assert {p.expect.value for p in gen.suite if p.arm is Arm.ANSWER_BEARING} == {"ANSWER"}
    assert {p.expect.value for p in gen.suite if p.arm is Arm.CROSS_DOC} == {"REFUSAL"}


# ---------------------------------------------------- (2) declared ceiling, enforced

def test_no_ceiling_no_call():
    with pytest.raises(NoCeilingDeclared, match="no default"):
        require_ceiling(None)


def test_the_ceiling_stops_the_call_before_it_is_made_not_after():
    """'We noticed at 501' is not a ceiling of 500."""
    ledger = SpendLedger(_ceiling(max_calls=2))
    ledger.check(1); ledger.record("m", 10, 5)
    ledger.check(1); ledger.record("m", 10, 5)
    with pytest.raises(LedgerFull, match="would be exceeded"):
        ledger.check(1)
    assert ledger.calls == 2, "the ledger recorded a call it had refused"


def test_there_is_no_way_to_raise_a_ceiling_on_a_live_ledger():
    """A ceiling the code that hit it can lift is a suggestion."""
    ledger = SpendLedger(_ceiling(max_calls=1))
    assert not any(n for n in dir(ledger) if "force" in n or "override" in n
                   or "raise_ceiling" in n or "allow" in n)
    import dataclasses
    with pytest.raises(dataclasses.FrozenInstanceError):
        ledger.ceiling.max_calls = 999


def test_a_zero_or_negative_ceiling_is_refused():
    for bad in (0, -1):
        with pytest.raises(ValueError, match="positive"):
            Ceiling(max_calls=bad, scope="s", declared_by="d", declared_at="t")


def test_an_undeclared_ceiling_is_refused():
    for missing in ("scope", "declared_by", "declared_at"):
        kwargs = dict(max_calls=5, scope="s", declared_by="d", declared_at="t")
        kwargs[missing] = "  "
        with pytest.raises(ValueError, match=missing):
            Ceiling(**kwargs)


def test_both_halves_are_reported_declared_and_spent():
    """Enforcement without reporting cannot be audited; reporting without enforcement is
    a spend log."""
    ledger = SpendLedger(_ceiling(max_calls=5))
    ledger.record("claude-opus-5", 100, 20)
    ledger.record("claude-haiku-4-5", 90, 15)
    blob = ledger.as_canonical()
    assert blob["ceiling"]["max_calls"] == 5
    assert blob["spent"] == {"calls": 2, "input_tokens": 190, "output_tokens": 35,
                             "by_model": {"claude-haiku-4-5": 1, "claude-opus-5": 1}}
    assert blob["remaining_calls"] == 3
    assert "5" in ledger.report() and "calls" in ledger.report()


def test_a_model_swap_is_visible_in_the_spend_ledger_alone():
    ledger = SpendLedger(_ceiling())
    ledger.record("claude-opus-5", 1, 1)
    ledger.record("claude-haiku-4-5", 1, 1)
    assert set(ledger.by_model) == {"claude-opus-5", "claude-haiku-4-5"}


def test_the_spend_ledger_is_canonicalisable_and_float_free():
    from canary.acj import canonical_bytes
    ledger = SpendLedger(_ceiling())
    ledger.record("m", 3, 4)
    canonical_bytes(ledger.as_canonical())


# ------------------------------------------------------------- (3) the demo script

def test_the_demo_runs_end_to_end_on_the_mock(tmp_path):
    """Baseline, silence, change, receipt — offline, free, and re-derived.

    Run as a subprocess, the way a person runs it, so an import-time or argparse defect
    is caught rather than bypassed by importing `main` directly.
    """
    p = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "demo_c4.py"), "--mock",
         "--store", str(tmp_path / "store")],
        capture_output=True, text=True, cwd=REPO)
    assert p.returncode == 0, p.stdout[-3000:] + p.stderr[-3000:]
    out = p.stdout
    assert out.count("UNCHANGED") >= 2, "the no-change receipts are missing"
    assert "CHANGED" in out
    assert "ok=True" in out and "ok=False" not in out
    assert "chain problems: none" in out
    assert "leaks      none" in out


def test_a_live_demo_run_refuses_without_the_seed_env_var():
    """The seed enters through the environment ONLY (Core -> Canary Response 006 §3).

    Not a flag: a flag lands in shell history. Not a config field: that lands in the
    repository. The run is refused outright when the variable is absent, rather than
    falling back to a default seed -- a default seed is a published seed.
    """
    env = {k: v for k, v in os.environ.items() if k != SEED_ENV}
    p = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "demo_c4.py")],
        capture_output=True, text=True, cwd=REPO, env=env)
    assert p.returncode != 0
    assert SEED_ENV in (p.stdout + p.stderr)
    assert "is not set" in (p.stdout + p.stderr)


def test_the_seed_is_never_a_command_line_flag():
    """A flag lands in shell history, which is the same objection as for the key."""
    source = (REPO / "scripts" / "demo_c4.py").read_text(encoding="utf-8")
    assert '"--seed"' not in source, "the seed is back as a flag"
    assert f'os.environ.get(SEED_ENV' in source


def test_the_seed_variable_is_a_leak_marker():
    """An exported seed in a log or receipt is as bad as an exported key."""
    from canary.target.live import KEY_MARKERS
    assert any(SEED_ENV in m for m in KEY_MARKERS)


# ---------------------------------------------------------- (4) the key stays out

def test_no_key_material_anywhere_in_the_repository():
    """Condition (4), checked against every tracked file rather than trusted."""
    tracked = subprocess.run(["git", "-C", str(REPO), "ls-files"],
                             capture_output=True, text=True, check=True).stdout.split()
    assert tracked
    offenders = []
    for rel in tracked:
        path = REPO / rel
        if not path.is_file() or rel.endswith(".zip"):
            continue
        text = path.read_bytes().decode("utf-8", "replace")
        for marker in scan_for_key_material(text):
            # This test file and the module that defines the markers necessarily name
            # them; nothing else may.
            if rel in ("tests/test_c4_conditions.py", "canary/target/live.py"):
                continue
            offenders.append(f"{rel}: {marker}")
    assert not offenders, "credential material in tracked files:\n" + "\n".join(offenders)


def test_the_key_is_read_from_the_environment_and_never_held(monkeypatch):
    """Not a constructor argument, not an attribute, not a config field."""
    import dataclasses
    fields = {f.name for f in dataclasses.fields(LiveTarget)}
    for suspicious in ("api_key", "key", "token", "secret", "credential", "auth"):
        assert not any(suspicious in f for f in fields), f"LiveTarget holds {suspicious}"
    assert API_KEY_ENV == "ANTHROPIC_API_KEY"


def test_the_target_declaration_has_no_field_a_credential_could_occupy(monkeypatch):
    monkeypatch.setenv(API_KEY_ENV, "sk-ant-not-a-real-key")
    target = LiveTarget(model_requested="claude-opus-5", generation=_gen(),
                        ledger=SpendLedger(_ceiling()))
    blob = str(target.declaration())
    assert scan_for_key_material(blob) == []
    assert "sk-ant-not-a-real-key" not in blob


def test_the_scanner_catches_what_it_is_for():
    """Both directions: it must be able to fire, or it attests nothing."""
    for marker in KEY_MARKERS:
        assert scan_for_key_material(f"prefix {marker} suffix") == [marker]
    assert scan_for_key_material("model=claude-opus-5 served=claude-haiku-4-5") == []


def test_the_sdk_is_a_hard_requirement_never_a_degraded_mode():
    """X-6: an alarm dependency must not degrade quietly.

    `_client()` raises with an install instruction. There is no mock fallback and no
    'live unavailable, continuing' path — a live phase that quietly ran against fixtures
    would emit receipts that look real and prove nothing.
    """
    source = (REPO / "canary" / "target" / "live.py").read_text(encoding="utf-8")
    assert "SDKUnavailable" in source
    for smell in ("except ImportError:\n        return", "fallback to mock", "MockTarget"):
        assert smell not in source, f"live.py contains a degraded path: {smell!r}"


def test_re_derivation_never_imports_the_live_module():
    """The dependency split that makes the extra safe: collection may depend,
    verification may not."""
    for mod in ("canary/receipt/rederive.py", "canary/detector/compare.py",
                "canary/receipt/store.py", "canary/receipt/emit.py"):
        source = (REPO / mod).read_text(encoding="utf-8")
        assert "target.live" not in source and "import anthropic" not in source, mod


def test_the_demo_defaults_are_the_ruled_model_pair():
    """Core -> Canary Response 006 §3 ruled the pair; the defaults must BE that pair.

    A default that differed would let a bare invocation probe an unruled model, and
    §3 permits no substitution without a ruling. The ruling lives in one place, and
    this is the test that keeps the code agreeing with it.
    """
    source = (REPO / "scripts" / "demo_c4.py").read_text(encoding="utf-8")
    assert '"--baseline-model", default="claude-sonnet-5"' in source
    assert '"--switch-model", default="claude-haiku-4-5"' in source


def test_the_demo_summary_counts_outcomes_rather_than_narrating_them():
    """The summary must report what happened, not what the script expected.

    The first live C4 run switched models and the behaviour did not change. The summary
    line had "1 changed receipt" hard-coded and reported a changed receipt that did not
    exist. A demo whose narration is fixed in advance will narrate a result it did not
    get, which is the same family as a guard that cannot fail against its subject.
    """
    source = (REPO / "scripts" / "demo_c4.py").read_text(encoding="utf-8")
    assert '"1 changed receipt' not in source, "the outcome is hard-coded again"
    assert 'tally[c.outcome.value]' in source
    assert 'if changed == 0:' in source, "a zero-change run must say so explicitly"
