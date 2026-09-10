"""onewatch: the page over the real store, and the properties that hold for every page.

Rendered from `docs/evidence/c4-incident-of-record/` — the committed launch deliverable, not
a fixture. The page a test checks is the page that ships.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from canary.freezer import freeze_run
from canary.health.check import run_health_check
from canary.suite.refusal import RefusalInstrument
from canary.suite.retrieval import build_retrieval_generation
from canary.target.retrieval_mock import (RetrievalChange, RetrievalMockConfig,
                                          RetrievalMockTarget)
from canary.viewer.model import build_model
from canary.viewer.page import build_page, render

sys.path.insert(0, str(Path(__file__).resolve().parent))
from assertions import (PropertyViolation, assert_absence_is_rendered_as_a_state,  # noqa: E402
                        assert_every_page_property, assert_labels_survive,
                        assert_seal_never_signals_state, content)

REPO = Path(__file__).resolve().parent.parent.parent
INCIDENT = REPO / "docs" / "evidence" / "c4-incident-of-record"
STAMP = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def page() -> str:
    return build_page(INCIDENT)


@pytest.fixture(scope="module")
def health_page(tmp_path_factory) -> str:
    """A store containing a health receipt, so the second kind is actually rendered.

    The C4 store legitimately holds none (W5), and a kind that no test ever renders is a
    kind whose treatment nobody has checked.
    """
    store = tmp_path_factory.mktemp("healthstore")
    generation = build_retrieval_generation("view-h", "viewer-test-seed", n_documents=6,
                                            facts_per_document=2)
    for label, change in (("sat", None), ("disc", RetrievalChange.GROUNDING_DRIFT)):
        config = RetrievalMockConfig(change=change) if change else RetrievalMockConfig()
        run = freeze_run(f"v-{label}", generation.suite,
                         RetrievalMockTarget(corpus=generation.corpus, config=config),
                         instrument=RefusalInstrument("v3"))
        run_health_check(store, run, baseline_id="view-baseline",
                         baseline_model="mock-rag-1", created_at=STAMP)
    return build_page(store)


# ------------------------------------------------------- every page, every property


def test_the_real_page_holds_every_property(page):
    assert_every_page_property(page)


def test_the_health_page_holds_every_property(health_page):
    assert_every_page_property(health_page)


# ------------------------------------------------------------ the page's one job


def test_the_incident_answers_both_halves_above_the_fold(page):
    """The operator's first question is "has anything changed, and can I check that?"

    For this pillar the first half has two answers that must not be collapsed, and the C4
    incident is precisely the case where they differ. The title carries both; the badge
    carries the behavioural verdict alone.
    """
    body = content(page)
    assert "Served model changed · behaviour unchanged" in body, (
        "the launch card's title must state both facts side by side")
    identity = body.index("Served model changed · behaviour unchanged")
    anchor = body.index("38ff95dbc6c4c31f6c55485fb1fdb71039db0cb8c671a02b4d95a33d60b956dd")
    rederived = body.index("RE-DERIVED")
    assert rederived < anchor, "the re-derivation status must precede the anchor line"
    assert identity < body.index("The ledger"), "the certificate must precede the tail"


def test_the_behavioural_verdict_is_the_only_badge(page):
    """One badge per card, and it carries the verdict -- not the recorded fact."""
    for card in _cards(page):
        badges = re.findall(r'class="badge badge-(\w+)"', card)
        assert len(badges) <= 1, f"a card carries {len(badges)} badges: {badges}"


def test_model_identity_is_a_fact_not_a_verdict(page):
    """Response 015 §1: a served-model change is a recorded fact, the third member of the
    non-verdict category. It renders in bold ink -- never seal, never the semantic pair."""
    match = re.search(r'Model identity</span>\s*<span class="fv">(.*?)</span>', page, re.S)
    assert match, "the Model identity row is missing"
    assert 'class="fact"' in match.group(1), "model identity must use the fact register"
    assert "--seal" not in match.group(1) and "badge" not in match.group(1)


# ----------------------------------------------------- three kinds, one anatomy


def test_the_banner_is_the_only_element_that_varies(page, health_page):
    """Same header, same grid, same chain block, same footer. Only the banner differs."""
    change_card = _cards(page)[0]
    health_card = _cards(health_page)[0]
    for shared in ('class="chead"', 'class="kind"', 'class="grid"',
                   'class="chain"', 'class="foot"'):
        assert shared in change_card, f"change card lost {shared}"
        assert shared in health_card, f"health card lost {shared}"
    assert 'class="badge badge-' in change_card, "a verdict must wear the semantic pair"
    assert 'class="badge badge-' not in health_card, (
        "instrument health wore a verdict badge; it is a report, not an alarm")
    assert 'class="state"' in health_card, "health must use the neutral register"


def test_a_retirement_would_carry_no_banner_at_all():
    """A retirement is an event, not a verdict -- so it has no verdict banner.

    Asserted against the renderer directly: the retirement of 2026-09-10 is written to the
    instrument history, not to the change receipts this page reads, so no history card
    exists in this store to render (which is the point of the absence test below).
    """
    from canary.viewer.page import _verdict_banner
    from canary.viewer.model import Card, Verification
    from canary.receipt import ledger
    row = ledger.Row(seq=0, prev_hash="0" * 64, receipt_id="a" * 64, e_digest="b" * 64,
                     i_digest="c" * 64, v_digest="d" * 64, outcome="retired",
                     created_at=STAMP.isoformat())
    card = Card(kind="history", receipt={}, verification=Verification(True, 0, (), ()),
                row=row, fields=(), title="t", verdict_word="RETIRED", verdict_why="w")
    assert _verdict_banner(card) == ""


def test_health_verdicts_never_wear_the_semantic_pair(health_page):
    for card in _cards(health_page):
        assert re.search(r'class="state">\s*(SATURATED|DISCRIMINATING)', card), (
            "a health verdict is not in the neutral register")
    # Checked against the CONTENT, not the whole page: the stylesheet always DECLARES
    # the badge classes -- one page's card set does not change what the design system
    # defines. What matters is whether any health card WEARS one.
    rendered = content(health_page)
    assert "badge-ok" not in rendered and "badge-bad" not in rendered


# -------------------------------------------------------------- absence is a state


def test_absence_is_rendered_as_a_state(page):
    assert_absence_is_rendered_as_a_state(page)


def test_the_two_absent_kinds_each_explain_themselves(page):
    body = content(page)
    assert "No instrument-health receipt has been written to this store" in body
    assert "No retirement is recorded in this store" in body
    assert "Instrument health" in body and "Instrument history" in body


def test_a_store_with_health_receipts_stops_claiming_health_is_absent(health_page):
    """The absence must be measured, not declared. A section that says 'nothing recorded'
    over a store that records something would be worse than omitting it."""
    assert "No instrument-health receipt has been written" not in content(health_page)


# ------------------------------------------------------------------ labels survive


def test_every_label_survives_to_the_surface(page):
    assert_labels_survive(page)


@pytest.mark.parametrize("needle", [
    "probe text not shown here", "never which stage",
    "read from a verified artifact", "python -m canary.viewer",
])
def test_stripping_any_label_fails_the_label_test(page, needle):
    """Sabotage: each label is removed in turn and the check is required to notice.

    A labelling test that has never caught a missing label is indistinguishable from one
    that cannot -- and these labels are the difference between a claim and an overclaim.
    """
    sabotaged = page.replace(needle, "")
    with pytest.raises(PropertyViolation):
        assert_labels_survive(sabotaged)


def test_active_generations_appear_as_digests_and_never_as_probes(page):
    body = content(page)
    assert "gen-1-c4" in body and "ACTIVE" in body
    assert "e9cd77076c01a4b0f11a86d5d9051670c0ae96bb575be9818b2c60f9737a3806" in body
    for probe_marker in ("Answer the question using ONLY", "[doc-1]", "NOT FOUND"):
        assert probe_marker not in body, f"the page leaked probe substance: {probe_marker!r}"


# ------------------------------------------------------- the positive seal check


def test_the_positive_seal_check_catches_the_mockups_own_violation(page):
    """W1/W2: the reference mockup renders `Model identity: CHANGED` in seal.

    onedoor's check inspects `.verdict` CSS rules and would walk straight past it, because
    it is an inline style on a field value. This check is required to catch exactly that
    shape -- otherwise the fix is a claim rather than a check.
    """
    assert_seal_never_signals_state(page)          # the real page is clean

    injected = page.replace(
        '<b class="fact">CHANGED</b>',
        '<b style="color:var(--seal)">CHANGED</b>', 1)
    assert injected != page, "the sabotage did not apply; the test proves nothing"
    with pytest.raises(PropertyViolation, match="brand accent"):
        assert_seal_never_signals_state(injected)


def test_the_positive_seal_check_also_catches_a_class_route(page):
    """The same violation via a class whose rule resolves to seal, not an inline style."""
    injected = page.replace("</style>", ".sealed{color:var(--seal)}</style>", 1)
    injected = injected.replace('<b class="fact">CHANGED</b>',
                                '<b class="sealed">CHANGED</b>', 1)
    with pytest.raises(PropertyViolation, match="resolves to seal"):
        assert_seal_never_signals_state(injected)


def test_the_kind_label_may_wear_seal_because_it_is_not_a_state(page):
    """Seal marks identity. `Change-Evidence Certificate` is what this is, not how it went."""
    assert re.search(r'class="kind">Change-Evidence Certificate', page)
    rules = re.search(r"\.kind\s*\{([^}]*)\}", page).group(1)
    assert "--seal" in rules


# ------------------------------------------------------------------ X-11 on the page


def test_every_digest_on_the_page_is_in_the_store(page):
    """Spec §2: every displayed value is read from a verified artifact.

    Any 64-hex string on the page must appear in the store's own bytes. A digest the
    renderer computed for display would fail here, which is the point.
    """
    store_bytes = b"".join(p.read_bytes() for p in INCIDENT.rglob("*") if p.is_file())
    store_text = store_bytes.decode("utf-8", "replace")
    for digest in set(re.findall(r"\b[0-9a-f]{64}\b", content(page))):
        assert digest in store_text, (
            f"digest {digest[:16]}… is on the page but not in the store; the renderer "
            f"computed something for display")


def test_the_page_shows_the_boolean_the_engine_carries_not_a_slot_count(page):
    """W3: the mockup's "28 of 90 reply slots differ" has no engine function behind it.

    An illustrative number is a design reference's privilege and a viewer's defect.
    """
    body = content(page)
    assert re.search(r"Raw bytes</span>\s*<span class=\"fv\">(differ|identical)", page)
    assert "of 90" not in body


def test_probe_totals_come_from_the_sealed_counts(page):
    receipt = json.loads(
        (INCIDENT / "receipts" /
         "f5b5b7c16bb8f10ece6a9c7658ce5f723068557eed1579b0f4693ac28580f3d3.json").read_bytes())
    total = sum(b["current"]["denominator"]
                for b in receipt["verdict"]["count_deltas"].values())
    assert f"0 of {total}" in content(page)


# ------------------------------------------------------------- regeneration


def test_the_page_regenerates_identically(page):
    """Same store, same bytes. A page that varied per run could not be diffed or trusted."""
    assert build_page(INCIDENT) == page


def test_the_module_entry_point_writes_the_page(tmp_path):
    out = tmp_path / "onewatch.html"
    result = subprocess.run(
        [sys.executable, "-m", "canary.viewer", "--store", str(INCIDENT),
         "--out", str(out)], capture_output=True, text=True, cwd=REPO)
    assert result.returncode == 0, result.stderr
    assert out.read_text(encoding="utf-8") == build_page(INCIDENT)


def test_the_page_carries_no_absolute_path(page):
    """An absolute path bakes a home directory into a published artifact and would differ
    between a cold clone and a working tree."""
    body = content(page)
    assert "C:\\Users" not in body and "/home/" not in body
    assert "docs/evidence/c4-incident-of-record" in body


def _cards(html: str) -> list[str]:
    return re.findall(r"<article class=\"card\">.*?</article>", html, flags=re.S)
