"""What the viewer's modules may reach, and what the emitted page may contain.

Two disciplines that are properties of structure rather than of anyone's memory:

**The renderer cannot form an opinion about validity.** It imports no hashing module and
reaches the engine not at all. "Never re-derive for display" then holds because there is
nothing in scope to re-derive with, not because a rule was followed.

**The page is an output surface, so the leak discipline extends to it.** Constraint 6: both
halves run over the emitted HTML. A viewer that rendered an ACTIVE probe because a template
interpolated the wrong field would be disclosure by accident; these make it a test failure.
"""
from __future__ import annotations

import ast
import hashlib
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
VIEWER = REPO / "canary" / "viewer"
INCIDENT = REPO / "docs" / "evidence" / "c4-incident-of-record"

sys.path.insert(0, str(REPO / "scripts"))
import stage_disclosure  # noqa: E402

from canary.viewer.page import build_page  # noqa: E402
from canary.viewer.tokens import (SPEC_DIGEST, SPEC_FENCE_DIGEST, SPEC_PATH,  # noqa: E402
                                  TokenError, css_block, palette)

HASHING = {"hashlib", "hmac"}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
    return out


# ------------------------------------------------------------------ structure


def test_the_renderer_cannot_form_an_opinion_about_validity():
    """`page.py` renders what the model carried and computes nothing of its own."""
    imported = _imports(VIEWER / "page.py")
    assert not (imported & HASHING), (
        f"the renderer imports {sorted(imported & HASHING)}: it is one step from computing "
        f"a digest for display, which spec §2 forbids")
    engine = {m for m in imported
              if m.startswith("canary.") and not m.startswith("canary.viewer")}
    assert engine == set(), (
        f"the renderer reaches into the engine directly: {sorted(engine)}. Everything it "
        f"shows must come through the model, which ran the verifiers.")


def test_only_the_vendoring_module_hashes_anything():
    """One declared exception, and it hashes the SPEC, never the store."""
    offenders = {p.name: sorted(_imports(p) & HASHING)
                 for p in VIEWER.rglob("*.py") if _imports(p) & HASHING}
    assert offenders == {"tokens.py": ["hashlib"]}, (
        f"hashing appeared outside the vendoring module: {offenders}")
    source = (VIEWER / "tokens.py").read_text(encoding="utf-8")
    assert "sha256(block.encode" in source
    assert "store" not in source.lower().replace("stores", ""), (
        "the vendoring module must never see the store")


def test_the_model_runs_the_verifiers_rather_than_re_implementing_them():
    imported = _imports(VIEWER / "model.py")
    assert "canary.receipt.rederive" in imported
    assert "canary.health.rederive" in imported
    assert not (imported & HASHING), "the model computes digests instead of reading them"


# --------------------------------------------------------------- the vendored spec


def test_the_vendored_spec_matches_its_pin():
    digest = hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest()
    assert digest == SPEC_DIGEST, (
        f"the vendored spec hashes to {digest[:12]}…, pinned {SPEC_DIGEST[:12]}…")
    assert hashlib.sha256(css_block().encode("utf-8")).hexdigest() == SPEC_FENCE_DIGEST


def test_the_spec_ships_in_the_package_not_only_in_the_repo():
    """A repo directory does not travel in a wheel; an installed viewer must still find it."""
    assert SPEC_PATH.is_file()
    assert SPEC_PATH.parent.name == "_vendor"
    assert SPEC_PATH.is_relative_to(REPO / "canary")


def test_a_missing_spec_raises_rather_than_falling_back(monkeypatch, tmp_path):
    """X-6: the design system is a hard requirement, never an optional extra.

    A viewer that silently uses last week's palette when it cannot find the spec is a
    viewer that will be shipped with last week's palette.
    """
    from canary.viewer import tokens
    monkeypatch.setattr(tokens, "SPEC_PATH", tmp_path / "absent.md")
    tokens.css_block.cache_clear()
    tokens.palette.cache_clear()
    with pytest.raises(TokenError, match="hard requirement"):
        tokens.css_block()
    tokens.css_block.cache_clear()
    tokens.palette.cache_clear()


def test_a_drifted_spec_raises_rather_than_rendering_the_old_palette(monkeypatch, tmp_path):
    from canary.viewer import tokens
    drifted = tmp_path / "spec.md"
    drifted.write_text(SPEC_PATH.read_text(encoding="utf-8").replace("#46C08E", "#46C08F"),
                       encoding="utf-8")
    monkeypatch.setattr(tokens, "SPEC_PATH", drifted)
    tokens.css_block.cache_clear()
    tokens.palette.cache_clear()
    with pytest.raises(TokenError, match="Re-vendor deliberately"):
        tokens.css_block()
    tokens.css_block.cache_clear()
    tokens.palette.cache_clear()


def test_the_palette_carries_the_tokens_the_page_uses():
    p = palette()
    for token in ("--ground", "--card", "--ink", "--muted", "--faint", "--seal",
                  "--ok", "--bad", "--border"):
        assert token in p, f"the spec's §4 fence no longer declares {token}"


def test_there_are_no_declared_non_token_colours():
    """The exception list is empty and asserted so, because an allowance without a reason
    beside it becomes a habit."""
    from canary.viewer.tokens import ALLOWED_NON_TOKEN_COLOURS
    assert ALLOWED_NON_TOKEN_COLOURS == {}


# ------------------------------------------- constraint 6: the leak halves, on the page


@pytest.fixture(scope="module")
def page() -> str:
    return build_page(INCIDENT)


def test_the_negative_leak_half_runs_over_the_emitted_page(page, tmp_path):
    """Named secrets: the seed, the credential, the generator entry points."""
    emitted = tmp_path / "onewatch.html"
    emitted.write_text(page, encoding="utf-8")
    assert stage_disclosure.check_no_generator_leak([emitted]) == []


def test_the_positive_confinement_half_runs_over_the_emitted_page(page, tmp_path):
    """Unnamed secrets: probe text from the ACTIVE generation the page reports on.

    N-C005's pair, applied to a new output surface. The negative half catches what someone
    thought to name; this catches a template that interpolated the wrong field.
    """
    staging = tmp_path / "staged"
    staging.mkdir()
    suite = (INCIDENT / "runs" /
             "c5d0ff3825a7f7340bcca8681ecf662dd7eebd8c32a33b37ed1c32977006f18d" /
             "suite.json")
    (staging / "suite.json").write_bytes(stage_disclosure._read(suite))
    (staging / "onewatch.html").write_text(page, encoding="utf-8")
    assert stage_disclosure.check_probe_text_confined(staging) == []


def test_the_confinement_half_catches_a_template_that_leaked_a_probe(page, tmp_path):
    """The failure this exists for, shown happening.

    A viewer that rendered an ACTIVE probe because a template interpolated `query` instead
    of `probe_id` would be disclosure by accident. Here it is a test failure instead.
    """
    import json
    staging = tmp_path / "staged"
    staging.mkdir()
    suite_path = (INCIDENT / "runs" /
                  "c5d0ff3825a7f7340bcca8681ecf662dd7eebd8c32a33b37ed1c32977006f18d" /
                  "suite.json")
    raw = stage_disclosure._read(suite_path)
    (staging / "suite.json").write_bytes(raw)

    leaked_probe = json.loads(raw)["probes"][0]["query"]
    sabotaged = page.replace("</body>", f"<p>{leaked_probe}</p></body>")
    (staging / "onewatch.html").write_text(sabotaged, encoding="utf-8")

    problems = stage_disclosure.check_probe_text_confined(staging)
    assert problems and "onewatch.html" in problems[0], (
        f"a probe rendered onto the page was not caught: {problems}")


def test_the_page_carries_no_probe_text_from_any_generation(page):
    """The property, stated directly rather than only via the confinement helper."""
    for marker in ("Answer the question using ONLY", "[doc-1]", "Context:",
                   "CANARY_GEN_SEED", "ANTHROPIC_API_KEY"):
        assert marker not in page, f"the page leaked {marker!r}"


def test_the_page_shows_generation_digests_and_never_probe_counts_it_invented(page):
    digests = re.findall(r"\b[0-9a-f]{64}\b", page)
    assert "e9cd77076c01a4b0f11a86d5d9051670c0ae96bb575be9818b2c60f9737a3806" in digests
