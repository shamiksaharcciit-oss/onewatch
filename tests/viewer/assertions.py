"""The page's properties, named once and applied to every page any test renders.

A property stated inside one test protects one page. Stated here and applied by
`assert_every_page_property`, it protects every page the suite builds — including the
failure pages, the empty-store pages and the sabotaged ones, which are exactly the pages
nobody remembers to re-check.
"""
from __future__ import annotations

import re

from canary.viewer.tokens import hex_values

HEXCOLOUR = re.compile(r"#[0-9A-Fa-f]{6}")
FONT_ORIGIN = "https://fonts.googleapis.com"

#: Words that assert a state. The positive seal check refuses to see any of them rendered
#: in seal, wherever and however they appear -- Core -> Canary Response 015 §3.
STATE_WORDS = ("UNCHANGED", "CHANGED", "SATURATED", "DISCRIMINATING",
               "VERIFIED", "FAILED", "UNVERIFIABLE", "ACTIVE", "RETIRED")


class PropertyViolation(AssertionError):
    """A page broke a property that holds for every page."""


def content(html: str) -> str:
    """The page with its `<style>` block removed: what a reader actually sees."""
    return re.sub(r"<style>.*?</style>", "", html, flags=re.S)


# ------------------------------------------------------------------ colour rights


def assert_no_foreign_hex_colour(html: str) -> None:
    """Every colour is a token (spec §4). No stray hex from a mockup or a habit."""
    foreign = {c.lower() for c in HEXCOLOUR.findall(html)} - hex_values()
    if foreign:
        raise PropertyViolation(f"non-token colours on the page: {sorted(foreign)}")


def assert_seal_never_signals_state(html: str) -> None:
    """Spec §4, in the POSITIVE form core ruled (Response 015 §3).

    onedoor's version inspects CSS rules matching `.verdict*`, which is a negative list with
    one entry -- and the reference mockup's own violation walks straight past it, because it
    is an inline style on a field value rather than a verdict rule. N-C005 in a new place: a
    negative check catches what someone thought to name.

    So this checks the emitted HTML for the property itself: **no state word is rendered in
    seal, wherever and however it appears.** Three routes are covered -- an inline
    `style="color:var(--seal)"`, an inline literal seal hex, and any class whose rule
    resolves to seal.
    """
    palette_seal = "#d4a855"
    seal_classes = {name for name, rule in _class_rules(html).items()
                    if "--seal" in rule or palette_seal in rule.lower()}

    for match in re.finditer(r"<([a-z]+)([^>]*)>([^<]*)", content(html)):
        attrs, text = match.group(2), match.group(3).strip().upper()
        if not any(word == text or word in text.split() for word in STATE_WORDS):
            continue
        style = re.search(r'style\s*=\s*"([^"]*)"', attrs)
        if style and ("--seal" in style.group(1) or palette_seal in style.group(1).lower()):
            raise PropertyViolation(
                f"a state word is rendered in the brand accent: {match.group(0)[:80]!r}. "
                f"Seal is brand and brand only (spec §4).")
        classes = re.search(r'class\s*=\s*"([^"]*)"', attrs)
        if classes and (set(classes.group(1).split()) & seal_classes):
            raise PropertyViolation(
                f"a state word wears a class that resolves to seal: "
                f"{match.group(0)[:80]!r}")


def assert_semantic_colours_belong_to_verdicts(html: str) -> None:
    """The semantic pair is reserved for canary's two verdicts.

    `saturated | discriminating` is a report, not an alarm (N-C007), and a served-model
    change is a recorded fact, not a verdict. Neither may wear ok/bad, or the page would be
    alarming about things that are not alarms.
    """
    rules = _class_rules(html)
    for name, rule in rules.items():
        if "--ok" not in rule and "--bad" not in rule:
            continue
        if name in {"badge-ok", "badge-bad", "vrow-ok", "vrow-bad"}:
            continue
        raise PropertyViolation(
            f"class .{name} uses a semantic colour but is not a verdict badge or a "
            f"verification status: {rule[:70]}…")
    for forbidden in ("state", "fact"):
        rule = rules.get(forbidden, "")
        if "--ok" in rule or "--bad" in rule:
            raise PropertyViolation(
                f".{forbidden} is the non-verdict register and must not use the semantic "
                f"pair: {rule[:70]}…")


def _class_rules(html: str) -> dict[str, str]:
    style = re.search(r"<style>(.*?)</style>", html, flags=re.S)
    if not style:
        return {}
    return {m.group(1): m.group(2)
            for m in re.finditer(r"\.([\w-]+)\s*\{([^}]*)\}", style.group(1))}


# ------------------------------------------------------------------- the scope fence


def assert_scope_fence(html: str) -> None:
    """Spec §3, enforced rather than intended: static, read-only, no network at view time.

    The one allowed off-disk origin is the fonts stylesheet the reference mockup uses,
    named explicitly rather than matched by pattern -- an allowlist that takes a pattern
    will eventually admit something nobody meant to allow.
    """
    for banned, why in (
        ("fetch(", "a network call at view time"),
        ("XMLHttpRequest", "a network call at view time"),
        ("WebSocket", "a network call at view time"),
        ("<form", "a form implies something to submit to"),
        ("<input", "an input is a filter or a search box waiting to happen"),
        ("<select", "a filter control"),
        ("<button", "a button that cannot verify is an overclaim rendered in HTML"),
        ("localStorage", "state that outlives the page"),
        ("onclick", "behaviour after generation"),
    ):
        if banned in html:
            raise PropertyViolation(f"scope fence: {banned!r} on the page — {why}")
    for url in re.findall(r'(?:src|href)\s*=\s*"([^"]+)"', html):
        if url.startswith(("http://", "https://", "//")) and not url.startswith(FONT_ORIGIN):
            raise PropertyViolation(f"scope fence: off-disk reference to {url}")


def assert_page_is_self_contained(html: str) -> None:
    """Opened from disk, with no build step, no sibling files and no script.

    §3 permits inline JS; this viewer carries none. Every line of script is a line that
    could change what the reader sees after generation, and a receipt page that can change
    after it is signed is not a receipt page.
    """
    if "<style>" not in html:
        raise PropertyViolation("styles are not inline; the page is not self-contained")
    if re.search(r"<script\b", html):
        raise PropertyViolation("the page carries script")


def assert_store_values_are_escaped(html: str) -> None:
    """Values from the store reach the page through `escape`, never raw."""
    if re.search(r"<b class=\"fact\">[^<]*<", html) is None and "fact" in html:
        pass
    for bad in ("<script>alert", "onerror=", 'javascript:'):
        if bad in html:
            raise PropertyViolation(f"unescaped store value reached the page: {bad!r}")


# ------------------------------------------------------------------ labels and truth


def assert_labels_survive(html: str) -> None:
    """Every label that qualifies a claim must reach the surface.

    A sabotage that strips one of these fails here. Each exists because a reader who does
    not see it would believe something stronger than the evidence supports.
    """
    body = content(html)
    required = {
        "probe text not published":
            "an ACTIVE generation must be shown as a digest, never as probes",
        "never which stage":
            "the anti-overclaim boundary must travel with the verdict",
        "read from a verified artifact":
            "the page must say its values came from verification",
        "python -m canary.viewer":
            "the footer must name the command that reproduces the page",
    }
    for needle, why in required.items():
        if needle not in body:
            raise PropertyViolation(f"label missing from the page: {needle!r} — {why}")


def assert_absence_is_rendered_as_a_state(html: str) -> None:
    """Absent is a state, not a gap.

    An omitted rotation record reads as "there is no rotation programme", which is the
    opposite of what is true. Every absent kind names itself and says why it is empty.
    """
    body = content(html)
    if "Nothing recorded" not in body:
        raise PropertyViolation("no absence is rendered; an empty section vanished")
    if "No generation has been retired" not in body:
        raise PropertyViolation(
            "the instrument-history absence does not explain itself; a reader cannot tell "
            "'not retired' from 'no rotation programme'")


def assert_every_page_property(html: str) -> None:
    """Everything that holds for EVERY page: sound, failed, empty, or sabotaged."""
    assert_no_foreign_hex_colour(html)
    assert_seal_never_signals_state(html)
    assert_semantic_colours_belong_to_verdicts(html)
    assert_scope_fence(html)
    assert_page_is_self_contained(html)
    assert_store_values_are_escaped(html)
