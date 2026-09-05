"""Render the canary store as a static receipt page. onewatch, the Detect pillar's viewer.

The receipt is the hero object; this is a certificate, not a dashboard row.

WHAT THIS MODULE MAY NOT DO
---------------------------
It computes nothing. It imports no hashing module, and it reaches the engine not at all —
only `canary.viewer.model`, which ran the verifiers, and `canary.viewer.tokens`, which
holds the vendored palette. `tests/viewer/test_structure.py` asserts both, so *"never
re-derive for display"* is a property of what this file can reach rather than of anyone
remembering it. If a value is not in the model, it does not go on the page.

COLOUR RIGHTS (spec §4, as ruled in Response 015 §2)
-----------------------------------------------------
**Seal is brand, and brand only.** It marks the wordmark and the kind label — identity, not
state. It never renders a verdict, a state word, or a status.

**The semantic pair belongs to verdicts, and canary has exactly two.** `UNCHANGED` and
`CHANGED` are verdicts and wear `--ok` / `--bad`.

**Recorded facts get bold ink.** A served-model change is a recorded fact, not a verdict —
the third member of the non-verdict category alongside `saturated | discriminating`. Both
render in `--ink`, bold, in the field grid: distinct, legible, and not an alarm.

The reference mockup renders `Model identity: CHANGED` in seal and this page does not,
deliberately: when a spec and its reference disagree, the resolution that makes the fewest
written sentences false wins, and §4's plain sentence — *seal gold never signals state* —
is the sentence that stays true this way.

THE THREE KINDS, ONE ANATOMY
-----------------------------
Same header, same field grid, same chain block, same footer. The **verdict banner is the
only element that varies**, and its variation carries the distinction:

    change certificate   badge in the semantic pair
    instrument health    banner in the neutral register
    instrument history   no banner -- **a retirement is an event, not a verdict**

NO BUTTON
---------
Spec §5.5 ends the card with a "Re-derive this receipt" button that runs the verifier. With
no backend and no script there is nothing for it to run. **A button that cannot verify is
an overclaim rendered in HTML** — so the footer names the command instead, which tells the
truth the button would fake.
"""
from __future__ import annotations

from html import escape

from canary.viewer.model import Absence, Card, PageModel
from canary.viewer.tokens import root_css

#: The one off-disk origin the reference mockup uses, named explicitly rather than matched
#: by pattern -- an allowlist that takes a pattern eventually admits something nobody meant.
FONT_ORIGIN = "https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap"

#: Verdict words that are verdicts, and therefore may wear the semantic pair. Anything not
#: in this map is a recorded fact and renders in bold ink.
VERDICT_TONE = {"UNCHANGED": "ok", "CHANGED": "bad"}


def _e(value: object) -> str:
    """Escape everything from the store. A digest cannot contain markup; a model name,
    a reason string or a generation id came from somewhere else and might."""
    return escape(str(value), quote=True)


def _verdict_banner(card: Card) -> str:
    """The only element that varies between kinds. See the module docstring."""
    if card.kind == "change":
        tone = VERDICT_TONE.get(card.verdict_word)
        if tone is None:
            # An outcome the renderer has no tone for is surfaced, never coloured by
            # guess. A new outcome is the one legitimate reason to touch this file.
            return (f'<div class="banner"><span class="badge badge-unknown">'
                    f'{_e(card.verdict_word)}</span><span class="why">This page has no '
                    f'declared treatment for that outcome; it is shown uncoloured rather '
                    f'than assigned one.</span></div>')
        return (f'<div class="banner"><span class="badge badge-{tone}">'
                f'{_e(card.verdict_word)}</span>'
                f'<span class="why">{_e(card.verdict_why)}</span></div>')
    if card.kind == "health":
        # Neutral register: a report, not an alarm (N-C007). No semantic colour, no seal.
        return (f'<div class="banner"><span class="state">{_e(card.verdict_word.upper())}'
                f'</span><span class="why">{_e(card.verdict_why)}</span></div>')
    return ""


def _fields(card: Card) -> str:
    out = []
    for label, value, style in card.fields:
        if style == "mono":
            rendered = f'<span class="m">{_e(value)}</span>'
        elif style == "fact":
            # Recorded facts: bold ink. Never seal, never the semantic pair.
            rendered = f'<b class="fact">{_e(value)}</b>'
        else:
            rendered = _e(value)
        out.append(f'<div class="frow"><span class="fk">{_e(label)}</span>'
                   f'<span class="fv">{rendered}</span></div>')
    return "".join(out)


def _verification(card: Card) -> str:
    """What the verifier said, carried verbatim. Three outcomes, held apart on the page.

    A failure state is shown INSTEAD of the values it would have vouched for, per spec §2:
    if verification fails, the page shows the failure; it never shows the value.
    """
    v = card.verification
    if v.status == "VERIFIED":
        return (f'<div class="vrow vrow-ok">RE-DERIVED · {v.checked} checks recomputed '
                f'from the frozen bytes · 0 failed · 0 unverifiable</div>')
    problems = "".join(f"<li>{_e(p)}</li>" for p in (v.failed + v.unverifiable))
    word = ("could not be checked" if v.status == "UNVERIFIABLE"
            else "was checked and did not hold")
    return (f'<div class="vrow vrow-bad">{_e(v.status)} — this receipt {word}. '
            f'The values it would have vouched for are withheld.<ul>{problems}</ul></div>')


def _chain(model: PageModel, card: Card) -> str:
    anchor = (f'{_e(model.anchor_root)} · tree size {model.anchor_size}'
              if model.anchor_root else
              'not anchored — an anchor is written only after every row re-verifies (X-8)')
    problems = ", ".join(model.chain_problems) if model.chain_problems else "intact"
    return f"""<div class="chain">
  <div class="crow"><span class="ck">Receipt digest</span><span class="cv">{_e(card.receipt['receipt_id'])}</span></div>
  <div class="crow"><span class="ck">Previous</span><span class="cv">{_e(card.row.prev_hash)}</span></div>
  <div class="crow"><span class="ck">Chain</span><span class="cv">seq {card.row.seq} · {_e(problems)}</span></div>
  <div class="crow"><span class="ck">Anchor</span><span class="cv">{anchor}</span></div>
</div>"""


def _card(model: PageModel, card: Card) -> str:
    kind_label = {"change": "Change-Evidence Certificate",
                  "health": "Instrument-Health Receipt"}.get(card.kind, "Receipt")
    body = _fields(card) if card.verification.status == "VERIFIED" else ""
    return f"""<article class="card">
  <div class="chead">
    <div><div class="kind">{_e(kind_label)}</div><div class="title">{_e(card.title)}</div></div>
    <div class="meta"><span class="m">{_e(card.receipt['receipt_id'][:16])}…</span><br>{_e(card.receipt['created_at'])}</div>
  </div>
  {_verdict_banner(card)}
  {_verification(card)}
  <div class="grid">{body}</div>
  {_chain(model, card)}
  <div class="foot">Every value above was read from a verified artifact. Re-run
    <span class="m">python -m canary.viewer</span> against the same store, or
    <span class="m">python scripts/rederive_incident.py</span>, to recompute them yourself.</div>
</article>"""


def _absence(absence: Absence) -> str:
    """Absent is a state, rendered. See `model.py` — an omitted rotation record reads as
    'there is no rotation programme', which is the opposite of what is true."""
    return f"""<article class="card card-absent">
  <div class="chead"><div><div class="kind">{_e(absence.heading)}</div>
    <div class="title">Nothing recorded</div></div></div>
  <div class="absent">{_e(absence.because)}</div>
</article>"""


def _generations(model: PageModel) -> str:
    if not model.generations:
        return ""
    rows = "".join(
        f'<div class="frow"><span class="fk">{_e(g["generation_id"])}</span>'
        f'<span class="fv"><b class="fact">{_e(g["status"].upper())}</b> '
        f'<span class="m">{_e(g["digest"])}</span> '
        f'<span class="dim">· {_e(g["n_probes"])} probes · probe text not published</span>'
        f'</span></div>'
        for g in model.generations)
    return f'<div class="grid">{rows}</div>'


def render(model: PageModel) -> str:
    cards = "".join(_card(model, c) for c in model.cards)
    absences = "".join(_absence(a) for a in model.absences)
    tail = "".join(
        f'<div class="trow"><span class="m">{_e(when)}</span><span>{_e(what)}</span></div>'
        for when, what in model.tail)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>onewatch — change evidence</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="{FONT_ORIGIN}">
<style>
{root_css()}
*{{box-sizing:border-box;margin:0}}
html{{background:var(--ground)}}
body{{background:var(--ground);color:var(--ink);font-family:var(--sans);line-height:1.5;padding:0 20px 72px}}
.shell{{max-width:840px;margin:0 auto}}
header.mast{{display:flex;align-items:baseline;justify-content:space-between;padding:30px 2px 22px}}
.wordmark{{font-weight:700;font-size:17px;letter-spacing:.02em}}
.wordmark span{{color:var(--seal)}}
.mast-note{{font-size:12px;color:var(--faint);letter-spacing:.04em}}
.lede{{color:var(--muted);font-size:14px;padding:0 2px 20px}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:22px;margin-bottom:18px}}
.card-absent{{background:var(--surface)}}
.chead{{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding-bottom:16px}}
.kind{{color:var(--seal);font-size:11px;font-weight:600;letter-spacing:.12em;text-transform:uppercase}}
.title{{font-size:17px;font-weight:600;padding-top:4px}}
.meta{{text-align:right;font-size:11.5px;color:var(--faint)}}
.banner{{display:flex;gap:14px;align-items:flex-start;padding:14px 0 16px;border-top:1px solid var(--border-soft)}}
.badge{{font:600 13px var(--mono);letter-spacing:.08em;padding:7px 14px;border-radius:6px;border:1px solid;white-space:nowrap}}
.badge-ok{{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-bd)}}
.badge-bad{{color:var(--bad);background:var(--bad-bg);border-color:var(--bad-bd)}}
.badge-unknown{{color:var(--muted);background:var(--surface);border-color:var(--border)}}
.state{{font:600 13px var(--mono);letter-spacing:.08em;padding:7px 14px;border-radius:6px;border:1px solid var(--border);background:var(--surface);color:var(--ink);white-space:nowrap}}
.why{{font-size:13.5px;color:var(--muted)}}
.vrow{{font:500 12px var(--mono);letter-spacing:.04em;padding:10px 0}}
.vrow-ok{{color:var(--ok)}}
.vrow-bad{{color:var(--bad)}}
.grid{{padding:6px 0 4px}}
.frow{{display:flex;gap:18px;padding:9px 0;border-top:1px solid var(--border-soft)}}
.fk{{flex:0 0 170px;font-size:11px;color:var(--faint);letter-spacing:.09em;text-transform:uppercase;padding-top:2px}}
.fv{{font-size:13.5px}}
.fact{{color:var(--ink);font-weight:700}}
.m{{font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:12.5px}}
.dim{{color:var(--muted)}}
.absent{{font-size:13.5px;color:var(--muted);padding-top:4px}}
.chain{{background:var(--surface);border:1px solid var(--border-soft);border-radius:8px;padding:14px;margin-top:14px}}
.crow{{display:flex;gap:14px;padding:4px 0}}
.ck{{flex:0 0 140px;font-size:10.5px;color:var(--faint);letter-spacing:.09em;text-transform:uppercase;padding-top:3px}}
.cv{{font-family:var(--mono);font-size:11.5px;word-break:break-all;color:var(--muted)}}
.foot{{font-size:12.5px;color:var(--faint);padding-top:14px}}
.trow{{display:flex;gap:16px;padding:7px 2px;border-top:1px solid var(--border-soft);font-size:13px;color:var(--muted)}}
h3{{font-size:13px;letter-spacing:.09em;text-transform:uppercase;color:var(--faint);padding:26px 2px 8px;font-weight:600}}
</style></head>
<body><div class="shell">
<header class="mast">
  <div class="wordmark">one<span>watch</span></div>
  <div class="mast-note">READ-ONLY · GENERATED FROM THE STORE · EVERY VALUE FROM A VERIFIED ARTIFACT</div>
</header>
<p class="lede">The change certificate. Probed against the sealed baseline; every verdict
recomputed from frozen bytes before it was shown. <b>A dashboard cannot prove a negative;
this signs one.</b></p>
{cards}
{absences}
<h3>Generations</h3>
{_generations(model)}
<h3>The ledger</h3>
{tail}
<p class="lede" style="padding-top:18px">Store: <span class="m">{_e(model.store_path)}</span>.
The canary reports <b>that</b> behaviour moved, under a named instrument, and where
behaviourally — never which stage of the target caused it.</p>
</div></body></html>"""


def build_page(store_root) -> str:
    from canary.viewer.model import build_model
    return render(build_model(store_root))
