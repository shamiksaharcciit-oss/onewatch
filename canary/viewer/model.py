"""What the page shows, read from a verified store. No rendering, no colours, no HTML.

**Every displayed value is read from a verified artifact** (spec §2). This module runs the
same verification the CLI runs — `rederive` for change receipts, `rederive_health` for
health receipts, `ledger.verify_chain` and `ledger.anchor` for the chain — and carries its
output. It re-derives nothing of its own and computes no digest for display.

The separation from `page.py` is deliberate and is enforced by a test: the renderer imports
no hashing module and cannot reach the engine except through this model, so "never
re-derive for display" is a property of what the renderer *can* reach rather than of anyone
remembering the rule.

THREE KINDS, AND WHY THE THIRD HAS NO VERDICT
----------------------------------------------
`change`   a change certificate. `UNCHANGED` / `CHANGED` are **verdicts** and wear the
           semantic pair.
`health`   an instrument-health report. `saturated` / `discriminating` is a report, not an
           alarm (N-C007), so it gets the neutral register.
`history`  a retirement. **A retirement is an event, not a verdict** — so it has no verdict
           banner at all, and that absence is the anatomy carrying the distinction.

ABSENT IS A STATE
-----------------
A store legitimately holds none of a given kind: the switch is unthrown, so there is no
instrument history; the C4 store holds change receipts and no health run. Those sections
**render with an explanation of what is absent and why** rather than vanishing. An omitted
rotation record reads as *"there is no rotation programme"* — the opposite of what
Response 013 §3 made visible. This is the measured-zero versus declared-zero distinction
arriving at the rendering layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from canary.health.rederive import rederive_health
from canary.receipt import ledger
from canary.receipt.rederive import rederive
from canary.receipt.store import Store, StoreError

#: Receipt schemas this viewer knows how to present. A schema absent from this map is
#: surfaced as an unknown kind rather than rendered as a guess -- the same refusal the
#: ledger makes about verdict digests.
KIND_BY_SCHEMA = {
    "canary/receipt/v1": "change",
    "canary/health-receipt/v1": "health",
}


@dataclass(frozen=True, slots=True)
class Verification:
    """What the verifier said, carried rather than re-decided.

    The three outcomes stay apart all the way to the page: a body that could not be read is
    *unverifiable*, not *failed*, and the page says which. Collapsing them would put "this
    evidence is wrong" on screen when the truth was "this reader could not check it".
    """

    ok: bool
    checked: int
    failed: tuple[str, ...]
    unverifiable: tuple[str, ...]

    @property
    def status(self) -> str:
        if self.failed:
            return "FAILED"
        if self.unverifiable:
            return "UNVERIFIABLE"
        return "VERIFIED"


@dataclass(frozen=True, slots=True)
class Card:
    """One receipt, prepared for rendering. Values only; no markup, no colour decisions."""

    kind: str
    receipt: dict
    verification: Verification
    row: ledger.Row
    #: Label/value rows, in display order. Values are strings the store already carries.
    fields: tuple[tuple[str, str, str], ...]
    title: str
    verdict_word: str
    verdict_why: str


@dataclass(frozen=True, slots=True)
class Absence:
    """A kind the store legitimately does not contain, and the reason it does not.

    Carried as data rather than handled by an `if` in the template, so that "why is this
    empty" is answerable from the model and testable without parsing HTML.
    """

    kind: str
    heading: str
    because: str


@dataclass(frozen=True, slots=True)
class PageModel:
    store_path: str
    cards: tuple[Card, ...]
    absences: tuple[Absence, ...]
    chain_rows: int
    chain_problems: tuple[str, ...]
    anchor_root: str | None
    anchor_size: int
    generations: tuple[dict, ...]
    history_present: bool
    tail: tuple[tuple[str, str], ...] = field(default_factory=tuple)


def _display_path(store_root: Path) -> str:
    """Repo-relative where possible, so the page does not vary by whose machine made it.

    An absolute path bakes a home directory into a published artifact: it differs between a
    cold clone and a working tree, which would defeat the regeneration test, and it tells a
    reader of the launch page the name of the account that generated it.
    """
    repo = Path(__file__).resolve().parent.parent.parent
    try:
        return store_root.resolve().relative_to(repo).as_posix()
    except ValueError:
        return store_root.name


def _fields_for_change(receipt: dict, baseline: dict | None) -> tuple:
    """The change certificate's grid. Every value is read; none is computed here."""
    target = receipt["target"]
    verdict = receipt["verdict"]
    baseline_model = ((baseline or {}).get("run", {}).get("target", {}) or {}).get(
        "served_model") or receipt.get("baseline_served_model") or "—"
    served = target["served_model"]

    # A recorded fact, not a verdict (Response 015 §1). The page renders it in bold ink,
    # never in seal and never in the semantic pair -- but the model only says WHAT it is;
    # the register is the renderer's job and the token is the spec's.
    identity_moved = baseline_model not in ("—", served)
    detector = receipt["instrument"]["detector"]
    band = receipt["baseline"]["band"]["per_arm"]

    rows = [
        ("Baseline", baseline_model, "mono"),
        ("Served this run", served, "mono"),
        ("Model identity", "CHANGED" if identity_moved else "UNCHANGED", "fact"),
        ("Behaviour", verdict["outcome"], "fact"),
        ("Probes moved", f"{verdict['n_probe_deltas']} of {_probe_total(verdict)}", "plain"),
        ("Instrument", f"{detector['family']} {detector['version']}", "mono"),
        ("Variance band", ", ".join(f"{k} {v}" for k, v in sorted(band.items())), "plain"),
        # W3: the engine carries a boolean and two content addresses for the seal question,
        # not a per-slot count. The page shows what exists. An illustrative number is a
        # design reference's privilege and a viewer's defect.
        ("Raw bytes", "differ" if verdict["seal"]["bytes_changed"] else "identical", "plain"),
    ]
    return tuple(rows)


def _probe_total(verdict: dict) -> int:
    """Denominator from the counts the run sealed, never recounted here."""
    return sum(bucket["current"]["denominator"]
               for bucket in verdict["count_deltas"].values())


def _fields_for_health(receipt: dict) -> tuple:
    headroom = receipt["headroom"]
    detector = receipt["instrument"]["detector"]
    rows = [
        ("Family", f"{detector['family']} {detector['version']}", "mono"),
        ("Baseline model", headroom["baseline_model"], "mono"),
        ("Headroom", f"{headroom['total_failures']} failure(s) across "
                     f"{headroom['total_probes']} probes", "plain"),
    ]
    for arm in sorted(headroom["per_arm"]):
        counts = headroom["per_arm"][arm]
        rows.append((arm.replace("_", " "),
                     f"{counts['numerator']} of {counts['denominator']}", "plain"))
    return tuple(rows)


def build_model(store_root: Path) -> PageModel:
    """Read the store, run the verifiers, and carry what they said."""
    store = Store(store_root)
    rows = ledger.read_rows(store.ledger_path())
    chain_problems = tuple(ledger.verify_chain(rows))

    baseline = None
    baselines = store_root / "baselines"
    if baselines.is_dir():
        for path in sorted(baselines.iterdir()):
            import json
            baseline = json.loads(path.read_bytes())
            break

    cards: list[Card] = []
    tail: list[tuple[str, str]] = []
    for row in rows:
        try:
            receipt = store.get_receipt(row.receipt_id)
        except (StoreError, OSError):
            continue
        kind = KIND_BY_SCHEMA.get(receipt.get("schema", ""), "unknown")
        if kind == "change":
            result = rederive(store_root, row.receipt_id)
            fields = _fields_for_change(receipt, baseline)
            word = receipt["verdict"]["outcome"]
            why = (receipt["verdict"]["reasons"] or ["—"])[0]
            title = _change_title(fields)
        elif kind == "health":
            result = rederive_health(store_root, row.receipt_id)
            fields = _fields_for_health(receipt)
            word = receipt["verdict"]
            why = ("The baseline passes every probe: this family cannot distinguish two "
                   "healthy models, and remains at maximum sensitivity to degradation."
                   if word == "saturated" else
                   "The baseline has measurable room below the ceiling; a later run can "
                   "move in either direction.")
            title = "Instrument health"
        else:
            continue
        cards.append(Card(
            kind=kind, receipt=receipt,
            verification=Verification(ok=result.ok, checked=len(result.checked),
                                      failed=tuple(result.failed),
                                      unverifiable=tuple(result.unverifiable)),
            row=row, fields=fields, title=title, verdict_word=word, verdict_why=why))
        tail.append((receipt["created_at"], f"{word} · seq {row.seq}"))

    anchor_root, anchor_size = None, 0
    if rows and not chain_problems:
        # X-8: the anchor is recomputed here only because every row above has just been
        # re-derived, and the reverifier hands `anchor` the problems it found. An anchor
        # asserted over an unread document is the failure the rule exists to prevent.
        verdicts = {c.row.receipt_id: c.verification for c in cards}

        def reverify(receipt_id: str) -> list[str]:
            v = verdicts.get(receipt_id)
            if v is None:
                return [f"{receipt_id[:16]}: not read by this page"]
            return list(v.failed) + list(v.unverifiable)

        try:
            anchor = ledger.anchor(rows, reverify)
            anchor_root, anchor_size = anchor["root"], anchor["tree_size"]
        except ledger.LedgerError:
            anchor_root, anchor_size = None, 0

    return PageModel(
        store_path=_display_path(store_root),
        cards=tuple(cards),
        absences=tuple(_absences(cards)),
        chain_rows=len(rows),
        chain_problems=chain_problems,
        anchor_root=anchor_root,
        anchor_size=anchor_size,
        generations=tuple(_generations(cards)),
        history_present=False,
        tail=tuple(tail),
    )


def _change_title(fields: tuple) -> str:
    """The card's human title: the two facts, side by side, above the fold.

    This is the product thesis as a sentence. The C4 incident is exactly the case where the
    two halves differ, and a title that collapsed them into one word would be false in
    whichever direction it chose.
    """
    values = {label: value for label, value, _ in fields}
    identity = "Served model changed" if values["Model identity"] == "CHANGED" \
        else "Served model unchanged"
    behaviour = "behaviour unchanged" if values["Behaviour"] == "UNCHANGED" \
        else "behaviour CHANGED"
    return f"{identity} · {behaviour}"


def _generations(cards) -> list[dict]:
    """Generations seen in the store, as identity + digest only.

    ACTIVE generations are shown as digests and never as probe text — the public trace the
    design allows, and no more. Rotation being visible is the point; the probes staying
    secret is the other half of it.
    """
    seen: dict[str, dict] = {}
    for card in cards:
        generation = card.receipt.get("target", {}).get("generation")
        if not generation:
            continue
        seen.setdefault(generation["generation_id"], {
            "generation_id": generation["generation_id"],
            "digest": generation["generation_digest"],
            "status": generation["status"],
            "n_probes": generation["n_probes"],
        })
    return list(seen.values())


def _absences(cards) -> list[Absence]:
    """What this store does not contain, and why. See the module docstring."""
    out = []
    if not any(c.kind == "health" for c in cards):
        out.append(Absence(
            kind="health", heading="Instrument health",
            because="No instrument-health receipt has been written to this store. Health "
                    "runs are scheduled separately and chain into the store they measure; "
                    "this store holds the change certificates of the live phase."))
    out.append(Absence(
        kind="history", heading="Instrument history",
        because="No retirement is recorded in this store. Retirement is a one-way, dated, "
                "visible instrument change, and when it happens it is written to the "
                "instrument history rather than to the change receipts this page reads."))
    return out
