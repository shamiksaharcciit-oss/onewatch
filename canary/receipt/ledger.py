"""The hash-chained ledger, and the Merkle anchor over it.

Each row commits to the row before it, so a receipt cannot be removed, reordered, or
back-dated without breaking every row that follows. The chain answers a question the
individual receipts cannot: *is this the complete set, in the order it happened?*

    row_hash = sha256(canonical({seq, prev_hash, receipt_id, ...}))

**X-8: anchor only what you have re-verified.** `anchor()` re-verifies every receipt it
is about to commit to and refuses the whole batch if any fails. An anchor is a public,
timestamped assertion that these receipts were real as of this moment; publishing one over
a receipt nobody re-checked would put the programme's signature on an unread document.

The Merkle construction is RFC 6962, taken from the vendored manifest: leaf/node domain
separation and split at the largest power of two below n, so the CVE-2012-2459 duplicate
collision is closed. It is not reimplemented here -- one implementation, one set of bytes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from canary.acj import canonical_bytes, digest_bytes, inclusion_proof, merkle_root

LEDGER_SCHEMA = "canary/ledger/v1"

#: The hash a first row commits to. A chain has to start somewhere, and it says so.
GENESIS = "0" * 64


class LedgerError(RuntimeError):
    """A chain that cannot be trusted to be complete and ordered."""


@dataclass(frozen=True, slots=True)
class Row:
    seq: int
    prev_hash: str
    receipt_id: str
    e_digest: str
    i_digest: str
    #: The digest of whatever verdict the receipt carries: `v_digest` for a change
    #: receipt (`v = I(E_baseline, E_t)`), `h_digest` for an instrument-health receipt
    #: (the headroom measurement). The field keeps its original name deliberately -- it
    #: is part of the row preimage, and renaming it would change `row_hash` for every row
    #: already written, including the anchored C4 incident of record. A launch
    #: deliverable's Merkle root does not move because a later feature wanted a tidier
    #: field name. `verdict_digest_field()` records which one a given schema supplies.
    v_digest: str
    outcome: str
    created_at: str

    def body(self) -> dict:
        """Everything the row commits to, except its own hash."""
        return {
            "schema": LEDGER_SCHEMA,
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "receipt_id": self.receipt_id,
            "e_digest": self.e_digest,
            "i_digest": self.i_digest,
            "v_digest": self.v_digest,
            "outcome": self.outcome,
            "created_at": self.created_at,
        }

    @property
    def row_hash(self) -> str:
        return digest_bytes(canonical_bytes(self.body()))

    def as_canonical(self) -> dict:
        return {**self.body(), "row_hash": self.row_hash}


def read_rows(path: Path) -> list[Row]:
    if not path.exists():
        return []
    rows: list[Row] = []
    for n, line in enumerate(path.read_bytes().decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        d = json.loads(line)
        row = Row(seq=d["seq"], prev_hash=d["prev_hash"], receipt_id=d["receipt_id"],
                  e_digest=d["e_digest"], i_digest=d["i_digest"], v_digest=d["v_digest"],
                  outcome=d["outcome"], created_at=d["created_at"])
        if row.row_hash != d.get("row_hash"):
            raise LedgerError(
                f"line {n}: row_hash does not match the row's content "
                f"(recorded {d.get('row_hash')}, recomputed {row.row_hash})")
        rows.append(row)
    return rows


#: Which field carries the verdict digest, per receipt schema. Explicit rather than
#: "whichever key happens to be present": a receipt missing both would otherwise chain
#: with whatever was found, and a receipt carrying both would chain with whichever the
#: lookup tried first.
_VERDICT_DIGEST_FIELD = {
    "canary/receipt/v1": "v_digest",
    "canary/health-receipt/v1": "h_digest",
}


def verdict_digest_field(schema: str) -> str:
    """The verdict-digest field name for a schema. Raises on one it does not know.

    An unknown schema is refused rather than defaulted. A ledger that chained a receipt
    shape it did not understand would be committing to a structure nobody had checked,
    and the chain's whole value is that every row means something specific.
    """
    try:
        return _VERDICT_DIGEST_FIELD[schema]
    except KeyError:
        raise LedgerError(
            f"unknown receipt schema {schema!r}; the ledger does not know which field "
            f"carries its verdict digest. Add it to _VERDICT_DIGEST_FIELD deliberately "
            f"rather than letting the chain guess.") from None


def _verdict_digest(receipt: dict) -> str:
    """The receipt's verdict digest, selected by its declared schema.

    A receipt with no `schema` is refused with a surfaced error rather than a `KeyError`
    from a dict lookup: "which field carries the verdict" is a question about the receipt,
    and a stack trace naming a missing key sends the reader looking for a bug in the
    ledger instead of a malformed receipt in front of it.
    """
    schema = receipt.get("schema")
    if not schema:
        raise LedgerError(
            "receipt declares no schema, so the ledger cannot tell which field carries "
            "its verdict digest. An unschema'd receipt is malformed, not a default case.")
    field = verdict_digest_field(schema)
    if field not in receipt:
        raise LedgerError(
            f"receipt declares schema {schema!r}, which must carry {field!r}, but that "
            f"field is absent. The receipt and its schema disagree.")
    return receipt[field]


def append(path: Path, receipt: dict, outcome: str) -> Row:
    """Append one receipt to the chain, committing to everything already in it."""
    rows = read_rows(path)
    problems = verify_chain(rows)
    if problems:
        raise LedgerError("refusing to append to a broken chain:\n" + "\n".join(problems))

    row = Row(
        seq=len(rows),
        prev_hash=rows[-1].row_hash if rows else GENESIS,
        receipt_id=receipt["receipt_id"],
        e_digest=receipt["e_digest"],
        i_digest=receipt["i_digest"],
        v_digest=_verdict_digest(receipt),
        outcome=outcome,
        created_at=receipt["created_at"],
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as fh:
        fh.write(canonical_bytes(row.as_canonical()) + b"\n")
    return row


def verify_chain(rows: list[Row]) -> list[str]:
    """Check sequence and linkage. Returns problems; empty means intact.

    Returns rather than raises: a broken chain is a finding a receipt should be able to
    state, not an exception that stops a verifier from reporting anything at all.
    """
    problems: list[str] = []
    expected_prev = GENESIS
    for i, row in enumerate(rows):
        if row.seq != i:
            problems.append(f"row {i}: seq is {row.seq}, expected {i}")
        if row.prev_hash != expected_prev:
            problems.append(
                f"row {i} (seq {row.seq}): prev_hash {row.prev_hash[:16]} does not match "
                f"the previous row's hash {expected_prev[:16]} — a row has been inserted, "
                f"removed, reordered, or altered")
        expected_prev = row.row_hash
    return problems


def anchor(rows: list[Row], reverify) -> dict:
    """Merkle-anchor a set of ledger rows, under X-8.

    `reverify` is called with each `receipt_id` and must return a list of problems -- empty
    for a receipt that re-derives. It is a required parameter with no default, because a
    default would let a caller anchor without re-verifying by simply not thinking about it,
    and X-8 exists precisely for the moments nobody is thinking about it.

    **The contract is enforced, not merely documented.** A caller that returns a bool --
    the natural mistake, since `True` reads like "it verified" -- used to sail into the
    failure branch as a truthy non-list and die inside the error formatter with
    `TypeError: can only join an iterable`. That is the wrong failure in two ways: it
    accuses the receipts when the caller is at fault, and it arrives as a stack trace
    from string formatting rather than as a surfaced error. A documented contract that
    nothing checks is a name outrunning its check (F5, self-caught while re-deriving this
    repository's own anchor).

    Note which way the bool fails: `True` means "problems present" to this function and
    "it verified" to the caller who wrote it. The two readings are exact opposites, so an
    unchecked bool does not merely crash -- it inverts the meaning of the check that X-8
    exists to guarantee.
    """
    if not rows:
        raise LedgerError("nothing to anchor")

    chain_problems = verify_chain(rows)
    if chain_problems:
        raise LedgerError("refusing to anchor a broken chain:\n" + "\n".join(chain_problems))

    failures: dict[str, list[str]] = {}
    for row in rows:
        problems = reverify(row.receipt_id)
        # Checked before use, and `bool` before `Sequence`: `True` is not a str/list, but
        # the check is written explicitly so the error names the actual mistake.
        if isinstance(problems, bool) or not isinstance(problems, (list, tuple)):
            raise LedgerError(
                f"reverify must return a list of problems -- empty for a receipt that "
                f"re-derives -- but it returned {problems!r} ({type(problems).__name__}) "
                f"for {row.receipt_id[:16]}. A bool is the natural mistake and the "
                f"dangerous one: True means 'problems present' here and 'it verified' to "
                f"the caller, which are opposite claims. Return `result.failed + "
                f"result.unverifiable`.")
        if problems:
            failures[row.receipt_id] = list(problems)
    if failures:
        detail = "\n".join(f"  {rid}: {'; '.join(p)}" for rid, p in sorted(failures.items()))
        raise LedgerError(
            "X-8: refusing to anchor receipts that did not re-verify. An anchor asserts "
            "these were real; asserting it over an unread document is the failure the "
            "rule exists to prevent.\n" + detail)

    leaves = [row.row_hash for row in rows]
    return {
        "schema": "canary/anchor/v1",
        "tree_size": len(leaves),
        "root": merkle_root(leaves),
        "leaves": leaves,
        "reverified": True,
    }


def prove_inclusion(anchor_obj: dict, receipt_row_hash: str) -> dict:
    """An inclusion proof for one row, so a third party can check one receipt alone.

    This is what makes an anchor useful to somebody who was given a single receipt: they
    verify that receipt and its path to the root, without needing the other receipts,
    which may be another customer's and none of their business.
    """
    leaves = anchor_obj["leaves"]
    if receipt_row_hash not in leaves:
        raise LedgerError(f"row {receipt_row_hash[:16]} is not in this anchor")
    index = leaves.index(receipt_row_hash)
    return {
        "leaf": receipt_row_hash,
        "index": index,
        "tree_size": len(leaves),
        "path": inclusion_proof(index, leaves),
        "root": anchor_obj["root"],
    }
