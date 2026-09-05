"""Canonical-form rules for re-derivable receipts.

Authoritative sources: Core->Delivery Response 002 (E8 + digest freeze) as amended
by Response 004 (2026-08-20): ACJ v2 (no Unicode normalisation in the hash
preimage, closing E14's UCD dependence for the canonicalisation path) and the
RFC 6962 Merkle construction (closing E12/E13, found by delivery's adversarial
probe of this artifact and verified independently by core).

Rules (frozen):
  1. Decimals: shortest exact fixed-point form. No exponent notation, no trailing
     fractional zeros, no leading zeros beyond a single "0" for |x|<1, no "+",
     "-" only on negative nonzero, negative zero renders "0". Uniform across
     dimensions. One form everywhere the PDP generates bytes.
  2. Datetimes: RFC3339, UTC, "T" separator, uppercase "Z", full seconds always,
     fractional seconds in shortest exact form (omitted when zero).
  3. Strings: hashed as the code points they contain - NO normalisation in the
     preimage (ACJ v2). Producers SHOULD emit NFC; the hash does not depend on
     any Unicode Character Database version. Operations that DO consult the UCD
     (e.g. an instrument's casefold) must have the runtime's Unicode version
     recorded in the manifest so a mismatch is diagnosable, not silent.
  4. JSON: keys sorted by code point, separators ("," , ":"), UTF-8, no ASCII
     escaping of non-ASCII. Floats are FORBIDDEN in canonical structures -
     quantities travel as canonical decimal strings (a schema must pin one
     representation per field; int and "int-string" are distinct bytes).
  5. Digests: SHA-256, lowercase hex, over the canonical bytes.
  6. Merkle: RFC 6962 section 2.1 - leaf/node domain separation (0x00/0x01
     prefixes) and split at the largest power of two below n. Never duplicate
     the last node (CVE-2012-2459 class collision). Inclusion proofs per
     RFC 6962 so a third party can verify one receipt without the whole set.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation


def canon_decimal(value) -> str:
    """Render a quantity in shortest exact fixed-point form.

    NOTE the trap this exists to close: str(Decimal("2.5E+2")) == "2.5E+2" and
    Decimal("250.00") vs Decimal("250") carry authored scale. Both are wrong for
    a preimage. This function makes semantically equal values byte-identical.
    """
    if isinstance(value, float):
        raise TypeError("floats are forbidden; pass str, int, or Decimal")
    try:
        d = value if isinstance(value, Decimal) else Decimal(str(value))
    except InvalidOperation as e:
        raise ValueError(f"not a decimal: {value!r}") from e
    if not d.is_finite():
        raise ValueError(f"non-finite decimal: {value!r}")
    if d == 0:
        return "0"  # covers -0, 0.00, 0E-2
    s = format(d.normalize(), "f")  # normalize strips trailing zeros; 'f' forbids exponent
    return s


def canon_datetime(dt: datetime) -> str:
    """RFC3339 UTC 'Z', full seconds, fractional seconds shortest-exact."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime; canonical form requires an explicit UTC instant")
    dt = dt.astimezone(timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        frac = f"{dt.microsecond:06d}".rstrip("0")
        return f"{base}.{frac}Z"
    return f"{base}Z"


def _check(obj):
    """Validate types for canonical structures. NO normalisation (ACJ v2):
    strings hash as the code points they contain, so the preimage is
    independent of the runtime's Unicode Character Database version (E14)."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, list):
        return [_check(x) for x in obj]
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise TypeError("canonical object keys must be strings")
        return {k: _check(v) for k, v in obj.items()}
    if isinstance(obj, float):
        raise TypeError("floats are forbidden in canonical structures; use canon_decimal strings")
    if isinstance(obj, (int, bool)) or obj is None:
        return obj
    raise TypeError(f"type not allowed in canonical structures: {type(obj).__name__}")


def canonical_bytes(obj) -> bytes:
    """Canonical JSON bytes: code-point-sorted keys, tight separators, UTF-8."""
    return json.dumps(_check(obj), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def digest_bytes(b: bytes) -> str:
    """SHA-256, lowercase hex."""
    return hashlib.sha256(b).hexdigest()


def digest_obj(obj) -> str:
    return digest_bytes(canonical_bytes(obj))


def digest_file(path) -> str:
    """Evidence files are archived verbatim and content-addressed as-is.

    This is the load-bearing half of the two-discipline design (Response 004 /
    E10): RECEIVED data is frozen and digested byte-for-byte, untransformed;
    only structures the PDP GENERATES are canonicalised before hashing."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------- Merkle (RFC 6962 §2.1) ---------------------------
# Patch authored by onedoor delivery (Escalation 004), verified independently by
# core against a separately-written reference implementation, exhaustive
# inclusion proofs for tree sizes 1-40, and five forgery classes.

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + entry).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """k such that k < n <= 2k. RFC 6962's split point."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root(entries: list[bytes]) -> bytes:
    n = len(entries)
    if n == 0:
        return hashlib.sha256(b"").digest()  # RFC 6962: MTH({}) = SHA-256()
    if n == 1:
        return _leaf_hash(entries[0])
    k = _largest_power_of_two_below(n)
    return _node_hash(_root(entries[:k]), _root(entries[k:]))


def merkle_root(leaf_digests: list[str]) -> str:
    """Merkle root over lowercase-hex leaves. RFC 6962 §2.1.

    Domain-separated (leaf 0x00 / node 0x01) and split-at-power-of-two: two
    different leaf sets cannot share a root (E12), and an internal node cannot
    be presented as a leaf (E13)."""
    return _root([bytes.fromhex(d) for d in leaf_digests]).hex()


def inclusion_proof(index: int, leaf_digests: list[str]) -> list[str]:
    """Audit path for the leaf at `index`, leaf-to-root. RFC 6962 §2.1.1."""
    if not 0 <= index < len(leaf_digests):
        raise IndexError("leaf index out of range")

    def _path(i: int, entries: list[bytes]) -> list[bytes]:
        if len(entries) == 1:
            return []
        k = _largest_power_of_two_below(len(entries))
        if i < k:
            return _path(i, entries[:k]) + [_root(entries[k:])]
        return _path(i - k, entries[k:]) + [_root(entries[:k])]

    return [h.hex() for h in _path(index, [bytes.fromhex(d) for d in leaf_digests])]


def verify_inclusion(leaf_digest: str, index: int, tree_size: int,
                     path: list[str], root: str) -> bool:
    """Recompute the root from a leaf and its audit path. RFC 6962 §2.1.2.

    The path is ordered leaf-to-root, so the walk reduces (fn, sn) bottom-up.
    Computing the split top-down against a bottom-up path silently fails every
    proof - the first draft of this patch did exactly that; the test caught it."""
    if not 0 <= index < tree_size:
        return False
    node = _leaf_hash(bytes.fromhex(leaf_digest))
    fn, sn = index, tree_size - 1
    for sibling_hex in path:
        if sn == 0:
            return False
        sibling = bytes.fromhex(sibling_hex)
        if fn % 2 == 1 or fn == sn:
            node = _node_hash(sibling, node)
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            node = _node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    return sn == 0 and node.hex() == root
