"""Seal and verify re-derivable verdict manifests.

seal():   freeze evidence -> run instrument -> emit content-addressed manifest.
verify(): schema-check the manifest, recompute all four digests AND re-derive
          v = I(E) from the archived evidence; a manifest verifies only if the
          verdict recomputes to the byte. "Don't trust the log - recompute it."
anchor(): RFC 6962 Merkle root over a set of manifest ids (the periodic anchor),
          with inclusion proofs so a third party can check one receipt.

Self-test: python3 validate.py --selftest
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from canonical import (canon_datetime, canon_decimal, canonical_bytes,
                       digest_bytes, digest_file, digest_obj,
                       inclusion_proof, merkle_root, verify_inclusion)
from instruments import INSTRUMENTS, run_instrument

HERE = Path(__file__).parent
SCHEMA_ID = "rederivable-manifest/1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_KEYS = {"schema", "created_at", "unicode_version", "evidence",
                  "instrument", "trust", "verdict", "e_digest", "i_digest",
                  "t_digest", "v_digest", "anchor_ref", "manifest_id"}
_OPTIONAL_KEYS = {"fidelity"}  # "exact" | "attested" (Arm-E vs alignment-inferred)


def load_evidence(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _contained_evidence_path(evidence_dir: Path, ref: str) -> Path:
    """Resolve an evidence ref and refuse escapes from the evidence directory."""
    base = evidence_dir.resolve()
    p = (base / ref).resolve()
    if base != p and base not in p.parents:
        raise ValueError(f"evidence ref escapes the evidence directory: {ref!r}")
    return p


def _nested(errs: list[str], m: dict, field: str, required: set[str],
            types: dict[str, type]) -> None:
    """Enforce a nested object's exact key set and value types (Escalation 005:
    additionalProperties: false must hold at every level, not only the top)."""
    v = m.get(field)
    if not isinstance(v, dict):
        errs.append(f"schema: {field} must be an object")
        return
    keys = set(v)
    if missing := required - keys:
        errs.append(f"schema: {field} missing {sorted(missing)}")
    if extra := keys - required:
        errs.append(f"schema: {field} has unexpected fields {sorted(extra)} "
                    f"(additionalProperties: false)")
    for k, t in types.items():
        if k in v and not isinstance(v[k], t):
            errs.append(f"schema: {field}.{k} must be {t.__name__}")


def _schema_check(m: dict) -> list[str]:
    """Structural check per manifest.schema.json (self-contained, no deps).

    Must agree with the normative schema at EVERY level — a receipt "verified" by
    one checker and invalid to another is the one thing a recompute-don't-trust
    artifact can't afford (Escalation 005)."""
    errs: list[str] = []
    keys = set(m)
    if missing := _REQUIRED_KEYS - keys:
        errs.append(f"schema: missing fields {sorted(missing)}")
    if extra := keys - _REQUIRED_KEYS - _OPTIONAL_KEYS:
        errs.append(f"schema: unexpected fields {sorted(extra)} (additionalProperties: false)")
    if m.get("schema") != SCHEMA_ID:
        errs.append(f"schema: field 'schema' must be {SCHEMA_ID!r}, got {m.get('schema')!r}")
    for f in ("created_at", "unicode_version"):
        if f in m and not isinstance(m[f], str):
            errs.append(f"schema: {f} must be a string")
    _nested(errs, m, "evidence", {"ref"}, {"ref": str})
    _nested(errs, m, "instrument", {"id"}, {"id": str})
    _nested(errs, m, "trust", {"set"}, {"set": list})
    if isinstance(m.get("trust"), dict) and isinstance(m["trust"].get("set"), list):
        if not all(isinstance(x, str) for x in m["trust"]["set"]):
            errs.append("schema: trust.set items must be strings")
    if "verdict" in m and not isinstance(m["verdict"], dict):
        errs.append("schema: verdict must be an object")
    if "fidelity" in m and m["fidelity"] not in ("exact", "attested"):
        errs.append("schema: fidelity must be 'exact' or 'attested'")
    for f in ("e_digest", "i_digest", "t_digest", "v_digest", "manifest_id"):
        if f in m and not (isinstance(m[f], str) and _HEX64.match(m[f])):
            errs.append(f"schema: {f} is not lowercase-hex SHA-256")
    if "anchor_ref" in m and not (m["anchor_ref"] is None or isinstance(m["anchor_ref"], str)):
        errs.append("schema: anchor_ref must be null or string")
    return errs


def seal(evidence_path: Path, instrument_id: str, trust: list[str] | None = None,
         created_at: datetime | None = None, out_dir: Path = HERE / "manifests",
         fidelity: str | None = None) -> dict:
    trust = sorted(trust or [])
    spec = INSTRUMENTS[instrument_id]
    replies = load_evidence(evidence_path)
    verdict = run_instrument(spec, replies)

    manifest = {
        "schema": SCHEMA_ID,
        "created_at": canon_datetime(created_at or datetime.now(timezone.utc)),
        "unicode_version": unicodedata.unidata_version,
        "evidence": {"ref": evidence_path.name},
        "instrument": {"id": instrument_id},
        "trust": {"set": trust},
        "verdict": verdict,
        "e_digest": digest_file(evidence_path),
        "i_digest": digest_obj(spec),
        "t_digest": digest_obj(trust),
        "v_digest": digest_obj(verdict),
        "anchor_ref": None,
    }
    if fidelity is not None:
        if fidelity not in ("exact", "attested"):
            raise ValueError("fidelity must be 'exact' or 'attested'")
        manifest["fidelity"] = fidelity
    manifest["manifest_id"] = digest_bytes(canonical_bytes(manifest))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{manifest['manifest_id']}.json"
    out.write_bytes(canonical_bytes(manifest))
    return manifest


def verify(manifest_path: Path, evidence_dir: Path = HERE / "evidence") -> tuple[bool, list[str]]:
    errors: list[str] = []
    m = json.loads(manifest_path.read_text(encoding="utf-8"))

    errors.extend(_schema_check(m))
    if errors:
        return (False, errors)

    body = {k: v for k, v in m.items() if k != "manifest_id"}
    if digest_bytes(canonical_bytes(body)) != m["manifest_id"]:
        errors.append("manifest_id does not match canonical content")

    try:
        epath = _contained_evidence_path(evidence_dir, m["evidence"]["ref"])
    except ValueError as e:
        return (False, errors + [str(e)])
    if not epath.exists():
        errors.append(f"evidence missing: {epath}")
    elif digest_file(epath) != m["e_digest"]:
        errors.append("e_digest mismatch: archived evidence differs from frozen evidence")

    spec = INSTRUMENTS.get(m["instrument"]["id"])
    if spec is None:
        errors.append(f"unknown instrument: {m['instrument']['id']}")
    elif digest_obj(spec) != m["i_digest"]:
        errors.append("i_digest mismatch: held instrument spec differs from sealed spec")

    if digest_obj(sorted(m["trust"]["set"])) != m["t_digest"]:
        errors.append("t_digest mismatch")

    if digest_obj(m["verdict"]) != m["v_digest"]:
        errors.append("v_digest mismatch: recorded verdict differs from its digest")

    # The re-derivation itself: v must recompute from E and I, to the byte.
    if not errors:
        rederived = run_instrument(spec, load_evidence(epath))
        if digest_obj(rederived) != m["v_digest"]:
            msg = "RE-DERIVATION FAILED: I(E) does not reproduce v"
            if m["unicode_version"] != unicodedata.unidata_version:
                msg += (f" - probable cause: Unicode version mismatch "
                        f"(sealed under UCD {m['unicode_version']}, "
                        f"running UCD {unicodedata.unidata_version}); "
                        f"UCD-sensitive instrument operations (e.g. casefold) "
                        f"may differ between these runtimes")
            errors.append(msg)

    return (not errors, errors)


def anchor(manifest_ids: list[str]) -> str:
    return merkle_root(sorted(manifest_ids))


# ----------------------------- self-test ------------------------------------

def selftest() -> int:
    import hashlib
    import tempfile
    from decimal import Decimal
    ok = True
    tmp = Path(tempfile.mkdtemp(prefix="rederivable-selftest-"))
    # All sealing in the self-test targets a temp dir, NEVER the artifact's own
    # manifests/ — a stray receipt quietly becoming "part of the artifact" is a
    # trap the forensics session hit on a no-unlink mount; closed here for good.

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" - {detail}" if detail and not cond else ""))
        ok = ok and cond

    print("canonical form:")
    check("scale-insensitivity", canon_decimal("250") == canon_decimal("250.00") == "250")
    check("exponent trap closed", canon_decimal(Decimal("2.5E+2")) == "250",
          f"got {canon_decimal(Decimal('2.5E+2'))!r}")
    check("negative zero", canon_decimal("-0.00") == "0")
    check("fraction shortest", canon_decimal("0.50") == "0.5")
    check("idempotent", canon_decimal(canon_decimal("00250.100")) == "250.1")
    try:
        canonical_bytes({"x": 1.5}); check("floats rejected", False)
    except TypeError:
        check("floats rejected", True)
    check("key order", digest_obj({"b": "y", "a": "x"}) == digest_obj({"a": "x", "b": "y"}))
    check("UCD-independent preimage (ACJ v2): NFC and NFD digests DIFFER by design",
          digest_obj({"s": "café"}) != digest_obj({"s": "café"}))
    dt = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)
    check("datetime canonical", canon_datetime(dt) == "2026-09-01T00:00:00Z")
    check("fractional shortest", canon_datetime(dt.replace(microsecond=120000)).endswith("00.12Z"))

    print("merkle (RFC 6962) - E12/E13 regressions:")
    A, B, C = [hashlib.sha256(x).hexdigest() for x in (b"A", b"B", b"C")]
    check("E12 closed: root([A,B,C]) != root([A,B,C,C])",
          merkle_root([A, B, C]) != merkle_root([A, B, C, C]))
    check("E13 closed: internal node does not pass as leaf",
          merkle_root([merkle_root([A, B])]) != merkle_root([A, B]))
    all_ok = True
    for n in range(1, 34):
        ds = [hashlib.sha256(bytes([i, n])).hexdigest() for i in range(n)]
        r = merkle_root(ds)
        for i in range(n):
            p = inclusion_proof(i, ds)
            if not verify_inclusion(ds[i], i, n, p, r):
                all_ok = False
            if verify_inclusion(hashlib.sha256(b"forged").hexdigest(), i, n, p, r):
                all_ok = False
    check("inclusion proofs verify + forgeries rejected, n=1..33", all_ok)

    print("seal/verify (toy mirrors the v2->v3 correction):")
    ev = HERE / "evidence" / "replies.jsonl"
    fixed = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    m2 = seal(ev, "refusal_sentinel@v2", trust=[], created_at=fixed, out_dir=tmp)
    m3 = seal(ev, "refusal_sentinel@v3", trust=[], created_at=fixed, out_dir=tmp)
    check("v2 flags 4/5", (m2["verdict"]["flagged"], m2["verdict"]["total"]) == (4, 5),
          f"got {m2['verdict']['flagged']}/{m2['verdict']['total']}")
    check("v3 flags 0/5", (m3["verdict"]["flagged"], m3["verdict"]["total"]) == (0, 5),
          f"got {m3['verdict']['flagged']}/{m3['verdict']['total']}")
    check("same E", m2["e_digest"] == m3["e_digest"])
    check("different I", m2["i_digest"] != m3["i_digest"])
    check("archive-closed T", m2["t_digest"] == digest_obj([]))
    check("unicode_version recorded", m2["unicode_version"] == unicodedata.unidata_version)
    for m in (m2, m3):
        good, errs = verify(tmp / f"{m['manifest_id']}.json")
        check(f"verify {m['instrument']['id']}", good, "; ".join(errs))
    check("deterministic seal",
          seal(ev, "refusal_sentinel@v2", trust=[], created_at=fixed,
               out_dir=tmp)["manifest_id"] == m2["manifest_id"])

    print("shipped manifests re-verify:")
    shipped = sorted((HERE / "manifests").glob("*.json"))
    check("shipped set present", len(shipped) >= 2)
    for sp in shipped:
        good, errs = verify(sp)
        check(f"verify shipped {sp.stem[:12]}…", good, "; ".join(errs))

    print("UCD-sensitive fixture (non-ASCII; cross-runtime probe target):")
    evu = HERE / "evidence" / "replies_unicode.jsonl"
    mu = seal(evu, "refusal_sentinel@v2", trust=[], created_at=fixed,
              out_dir=tmp, fidelity="exact")
    check("unicode fixture seals + flags via casefold",
          (mu["verdict"]["flagged"], mu["verdict"]["total"]) == (1, 3),
          f"got {mu['verdict']['flagged']}/{mu['verdict']['total']}")
    good, errs = verify(tmp / f"{mu['manifest_id']}.json")
    check("unicode fixture verifies", good, "; ".join(errs))
    check("fidelity field carried", mu.get("fidelity") == "exact")

    print("hardening (Escalations 004 minors + 005):")
    mt = dict(m2); mt["extra_field"] = "x"
    tp = tmp / "_extra_field.json"
    tp.write_bytes(canonical_bytes(mt))
    good, errs = verify(tp)
    check("top-level extra field rejected", not good and any("unexpected fields" in e for e in errs))

    # Escalation 005 reproduction: nested extra field, honestly re-addressed.
    mt = {k: v for k, v in m2.items() if k != "manifest_id"}
    mt["evidence"] = {"ref": mt["evidence"]["ref"], "stages": ["ingestion", "rerank"]}
    mt["manifest_id"] = digest_bytes(canonical_bytes(mt))
    tp = tmp / "_nested_extra.json"
    tp.write_bytes(canonical_bytes(mt))
    good, errs = verify(tp)
    check("E005 closed: nested extra field rejected",
          not good and any("evidence has unexpected fields" in e for e in errs))

    mt = dict(m2); mt["fidelity"] = "vibes"
    tp = tmp / "_bad_fidelity.json"
    tp.write_bytes(canonical_bytes(mt))
    good, errs = verify(tp)
    check("invalid fidelity rejected", not good and any("fidelity" in e for e in errs))

    mt = dict(m2); mt["schema"] = "rederivable-manifest/999"
    tp = tmp / "_bad_schema.json"
    tp.write_bytes(canonical_bytes(mt))
    good, errs = verify(tp)
    check("wrong schema id rejected", not good and any("'schema'" in e for e in errs))

    mt = json.loads((tmp / f"{m2['manifest_id']}.json").read_text())
    mt["evidence"]["ref"] = "../canonical.py"
    tp = tmp / "_traversal.json"
    tp.write_bytes(canonical_bytes(mt))
    good, errs = verify(tp)
    check("path traversal refused", not good and any("escapes" in e or "manifest_id" in e for e in errs))

    print("tamper detection:")
    tdir = tmp / "evidence"; tdir.mkdir(exist_ok=True)
    (tdir / "replies.jsonl").write_text(
        ev.read_text(encoding="utf-8").replace("reconciled", "adjusted"), encoding="utf-8")
    good, errs = verify(tmp / f"{m2['manifest_id']}.json", evidence_dir=tdir)
    check("tampered evidence caught", not good)

    print("anchor + inclusion:")
    ids = sorted([m2["manifest_id"], m3["manifest_id"]])
    root = anchor(ids)
    check("merkle root stable under input order", root == anchor(list(reversed(ids))))
    p = inclusion_proof(0, ids)
    check("receipt inclusion proof verifies", verify_inclusion(ids[0], 0, len(ids), p, root))
    check("non-member rejected",
          not verify_inclusion(hashlib.sha256(b"other").hexdigest(), 0, len(ids), p, root))
    print(f"  anchor root: {root}")

    print("ALL PASS" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--verify", type=Path, help="manifest file to verify")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())
    if a.verify:
        good, errs = verify(a.verify)
        print("VERIFIED" if good else "FAILED:\n  " + "\n  ".join(errs))
        sys.exit(0 if good else 1)
    ap.print_help()
