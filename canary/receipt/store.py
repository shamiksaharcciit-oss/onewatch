"""On-disk evidence: what a third party actually receives.

A receipt that can only be re-derived by the process that produced it is not a receipt.
So everything a verifier needs lands on disk, in a layout with one rule: **RECEIVED bytes
are stored raw and content-addressed; GENERATED structures are stored as canonical bytes.**

    <store>/runs/<e_digest>/run.json            the sealed run, canonical bytes
    <store>/runs/<e_digest>/suite.json          the probe suite, canonical bytes
    <store>/runs/<e_digest>/bodies/<sha256>     one reply body, EXACTLY as received
    <store>/baselines/<baseline_id>.json        the declaration and its band
    <store>/receipts/<receipt_id>.json          the receipt envelope
    <store>/ledger.jsonl                        the hash chain, one row per line

Bodies have no file extension on purpose. `.json` or `.txt` would be a claim about content
that the canary is not entitled to make: a reply is a sequence of bytes an endpoint
returned, and it may not be valid UTF-8, let alone the format anyone expected. Naming it
by its digest and nothing else is the honest description.

Bodies are also deduplicated by digest, which is not a space optimisation — it is the
content-addressing being real. Two probes that returned identical bytes *are* the same
evidence, and storing them twice would imply a distinction the bytes do not support.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from canary.acj import canonical_bytes, digest_bytes
from canary.baseline.declare import Baseline
from canary.freezer.freeze import FrozenRun

#: Windows' classic path limit. A content-addressed store is unusually exposed to it:
#: `runs/<64 hex>/bodies/<64 hex>` alone is 140 characters before any root, so a store
#: inside a moderately deep directory crosses 260 without anyone doing anything odd.
#: Measured during C3: a store under a temp path failed at 268 characters, and the error
#: Windows raises is `FileNotFoundError` -- which sends a reader hunting for a missing
#: file that was never missing. See `_long_path`.
_MAX_PATH = 260


class StoreError(RuntimeError):
    """A store operation that cannot be completed honestly. Never silently repaired."""


def _long_path(path: Path) -> str | os.PathLike:
    r"""Return a form of `path` the OS will accept, even past MAX_PATH.

    On Windows, prefixing an absolute path with `\\?\` opts out of the 260-character
    limit. The prefix demands a fully-resolved, backslash-separated absolute path, so the
    path is normalised first. On every other platform this is the identity.

    Doing this rather than shortening the digests is deliberate: truncating a
    content address to fit a filesystem would trade the property the whole design rests
    on for a platform's convenience.
    """
    if os.name != "nt":
        return path
    resolved = os.path.abspath(str(path))
    if resolved.startswith("\\\\?\\"):
        return resolved
    if len(resolved) < _MAX_PATH - 12:      # headroom for a filename being appended
        return resolved
    if resolved.startswith("\\\\"):          # UNC share
        return "\\\\?\\UNC\\" + resolved[2:]
    return "\\\\?\\" + resolved


@dataclass(frozen=True, slots=True)
class Store:
    """A directory of evidence. Writes are append-only in intent: nothing is overwritten
    with different content, because content-addressed paths make that a contradiction."""

    root: Path

    # ------------------------------------------------------------------ paths

    def run_dir(self, e_digest: str) -> Path:
        return self.root / "runs" / e_digest

    def receipts_dir(self) -> Path:
        return self.root / "receipts"

    def ledger_path(self) -> Path:
        return self.root / "ledger.jsonl"

    # ------------------------------------------------------------------ writes

    def _write_bytes(self, path: Path, data: bytes) -> None:
        """Write, or confirm identical content already present. Never silently differ."""
        os.makedirs(_long_path(path.parent), exist_ok=True)
        target = _long_path(path)
        if os.path.exists(target):
            with open(target, "rb") as fh:
                existing = fh.read()
            if existing != data:
                raise StoreError(
                    f"{path} already exists with different content. A content-addressed "
                    f"path holding two different byte strings means the address is wrong, "
                    f"which is a defect to surface and never to overwrite.")
            return
        try:
            with open(target, "wb") as fh:
                fh.write(data)
        except OSError as e:
            # Windows reports a too-long path as ENOENT, which reads as "the file is
            # missing" and sends the reader looking for the wrong thing entirely.
            raise StoreError(
                f"cannot write {path} ({len(str(path))} characters): {e}. On Windows a "
                f"path over {_MAX_PATH} characters fails this way even though nothing is "
                f"missing; the store already opts out of that limit where it can, so a "
                f"failure here usually means a filesystem or permissions problem, or a "
                f"store root that is itself unreachable."
            ) from e

    def read_bytes(self, path: Path) -> bytes:
        with open(_long_path(path), "rb") as fh:
            return fh.read()

    def exists(self, path: Path) -> bool:
        return os.path.exists(_long_path(path))

    def put_run(self, run: FrozenRun) -> Path:
        """Persist a sealed run and every body it froze."""
        problems = run.verify_bodies()
        if problems:
            raise StoreError("refusing to store a run that does not verify:\n"
                             + "\n".join(problems))

        d = self.run_dir(run.e_digest)
        self._write_bytes(d / "run.json", canonical_bytes(run.as_canonical()))
        self._write_bytes(d / "suite.json", canonical_bytes(run.suite.as_canonical()))
        for (probe_id, arm), body in run.bodies.items():
            # RECEIVED: raw bytes, addressed by their own digest, no transformation.
            self._write_bytes(d / "bodies" / digest_bytes(body), body)
        return d

    def put_baseline(self, baseline: Baseline) -> Path:
        p = self.root / "baselines" / f"{baseline.baseline_id}.json"
        self._write_bytes(p, canonical_bytes(baseline.as_canonical()))
        return p

    def put_receipt(self, receipt: dict) -> Path:
        p = self.receipts_dir() / f"{receipt['receipt_id']}.json"
        self._write_bytes(p, canonical_bytes(receipt))
        return p

    # ------------------------------------------------------------------ reads

    def get_run_json(self, e_digest: str) -> dict:
        p = self.run_dir(e_digest) / "run.json"
        if not self.exists(p):
            raise StoreError(f"no stored run for e_digest {e_digest}")
        return json.loads(self.read_bytes(p).decode("utf-8"))

    def get_body(self, e_digest: str, body_digest: str) -> bytes:
        """Return a stored body, verifying its address on the way out.

        The check is here rather than only in the verifier because a store that hands
        back bytes which do not match the name they were filed under has already failed,
        and every caller would otherwise have to remember to re-check.
        """
        p = self.run_dir(e_digest) / "bodies" / body_digest
        if not self.exists(p):
            raise StoreError(f"body {body_digest} missing from run {e_digest}")
        data = self.read_bytes(p)
        got = digest_bytes(data)
        if got != body_digest:
            raise StoreError(
                f"body filed as {body_digest} hashes to {got}; the stored evidence has "
                f"been modified since it was written")
        return data

    def get_receipt(self, receipt_id: str) -> dict:
        p = self.receipts_dir() / f"{receipt_id}.json"
        if not self.exists(p):
            raise StoreError(f"no receipt {receipt_id}")
        return json.loads(self.read_bytes(p).decode("utf-8"))

    def receipt_ids(self) -> list[str]:
        d = self.receipts_dir()
        if not d.exists():
            return []
        return sorted(p.stem for p in d.glob("*.json"))
