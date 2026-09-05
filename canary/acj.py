"""The one place that knows where the vendored canonicaliser lives.

Every GENERATED structure in this engine is canonicalised by
`vendor/rederivable-manifest/canonical.py` — the programme's shared ACJ v2
implementation, disk-copied through the clean channel and digest-pinned. This module
is a thin import shim and nothing else.

WHY A SHIM RATHER THAN AN IMPORT
--------------------------------
`vendor/rederivable-manifest` is not an importable package name: the hyphen makes it
illegal as an identifier, and adding an `__init__.py` to make it one would be an edit
to a vendored tree, which is forbidden (a byte changed there is indistinguishable from
tampering). So exactly one module does the `sys.path` insertion, and the rest of the
engine imports from here. When the vendored copy is updated, one file changes.

THE TWO DISCIPLINES, AND WHICH ONE THIS IS
------------------------------------------
E10 has two halves and they are opposites:

  RECEIVED data  — model responses, inbound memos, vendored files — is frozen VERBATIM,
                   byte-for-byte as it arrived, and never canonicalised. Normalising it
                   destroys the evidence.
  GENERATED data — structures this engine builds: manifests, verdicts, instrument
                   declarations — is ACJ-canonicalised so that semantically equal
                   structures are byte-identical.

**This module is for the GENERATED half only.** Nothing that arrived from outside is
ever passed through `canonical_bytes`. Applying either discipline to the other's data
is a defect, not a style choice.
"""
from __future__ import annotations

import sys
from pathlib import Path

_VENDOR = Path(__file__).resolve().parent.parent / "vendor" / "rederivable-manifest"

if not (_VENDOR / "canonical.py").exists():          # pragma: no cover - install error
    raise ImportError(
        f"vendored canonicaliser not found at {_VENDOR}. The engine has no fallback "
        f"canonicaliser by design: a second implementation would be a second set of "
        f"bytes for the same structure, which is the defect ACJ exists to prevent.")

if str(_VENDOR) not in sys.path:
    sys.path.insert(0, str(_VENDOR))

from canonical import (  # noqa: E402
    canon_datetime,
    canon_decimal,
    canonical_bytes,
    digest_bytes,
    digest_file,
    digest_obj,
    inclusion_proof,
    merkle_root,
    verify_inclusion,
)

VENDOR_PATH = _VENDOR

__all__ = [
    "VENDOR_PATH",
    "canon_datetime",
    "canon_decimal",
    "canonical_bytes",
    "digest_bytes",
    "digest_file",
    "digest_obj",
    "inclusion_proof",
    "merkle_root",
    "verify_inclusion",
]
