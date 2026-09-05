"""`python -m canary.viewer` — generate the onewatch page from a store.

Re-generating is the only way the page changes. There is no server, nothing polls, and
nothing on the page mutates anything: a file-watch or a re-run is the whole update model
(spec §3).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DEFAULT_STORE = REPO / "docs" / "evidence" / "c4-incident-of-record"
DEFAULT_OUT = REPO / "docs" / "launch" / "onewatch.html"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m canary.viewer",
        description="Generate the onewatch receipt page from a canary store.")
    parser.add_argument("--store", type=Path, default=DEFAULT_STORE,
                        help="the canary store to render (default: the C4 incident)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="HTML file to write")
    args = parser.parse_args(argv)

    if not args.store.is_dir():
        print(f"store not found: {args.store}", file=sys.stderr)
        return 2

    from canary.viewer.page import build_page
    html = build_page(args.store)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(html, encoding="utf-8")
    print(f"wrote {args.out} ({len(html)} bytes) from {args.store}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
