"""Collection rules for the published verification package.

Two checks do not run everywhere, for two different reasons, and both say so
rather than passing. The distinction matters and is the same one this project
makes everywhere else: a check that goes green having verified nothing reports a
verification that never happened.

The [NOT-RUN] label below is deliberate. It is the label the reference verifier
uses for a check it declines to make, and it means the same thing here.
"""
from __future__ import annotations

import sys

import pytest

#: Not run because THIS REPOSITORY does not carry the inputs. The private
#: correspondence the canary channel ran on is not published here.
NOT_RUN_HERE: dict[str, str] = {
    "test_every_archived_memo_still_verifies": (
        "archived memos are private correspondence and are not published in this "
        "repository; this check runs where the memos live"
    ),
}

#: Not run because THIS PLATFORM cannot reproduce the condition. These assert
#: behaviour at Windows' 260-character MAX_PATH boundary; POSIX has no such limit,
#: so the scenario cannot be constructed and the test says so itself rather than
#: reporting a pass. Skipped here for the same reason its own sanity assertion
#: fails: "this platform does not reproduce the condition and the test would pass
#: vacuously."
WINDOWS_ONLY: dict[str, str] = {
    "test_the_coverage_scan_finds_a_file_whose_path_is_too_long": (
        "constructs a path past Windows' 260-character MAX_PATH; POSIX has no such "
        "limit, so the condition cannot be reproduced on this platform"
    ),
}

_ON_WINDOWS = sys.platform == "win32"


def _skipped_now() -> dict[str, str]:
    out = dict(NOT_RUN_HERE)
    if not _ON_WINDOWS:
        out.update(WINDOWS_ONLY)
    return out


def pytest_collection_modifyitems(items):
    skipped = _skipped_now()
    for item in items:
        reason = skipped.get(item.name)
        if reason is not None:
            item.add_marker(pytest.mark.skip(reason=reason))


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Announce what did not run, at any verbosity, with the reason."""
    skipped = _skipped_now()
    if not skipped:
        return
    terminalreporter.write_sep("-", "checks not run here")
    for name, reason in skipped.items():
        terminalreporter.write_line(f"[NOT-RUN] {name}")
        terminalreporter.write_line(f"          {reason}")
    if not _ON_WINDOWS and WINDOWS_ONLY:
        terminalreporter.write_line(
            f"          (platform: {sys.platform}; the MAX_PATH checks run on Windows)"
        )
