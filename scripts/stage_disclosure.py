#!/usr/bin/env python3
"""Stage the gen-1-c4 disclosure package, and — only when told — throw the switch.

Core → Canary Response 011 §3 approved retiring and disclosing `gen-1-c4` so the incident
of record can be verified by a third party. Response 012 §4 set the timing: **the one-way
switch is thrown at the moment of disclosure and not before**, because retirement's only
purpose is to permit disclosure. Early retirement buys nothing and closes optionality — an
unretired generation is still an instrument; a retired one is not, permanently.

So this script has two modes, and the default is the safe one:

    python scripts/stage_disclosure.py            # stage + verify, gen-1-c4 stays ACTIVE
    python scripts/stage_disclosure.py --fire YYYY-MM-DD    # throw the switch, then stage

Everything that can be built before launch week is built by the default mode, so the
firing-sequence step is throwing a switch rather than building a machine.

THE FOUR CONDITIONS, EACH CHECKED HERE
--------------------------------------
1. **Retirement is a visible instrument change**, with date and reason, recorded in the
   instrument history — not an attribute quietly flipped. `--fire` writes that record and
   refuses to run twice.
2. **The disclosed text is pinned to its ACTIVE-era digests.** The package proves that the
   published `suite.json` hashes to the `generation_digest` that three already-anchored
   receipts cite. This is what makes disclosure evidence rather than assertion: it shows
   the published probes are *the same instrument*, not a cleaned-up cousin.
3. **Probes are disclosed; generators are not.** The seed and anything that would let a
   reader rebuild `gen-2-c4` or `gen-3-c4` stays secret. Checked before staging, and the
   check fails the run rather than warning.
4. **Timing is launch week.** Enforced by `--fire` being explicit, dated, and absent from
   every default path.

WHY CONDITION 2 IS THE INTERESTING ONE
--------------------------------------
Anyone can publish a file and call it the probe set. The claim worth making is that *this*
text is what those receipts were computed against — and that is checkable without trusting
us, because the digest was sealed into the receipts before the text was ever disclosed, and
those receipts are Merkle-anchored. The disclosure does not ask to be believed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from canary.receipt.store import _long_path  # noqa: E402

INCIDENT = REPO / "docs" / "evidence" / "c4-incident-of-record"
STAGING = REPO / "docs" / "launch" / "gen-1-c4-disclosure"
HISTORY = REPO / "docs" / "launch" / "instrument-history.md"
GENERATION_ID = "gen-1-c4"

#: The run whose `suite.json` is published. Any run of this generation carries the same
#: suite bytes; the swap run is named because it is the one the incident turns on.
SUITE_SOURCE_E = "c5d0ff3825a7f7340bcca8681ecf662dd7eebd8c32a33b37ed1c32977006f18d"

#: Condition 3, stated in the vocabulary of what is *actually secret*.
#:
#: The first version of this list forbade `gen-2-c4` and `gen-3-c4` as well — names
#: standing in as a proxy for "content from those generations". That proxy was wrong, and
#: Core → Canary Response 013 §3 ruled it so: **the secrecy this design protects is probe
#: text and the generator, never the fact of rotation.** A monitor whose subjects know
#: they are watched by undisclosed probes is stronger, not weaker — the announced-but-
#: unmarked patrol — and Response 010 had already set names-plus-digests as the ACTIVE
#: generations' public trace.
#:
#: The fix is to narrow the check rather than to whitelist around it. A marker list that
#: needs a per-file exemption is measuring the wrong thing, and an exemption is how a
#: check quietly stops applying to the file that most needed it.
SECRET_MARKERS = (
    "CANARY_GEN_SEED",            # the seed's variable name: the seed is the secret
    "ANTHROPIC_API_KEY",          # the credential's variable name
    "_rng_stream",                # the deterministic stream a generation is built from
    "build_generation",           # …and the three entry points that drive it
    "build_hard_generation",
    "build_multihop_generation",
)

#: Names that MAY appear in a published package, listed explicitly rather than merely
#: omitted from `SECRET_MARKERS`.
#:
#: Explicitly, because "allowed by omission" and "allowed on purpose" look identical in a
#: source file and are very different claims. Anyone adding a generation later must decide
#: which list it belongs in, and the decision is recorded here rather than inferred from
#: a list it happens not to be on.
#:
#: A generation *name* is not a probe set. Publishing that `gen-2-c4` exists and is ACTIVE
#: discloses the shape of the programme, which is the part we want disclosed; it discloses
#: nothing about what the probes ask.
ALLOWED_GENERATION_NAMES = ("gen-1-c4", "gen-2-c4", "gen-3-c4")


def _read(path: Path) -> bytes:
    with open(_long_path(path), "rb") as fh:
        return fh.read()


def _display(path: Path) -> str:
    """Repo-relative when it can be, absolute otherwise -- never a crash.

    These paths are monkeypatched to a temp directory under test, and a progress line
    that raises because it could not prettify itself would fail the run for cosmetics.
    """
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def cited_generation_digest() -> tuple[str, list[str]]:
    """The `generation_digest` the receipts cite, and the receipts that cite it.

    Read from the receipts rather than from the suite: the whole point of condition 2 is
    that the digest was committed to *before* disclosure, so it is the receipts that are
    authoritative and the published text that must match them.
    """
    digests: dict[str, list[str]] = {}
    for receipt_path in sorted((INCIDENT / "receipts").iterdir()):
        receipt = json.loads(_read(receipt_path))
        generation = receipt["target"]["generation"]
        if generation["generation_id"] != GENERATION_ID:
            continue
        digests.setdefault(generation["generation_digest"], []).append(receipt_path.stem)
    if len(digests) != 1:
        raise SystemExit(
            f"expected exactly one generation_digest across the receipts, found "
            f"{len(digests)}: {sorted(digests)}. Disclosure cannot proceed against an "
            f"ambiguous instrument identity.")
    (digest, receipts), = digests.items()
    return digest, receipts


def check_no_generator_leak(paths: list[Path]) -> list[str]:
    """Condition 3, enforced. Returns the problems; empty means the package is clean."""
    problems = []
    for path in paths:
        try:
            text = _read(path).decode("utf-8")
        except UnicodeDecodeError:
            continue
        for marker in SECRET_MARKERS:
            if marker in text:
                problems.append(f"{_display(path)}: contains {marker!r}")
    return problems


def _normalise(text: str) -> str:
    """Line endings folded to LF, for COMPARISON only.

    Defect F9, self-caught by the sabotage test Response 015 §6 asked for: the first
    version compared fragments carrying LF against file text carrying CRLF, because
    `Path.write_text` translates newlines on Windows. A multi-line probe rendered onto a
    page therefore went **unreported** -- a leak check failing open, which is the only
    direction this programme genuinely fears.

    Normalising here does not violate E10. E10 governs *evidence*: bytes that are hashed,
    compared for identity, or re-derived from. This is a **search for a substring**, and a
    leak that arrived with different line endings is still a leak. The distinction is that
    nothing here produces a digest or a verdict about integrity -- it decides only whether
    to refuse a package.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _fragments(suite: dict, line_min: int = 30, window: int = 60,
               stride: int = 30) -> set[str]:
    """What to search for: every substantial LINE, plus sliding windows over long values.

    Two failures shaped this, both self-caught by sabotage tests rather than by reading the
    code (F9).

    **Deduplicated prefixes collapse.** The first version took `value[:120]` into a set,
    which over a real generation produced *one* fragment from thirty probes: every probe
    shares an instruction preamble, so the set reduced to the text the probes have in
    common. It searched for the least identifying thing available.

    **Fixed windows miss short distinctive parts.** Sliding 60-character windows over the
    whole value never fit inside a 48-character question line, so a leak of exactly the
    part that identifies a probe -- what it asks -- went uncaught while the preamble was
    covered twice.

    Probe text is written in lines, and a line is the unit a leak actually travels in: a
    quoted question, a pasted corpus sentence. So each substantial line becomes a fragment,
    and long values additionally get overlapping windows so a partial quotation spanning a
    line break is still caught. `line_min` is high enough that a match is not coincidence.
    """
    out: set[str] = set()
    for probe in suite.get("probes", []):
        for value in probe.values():
            if not isinstance(value, str):
                continue
            text = _normalise(value)
            for line in text.splitlines():
                line = line.strip()
                if len(line) >= line_min:
                    out.add(line)
            if len(text) >= window:
                for begin in range(0, len(text) - window + 1, stride):
                    out.add(text[begin:begin + window])
                out.add(text[-window:])
    return out


def check_probe_text_confined(staging: Path, suite_name: str = "suite.json") -> list[str]:
    """The positive half of condition 3: probe text lives in the disclosed file, or nowhere.

    `SECRET_MARKERS` is a list of things we thought to name. This check does not depend on
    having thought of anything: it takes the probe text actually present in the published
    suite and requires it to appear in no other staged file. It catches the accident a
    marker list cannot -- a README quoting a probe to illustrate a point, a summary pasting
    a corpus document, a debug dump nobody re-read before staging.

    Scoped to the *disclosed* generation deliberately. Text from an ACTIVE generation
    cannot be searched for here because we do not hold it: those calibration runs were
    never persisted (defect F3). What this guarantees is narrower and true -- the package
    discloses probe text in exactly one file, the one whose digest the receipts pin. A
    future disclosure of gen-2 or gen-3 runs the same check against its own suite.
    """
    suite_path = staging / suite_name
    if not suite_path.is_file():
        return [f"no {suite_name} staged; probe-text confinement cannot be checked"]

    suite = json.loads(_read(suite_path))
    fragments = _fragments(suite)
    if not fragments:
        return [f"{suite_name} yielded no probe text to search for; refusing to report "
                f"confinement on the basis of an empty search"]

    problems = []
    for path in staging.rglob("*"):
        if not path.is_file() or path.name == suite_name:
            continue
        try:
            text = _normalise(_read(path).decode("utf-8"))
        except UnicodeDecodeError:
            continue
        if any(fragment in text for fragment in fragments):
            problems.append(f"{_display(path)}: carries probe text that belongs only "
                            f"in {suite_name}")
    return problems


def active_generation_digests() -> dict[str, str]:
    """The ACTIVE generations' digests, read from the calibration logs that recorded them.

    Generated, never transcribed (X-11): these are parsed out of
    `docs/evidence/c4_calibration_gen*.log`, the frozen output of the runs that built them.

    **They are truncated to 16 hex characters, and that is a real limitation, not a
    stylistic choice.** The full digests are not recoverable from anything in this
    repository, because `scripts/calibrate_c4.py` froze its runs in memory and exited
    without persisting them — defect F3, self-reported in Note 007. Rebuilding a full
    digest requires `CANARY_GEN_SEED`, which lives outside the repository by design.

    A seed-holder can complete this record offline, at zero cost and with no live call:

        python -c "from canary.suite.generation import generation_digest;
                   print(generation_digest(SEED, 'gen-2-c4', '2026-08-22'))"

    Until then the record publishes what was actually measured and says what it is. A
    16-hex prefix is a weaker commitment than a full digest; it is not no commitment, and
    it is not dressed up as more than it is.
    """
    digests: dict[str, str] = {}
    for log in sorted((REPO / "docs" / "evidence").glob("c4_calibration_gen*.log")):
        for line in log.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "generation" and parts[2].startswith("digest="):
                digests[parts[1]] = parts[2].split("=", 1)[1]
    return digests


def fire(disclosed_at: str) -> None:
    """Throw the one-way switch: record the retirement as a visible instrument change.

    There is deliberately no `unretire`, here or in `canary.suite.generation`. This
    function refuses to run a second time rather than quietly re-dating a retirement,
    because a retirement with two dates is a retirement nobody can cite.
    """
    from canary.suite.generation import Status

    if HISTORY.exists() and GENERATION_ID in HISTORY.read_text(encoding="utf-8"):
        raise SystemExit(
            f"{GENERATION_ID} already has a retirement record in {HISTORY.name}. "
            f"Retirement is one-way and is recorded once; refusing to re-date it.")

    digest, receipts = cited_generation_digest()
    active = {gid: d for gid, d in active_generation_digests().items()
              if gid != GENERATION_ID}
    active_table = "\n".join(
        f"- **`{gid}`** — ACTIVE, digest `{d}…` (truncated; see below)"
        for gid, d in sorted(active.items())) or "- (none recorded)"
    truncation_note = (
        "*The digests above are 16-hex prefixes, which is what the calibration runs "
        "recorded. The full values require the seed, which is held outside this "
        "repository; a seed-holder can complete this record offline at any time. The "
        "prefix is published rather than nothing, and labelled rather than padded.*")
    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    record = f"""# Instrument history

A generation's lifecycle is part of the instrument, so every change to it is recorded
here in the open. Rotation and retirement are **visible instrument changes**, never
silent attribute flips — that is the whole of the secrecy/verifiability resolution:
probes stay secret while ACTIVE, and disclosure happens *because* retirement happened,
on a date anyone can cite.

## {GENERATION_ID} — RETIRED {disclosed_at}

- **Status:** `{Status.ACTIVE.value}` → `{Status.RETIRED.value}`
- **Date:** {disclosed_at}
- **Reason:** Retired to permit disclosure. The generation faced a live system in the C4
  phase of 2026-08-22 and its purpose is complete; publishing the probes lets a third
  party verify the incident of record without trusting us. Approved by Core → Canary
  Response 011 §3; timing set by Response 012 §4.
- **Generation digest:** `{digest}`
- **Cited by receipts:** {", ".join(f"`{r[:16]}…`" for r in receipts)}
- **Consequence:** `{GENERATION_ID}` may never probe a live system again.
  `assert_may_probe_live()` enforces this; there is no `unretire`.

## Generations still in service

`gen-2-c4` and `gen-3-c4` remain **ACTIVE**. Their probe text is not published and neither
is the seed that generated them; what is published is their identity and their digest,
which is the ACTIVE generations' public trace by design.

{active_table}

Naming them is deliberate. The secrecy this design protects is **probe text and the
generator, never the fact of rotation** — a monitor whose subjects know they are watched
by undisclosed probes is stronger than one that hides the patrol entirely.

**Publishing these digests is a commitment.** When `gen-2-c4` or `gen-3-c4` is eventually
retired and disclosed, its published text will have to hash to the digest recorded here —
a digest that has been public since this date, fixed long before the text it describes was
ever shown. That is the same proof the disclosure above rests on, with a longer fuse: the
check is handed to the reader before the thing being checked exists in public.

{truncation_note}
"""
    HISTORY.write_text(record, encoding="utf-8")
    print(f"FIRED        retirement recorded in {_display(HISTORY)}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fire", metavar="YYYY-MM-DD",
                    help="throw the one-way retirement switch, dated. Launch week only.")
    args = ap.parse_args(argv)

    if args.fire:
        fire(args.fire)

    retired = HISTORY.exists() and GENERATION_ID in HISTORY.read_text(encoding="utf-8")

    # --- condition 2: the published text, pinned to the digest the receipts already cite
    digest, receipts = cited_generation_digest()
    suite_bytes = _read(INCIDENT / "runs" / SUITE_SOURCE_E / "suite.json")
    computed = hashlib.sha256(suite_bytes).hexdigest()

    print(f"generation   {GENERATION_ID}")
    print(f"status       {'RETIRED -- disclosure permitted' if retired else 'ACTIVE -- staged, NOT disclosed'}")
    print(f"\ncondition 2  the disclosed text pinned to its ACTIVE-era digest")
    print(f"  cited by   {len(receipts)} anchored receipt(s): "
          f"{', '.join(r[:16] for r in receipts)}")
    print(f"  they cite  {digest}")
    print(f"  published  sha256(suite.json) = {computed}")
    if computed != digest:
        print("\n  MISMATCH -- the text to be published is NOT the instrument the "
              "receipts were computed against. Refusing to stage.", file=sys.stderr)
        return 2
    print(f"  MATCH      the published probes are the instrument the receipts cite")

    # --- stage
    STAGING.mkdir(parents=True, exist_ok=True)
    staged = STAGING / "suite.json"
    with open(_long_path(staged), "wb") as fh:
        fh.write(suite_bytes)
    for name in ("c4-incident-of-record.SHA256",):
        shutil.copy2(INCIDENT / name, STAGING / name)

    (STAGING / "README.md").write_text(_package_readme(digest, receipts, retired),
                                       encoding="utf-8")

    # --- condition 3: probes disclosed, generators never
    files = [p for p in STAGING.rglob("*") if p.is_file()]
    problems = (check_no_generator_leak(files)
                + check_probe_text_confined(STAGING))
    print(f"\ncondition 3  probes disclosed, generators never")
    print(f"  scanned    {len(files)} staged file(s) for {len(SECRET_MARKERS)} secret marker(s)")
    print(f"  names      {', '.join(ALLOWED_GENERATION_NAMES)} may appear -- a "
          f"generation name is not a probe set")
    print("  confined   probe text appears in suite.json and nowhere else")
    if problems:
        print("  LEAK       staging refused:", file=sys.stderr)
        for p in problems:
            print(f"    {p}", file=sys.stderr)
        return 2
    print(f"  CLEAN      no seed, no key, no generator; probe text confined")

    print(f"\nstaged in    {_display(STAGING)}")
    if retired:
        print("READY        retired and disclosable.")
    else:
        print("STAGED       gen-1-c4 is still ACTIVE and this package is NOT to be "
              "published.\n             Launch week: rerun with --fire YYYY-MM-DD.")
    return 0


def _package_readme(digest: str, receipts: list[str], retired: bool) -> str:
    status = ("`gen-1-c4` was retired to permit this disclosure; see "
              "`docs/launch/instrument-history.md` for the dated record."
              if retired else
              "**NOT FOR PUBLICATION.** `gen-1-c4` is still ACTIVE. This package is "
              "staged ahead of launch week and the retirement switch has not been "
              "thrown.")
    return f"""# gen-1-c4 — disclosed probe set

{status}

## What this is

`suite.json` is the probe set used against a live endpoint in the C4 phase of
2026-08-22 — the run that produced [the incident of record](../../evidence/c4-incident-of-record/):
the vendor served a different model, and the validated behaviour did not move.

## Why you can believe it is the same instrument

You do not have to believe it. Check it:

```sh
sha256sum suite.json
# {digest}
```

That digest is `generation_digest` inside {len(receipts)} receipts that were sealed,
hash-chained and Merkle-anchored **before these probes were ever published**. A
cleaned-up or reconstructed probe set would not reproduce it. The receipts commit to the
instrument; this file merely reveals it.

Re-derive the receipts themselves with `python scripts/rederive_incident.py` — it reads
frozen bytes and never queries a model.

## What is not here, and why

The **seed** that generated this set is not published, and neither is anything that would
let you rebuild the generations still in service. Probes are disclosed at retirement;
generators never are. That is the resolution the design rests on: the seed is the secret,
the digest is the public commitment, and rotation is a visible instrument change rather
than silent drift.

## The honest limit

This probe set is **retired**: it may never probe a live system again, and
`assert_may_probe_live()` enforces that. A system that has seen the probes can pass them
without behaving well, so a passing result from a published set proves nothing. That is
why disclosure follows retirement instead of preceding it.
"""


if __name__ == "__main__":
    raise SystemExit(main())
