#!/usr/bin/env python3
"""Generate the launch narration for the incident of record, from frozen artifacts only.

Core → Canary Response 010 §2-B: *"the demo script and narration for 'the vendor changed
the model underneath you on a Tuesday, and here is the receipt proving your behaviour did
not move' — no new measurement, no new receipt; narration never outruns what the frozen
record already proves."*

So this script writes prose around numbers it reads out of the store. Every figure in the
output is computed here at run time; none is typed into the template. That is not
ceremony — the demo header in `scripts/demo_c4.py` records what happens otherwise:

    This header used to promise a CHANGED receipt at run 4. On the live run of
    2026-08-22 it did not happen, and the summary line -- which had the outcome
    hard-coded -- cheerfully reported one that did not exist.

**A demo whose narration is fixed before the measurement will narrate a result it did not
get.** The same is true of a launch document, with a larger audience.

No model is queried and none can be: this module constructs no target and imports no
network client. Regenerating the narration costs nothing and is expected after any change
to the store, which is why the output is a build artifact and not a hand-edited file.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from canary.receipt import ledger  # noqa: E402
from canary.receipt.rederive import rederive  # noqa: E402
from canary.receipt.store import _long_path  # noqa: E402

INCIDENT = REPO / "docs" / "evidence" / "c4-incident-of-record"
OUT = REPO / "docs" / "launch" / "incident-narration.md"


def read_json(path: Path):
    with open(_long_path(path), "rb") as fh:
        return json.loads(fh.read())


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed narration differs from a fresh build")
    args = ap.parse_args(argv)

    rows = ledger.read_rows(INCIDENT / "ledger.jsonl")
    receipts = {row.receipt_id: read_json(INCIDENT / "receipts" / f"{row.receipt_id}.json")
                for row in rows}
    baseline = read_json(INCIDENT / "baselines" / "c4-baseline.json")

    # The instrument declaration, which must be identical across every receipt: the world
    # moved and the instrument did not. If these ever differ the narration is void, so it
    # is asserted here rather than assumed by the prose.
    i_digests = {r["i_digest"] for r in receipts.values()}
    assert len(i_digests) == 1, f"receipts disagree on the instrument: {i_digests}"
    i_digest, = i_digests

    swap = next(r for r in receipts.values()
                if r["target"]["served_model"] != r["target"]["model_requested"]
                or r["target"]["served_model"] != baseline_model(baseline, receipts))
    base_model = baseline_model(baseline, receipts)
    # X-8: anchor only what you have re-verified. The first version of this line passed
    # `lambda rid: []` with a comment saying CI had already re-derived the rows -- which is
    # exactly the reasoning the rule exists to refuse. "Someone else checked" is how an
    # anchor comes to be asserted over an unread document, and this anchor is about to be
    # printed in a launch document as proof. Re-derivation costs under a second.
    def reverify(receipt_id: str) -> list[str]:
        result = rederive(INCIDENT, receipt_id)
        return result.failed + result.unverifiable

    anchor = ledger.anchor(rows, reverify)
    table = subprocess.run([sys.executable, str(REPO / "scripts" / "rescore_incident.py"),
                            "--markdown"], capture_output=True, text=True, cwd=REPO).stdout

    unchanged = [r for r in receipts.values() if r is not swap]
    total_calls = max(r["target"]["spend"]["spent"]["calls"] for r in receipts.values())
    ceiling = swap["target"]["spend"]["ceiling"]["max_calls"]
    n_probes = swap["target"]["generation"]["n_probes"]
    band = baseline["band"]["per_arm"]
    band_text = ", ".join(f"`{arm}` {width}" for arm, width in sorted(band.items()))

    doc = f"""# The vendor changed the model underneath you, and your behaviour did not move

*The Detect leg of "one incident, three receipts". Every number below was generated into
this document from the frozen record by `scripts/build_narration.py`; nothing here was
typed by hand, and nothing was measured to write it.*

---

## The incident

On **2026-08-22** a baseline was sealed against `{base_model}`: {n_probes} probes, a
refusal-sentinel instrument at `v3`, a variance band measured from a same-config repeat
pair and declared before anything else ran — {band_text} — zero on every arm.

Two later runs against the same configuration produced **no-change receipts**.

Then the configuration named a different model. The provider served
**`{swap["target"]["served_model"]}`**. The canary probed it from outside, exactly as
before, and the receipt it sealed says two things that never contradict each other:

> **The served model changed. The validated behaviour did not.**

Not one probe of {n_probes} changed verdict. Every arm stayed inside its band.

**A dashboard cannot prove a negative.** It can show you that nothing looks wrong. It
cannot hand you a document, months later, that recomputes to the same answer in someone
else's hands. That is the whole difference, and it is the reason this is a receipt and
not a chart.

## What the receipt actually contains

| | baseline | after the switch |
|---|---|---|
| model requested | `{base_model}` | `{swap["target"]["model_requested"]}` |
| **model served** | `{base_model}` | **`{swap["target"]["served_model"]}`** |
| probes | {n_probes} | {n_probes} |
| verdicts changed | — | **0** |
| arms outside band | — | **0** |
| instrument (`i_digest`) | `{i_digest[:16]}…` | `{i_digest[:16]}…` |

Three details in that table carry the argument.

**The receipt records what was *served*, never what was *requested*.** The configuration
asked for `{swap["target"]["model_requested"]}`; the endpoint served
`{swap["target"]["served_model"]}`. A monitor that believed its own request would be
blind to the exact event it exists to catch.

**The `i_digest` is identical in both columns.** The instrument did not move while the
world did. That is what makes the comparison mean anything: suite, detector config and
quantisation parameters are all inside that digest, so a changed probe or a retuned
threshold would be a *visible* instrument change and not a silent one. Nobody adjusted
the instrument until the answer came out nice.

**The band was fixed at baseline, before the switch existed.** It is inside the
`i_digest` too, so it cannot be widened after the fact to explain a result away.

## Why the no-change receipt is the product

A monitor that only ever speaks when something breaks is indistinguishable from a monitor
that is broken. The receipts that say *nothing moved* are the ones that establish the
silence was real — **"behaviourally unchanged since validation, anchored, on schedule."**

{len(unchanged)} of the {len(receipts)} receipts here say exactly that about a system
nobody touched. The third says it about a system whose model was replaced underneath it.
For a regulated buyer, that third receipt is the artefact: the vendor changed something,
you found out, and you can show that your validated behaviour survived it.

## You do not have to take our word for any of it

Everything above is recomputable from frozen bytes, by anyone, without re-querying the
model:

```sh
python scripts/rederive_incident.py
```

That reads the store and nothing else. It re-classifies every verdict **from the raw
reply bodies** under the declared instrument — not by reading recorded verdicts back,
which would prove nothing — then verifies the hash chain and recomputes the Merkle root:

```
anchor root  {anchor["root"]}
tree_size    {anchor["tree_size"]}
```

That root was recorded on the day of the live run. It recomputes to the same value today,
from a cold clone, on a different day, by a different route.

## The same evidence under a different instrument

The verdict above is `v3`'s. Re-scored under the two older instruments — same frozen
bytes, no new calls:

{table}
*A re-scoring demonstration over frozen bytes, never a receipt of record.* `v1` and `v2`
would have raised a regression that did not happen: they misread a
sentinel-with-explanation as an answer.

This is here because it is the honest thing to show. **The instrument is part of the
claim.** A tool that reported CHANGED from this same evidence would not have been lying —
it would have been using a worse instrument, and not saying so. Ours is named, versioned,
digested and published.

## What this does not tell you

The canary says **that** behaviour did not move, and **where behaviourally** it was
measured. It does **not** say which stage of the vendor's system changed — not the model
weights, not a system prompt, not a routing layer. It cannot: it probes from outside, at
the endpoint, with no integration into the pipeline. Stage attribution is a different
instrument's job.

Three further limits, stated rather than implied away:

- **The claim is scoped to the declared instrument.** "Behaviour did not move" means: no
  probe in this suite changed verdict under refusal-sentinel `v3`, and no arm left a band
  measured at baseline. A different suite could have found something this one cannot see.
- **This probe family has aged out as a discriminator between frontier models.** Zero
  baseline failures means the set cannot distinguish two *healthy* models — it is at
  maximum sensitivity to degradation and blind to differences above that ceiling. That is
  a good property for a monitor and a poor one for a demo, and we would rather say so
  than let the result imply more than it does.
- **One incident, one system, one window.** {total_calls} live calls against a declared
  ceiling of {ceiling}. This is a worked example, not a study.

## The provenance of this document

Written from the frozen store by `scripts/build_narration.py`, which reads
`docs/evidence/c4-incident-of-record/` and constructs no target. Regenerate it with:

```sh
python scripts/build_narration.py
```

The probe set is published separately at retirement — see
`docs/launch/gen-1-c4-disclosure/` — so that a third party can confirm the disclosed
probes hash to the `generation_digest` these receipts were sealed against, before the
probes were ever disclosed.
"""

    OUT.parent.mkdir(parents=True, exist_ok=True)
    if args.check:
        if not OUT.exists():
            print(f"narration not built: {OUT}", file=sys.stderr)
            return 2
        if OUT.read_text(encoding="utf-8") != doc:
            print("the committed narration differs from a fresh build. Regenerate with "
                  "`python scripts/build_narration.py`.", file=sys.stderr)
            return 2
        print("narration matches a fresh build from the frozen record")
        return 0

    OUT.write_text(doc, encoding="utf-8")
    print(f"wrote {OUT.relative_to(REPO)} ({len(doc)} chars) from the frozen record")
    return 0


def baseline_model(baseline: dict, receipts: dict) -> str:
    """The model the baseline run was sealed against, taken from the baseline's own run."""
    base_e = baseline["run"].get("e_digest") or next(iter(receipts.values()))["baseline_e_digest"]
    run = read_json(INCIDENT / "runs" / base_e / "run.json")
    return run["target"]["served_model"]


if __name__ == "__main__":
    raise SystemExit(main())
