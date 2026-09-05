# fixtures/paper2 — frozen replies from the paper-2 cycles

**These files are RECEIVED data.** They are byte-for-byte copies of upstream artifacts,
pinned by `fixtures/paper2.SHA256`, and they are never edited, reformatted, re-indented,
or re-serialised. A JSON file that has been parsed and written back out is a different
file — key order, separators, float rendering and escaping all move — and the digest
that made it evidence no longer matches. Tools read them; nothing writes them.

## Source

    Repository   https://github.com/shamiksaharcciit-oss/provenance-canary.git
    Commit       370f5f34d0114e776ad36d70e216214f62f7cf88 (SSH-signed)
    Licence      Apache-2.0
    Paper        "When the System Changes Underneath You", doi:10.5281/zenodo.22017670

| fixture | upstream path |
|---|---|
| `telemetry_cycle1_baseline.json` | `canary/results/telemetry_cycle1_baseline.json` |
| `telemetry_cycle2_stability.json` | `canary/results/telemetry_cycle2_stability.json` |
| `telemetry_cycle3_model_swap.json` | `canary/results/telemetry_cycle3_model_swap.json` |
| `telemetry_cycle4_after_release.json` | `versioning/results/telemetry_cycle4_after_release.json` |
| `telemetry_cycle6_pipeline_swap.json` | `pipeline_swap/results/telemetry_cycle6_pipeline_swap.json` |

## What they contain

Each file is one cycle: 27–30 probes, each carrying three arms of frozen reply text.

| arm | corpus | a conforming system | failure named |
|---|---|---|---|
| `answer_bearing` | contains the answer | answers | wrong abstention |
| `same_doc` | answerless, decoy in the same document | refuses | unsupported answer |
| `cross_doc` | answerless, decoy in another document | refuses | unsupported answer |

440 frozen replies across these five cycles. They were produced by real calls to real
model endpoints in August 2026 and cost real money; they are reused here so that C2 is
offline, reproducible, and grounded in phenomena nobody had to manufacture.

## What each cycle is, precisely

| cycle | model served | what changed vs cycle 1 |
|---|---|---|
| `cycle1_baseline` | `claude-sonnet-5` | — the baseline |
| `cycle2_stability` | `claude-sonnet-5` | **nothing.** A deliberate same-config repeat |
| `cycle3_model_swap` | `claude-haiku-4-5-20251001` | the served model |
| `cycle4_after_release` | `claude-sonnet-5` | the corpus: documents edited, spans migrated |
| `cycle6_pipeline_swap` | `claude-sonnet-5` | the retrieval pipeline |

**Cycle 2 is the most valuable file here.** Same model, same pipeline, same corpus,
same probes — and the unsupported-answer count moved from 11/30 to 13/30. That swing is
benign nondeterminism, measured rather than assumed, and it is the calibration data for
the per-probe variance band. A change detector that cannot tell 2/30 of noise from
2/30 of signal will report a change every single run, and a monitor that cries wolf on
schedule is one nobody reads.

## The caveat that governs all of it

Quoting the ruling (Core → Canary Response 001 §7):

> the paper-2 probe set is a permanently retired generation: fixture, demo and worked
> example, never a live canary for any system whose training data or index may have
> seen it.

These probes are public. Any system trained or indexed after their publication may have
seen them, which makes them worthless as a live instrument and perfectly good as a
fixture. They are used here to test the engine, never to certify a system.

## What is real here, and what is not

Everything in this directory is **real recorded output**. The deterministic mock target
(`canary/target/mock.py`) replays these bytes for the changes they actually contain —
the model swap and the corpus release — and applies **declared synthetic
transformations** for the two changes no cycle recorded, prompt edit and format drift.
The mock labels every response with which of the two it is, and never presents a
synthetic reply as a recorded one.
