# onewatch

**Change evidence for LLM/RAG systems.**

*Repository and tool: `onewatch`. The Python package inside is `canary`, and one probe
run is a canary run.*

A canary run is not a score on a dashboard. It is a frozen, content-addressed,
recomputable record that behaviour changed: what was probed, what came back, what the
instrument was — verifiable by a third party without re-querying the model.

The word for what this emits is a **receipt**.

> **Status: C4 complete.** The run loop has been exercised end to end against live
> endpoints. A baseline was sealed against `claude-sonnet-5`, the provider was switched to
> `claude-haiku-4-5-20251001`, and the receipts record both facts: **the served model
> changed, and its validated behaviour did not.** 210 API calls against a declared ceiling
> of 500. See [What works today](#what-works-today), the only section making claims about
> the present.

---

## The distinction this tool is built on

Observability and eval tools *observe*: they show you traces, scores and trends, and
you decide whether to believe them. This tool *proves*: it emits an artifact a third
party can recompute without access to your model, your pipeline, or your logs.

The difference shows up on the day it matters. A dashboard says "quality dropped on
Tuesday" and the record of that claim is the dashboard itself — re-render it after the
index changed and the number moves. A receipt says "these exact probes, frozen
byte-for-byte, produced these exact responses under this exact instrument, and here is
the hash chain and the Merkle anchor that fix it in time." One is a reading. The other
survives the argument about the reading.

## What a receipt fixes in place

- **The probes** — a frozen, versioned suite. The suite *is* the instrument: suite,
  detector config and quantisation parameters together form an `i_digest`. Changing a
  probe is a visible instrument change, never silent drift.
- **The responses** — frozen verbatim, byte-for-byte as received, never normalised.
- **The comparison** — a pure, float-free re-derivation against a declared baseline.
  Re-derivation replays the comparison; it never re-queries the model.
- **The instrument** — recorded, including the served model's identity, so a magnitude
  can never travel without the instrument that produced it.

A **no-change receipt** is a product in itself: *behaviourally unchanged since
validation, anchored, on schedule.* It takes the identical path — same envelope, same
chain, same anchor — because "nothing moved" is a claim that needs proving too.

**Two questions, two answers, never reconciled.** The seal answers *did anything change*
(the bytes, content-addressed). The verdicts answer *did behaviour change* (counts under
a named instrument). A receipt carries both and never collapses them into one number,
because they genuinely disagree: a prompt edit that makes a model explain its abstentions
changes every byte of every refusal and moves not one verdict. "Unchanged" would hide
that the output is visibly different; "changed" would imply a regression that did not
happen. Collapsing them into one number is what a dashboard does.

## Honest scope

**It says *that* behaviour changed, and *where behaviourally*. It never says *which
stage* caused it.** The canary probes an endpoint from outside; it has no view into
retrieval, ranking, prompt assembly or generation as separate stages. Stage attribution
is a different instrument's job. This is a design boundary, not a gap awaiting a
release — a tool that inferred stage from endpoint behaviour would be guessing, and a
guess in a receipt is worse than no receipt.

**A baseline is declared, never learned.** It is a specific, content-addressed run —
"the validated system as of date X" — and never a rolling average. Rebaselining is an
audited event that keeps the chain. A monitor that silently accepts change as the new
normal is a monitor that forgets, and forgetting is the failure this category exists to
prevent.

**Magnitudes are instrument-relative and never travel alone.** A detection claim is
citable only with its instrument named. This is not a stylistic preference: the paper-2
record contains a case where the same frozen replies read as three different
magnitudes of change under three different instruments. Any number this tool reports
carries the `i_digest` that produced it.

**Benign nondeterminism is banded at baseline, not tuned afterwards.** The per-probe
variance band is measured when the baseline is sealed and declared in config, which
puts it inside the `i_digest`. It cannot be widened after seeing a result you dislike
without that being a visible instrument change.

**The published paper-2 probe set is not a live instrument.** Quoting the ruling that
governs its use:

> the paper-2 probe set is a permanently retired generation: fixture, demo and worked
> example, never a live canary for any system whose training data or index may have
> seen it.

**Every published paper-2 number is a v1 number.** The refusal-sentinel instrument ships
in three versions. **v3 is this implementation's default**, because it is the only one
that reads the declared abstention form as declared. But every figure in the paper, and
every count in the frozen telemetry under `fixtures/`, was produced by **v1** — and v1
misclassifies the sentinel-with-explanation style that at least one major model actually
uses. So the paper's numbers and this tool's default do not agree, and they are not
supposed to: they are different instruments.

v1 remains in the tree, unmodified and selectable, as the classifier of record. **A later
instrument never retroactively restates an earlier result.** If you want the paper's
numbers, ask for v1 explicitly and you will get them to the unit; the test suite asserts
exactly that. If you want to know what the system is doing, use the default.

How far apart they are is not a rounding matter. On the recorded provider swap in
`fixtures/`, v1 reads *unsupported answers went 4 → 26* and v3 reads *unsupported answers
fell and the model started over-refusing*: **the same frozen replies, opposite
directions.** Not even the sign of a change survives an instrument swap. The instrument is
not a precision qualifier on a finding — it is part of what the finding is.

**It is not a security control, a jailbreak detector, or a correctness oracle.** It
detects *change against a baseline you declared*. If the baseline was already wrong,
every receipt faithfully records that it stayed wrong.

## What works today

Measured, not asserted. Everything below is produced by the command shown.

| Component | State |
|---|---|
| Probe suite (`canary/suite/`) | **Works.** Frozen, content-addressed; every field moves the digest. |
| Refusal-sentinel instrument, v1/v2/v3 | **Works.** Reproduces upstream's published counts to the unit. |
| Target interface + deterministic mock (`canary/target/`) | **Works.** Four declared injectable changes; two replay real recorded cycles. |
| Freezer (`canary/freezer/`) | **Works.** Bodies digested as received; runs seal as `E_t`; the seal verifies itself. |
| E006 quantisation boundary (`canary/quantise.py`) | **Works**, and **unused by C2's family** — its measurements are integer counts. First real caller is C3. |
| Memo protocol verifier (`scripts/verify_memo.py`) | **Works.** Three outcomes held apart; both failure directions tested. |
| Byte-exactness discipline (E10, three layers) | **Works.** `.gitattributes`, formatter exclusions, digest tests — all three mutation-tested. |
| Vendored `rederivable-manifest` v3 | **Verified**, digest-pinned, self-test green. |
| CI (py3.12 / py3.13, offline) | **Configured**, not yet observed on a runner — this repository has no remote. |
| Baseline manager (`canary/baseline/`) | **Works.** Declared, chained, band bound to `(family, instrument version)`. |
| Change detector (`canary/detector/`) | **Works.** Per-probe, float-free; three outcomes including `INCOMPARABLE`. |
| Receipt emitter (`canary/receipt/`) | **Works.** Envelope, content-addressed store, hash-chained ledger, RFC 6962 anchor under X-8. |
| Second-route re-derivation | **Works.** Reads a directory and a receipt id; recomputes every verdict from the raw bytes. |
| Probe generations + rotation (`canary/suite/generation.py`) | **Works.** Deterministic from a secret seed; retirement is one-way and enforced. |
| Call ceiling (`canary/spend.py`) | **Works.** Declared, enforced before each call, reported in every receipt. |
| Live endpoint adapter (`canary/target/live.py`) | **Run.** 210 calls against `claude-sonnet-5` and `claude-haiku-4-5-20251001`, ceiling 500. |
| Demo script (`scripts/demo_c4.py`) | **Run live.** Baseline, two repeats, a provider swap; all receipts re-derived and anchored. |
| Probe-family headroom | **Saturated.** Three generations, three shapes, 0/30 baseline failures each. See below. |

### Time to first receipt

The make-or-break metric, measured end to end on the mock: **baseline sealed on run one,
recomputable change verdict and a receipt on disk on run two.**

| stage | median | min | max |
|---|---|---|---|
| baseline declared and sealed | 345 ms | 244 ms | 743 ms |
| run 2 → receipt on disk | 248 ms | 167 ms | 668 ms |
| **time to first receipt** | **559 ms** | 419 ms | 1411 ms |
| second-route re-derivation | 622 ms | 361 ms | 943 ms |

90 probes, cold store, n=5, Python 3.12.10, on an otherwise idle machine.
**Minutes-not-days by three orders of magnitude**, and self-serve: no pipeline
integration, no vendor cooperation, and nothing re-queried at verify time.

The spread is filesystem, not engine — a content-addressed store writes one file per reply
body. The engine alone, no disk, runs in **50–67 ms**. These figures move a great deal with
host load: measured while a test suite ran in the background, the same code took 0.5–9 s.
Any timing here is worth exactly as much as the state of the machine it was taken on, which
is why the measurement conditions are stated rather than assumed.

```sh
python -m pytest                 # the whole suite; the gate, verbatim
python scripts/verify_memo.py docs/from_core/*.md docs/to_core/*.md
cd vendor/rederivable-manifest && python validate.py --selftest
```

Requires Python 3.12+. No runtime dependencies; `pytest` is the only dev dependency.

## Repository layout

```
canary/            the engine
  acj.py             the one place that knows where the vendored canonicaliser lives
  quantise.py        E006: the single measurement boundary
  suite/             the frozen, versioned probe set -- the instrument itself
  target/            the probed system: interface, and the deterministic mock
  freezer/           E10-verbatim freezing; seals each run as E_t
  baseline/          declared baselines and the variance band
  detector/          the pure comparison v = I(E_baseline, E_t)
  receipt/           envelope, evidence store, ledger, anchor, re-derivation
  spend.py           the declared call ceiling: enforced and reported
  suite/generation.py  probe generations: rotation, retirement, disclosure
  target/live.py     the live endpoint adapter (requires the `live` extra)
fixtures/paper2/   440 frozen replies from real cycles -- RECEIVED data, digest-pinned
scripts/           tools, and their tests
  verify_memo.py     memo integrity footers: verify and seal
tests/             repository-wide discipline tests
vendor/            frozen, digest-pinned third-party copies -- never edited in place
docs/evidence/     the C4 incident of record: live replies frozen 2026-08-22,
                   digest-pinned, and the calibration logs for all three generations
docs/launch/       the gen-1-c4 disclosure package, the incident narration, the viewer
NOTICE             upstream attribution (Apache-2.0 §4)
INTEGRITY.md       sidecar annotations against immutable artifacts -- errata live here
```

## Two disciplines that explain most of the code

**Received bytes are never rewritten.** Anything received — a frozen model response, a
vendored file, an inbound memo in the private repository — is kept exactly as it arrived. Its digest is over
those bytes, so any tool that "tidies" them destroys the evidence. Three layers enforce
it, on the assumption that the first two will eventually fail: `.gitattributes`
(`* -text`), formatter exclusion lists in `pyproject.toml`, and digest tests in
`tests/test_byte_discipline.py`. Generated structures, by contrast, are canonicalised —
the two disciplines are opposites, and applying either to the other's data is a defect.

**Quantise once, then stay float-free.** Scores cross a single quantisation boundary at
measurement — round-half-even, 6 decimal places — and the engine holds no floats after
that point. Verdicts carry `(integer numerator, integer denominator, probe-set digest)`;
a rate is computed at render time and never stored, compared, or chained. Denominators
legitimately move when probes retire, which is exactly why comparing rates is a bug.

## What the live phase found

**The provider swap was detected. The behaviour change was not — because there wasn't one.**

A baseline was sealed against `claude-sonnet-5`. The configuration then switched to
`claude-haiku-4-5-20251001`, and the endpoint served it. Under the declared instrument
(refusal-sentinel v3) not one probe changed verdict: haiku refused every answerless probe,
merely explaining four of them where sonnet-5 answered with a bare sentinel. Both models
scored 30/30.

So the receipt records two facts that never contradict each other — **the served model
changed, and its validated behaviour did not.** That is the incident, and it is probably
the most common real incident this product will meet. *A dashboard cannot prove a
negative.*

Re-scoring the same frozen bytes under the older instruments, at zero additional cost:

| instrument | baseline failures | after the swap | verdict flips | would report |
|---|---|---|---|---|
| v1 | 0 / 30 | 4 / 30 | 4 | CHANGED |
| v2 | 0 / 30 | 4 / 30 | 4 | CHANGED |
| **v3** (default) | 0 / 30 | 0 / 30 | 0 | **UNCHANGED** |

v1 and v2 would have raised a regression that did not happen — they misread a
sentinel-with-explanation as an answer. This table ships as a *re-scoring demonstration
over frozen bytes*, never as a receipt of record.

Regenerate it from the frozen evidence — no model queried, nothing spent:

```sh
python scripts/rescore_incident.py --markdown
```

### The refusal-sentinel family has aged out as a discriminator

Three probe generations were built and calibrated against the baseline model: direct
lookup; nine-document packages with near-miss sibling entities carrying the asked-for
attribute; and two-hop derivation with a deliberately broken link. **All three saturated —
0 failures of 30 each.** Paper-2 built this family when models produced 11–16 unsupported
answers per 30 on the same shape.

The family did not break. **The models improved, and took the instrument's sensitivity
with them.**

Two consequences, both adopted:

- **Probe-family headroom is a maintained property, not a design-time decision.** A family
  calibrated against today's models will silently stop discriminating, and the only way to
  know is to re-calibrate against the baseline and watch for saturation.
- **A saturated set is bad for a demo and good for a monitor.** Zero baseline failures with
  a zero band is *maximum* sensitivity to degradation: any failure in any later run exceeds
  the band. Such a set cannot distinguish two healthy models, and will catch the first
  moment either stops being healthy.

Calibration consults the **baseline model only** — never the switch model. A set tuned
until a particular swap shows up would be an instrument fitted to its finding. The
calibration gate refuses to let a swap run against a saturated set, which is why no
measurement was taken against one.

## The live phase, and what governs it

210 live calls have been made from this repository, all of them in the C4 live phase of
2026-08-22 and all of them accounted for in [the incident of record](docs/evidence/c4-incident-of-record/).
The ceiling stands at 500 and the spend is closed; no further call is made without a new
declaration. Four conditions bind every live call, and each is enforced in code rather
than described here:

**A fresh probe generation, always.** The published paper-2 probe set is permanently
retired and `assert_may_probe_live()` raises on it. A system that has seen the probes can
pass them without behaving well, so a passing result from a public set proves nothing.
Generations are built deterministically from a **secret seed** supplied from outside the
repository — the seed is the secret, the digest is the public commitment, and a verifier
holding the seed can confirm which instrument ran without the probes ever being published.
Retirement discloses them and is one-way; there is deliberately no `unretire`.

**A declared ceiling, before the first call.** No ceiling, no call. It is checked *before*
each request, not after — "we noticed at 501" is not a ceiling of 500 — and there is no
flag that lifts it mid-run. Every receipt carries both halves: what was declared and what
was spent, per model.

**The key never enters the repository.** It is read from `ANTHROPIC_API_KEY` at call time,
never stored on an object, never passed as an argument, never written to a config, log,
receipt, or memo. `LiveTarget` has no field a credential could occupy, and a test scans
every tracked file for credential markers.

**The receipt records the model served, never the model requested.** A provider quietly
serving a different model is precisely the incident this pillar exists to catch; believing
our own request would blind the instrument to its own subject.

```sh
python scripts/demo_c4.py --mock          # offline, free, no key — what CI runs
```

## What does not run here, and why

This repository is the published verification package. The canary was built through a
correspondence channel whose memos are private and are not published here, so one
repository-wide check has nothing to verify:

```
[NOT-RUN] test_every_archived_memo_still_verifies
          archived memos are private correspondence and are not published in this
          repository; this check runs where the memos live
```

It is skipped with a stated reason rather than deleted, and rather than pointed at an
empty directory so it would pass. Its own assertion message is `no archived memos found;
refusing to pass vacuously` — a check that goes green on an empty set is worse than one
that is absent, because it reports a verification that never happened. The same
distinction runs through everything else here: a receipt that cannot separate *checked
and fine* from *could not check* is not evidence.

Everything else runs. On a cold clone: **374 passed, 1 skipped**, Python 3.12.

`pyproject.toml` still names `docs/from_core` and `docs/to_core` in its formatter
exclusion lists, and a test fails if it stops. Those lists are a rule about what
formatters may rewrite, not an inventory of what is present — the rule is what has to
survive, so the names stay whether or not the directories are here.

## Licence

Apache-2.0. Upstream attribution in [NOTICE](NOTICE); errata against immutable
artifacts in [INTEGRITY.md](INTEGRITY.md).
