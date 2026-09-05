# The vendor changed the model underneath you, and your behaviour did not move

*The Detect leg of "one incident, three receipts". Every number below was generated into
this document from the frozen record by `scripts/build_narration.py`; nothing here was
typed by hand, and nothing was measured to write it.*

---

## The incident

On **2026-08-22** a baseline was sealed against `claude-sonnet-5`: 30 probes, a
refusal-sentinel instrument at `v3`, a variance band measured from a same-config repeat
pair and declared before anything else ran — `answer_bearing` 0, `cross_doc` 0, `same_doc` 0 — zero on every arm.

Two later runs against the same configuration produced **no-change receipts**.

Then the configuration named a different model. The provider served
**`claude-haiku-4-5-20251001`**. The canary probed it from outside, exactly as
before, and the receipt it sealed says two things that never contradict each other:

> **The served model changed. The validated behaviour did not.**

Not one probe of 30 changed verdict. Every arm stayed inside its band.

**A dashboard cannot prove a negative.** It can show you that nothing looks wrong. It
cannot hand you a document, months later, that recomputes to the same answer in someone
else's hands. That is the whole difference, and it is the reason this is a receipt and
not a chart.

## What the receipt actually contains

| | baseline | after the switch |
|---|---|---|
| model requested | `claude-sonnet-5` | `claude-haiku-4-5` |
| **model served** | `claude-sonnet-5` | **`claude-haiku-4-5-20251001`** |
| probes | 30 | 30 |
| verdicts changed | — | **0** |
| arms outside band | — | **0** |
| instrument (`i_digest`) | `ecbd44f6f3d95a84…` | `ecbd44f6f3d95a84…` |

Three details in that table carry the argument.

**The receipt records what was *served*, never what was *requested*.** The configuration
asked for `claude-haiku-4-5`; the endpoint served
`claude-haiku-4-5-20251001`. A monitor that believed its own request would be
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

2 of the 3 receipts here say exactly that about a system
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
anchor root  38ff95dbc6c4c31f6c55485fb1fdb71039db0cb8c671a02b4d95a33d60b956dd
tree_size    3
```

That root was recorded on the day of the live run. It recomputes to the same value today,
from a cold clone, on a different day, by a different route.

## The same evidence under a different instrument

The verdict above is `v3`'s. Re-scored under the two older instruments — same frozen
bytes, no new calls:

| instrument | baseline failures | after the swap | verdict flips | would report |
|---|---|---|---|---|
| v1 | 0 / 30 | 4 / 30 | 4 | CHANGED |
| v2 | 0 / 30 | 4 / 30 | 4 | CHANGED |
| **v3** (default) | 0 / 30 | 0 / 30 | 0 | **UNCHANGED** |

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
- **One incident, one system, one window.** 150 live calls against a declared
  ceiling of 500. This is a worked example, not a study.

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
