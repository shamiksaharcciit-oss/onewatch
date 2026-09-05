# How a canary generation retires

A canary only proves anything if two things are true: it existed **before** the change it
is meant to catch, and its evidence cannot be quietly rewritten afterwards. Everything
below exists to keep both true, including on the day the canary is retired — which is the
day its author has the most reason to be careless.

This document describes the process. The commands are the real ones, so that a reader can
check that what happened is what is described here.

---

## Why retirement is part of the discipline, not a concession

**A canary whose text is public is dead.** Anyone operating the system it watches can
special-case it. So the probes cannot be published while the generation is working, and a
generation that is never published can never be checked. Retirement is how those two facts
are reconciled: the instrument stops working at the moment it becomes checkable, and not
before.

That gives the retirement its shape. It is **one-way**. There is no `unretire`, in the
disclosure tooling or in `canary.suite.generation`, and the absence is deliberate. A
retirement you could reverse is a retirement you could deny.

## Before anything: confirm the state has not moved

From a clean clone — on Windows, `git clone -c core.longpaths=true`:

```sh
python -m pytest                        # the suite, by the gate's own command
python scripts/rederive_incident.py     # the anchor must match the live-day root
python scripts/stage_disclosure.py      # reports the generation's status; changes nothing
```

`rederive_incident.py` must print `MATCH -- bit-for-bit identical to the live-day root`.
If it does not, the process stops there. The thing about to be published is no longer the
thing that was measured, and no amount of care further down compensates for that.

`stage_disclosure.py` with no arguments is a report, not an action. It states the
generation's status, checks that the published probe bytes hash to the digest the anchored
receipts cite, and scans the staged package for secret markers. Before retirement it ends
by refusing:

```
STAGED    gen-N is still ACTIVE and this package is NOT to be published.
```

## Act 1 — confirm the leak check still covers every generation

```sh
python -m pytest tests/test_disclosure.py -k "allowed or secret or confin"
```

The secrecy this design protects is **probe text and the generator, never the fact of
rotation**. Generation names appear in the instrument history deliberately; a name is not
a probe set. What must never appear is the seed the generations are built from, and the
leak check is built around that distinction rather than around a blanket rule.

## Act 2 — throw the switch

One command, dated, and it refuses to run twice:

```sh
python scripts/stage_disclosure.py --fire YYYY-MM-DD
```

It writes the instrument history: the status transition, the date, the reason, the
generation digest, the receipts that cite it, and the consequence that the retired
generation may never probe a live system again. It also publishes the **next**
generations' digests, which is a commitment: a future disclosure's text will have to hash
to a digest that has been public since this date.

Those digests are published as sixteen-hex prefixes rather than full digests. The tool
that calibrated the generations did not retain the full runs. That is a defect, it is
recorded as one, and a holder of the seed can complete the record offline at no cost. A
truncated digest is a weaker commitment than a full one and is labelled as truncated
rather than padded to look complete.

Re-staging then reports `RETIRED -- disclosure permitted`.

**One test changes in the same commit, and it names itself.** `test_gen_N_is_not_retired_yet`
fails once the retirement record exists, and its failure message says why. The freeze is
structural rather than remembered: firing is a deliberate act, not an archaeology
exercise, and the retirement is as visible in the history as the canary was.

## Act 3 — publish

Published together, because each of them is useless for checking without the others:

- the disclosure package — the probe set, its digest manifest, and its README
- the incident narration, regenerated from the frozen record (`build_narration.py`, then
  `--check`)
- the incident of record itself, so a reader can run `rederive_incident.py` and check the
  anchor without asking anyone's permission
- the re-scoring table under its label (`rescore_incident.py --markdown`)
- the viewer, regenerated after Act 2 (`python -m canary.viewer`) so the page shows the
  retirement rather than the absence notice it carries beforehand

The viewer is a pure function of the store. Regenerating is the only way it changes, and
there is no background process that could change it otherwise.

**The sentence the disclosure rests on:** *the disclosure hands the reader a check against
evidence that predates it, rather than asking to be believed.* That check is the published
probe set hashing to a digest sealed into three Merkle-anchored receipts **before the
probes were ever disclosed**.

## What must not happen

- **No publishing before Act 2.** The frozen runs inside the incident of record carry full
  probe and document text. Until retirement is executed, that is an ACTIVE instrument, and
  publishing it early does not merely leak the probes — it converts a disclosure made on
  schedule into cleanup after an accident.
- **No live call outside a declared ceiling.** Spend is declared, enforced and reported. It
  does not move without a new declaration naming its budget.
- **No seed, anywhere.** The seed the generations are built from appears in no artifact, no
  test and no memo. Every seed literal in this repository is a test string that says so in
  its own name. The seed's *variable name* appears throughout, because the leak scanner and
  the tests that verify it are built around that name — the rule protects the value.
- **No claim about an untested environment.** Every current measurement is a Python 3.12
  result and is labelled as one. A green gate is a claim about an environment.

## The cycle

Each generation's disclosure is verified against the previous pre-commitment and carries
the next one. What that establishes is narrow and worth stating exactly: it proves the
probes were fixed before the observations, and that nobody adjusted the instrument until
the answer came out nice. It does not, by itself, establish that any generation is sharp
enough to detect what you care about. That is a separate property, measured by calibration
and reported honestly whether or not the result flatters the tool.
