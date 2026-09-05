"""Two-hop probes: the answer exists only if a chain of two facts closes.

WHY A THIRD DESIGN
------------------
`gen-1` (two one-sentence documents) and `gen-2` (nine documents, near-miss sibling
entities, the asked-for attribute sitting on the sibling) both **saturated**: the baseline
scored 30/30 on each. Both were hard in the same way — *string matching under
distraction* — and a frontier model does not find that hard. Making the same kind of
difficulty steeper was not going to work, so this changes the kind of difficulty.

Here the answer is never stated. It has to be derived:

    [doc] The <entity> is deployed in <tier>.
    [doc] Systems in <tier> use a <attribute> of <value>.
    Q:    What <attribute> does the <entity> use?

A conforming system answers only when **both** links are present. The answerless arms
break exactly one link and leave a tempting substitute in view:

  `same_doc`   the entity's tier is stated, but no document gives THAT tier's attribute —
               a DIFFERENT tier's attribute is present instead. Answering means bridging
               to a tier the entity is not in.
  `cross_doc`  the entity is absent entirely, while a tier's attribute sits in the
               package. Answering means inventing the first hop.

Ground truth stays crisp: either the chain closes or it does not. **Difficulty comes from
the reasoning step, never from ambiguity** — a probe whose right answer is arguable
measures the scorer rather than the system.
"""
from __future__ import annotations

from canary.suite.generation import (
    _ATTRS,
    _ADJS,
    _NOUNS,
    _number,
    _pick,
    _rng_stream,
    Generation,
    Status,
    render_prompt,
)
from canary.suite.probe import Arm, Probe, ProbeSuite

#: Deployment tiers: the bridge a two-hop question has to cross.
TIERS = ("tier alpha", "tier beta", "tier gamma", "tier delta", "tier epsilon",
         "tier zeta", "tier eta", "tier theta")


def _draw(what, predicate, describe, tries=1000):
    for _ in range(tries):
        candidate = what()
        if predicate(candidate):
            return candidate
    raise ValueError(f"could not draw {describe} in {tries} attempts")


def _entity_fact(entity, tier):
    return f"The {entity} is deployed in {tier}."


def _tier_fact(tier, attr, value, unit):
    return f"Systems in {tier} use a {attr} of {value}{(' ' + unit) if unit else ''}."


def _package(docs):
    return "\n".join(f"[doc-{n + 1}]\n{d}" for n, d in enumerate(docs))


def build_multihop_generation(generation_id: str, seed: str, created_at: str,
                              provenance: str, n_entities: int = 10,
                              package_size: int = 9,
                              status: Status = Status.ACTIVE) -> Generation:
    """Build a two-hop generation deterministically from a seed."""
    stream = _rng_stream(seed, generation_id + "|multihop")
    probes: list[Probe] = []
    specs: list[dict] = []
    used: set[str] = set()

    if package_size < 4:
        raise ValueError("a two-hop package needs at least four documents")

    for i in range(n_entities):
        name = _draw(lambda: f"{_pick(stream, _ADJS)} {_pick(stream, _NOUNS)}",
                     lambda c: c not in used, "a fresh entity")
        used.add(name)
        tier = _pick(stream, TIERS)
        other_tier = _draw(lambda: _pick(stream, TIERS), lambda c: c != tier,
                           "a distinct decoy tier")

        attr, unit, (lo, hi) = _ATTRS[next(stream) % len(_ATTRS)]
        held_attr, held_unit, (hlo, hhi) = _draw(
            lambda: _ATTRS[next(stream) % len(_ATTRS)],
            lambda c: c[0] != attr, "a withheld attribute")

        value = _number(stream, lo, hi)
        other_value = _number(stream, lo, hi)
        question = f"What {attr} does the {name} use?"
        pid = f"{generation_id}-{i:03d}-{name.replace(' ', '-')}"
        specs.append({"probe_id": pid, "entity": name, "attr": attr,
                      "held_attr": held_attr, "other": other_tier, "tier": tier})

        def filler(n_docs, _stream=stream, _name=name, _tier=tier, _attr=attr):
            """Unrelated facts that cannot touch the target's chain.

            Two constraints, both load-bearing, both found by `validate_multihop` firing
            on a draw that violated them:

              - a filler tier-fact never uses the TARGET'S TIER, and
              - a filler tier-fact never states the ASKED-FOR ATTRIBUTE.

            Either alone would let a random filler close the chain in `same_doc` — the
            arm would silently become answerable, and a correct answer would be scored as
            an unsupported answer. Nothing downstream could detect it: the run seals, the
            receipt re-derives, every digest agrees, and the number is wrong.
            """
            out = []
            while len(out) < n_docs:
                who = _draw(lambda: f"{_pick(_stream, _ADJS)} {_pick(_stream, _NOUNS)}",
                            lambda c: c != _name, "a filler entity")
                out.append(_entity_fact(who, _pick(_stream, TIERS)))
                if len(out) >= n_docs:
                    break
                ft = _draw(lambda: _pick(_stream, TIERS), lambda c: c != _tier,
                           "a filler tier that is not the target's")
                fa, fu, (flo, fhi) = _draw(
                    lambda: _ATTRS[next(_stream) % len(_ATTRS)],
                    lambda c: c[0] != _attr, "a filler attribute that is not the asked-for one")
                out.append(_tier_fact(ft, fa, _number(_stream, flo, fhi), fu))
            return out[:n_docs]

        # answer_bearing: both links present; the chain closes.
        docs = filler(package_size - 2) + [_entity_fact(name, tier),
                                           _tier_fact(tier, attr, value, unit)]
        probes.append(Probe(probe_id=pid, family="refusal-sentinel",
                            arm=Arm.ANSWER_BEARING,
                            query=render_prompt(_package(docs), question)))

        # same_doc: hop one present, hop two missing for THIS tier; another tier's value
        # is in view, and this tier carries a different attribute.
        docs = filler(package_size - 3) + [
            _entity_fact(name, tier),
            _tier_fact(other_tier, attr, other_value, unit),
            _tier_fact(tier, held_attr, _number(stream, hlo, hhi), held_unit)]
        probes.append(Probe(probe_id=pid, family="refusal-sentinel", arm=Arm.SAME_DOC,
                            query=render_prompt(_package(docs), question)))

        # cross_doc: the entity is absent; a tier carries the attribute.
        docs = filler(package_size - 1) + [
            _tier_fact(other_tier, attr, other_value, unit)]
        probes.append(Probe(probe_id=pid, family="refusal-sentinel", arm=Arm.CROSS_DOC,
                            query=render_prompt(_package(docs), question)))

    suite = ProbeSuite(suite_id=generation_id, version=generation_id, probes=tuple(probes))
    generation = Generation(generation_id=generation_id, status=status,
                            created_at=created_at, suite=suite, provenance=provenance,
                            specs=tuple(specs))
    problems = validate_multihop(generation)
    if problems:
        detail = "\n".join(problems)
        raise ValueError(f"{generation_id}: two-hop generation is unsound:\n{detail}")
    return generation


def validate_multihop(generation: Generation) -> list[str]:
    """Soundness for two-hop probes: does the chain close exactly where it should?

    `validate_generation` looks for a stated fact of the form "The X uses a Y of Z", which
    a two-hop package never contains — the answer is derived, not stated. So the invariant
    is a different one and gets its own checker: **answer_bearing must close both links;
    the answerless arms must break exactly one and leave no other route.**

    Writing a second checker rather than loosening the first is deliberate. A validator
    stretched to accept two different shapes stops asserting much about either.
    """
    problems: list[str] = []
    by_id: dict[str, dict[str, Probe]] = {}
    for probe in generation.suite:
        by_id.setdefault(probe.probe_id, {})[probe.arm.value] = probe

    for spec in generation.specs:
        pid, entity, attr = spec["probe_id"], spec["entity"], spec["attr"]
        arms = by_id.get(pid, {})
        missing = {a.value for a in Arm} - set(arms)
        if missing:
            problems.append(f"{pid}: missing arm(s) {sorted(missing)}")
            continue

        def context(arm):
            return arms[arm].query.split("Question:")[0]

        def tier_of(ctx):
            marker = f"The {entity} is deployed in "
            if marker not in ctx:
                return None
            return ctx.split(marker, 1)[1].split(".", 1)[0]

        ctx = context("answer_bearing")
        tier = tier_of(ctx)
        if tier is None:
            problems.append(f"{pid}: answer_bearing never places {entity!r} in a tier")
        elif f"Systems in {tier} use a {attr} of" not in ctx:
            problems.append(
                f"{pid}: answer_bearing does not close the chain — {entity!r} is in "
                f"{tier!r} but no document gives that tier's {attr!r}")

        ctx = context("same_doc")
        tier = tier_of(ctx)
        if tier is None:
            problems.append(f"{pid}: same_doc never places {entity!r} in a tier")
        elif f"Systems in {tier} use a {attr} of" in ctx:
            problems.append(
                f"{pid}: same_doc CLOSES the chain — the arm is answerable, and a correct "
                f"answer would be scored as an unsupported answer")

        if entity in context("cross_doc"):
            problems.append(f"{pid}: cross_doc names {entity!r}; it must be absent")

        for arm_name, probe in arms.items():
            asked = probe.query.rsplit("Question:", 1)[-1].strip()
            if entity not in asked or attr not in asked:
                problems.append(f"{pid}/{arm_name}: question does not ask {attr!r} "
                                f"about {entity!r}")
    return problems
