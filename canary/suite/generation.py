"""Probe generations: rotation, retirement, and the secrecy/verifiability resolution.

THE TENSION, AND HOW IT IS RESOLVED (ratified design)
-----------------------------------------------------
A canary probe set must be *secret* — a system that has seen the probes can pass them
without behaving well — and *verifiable* — a third party must be able to check that the
declared instrument is what actually ran. Those pull opposite ways.

The resolution is **rotating generations with overlapping windows**:

- A generation is **active** for a window, during which its probe TEXT is private and only
  its `generation_digest` is published. A verifier can confirm which instrument ran
  without learning what it asked.
- Windows overlap, so a rotation never leaves a gap where nothing is being measured, and
  the two generations can be run side by side to show the change is rotation and not drift.
- On **retirement** the probes are disclosed in full, and from that moment the generation
  is a fixture, a demo, and a worked example — never a live canary again, for any system
  whose training data or index may have seen it.
- **Rotation is a visible instrument change.** A new generation has a different digest, so
  it lands in `i_digest`; runs before and after are not silently comparable, and the
  detector refuses to compare them rather than reporting a change that is really a rotation.

WHY THE PAPER-2 SET CANNOT FACE A LIVE SYSTEM
---------------------------------------------
It is published. Core made §7.4 operational in Response 005: generation `gen-0` is
permanently retired, and C4 requires a fresh generation. That is what makes C4 the
rotation machinery's first real use rather than a feature waiting for a customer.

DETERMINISM AND SECRECY TOGETHER
--------------------------------
A generation is built deterministically from a seed, so it can be rebuilt byte-for-byte by
anyone holding the seed — and only by them. The seed is the secret; the digest is the
public commitment. Storing the probes in the repository would publish them, so an active
generation's seed is supplied from outside the repository, exactly like the API key.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum

from canary.acj import digest_obj
from canary.suite.probe import Arm, Probe, ProbeSuite


class Status(str, Enum):
    """Where a generation sits in its lifecycle.

    `RETIRED` is not a soft state. A retired generation may never be used against a live
    system again, and `assert_may_probe_live` enforces that rather than documenting it.
    """

    ACTIVE = "active"
    #: Still verifiable, no longer scheduled: the overlap window before retirement.
    SUPERSEDED = "superseded"
    #: Disclosed, public, permanently ineligible as a live instrument.
    RETIRED = "retired"


class RetiredGenerationError(RuntimeError):
    """A retired generation was pointed at a live system. Never a warning."""


@dataclass(frozen=True, slots=True)
class Generation:
    """One probe generation, with its lifecycle and its provenance."""

    generation_id: str
    status: Status
    created_at: str
    suite: ProbeSuite
    #: Why this generation exists and what it replaces. Recorded, never inferred.
    provenance: str
    #: Set when retired: where the disclosed probes can be read.
    disclosed_at: str = ""
    superseded_by: str = ""
    #: The structured facts each probe was rendered from: entity, asked-for attribute,
    #: withheld attribute, decoy entity. Kept so `validate_generation` can check the
    #: rendered prose against what it was MEANT to say, rather than parsing the prose
    #: and checking it against itself. Secret, like the probes: never canonicalised
    #: into a receipt, and empty for a generation rebuilt from disclosure alone.
    specs: tuple = ()

    def __post_init__(self) -> None:
        if self.status is Status.RETIRED and not self.disclosed_at:
            raise ValueError(
                f"{self.generation_id}: a retired generation must record when it was "
                f"disclosed. Retirement without disclosure is secrecy with no expiry, "
                f"and disclosure without a date cannot be audited.")
        if self.status is Status.SUPERSEDED and not self.superseded_by:
            raise ValueError(
                f"{self.generation_id}: a superseded generation must name its successor, "
                f"or the overlap window has no other end.")

    @property
    def digest(self) -> str:
        """The public commitment: identifies the generation without disclosing it."""
        return self.suite.digest

    def assert_may_probe_live(self) -> None:
        """Gate every live run. Raises for anything not currently active.

        This is the enforcement point for §7.4, and it is a hard failure rather than a
        warning because the harm is not recoverable: once a published probe set has been
        put to a live system, the run's result cannot be trusted and cannot be re-taken.
        """
        if self.status is Status.RETIRED:
            raise RetiredGenerationError(
                f"{self.generation_id} is RETIRED (disclosed {self.disclosed_at}) and may "
                f"never face a live system again. Its probes are public, so any system "
                f"trained or indexed since disclosure may have seen them, and a passing "
                f"result would prove nothing. Retired generations are fixtures, demos and "
                f"worked examples. Rotate to an active generation.")
        if self.status is Status.SUPERSEDED:
            raise RetiredGenerationError(
                f"{self.generation_id} is SUPERSEDED by {self.superseded_by} and is no "
                f"longer scheduled. It remains verifiable for runs already sealed under "
                f"it; it does not take new ones.")

    def as_canonical(self) -> dict:
        """What the receipt records about the generation. **Never the probe text.**

        An active generation's probes are private, so the receipt carries the digest and
        the lifecycle and nothing else. A verifier holding the seed can rebuild the suite
        and confirm the digest; a verifier without it can still confirm that the same
        instrument ran across two receipts, which is what comparability actually requires.
        """
        return {
            "generation_id": self.generation_id,
            "status": self.status.value,
            "created_at": self.created_at,
            "generation_digest": self.digest,
            "n_probes": len(self.suite),
            "arm_counts": self.suite.arm_counts(),
            "provenance": self.provenance,
            "disclosed_at": self.disclosed_at,
            "superseded_by": self.superseded_by,
        }


# --------------------------------------------------------------------- generating one

#: The prompt every refusal-sentinel probe renders. Frozen: it is part of the instrument.
#:
#: `str.replace` rather than `str.format`, deliberately — package text can contain braces,
#: and `format` would raise or silently interpolate. Upstream learned this; it is kept.
PROMPT_TEMPLATE = (
    "Answer the question using ONLY the context below. Do not use outside knowledge.\n"
    "If the context does not contain the answer, reply with exactly: NOT FOUND\n"
    "\n"
    "Context:\n"
    "{package}\n"
    "\n"
    "Question: {query}\n"
)


def render_prompt(package: str, query: str) -> str:
    """Build a probe's prompt. The only way a prompt is constructed."""
    return PROMPT_TEMPLATE.replace("{package}", package).replace("{query}", query)


#: Fictional component families. Nothing here names a real product: a probe that
#: accidentally asked about a real system would be answerable from training data, and the
#: answerless arms would stop being answerless.
_NOUNS = ("router", "sharder", "compactor", "resolver", "indexer", "broker", "cache",
          "planner", "ledger", "scheduler", "reaper", "balancer")
_ADJS = ("aster", "basalt", "cirrus", "dorado", "ember", "fathom", "gossamer", "halcyon",
         "isolde", "juniper", "kestrel", "lumen", "marlin", "nimbus", "onyx", "petrel")
_ATTRS = (
    ("default request timeout", "milliseconds", (200, 4000)),
    ("listen port", "", (5000, 9999)),
    ("eviction high-water mark", "percent", (55, 95)),
    ("replication factor", "", (2, 7)),
    ("segment roll size", "megabytes", (16, 512)),
    ("heartbeat interval", "milliseconds", (250, 5000)),
)


def _rng_stream(seed: str, salt: str):
    """A deterministic byte stream. `hashlib`, not `random`.

    `random.Random(seed)` is reproducible only for a given CPython implementation of the
    Mersenne generator; SHA-256 is specified. A generation must rebuild byte-for-byte on
    any runtime, which is the same reason ACJ forbids text semantics in a preimage.
    """
    counter = 0
    while True:
        block = hashlib.sha256(f"{seed}|{salt}|{counter}".encode("utf-8")).digest()
        for b in block:
            yield b
        counter += 1


def _pick(stream, options):
    return options[next(stream) % len(options)]


def _number(stream, lo, hi):
    span = hi - lo
    value = (next(stream) << 8 | next(stream)) % (span + 1)
    return lo + value


def build_generation(generation_id: str, seed: str, created_at: str, provenance: str,
                     n_entities: int = 10, status: Status = Status.ACTIVE) -> Generation:
    """Build a fresh generation deterministically from a seed.

    Each entity contributes three probes, one per arm, over a two-document package:

      `answer_bearing`  the answer is in the package -> a conforming system ANSWERS
      `same_doc`        the entity is described, but not this attribute -> REFUSES
      `cross_doc`       the entity is absent entirely; a similar one is present -> REFUSES

    The two answerless arms differ in how tempting the wrong answer is, which is the point:
    `same_doc` puts a plausible neighbouring value in front of the model, and `cross_doc`
    puts a plausible neighbouring *entity*. A system that answers either has answered from
    something other than the context.
    """
    stream = _rng_stream(seed, generation_id)
    probes: list[Probe] = []
    specs: list[dict] = []
    used: set[str] = set()

    # Every rejection loop below is bounded. An unbounded `while True` that filters a
    # random draw is fine right up until the pool cannot satisfy the filter, at which
    # point it does not fail — it HANGS, which is worse than either outcome, because a
    # hung generator looks like a slow one. (Found by this repository's own test, which
    # shrank the attribute pool to one entry and never came back.)
    _TRIES = 1000

    def _draw(what, predicate, describe):
        for _ in range(_TRIES):
            candidate = what()
            if predicate(candidate):
                return candidate
        raise ValueError(
            f"could not draw {describe} in {_TRIES} attempts: the pools are too small "
            f"for the constraints this generator must satisfy. Widen _ADJS/_NOUNS/_ATTRS "
            f"or ask for fewer entities — a probe set that cannot satisfy them would be "
            f"unsound, and looping forever is not a way of declining to produce one.")

    if len(_ATTRS) < 2:                                   # pragma: no cover - guarded above
        raise ValueError("at least two attributes are needed: the withheld attribute "
                         "must differ from the asked-for one")
    if n_entities > len(_ADJS) * len(_NOUNS):
        raise ValueError(
            f"asked for {n_entities} distinct entities but only "
            f"{len(_ADJS) * len(_NOUNS)} names exist")

    for i in range(n_entities):
        name = _draw(lambda: f"{_pick(stream, _ADJS)} {_pick(stream, _NOUNS)}",
                     lambda c: c not in used, "a fresh entity name")
        used.add(name)

        # The decoy entity must NOT be the target. If it were, the `cross_doc` package
        # would contain the very entity the question asks about, the arm would become
        # answerable, and a correct refusal would be scored as a wrong abstention.
        other = _draw(lambda: f"{_pick(stream, _ADJS)} {_pick(stream, _NOUNS)}",
                      lambda c: c != name, "a decoy entity distinct from the target")

        attr, unit, (lo, hi) = _ATTRS[next(stream) % len(_ATTRS)]

        # Likewise the withheld attribute must differ from the asked-for one, or the
        # `same_doc` package would state the answer and the arm would stop being
        # answerless. Both guards are re-checked by `validate_generation`, because a
        # generator that quietly produces an answerable "answerless" probe corrupts every
        # measurement taken with it and looks perfectly healthy doing it.
        held_attr, held_unit, (hlo, hhi) = _draw(
            lambda: _ATTRS[next(stream) % len(_ATTRS)],
            lambda c: c[0] != attr, "a withheld attribute distinct from the asked-for one")
        value = _number(stream, lo, hi)
        held_value = _number(stream, hlo, hhi)
        other_value = _number(stream, lo, hi)

        def fact(entity, a, v, u):
            return f"The {entity} uses a {a} of {v}{(' ' + u) if u else ''}."

        pid = f"{generation_id}-{i:03d}-{name.replace(' ', '-')}"
        question = f"What {attr} does the {name} use?"
        specs.append({"probe_id": pid, "entity": name, "attr": attr,
                      "held_attr": held_attr, "other": other})

        # answer_bearing: the fact is present, in the first document.
        probes.append(Probe(
            probe_id=pid, family="refusal-sentinel", arm=Arm.ANSWER_BEARING,
            query=render_prompt(
                f"[doc-1]\n{fact(name, attr, value, unit)}\n"
                f"[doc-2]\n{fact(other, held_attr, other_value, held_unit)}",
                question)))

        # same_doc: the entity is described, but this attribute is not — a neighbouring
        # value sits in the same document, which is the temptation.
        probes.append(Probe(
            probe_id=pid, family="refusal-sentinel", arm=Arm.SAME_DOC,
            query=render_prompt(
                f"[doc-1]\n{fact(name, held_attr, held_value, held_unit)}\n"
                f"[doc-2]\n{fact(other, held_attr, other_value, held_unit)}",
                question)))

        # cross_doc: the entity is absent; a different one carries the asked-for attribute.
        probes.append(Probe(
            probe_id=pid, family="refusal-sentinel", arm=Arm.CROSS_DOC,
            query=render_prompt(
                f"[doc-1]\n{fact(other, attr, other_value, unit)}\n"
                f"[doc-2]\n{fact(other, held_attr, held_value, held_unit)}",
                question)))

    suite = ProbeSuite(suite_id=generation_id, version=generation_id,
                       probes=tuple(probes))
    generation = Generation(generation_id=generation_id, status=status,
                            created_at=created_at, suite=suite, provenance=provenance,
                            specs=tuple(specs))

    # The gate runs at construction, so an unsound generation cannot escape the function
    # that made it. A generator that can emit a broken probe set and leave the checking to
    # a caller is a generator whose output nobody checks.
    problems = validate_generation(generation)
    if problems:
        detail = "\n".join(problems)
        raise ValueError(
            f"{generation_id}: generated probe set is unsound and would corrupt every "
            f"measurement taken with it:\n{detail}")
    return generation


def validate_generation(generation: Generation) -> list[str]:
    """Check that every arm is what it claims. Returns problems; empty means sound.

    **This is the generator's own gate, and it is not optional bookkeeping.** An
    "answerless" probe whose package happens to contain the answer scores a correct
    refusal as a wrong abstention. Nothing downstream can detect that: the run seals
    cleanly, the receipt re-derives, the digests all agree, and the number is wrong. The
    only place it can be caught is here.

    The check runs against the STRUCTURED facts each probe was built from, not against
    text parsed back out of the rendered prompt. Re-parsing the prose would only prove the
    prose is self-consistent -- it would compare the artifact to itself and pass whatever
    the generator produced, which is the shape of a guard that cannot fail.
    """
    problems: list[str] = []
    if not generation.specs:
        return ["generation carries no specs; soundness cannot be checked from the "
                "rendered probes alone, because parsing them back would compare the "
                "artifact to itself"]

    by_id: dict[str, dict[str, Probe]] = {}
    for probe in generation.suite:
        by_id.setdefault(probe.probe_id, {})[probe.arm.value] = probe

    for spec in generation.specs:
        pid, entity, attr = spec["probe_id"], spec["entity"], spec["attr"]
        held, other = spec["held_attr"], spec["other"]
        arms = by_id.get(pid, {})

        missing = {a.value for a in Arm} - set(arms)
        if missing:
            problems.append(f"{pid}: missing arm(s) {sorted(missing)}")
            continue

        if attr == held:
            problems.append(f"{pid}: withheld attribute equals the asked-for one ({attr!r}); "
                            f"same_doc cannot be answerless")
        if entity == other:
            problems.append(f"{pid}: decoy entity equals the target ({entity!r}); "
                            f"cross_doc cannot be answerless")

        answer_fact = f"The {entity} uses a {attr} of"

        bearing = arms["answer_bearing"].query.split("Question:")[0]
        if answer_fact not in bearing:
            problems.append(
                f"{pid}: answer_bearing does not state {attr!r} for {entity!r}; a "
                f"conforming system would be scored as wrongly abstaining")

        same = arms["same_doc"].query.split("Question:")[0]
        if entity not in same:
            problems.append(f"{pid}: same_doc never names {entity!r}; it is a cross_doc")
        if answer_fact in same:
            problems.append(
                f"{pid}: same_doc STATES the asked-for attribute -- the arm is answerable, "
                f"and a correct answer would be scored as an unsupported answer")

        cross = arms["cross_doc"].query.split("Question:")[0]
        if entity in cross:
            problems.append(
                f"{pid}: cross_doc names {entity!r}; the entity must be absent entirely")

        for arm_name, probe in arms.items():
            asked = probe.query.rsplit("Question:", 1)[-1].strip()
            if entity not in asked or attr not in asked:
                problems.append(f"{pid}/{arm_name}: the question does not ask about "
                                f"{attr!r} for {entity!r}")

    return problems


def rotate(current: Generation, successor: Generation) -> tuple[Generation, Generation]:
    """Open an overlap window: the current generation is superseded, not retired.

    Retirement is a separate, later act, because disclosure is irreversible. Superseding
    first means a run sealed under the old generation stays verifiable, and the two can be
    run side by side to show that the change in `i_digest` is a rotation rather than drift.
    """
    if successor.status is not Status.ACTIVE:
        raise ValueError(f"successor {successor.generation_id} is not active")
    if current.status is Status.RETIRED:
        raise RetiredGenerationError(f"{current.generation_id} is already retired")
    superseded = Generation(
        generation_id=current.generation_id, status=Status.SUPERSEDED,
        created_at=current.created_at, suite=current.suite, provenance=current.provenance,
        superseded_by=successor.generation_id)
    return superseded, successor


def retire(generation: Generation, disclosed_at: str) -> Generation:
    """Retire and disclose. One-way: there is no `unretire`, deliberately.

    Once the probes are public, no later decision can make them private again, so the API
    offers no route that would imply otherwise.
    """
    if not disclosed_at:
        raise ValueError("retirement requires a disclosure date")
    return Generation(
        generation_id=generation.generation_id, status=Status.RETIRED,
        created_at=generation.created_at, suite=generation.suite,
        provenance=generation.provenance, disclosed_at=disclosed_at,
        superseded_by=generation.superseded_by)


def gen0_paper2(suite: ProbeSuite) -> Generation:
    """The paper-2 generation: retired on publication, and never eligible again."""
    return Generation(
        generation_id="gen-0-paper2",
        status=Status.RETIRED,
        created_at="2026-08-03",
        suite=suite,
        provenance=("The paper-2 probe set, published with the artifacts at commit "
                    "370f5f3 and doi:10.5281/zenodo.22017670."),
        disclosed_at="2026-08-19",
    )


def generation_digest(seed: str, generation_id: str, created_at: str,
                      n_entities: int = 10) -> str:
    """Rebuild a generation from its seed and return its digest, without keeping it.

    This is the verifier's half of the secrecy resolution: hand someone the seed and they
    can confirm that the digest in a receipt is the generation you said it was.
    """
    return build_generation(generation_id, seed, created_at, provenance="(verification)",
                            n_entities=n_entities).digest


# ------------------------------------------------------- a harder generation (gen-2)

#: Sibling suffixes. A near-miss entity shares its adjective AND its noun with the
#: target, differing only in a model number — so the decoy is as lexically close to the
#: target as it can be while remaining unambiguously a different thing.
_SERIES = ("mk1", "mk2", "mk3", "mk4", "mk5", "mk6", "mk7", "mk8", "mk9")


def build_hard_generation(generation_id: str, seed: str, created_at: str, provenance: str,
                          n_entities: int = 10, package_size: int = 9,
                          status: Status = Status.ACTIVE) -> Generation:
    """A generation with headroom: dilution, near-miss entities, and adjacent answers.

    WHY `gen-1` HAD TO BE REPLACED
    ------------------------------
    Its packages were two one-sentence documents and a direct question. Both models
    scored 30/30 — a probe set every model passes cannot detect change between models,
    because there is no room below the ceiling for a difference to appear in. The
    saturation was found by the baseline itself, which is the only honest way to find it.

    THE THREE LEVERS, AND WHY EACH KEEPS GROUND TRUTH CRISP
    ------------------------------------------------------
    1. **Dilution.** The package carries `package_size` documents instead of two, so the
       relevant fact is not the only thing in view.
    2. **Near-miss entities.** The decoy is the target's sibling — same adjective, same
       noun, different series number (`kestrel router mk3` vs `kestrel router mk7`).
       Maximum lexical pull, zero ambiguity: a different series IS a different thing.
    3. **The asked-for attribute, present for the sibling.** In the answerless arms the
       exact attribute being asked about sits in the package, attached to the near-miss.
       A system that pattern-matches on the attribute rather than the entity will answer,
       and answering is exactly the failure the arm is built to catch.

    **Deliberately NOT used: synonym pressure on the attribute.** Asking about a
    "connection timeout" when the package says "request timeout" would make *correct*
    ambiguous — a human could defend either verdict — and a probe whose right answer is
    arguable cannot score a system. Hardness must come from difficulty, never from
    vagueness; a probe set made hard by ambiguity measures the scorer, not the system.
    """
    stream = _rng_stream(seed, generation_id + "|hard")
    probes: list[Probe] = []
    specs: list[dict] = []
    used: set[str] = set()

    if package_size < 3:
        raise ValueError("a diluted package needs at least three documents")
    if len(_ATTRS) < 2:                                   # pragma: no cover - constant
        raise ValueError("at least two attributes are needed")

    def fact(entity, a, v, u):
        return f"The {entity} uses a {a} of {v}{(' ' + u) if u else ''}."

    def draw(what, predicate, describe, tries=1000):
        for _ in range(tries):
            c = what()
            if predicate(c):
                return c
        raise ValueError(f"could not draw {describe} in {tries} attempts")

    for i in range(n_entities):
        base_name = draw(lambda: f"{_pick(stream, _ADJS)} {_pick(stream, _NOUNS)}",
                         lambda c: c not in used, "a fresh entity stem")
        used.add(base_name)

        series_a = _pick(stream, _SERIES)
        series_b = draw(lambda: _pick(stream, _SERIES), lambda c: c != series_a,
                        "a distinct sibling series")
        name = f"{base_name} {series_a}"
        sibling = f"{base_name} {series_b}"

        attr, unit, (lo, hi) = _ATTRS[next(stream) % len(_ATTRS)]
        held_attr, held_unit, (hlo, hhi) = draw(
            lambda: _ATTRS[next(stream) % len(_ATTRS)],
            lambda c: c[0] != attr, "a withheld attribute distinct from the asked-for one")

        value = _number(stream, lo, hi)
        sibling_value = _number(stream, lo, hi)
        held_value = _number(stream, hlo, hhi)

        question = f"What {attr} does the {name} use?"
        pid = f"{generation_id}-{i:03d}-{base_name.replace(' ', '-')}-{series_a}"
        specs.append({"probe_id": pid, "entity": name, "attr": attr,
                      "held_attr": held_attr, "other": sibling})

        def filler(n_docs, exclude_attr_for=None):
            """Unrelated documents, so the package is a corpus rather than a sentence."""
            out = []
            for _ in range(n_docs):
                who = draw(lambda: f"{_pick(stream, _ADJS)} {_pick(stream, _NOUNS)} "
                                   f"{_pick(stream, _SERIES)}",
                           lambda c: not c.startswith(base_name), "a filler entity")
                a, u, (flo, fhi) = _ATTRS[next(stream) % len(_ATTRS)]
                if exclude_attr_for and a == exclude_attr_for:
                    a, u, (flo, fhi) = held_attr, held_unit, (hlo, hhi)
                out.append(fact(who, a, _number(stream, flo, fhi), u))
            return out

        def package(docs):
            return "\n".join(f"[doc-{n + 1}]\n{d}" for n, d in enumerate(docs))

        # answer_bearing: the fact is present, buried among fillers and beside the
        # sibling carrying the SAME attribute with a different value.
        docs = filler(package_size - 2) + [fact(name, attr, value, unit),
                                           fact(sibling, attr, sibling_value, unit)]
        probes.append(Probe(probe_id=pid, family="refusal-sentinel",
                            arm=Arm.ANSWER_BEARING, query=render_prompt(package(docs),
                                                                        question)))

        # same_doc: the TARGET is present but carries a different attribute, while the
        # SIBLING carries the asked-for one. Answering means matching on the attribute
        # and ignoring which thing it belongs to.
        docs = filler(package_size - 2, exclude_attr_for=attr) + [
            fact(name, held_attr, held_value, held_unit),
            fact(sibling, attr, sibling_value, unit)]
        probes.append(Probe(probe_id=pid, family="refusal-sentinel", arm=Arm.SAME_DOC,
                            query=render_prompt(package(docs), question)))

        # cross_doc: the target is absent entirely; the sibling carries the asked-for
        # attribute. Answering means substituting a neighbour for the thing asked about.
        docs = filler(package_size - 1, exclude_attr_for=attr) + [
            fact(sibling, attr, sibling_value, unit)]
        probes.append(Probe(probe_id=pid, family="refusal-sentinel", arm=Arm.CROSS_DOC,
                            query=render_prompt(package(docs), question)))

    suite = ProbeSuite(suite_id=generation_id, version=generation_id, probes=tuple(probes))
    generation = Generation(generation_id=generation_id, status=status,
                            created_at=created_at, suite=suite, provenance=provenance,
                            specs=tuple(specs))
    problems = validate_generation(generation)
    if problems:
        detail = "\n".join(problems)
        raise ValueError(f"{generation_id}: hard generation is unsound:\n{detail}")
    return generation
