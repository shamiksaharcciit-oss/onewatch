#!/usr/bin/env python3
"""C's mock dry run: the calibration path executed end to end, offline and free.

Q08 ruled the mock in scope -- the line is the live endpoint, not testing -- and the
reason to run it is narrow and worth stating: it proves the calibration harness works
before a budgeted session spends anything on it. Shipping an uncalibrated family whose
calibration path had never executed would be the worse outcome.

**This is not a calibration.** The band below is measured from a same-config repeat pair
of MOCK runs. It says nothing about a live system's noise floor and is not a headroom
result for this family; the mock is deterministic, so its noise is zero by construction
rather than by measurement.
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from canary.baseline import Declaration, calibrate, declare
from canary.detector import compare
from canary.freezer import freeze_run
from canary.suite.refusal import RefusalInstrument
from canary.suite.retrieval import build_retrieval_generation
from canary.target.retrieval_mock import (RetrievalChange, RetrievalMockConfig,
                                          RetrievalMockTarget)

SEED = "dry-run-seed-not-the-real-one"
V3 = RefusalInstrument("v3")
g = build_retrieval_generation("rg-dry", SEED, n_documents=6, facts_per_document=2)

def run(cfg, label):
    return freeze_run(f"rg-{label}", g.suite,
                      RetrievalMockTarget(corpus=g.corpus, config=cfg), instrument=V3)

print("family       retrieval-grounded (Q01(a) seed pack)")
print(f"corpus       {len(g.corpus.documents)} documents, {len(g.corpus.facts)} facts, "
      f"digest {g.corpus.digest[:16]}")
print(f"suite        {len(g.suite)} probes  arms={g.suite.arm_counts()}  "
      f"digest {g.suite.digest[:16]}")
print(f"census       {len(g.exclusions)} package(s) excluded with cause")
for e in g.exclusions:
    print(f"             {e.arm}/{e.entity}: {e.cause[:70]}")

b1, b2 = run(RetrievalMockConfig(), "b1"), run(RetrievalMockConfig(), "b2")
band = calibrate("refusal-sentinel", "v3", [b1, b2],
                 "same-config repeat pair, measured at baseline")
baseline = declare("rg-baseline", b1, band,
                   Declaration(declared_by="canary build session (mock dry run)",
                               declared_at="2026-08-27T12:00:00Z",
                               reason="mock dry run; NOT a live calibration"))
print(f"\nband         {band.per_arm}  (deterministic mock: zero by construction)")
print(f"baseline     e_digest {b1.e_digest[:16]}  i_digest {b1.i_digest[:16]}\n")

print(f"{'injected change':18} {'outcome':10} {'moved':>5}  why")
cases = [("(repeat, no change)", RetrievalMockConfig()),
         ("index_refresh", RetrievalMockConfig(change=RetrievalChange.INDEX_REFRESH,
                                               dropped_doc_id=g.corpus.documents[0].doc_id)),
         ("grounding_drift", RetrievalMockConfig(change=RetrievalChange.GROUNDING_DRIFT)),
         ("format_drift", RetrievalMockConfig(change=RetrievalChange.FORMAT_DRIFT))]
runs = []
for label, cfg in cases:
    r = run(cfg, label)
    runs.append(r)
    d = compare(baseline, r).as_canonical()
    why = d["reasons"][0] if d["reasons"] else "-"
    print(f"{label:18} {d['outcome']:10} {d['n_probe_deltas']:>5}  {why[:64]}")

print(f"\nX-7          i_digest identical across clean and all variants: "
      f"{len({r.i_digest for r in runs}) == 1}")
print(f"             bodies moved under format_drift: "
      f"{runs[0].bodies_digest != runs[3].bodies_digest}")
print("\nSTOPPING LINE  calibration-ready. No live endpoint was touched; no spend.")
print("               " + g.headroom_note())
