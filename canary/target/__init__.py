"""Targets: the probed system, seen only from outside.

Endpoint-level, zero pipeline integration at run time — at most a one-time seed-document
onboarding act, which is content placed in a corpus and never code placed in a pipeline
(Core → Canary Response 001 §2). Nothing here reaches inside the system under test.
"""
from canary.target.base import Provenance, RawResponse, Target
from canary.target.mock import (
    BASELINE_CYCLE,
    REPEAT_CYCLE,
    Change,
    MockConfig,
    MockTarget,
    suite_from_cycle,
)

__all__ = [
    "BASELINE_CYCLE",
    "Change",
    "MockConfig",
    "MockTarget",
    "Provenance",
    "REPEAT_CYCLE",
    "RawResponse",
    "Target",
    "suite_from_cycle",
]
