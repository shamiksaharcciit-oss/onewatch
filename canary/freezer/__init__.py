"""The freezer: responses frozen verbatim as received; each run sealed as `E_t`.

E10 verbatim on the received half, ACJ-canonical on the generated half, and E006's
single quantise boundary between measurement and everything downstream.
"""
from canary.freezer.freeze import FROZEN_SCHEMA, FrozenReply, FrozenRun, freeze_run

__all__ = ["FROZEN_SCHEMA", "FrozenReply", "FrozenRun", "freeze_run"]
