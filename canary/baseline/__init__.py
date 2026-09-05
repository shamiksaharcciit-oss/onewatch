"""Baselines: declared, content-addressed, chained — never a rolling average.

A monitor that silently accepts change as the new normal is a monitor that forgets.
"""
from canary.baseline.band import BandViolation, VarianceBand, calibrate
from canary.baseline.declare import Baseline, Declaration, chain, declare

__all__ = ["Baseline", "BandViolation", "Declaration", "VarianceBand", "calibrate",
           "chain", "declare"]
