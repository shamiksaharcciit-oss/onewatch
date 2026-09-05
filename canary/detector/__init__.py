"""The change detector: a pure, float-free comparison that never re-queries the model."""
from canary.detector.compare import Comparison, Outcome, ProbeDelta, compare

__all__ = ["Comparison", "Outcome", "ProbeDelta", "compare"]
