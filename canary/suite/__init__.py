"""The canary suite: a frozen, versioned probe set.

**The suite IS the instrument.** Suite, detector config and quantisation parameters
together form the `i_digest`. Changing a probe is therefore a visible instrument
change, never silent drift — a run under a different suite carries a different
instrument digest and cannot be quietly compared against runs that came before it.
"""
from canary.suite.probe import Arm, Expect, Probe, ProbeSuite
from canary.suite.refusal import (
    REFUSAL_INSTRUMENT_VERSIONS,
    RefusalInstrument,
    Verdict,
)

__all__ = [
    "Arm",
    "Expect",
    "Probe",
    "ProbeSuite",
    "REFUSAL_INSTRUMENT_VERSIONS",
    "RefusalInstrument",
    "Verdict",
]
