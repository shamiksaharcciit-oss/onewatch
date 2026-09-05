"""E006: quantise once, round-half-even, 6 decimal places, at the measurement boundary.

After this boundary the engine holds no floats. Not "avoids floats where convenient" —
holds none. A float that survives into a comparison makes the comparison's result
depend on accumulated representation error, and a receipt whose verdict depends on
representation error is not re-derivable by anyone who computed in a different order.

    measurement  ──quantise()──>  Decimal / canonical string  ──>  engine, detector,
      (float)      THE boundary      (exact, comparable)            receipt, ledger

`canonical_bytes` enforces the second half of this independently: it raises TypeError
on any float in a canonical structure. The two controls are deliberately redundant —
this module makes floats leave, the canonicaliser makes sure they never arrive.

A NOTE ON WHERE THIS IS AND IS NOT USED
---------------------------------------
The refusal-sentinel family built in C2 never calls this. Its measurements are counts:
how many probes refused, out of how many asked. Those are integers from the start, and
integers do not need a quantisation boundary — they need only to not be turned into
rates, which is a separate rule (see `canary/suite/refusal.py`). This module exists for
the continuous measures that arrive with the retrieval family in C3: similarity scores,
overlap fractions, distances.

That is worth stating rather than leaving implicit, because an unused boundary is a
boundary nobody has tested against real data. It is tested here against constructed
data, and the first real caller arrives in C3.

THE TIE INTERPRETATION, DECLARED
--------------------------------
"Round-half-even" presupposes that ties exist. Whether a tie exists at all depends on
how the incoming float is read, and the two readings disagree:

    value = 1.0000015                      (the literal a human wrote)

    Decimal(value)      = 1.00000149999999993306...   -> quantises to 1.000001
    Decimal(str(value)) = Decimal("1.0000015")        -> a true tie, half-even -> 1.000002

**This module uses `Decimal(str(value))`**, for two reasons, and the rival reading is
recorded here so the choice is auditable rather than accidental:

1. Under the exact-binary reading, a tie is essentially unreachable — IEEE-754 doubles
   almost never land exactly on a 7th-decimal half. A rule that specifies round-half-even
   and then never encounters a half is a rule whose stated content is dead. Reading the
   value as the decimal a human wrote makes half-even mean what it says.
2. `repr()` of a float in Python 3 is the shortest string that round-trips, which is
   specified behaviour and identical across platforms and versions. It is not the E14
   hazard: that was `str.rstrip()` consulting the Unicode Character Database, whose
   content changes between releases. Float repr does not move.

This interpretation is inside `i_digest` via `QUANTISATION`, so a run that used a
different reading is a run with a different instrument, and says so.
"""
from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation

#: Decimal places. Inside `i_digest`; changing it is a visible instrument change.
PLACES = 6

#: The exponent `Decimal.quantize` needs: 6 places -> Decimal("0.000001").
_EXP = Decimal(1).scaleb(-PLACES)

#: Declared quantisation parameters. Travels inside the instrument digest, so a run
#: that quantised differently cannot be silently compared against one that did not.
QUANTISATION = {
    "places": PLACES,
    "rounding": "ROUND_HALF_EVEN",
    "float_reading": "decimal-repr",   # Decimal(str(x)); see the module docstring
}


class QuantisationError(ValueError):
    """A value that cannot cross the boundary. Never silently dropped or defaulted."""


def quantise(value: float | int | str | Decimal) -> Decimal:
    """Cross the measurement boundary exactly once. Returns an exact Decimal.

    Float input is accepted **here and nowhere else in the engine** — that is the
    entire point of a boundary. Non-finite values are refused rather than encoded:
    NaN and infinity have no canonical decimal form, and a receipt that recorded one
    would be a receipt asserting a quantity that does not exist.
    """
    if isinstance(value, bool):
        # bool is an int subclass; quantising True to 1.000000 is almost certainly a
        # measurement bug upstream, so it is surfaced rather than accommodated.
        raise QuantisationError("bool is not a measurement; refusing to quantise it")
    try:
        d = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as e:
        raise QuantisationError(f"not a decimal quantity: {value!r}") from e
    if not d.is_finite():
        raise QuantisationError(
            f"non-finite measurement: {value!r}. NaN and infinity have no canonical "
            f"decimal form; the measurement is wrong and must be fixed upstream.")
    return d.quantize(_EXP, rounding=ROUND_HALF_EVEN)


def quantised_str(value: float | int | str | Decimal) -> str:
    """Quantise, then render in the canonical decimal form the receipt will carry.

    Note the shape: `canon_decimal` strips trailing zeros, so 0.5 renders "0.5" and not
    "0.500000". The quantisation fixes the PRECISION of the measurement; the canonical
    form fixes the BYTES of its rendering. Conflating them is how two equal quantities
    end up with two digests.
    """
    from canary.acj import canon_decimal
    return canon_decimal(quantise(value))
