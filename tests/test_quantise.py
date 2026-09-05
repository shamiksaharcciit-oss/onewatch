"""E006: the single quantisation boundary."""
from __future__ import annotations

from decimal import Decimal

import pytest

from canary.acj import canon_decimal, canonical_bytes
from canary.quantise import PLACES, QUANTISATION, QuantisationError, quantise, quantised_str


def test_six_places_round_half_even():
    assert PLACES == 6
    assert QUANTISATION["rounding"] == "ROUND_HALF_EVEN"


@pytest.mark.parametrize("value,expected", [
    ("0.0000015", "0.000002"),   # tie -> even
    ("0.0000025", "0.000002"),   # tie -> even (down, because 2 is even)
    ("0.0000035", "0.000004"),   # tie -> even (up)
    ("0.0000005", "0.000000"),   # tie -> even, and zero is even
    ("0.0000014", "0.000001"),   # below the half
    ("0.0000016", "0.000002"),   # above the half
])
def test_ties_go_to_even_not_away_from_zero(value, expected):
    """Half-even, not half-up. Half-up biases every tied measurement upward, and a
    detector fed a systematically inflated series drifts in one direction forever."""
    assert quantise(value) == Decimal(expected)


def test_the_declared_float_reading_is_the_one_implemented():
    """The module declares `Decimal(str(x))`; this asserts the declaration is true.

    Under the rival reading -- `Decimal(value)`, the exact binary expansion -- 1.0000015
    is 1.00000149999999993... and quantises DOWN to 1.000001. The declared reading sees a
    true tie and rounds half-even to 1.000002. The choice is inside `i_digest`, so a run
    that used the other reading is a run under a different instrument; this test is what
    stops the two being confused.
    """
    assert quantise(1.0000015) == Decimal("1.000002")
    assert QUANTISATION["float_reading"] == "decimal-repr"


def test_quantise_returns_an_exact_decimal_never_a_float():
    result = quantise(0.1 + 0.2)
    assert isinstance(result, Decimal)
    assert not isinstance(result, float)
    assert result == Decimal("0.3")


def test_the_boundary_is_idempotent():
    """Quantise ONCE. Applying it twice must not move the value, or 'once' would be a
    property of call sites rather than of the function."""
    once = quantise(0.123456789)
    assert quantise(once) == once


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_measurements_are_refused_not_encoded(bad):
    """NaN and infinity have no canonical decimal form. A receipt asserting one would
    assert a quantity that does not exist."""
    with pytest.raises(QuantisationError, match="non-finite"):
        quantise(bad)


def test_bool_is_not_a_measurement():
    with pytest.raises(QuantisationError, match="bool is not a measurement"):
        quantise(True)


def test_a_non_numeric_value_is_refused_with_its_value_named():
    with pytest.raises(QuantisationError, match="not a decimal quantity"):
        quantise("not a number")


def test_quantised_output_survives_canonicalisation():
    """The other half of E006: `canonical_bytes` forbids floats outright, so anything
    that crossed the boundary correctly can enter a receipt and anything that did not,
    cannot."""
    payload = {"score": quantised_str(0.3333333333)}
    assert payload["score"] == "0.333333"
    canonical_bytes(payload)

    with pytest.raises(TypeError, match="floats are forbidden"):
        canonical_bytes({"score": 0.3333333333})


def test_quantisation_fixes_precision_and_canonical_form_fixes_bytes():
    """Two different jobs. Conflating them is how two equal quantities get two digests."""
    assert quantise("0.5") == Decimal("0.500000")
    assert quantised_str("0.5") == "0.5"
    assert canon_decimal(Decimal("0.500000")) == "0.5"
    assert quantised_str(0.5) == quantised_str("0.50") == quantised_str(Decimal("0.5"))


def test_zero_renders_canonically_regardless_of_sign_or_scale():
    assert quantised_str(-0.0) == "0"
    assert quantised_str("0.0000000001") == "0"
