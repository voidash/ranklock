from __future__ import annotations

from ranklock.field import BN254_BASE_FIELD
from ranklock.kzg_we_model import generator
from ranklock.public_multiplicand import (
    inventory,
    reconstruct_scalar_le,
    scalar_bits_le,
    verify_linearized_terminal_group_equation,
)


def test_exposing_b_removes_the_terminal_hidden_product() -> None:
    modulus = BN254_BASE_FIELD
    a, b, c, eq = 17, 19, 23, 29
    claim = eq * (a * b - c) % modulus
    assert verify_linearized_terminal_group_equation(
        current_claim=claim,
        equality_weight=eq,
        public_b=b,
        a_g1=generator("G1", modulus).scale(a),
        c_g1=generator("G1", modulus).scale(c),
    )
    assert not verify_linearized_terminal_group_equation(
        current_claim=claim,
        equality_weight=eq,
        public_b=b + 1,
        a_g1=generator("G1", modulus).scale(a),
        c_g1=generator("G1", modulus).scale(c),
    )


def test_exposed_scalar_roundtrips_through_projective_bits() -> None:
    value = BN254_BASE_FIELD - 12345
    bits = scalar_bits_le(value)
    assert len(bits) == 254
    assert reconstruct_scalar_le(bits) == value


def test_naive_catalog_for_132_bytes_plus_b_is_four_megabytes() -> None:
    estimate = inventory()
    assert estimate.total_projective_bytes == 164
    assert estimate.hidden_bilinear_gates == 0
    assert estimate.naive_compact_catalog_bytes == 4_030_560
    assert estimate.naive_compact_catalog_bytes > 1024 * 1024
