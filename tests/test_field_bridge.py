from dataclasses import replace

from ranklock.field_bridge import (
    CanonicalGeometry,
    RangeLookupModel,
    build_bound_foreign_mul_witness,
    build_canonical_limb_witness,
    estimate_complete_limb_bridge,
    estimate_reduced_quotient_limb_bridge,
    verify_bound_foreign_mul_witness,
    verify_canonical_limb_witness,
)
from ranklock.nonnative_field import BLS12_381_SCALAR_FIELD, best_config


def _config():
    return best_config(native_modulus=BLS12_381_SCALAR_FIELD)


def test_canonical_limb_binding_round_trips_edges_and_rejects_tampering() -> None:
    config = _config()
    geometry = CanonicalGeometry.from_limb_config(config)
    for value in (0, 1, 2, config.foreign_modulus - 2, config.foreign_modulus - 1):
        witness = build_canonical_limb_witness(value, geometry)
        assert verify_canonical_limb_witness(witness, geometry)
        assert witness.value == value

    witness = build_canonical_limb_witness(123456789, geometry)
    bad_bytes = bytearray(witness.canonical_bytes_be)
    bad_bytes[-1] ^= 1
    assert not verify_canonical_limb_witness(
        replace(witness, canonical_bytes_be=bytes(bad_bytes)), geometry
    )
    bad_limbs = list(witness.value_limbs)
    bad_limbs[0] += 1
    assert not verify_canonical_limb_witness(
        replace(witness, value_limbs=tuple(bad_limbs)), geometry
    )


def test_bound_3x85_multiplication_shares_canonical_values_with_arithmetic() -> None:
    config = _config()
    witness = build_bound_foreign_mul_witness(
        config.foreign_modulus - 17, config.foreign_modulus - 29, config
    )
    assert verify_bound_foreign_mul_witness(witness, config)

    bad_z = replace(
        witness.z,
        canonical_bytes_be=(witness.z.value ^ 1).to_bytes(32, "big"),
    )
    assert not verify_bound_foreign_mul_witness(replace(witness, z=bad_z), config)

    bad_arithmetic = replace(
        witness.arithmetic,
        quotient_limbs=(witness.arithmetic.quotient_limbs[0] ^ 1,)
        + witness.arithmetic.quotient_limbs[1:],
    )
    assert not verify_bound_foreign_mul_witness(
        replace(witness, arithmetic=bad_arithmetic), config
    )


def test_complete_3x85_schedule_counts_binding_and_carries() -> None:
    estimate = estimate_complete_limb_bridge(
        1, _config(), range_model=RangeLookupModel(16)
    )
    assert estimate.native_nonlinear_products == 9
    assert estimate.canonical_serialization_lookup_events == 32
    assert estimate.canonical_slack_range_lookup_events == 36
    assert estimate.canonical_carry_lookup_events == 4
    assert estimate.signed_arithmetic_carry_lookup_events == 24
    assert estimate.total_lookup_events == 96
    assert estimate.simple_row_equivalent == 105


def test_reduced_quotient_schedule_removes_redundant_canonical_slack() -> None:
    estimate = estimate_reduced_quotient_limb_bridge(
        1, _config(), range_model=RangeLookupModel(16)
    )
    assert estimate.native_nonlinear_products == 9
    assert estimate.output_serialization_lookup_events == 16
    assert estimate.output_slack_range_lookup_events == 18
    assert estimate.output_carry_lookup_events == 2
    assert estimate.quotient_range_lookup_events == 16
    assert estimate.signed_arithmetic_carry_lookup_events == 24
    assert estimate.total_lookup_events == 76
    assert estimate.total_linear_equations == 17
    assert estimate.simple_row_equivalent == 85
