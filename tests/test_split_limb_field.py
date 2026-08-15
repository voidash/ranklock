from dataclasses import replace

from ranklock.split_limb_field import (
    SplitLimbConfig,
    build_split_limb_mul_witness,
    estimate_split_limb_schedule,
    estimate_split_limb_reduced_quotient_schedule,
    randomized_self_test,
    verify_split_limb_mul_witness,
)


def test_2x127_geometry_has_exact_native_product_headroom() -> None:
    config = SplitLimbConfig()
    assert config.base**2 > config.foreign_modulus
    assert config.base**2 < config.native_modulus
    assert config.native_modulus.bit_length() == 255


def test_2x127_split_product_passes_edges_and_random_cases() -> None:
    randomized_self_test(cases=100, seed=0x2127)


def test_2x127_split_product_rejects_chunk_digit_and_carry_tampering() -> None:
    witness = build_split_limb_mul_witness(2**200 + 17, 2**199 + 29)
    assert verify_split_limb_mul_witness(witness)

    bad_splits = list(witness.xy_splits)
    bad_splits[0] = replace(bad_splits[0], low=bad_splits[0].low ^ 1)
    assert not verify_split_limb_mul_witness(
        replace(witness, xy_splits=tuple(bad_splits))
    )

    bad_digits = list(witness.normalized_digits)
    bad_digits[1] ^= 1
    assert not verify_split_limb_mul_witness(
        replace(witness, normalized_digits=tuple(bad_digits))
    )

    bad_carries = list(witness.reduction_carries)
    bad_carries[1] ^= 1
    assert not verify_split_limb_mul_witness(
        replace(witness, reduction_carries=tuple(bad_carries))
    )


def test_2x127_complete_schedule_exposes_lookup_tradeoff() -> None:
    estimate = estimate_split_limb_schedule(1)
    assert estimate.native_nonlinear_products == 4
    assert estimate.canonical_lookup_events == 66
    assert estimate.exact_product_split_lookup_events == 128
    assert estimate.normalized_digit_lookup_events == 24
    assert estimate.normalization_carry_lookup_events == 5
    assert estimate.total_lookup_events == 223
    assert estimate.simple_row_equivalent == 227


def test_2x127_reduced_quotient_schedule_removes_only_internal_slack() -> None:
    estimate = estimate_split_limb_reduced_quotient_schedule(1)
    assert estimate.native_nonlinear_products == 4
    assert estimate.canonical_lookup_events == 49
    assert estimate.exact_product_split_lookup_events == 128
    assert estimate.normalized_digit_lookup_events == 24
    assert estimate.normalization_carry_lookup_events == 5
    assert estimate.total_lookup_events == 206
    assert estimate.linear_equations == 26
    assert estimate.simple_row_equivalent == 210
