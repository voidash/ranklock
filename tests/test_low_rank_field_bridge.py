from dataclasses import replace

from ranklock.low_rank_field_bridge import (
    build_low_rank_bound_foreign_mul_witness,
    estimate_low_rank_limb_bridge,
    estimate_low_rank_reduced_quotient_limb_bridge,
    verify_low_rank_bound_foreign_mul_witness,
)
from ranklock.nonnative_field import BLS12_381_SCALAR_FIELD, best_config


def _config():
    return best_config(native_modulus=BLS12_381_SCALAR_FIELD)


def test_rank_five_3x85_bridge_passes_and_rejects_interpolation_tampering() -> None:
    config = _config()
    witness = build_low_rank_bound_foreign_mul_witness(
        config.foreign_modulus - 101, config.foreign_modulus - 211, config
    )
    assert verify_low_rank_bound_foreign_mul_witness(witness, config)

    coefficients = list(witness.convolution.coefficients)
    coefficients[2] ^= 1
    assert not verify_low_rank_bound_foreign_mul_witness(
        replace(
            witness,
            convolution=replace(
                witness.convolution, coefficients=tuple(coefficients)
            ),
        ),
        config,
    )


def test_rank_five_schedule_preserves_lookup_cost_and_removes_four_products() -> None:
    estimate = estimate_low_rank_limb_bridge(1, _config())
    assert estimate.convolution_rank == 5
    assert estimate.schoolbook_products_avoided == 4
    assert estimate.native_nonlinear_products == 5
    assert estimate.total_lookup_events == 96
    assert estimate.simple_row_equivalent == 101


def test_rank_five_reduced_quotient_schedule_is_new_single_field_baseline() -> None:
    estimate = estimate_low_rank_reduced_quotient_limb_bridge(1, _config())
    assert estimate.convolution_rank == 5
    assert estimate.native_nonlinear_products == 5
    assert estimate.total_lookup_events == 76
    assert estimate.total_linear_equations == 17
    assert estimate.simple_row_equivalent == 81
