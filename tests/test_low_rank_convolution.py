from dataclasses import replace

from ranklock.low_rank_convolution import (
    LowRankConvolutionPlan,
    build_low_rank_convolution_witness,
    exact_convolution,
    randomized_self_test,
    verify_low_rank_convolution_witness,
)
from ranklock.nonnative_field import BLS12_381_SCALAR_FIELD


def test_three_limb_convolution_uses_five_products_instead_of_nine() -> None:
    plan = LowRankConvolutionPlan.consecutive(3, BLS12_381_SCALAR_FIELD)
    witness = build_low_rank_convolution_witness(
        (3, 5, 7), (11, 13, 17), plan
    )
    assert plan.nonlinear_products == 5
    assert plan.schoolbook_products == 9
    assert witness.coefficients == exact_convolution(witness.left, witness.right)
    assert verify_low_rank_convolution_witness(witness, plan)


def test_low_rank_convolution_rejects_product_and_coefficient_tampering() -> None:
    plan = LowRankConvolutionPlan.consecutive(3, BLS12_381_SCALAR_FIELD)
    witness = build_low_rank_convolution_witness(
        (2**84 + 1, 2**83 + 3, 2**82 + 5),
        (2**81 + 7, 2**80 + 11, 2**79 + 13),
        plan,
    )
    bad_products = list(witness.point_products)
    bad_products[2] ^= 1
    assert not verify_low_rank_convolution_witness(
        replace(witness, point_products=tuple(bad_products)), plan
    )
    bad_coefficients = list(witness.coefficients)
    bad_coefficients[1] ^= 1
    assert not verify_low_rank_convolution_witness(
        replace(witness, coefficients=tuple(bad_coefficients)), plan
    )


def test_low_rank_convolution_randomized_for_supported_limb_geometries() -> None:
    for limbs, limb_bits in ((3, 85), (4, 64), (5, 51), (6, 43), (8, 32)):
        randomized_self_test(
            limbs=limbs,
            limb_bits=limb_bits,
            native_modulus=BLS12_381_SCALAR_FIELD,
            cases=20,
            seed=limbs * 1000 + limb_bits,
        )
