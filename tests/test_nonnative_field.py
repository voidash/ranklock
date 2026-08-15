from __future__ import annotations

from dataclasses import replace

from ranklock.field import BN254_BASE_FIELD
from ranklock.nonnative_field import (
    BLS12_381_SCALAR_FIELD,
    BN254_SCALAR_FIELD,
    best_config,
    build_mul_witness,
    candidate_configs,
    estimate_schedule,
    randomized_self_test,
    verify_mul_witness,
)


def test_three_limb_configuration_is_best_for_bn254_kzg() -> None:
    config = best_config(native_modulus=BN254_SCALAR_FIELD)
    assert config.limbs == 3
    assert config.limb_bits == 85
    assert config.nonlinear_products_per_mul == 9
    assert config.nonlinear_products_per_square == 6
    assert config.safe_no_wrap
    assert not any(candidate.limbs == 2 for candidate in candidate_configs())


def test_three_limb_configuration_also_works_for_bls12_381_kzg() -> None:
    config = best_config(native_modulus=BLS12_381_SCALAR_FIELD)
    assert config.limbs == 3
    assert config.limb_bits == 85
    assert config.safe_no_wrap


def test_exact_foreign_multiplication_witness_and_tampering() -> None:
    config = best_config()
    x = BN254_BASE_FIELD - 123456789
    y = BN254_BASE_FIELD - 987654321
    witness = build_mul_witness(x, y, config)
    assert verify_mul_witness(witness, config)
    bad_z = list(witness.z_limbs)
    bad_z[0] = (bad_z[0] + 1) % config.base
    assert not verify_mul_witness(replace(witness, z_limbs=tuple(bad_z)), config)
    bad_carries = list(witness.carries)
    bad_carries[1] += 1
    assert not verify_mul_witness(replace(witness, carries=tuple(bad_carries)), config)


def test_randomized_non_native_multiplication() -> None:
    randomized_self_test(best_config(), cases=200, seed=0x52414E4B)


def test_sparse_verifier_schedule_fits_real_pairing_field_route() -> None:
    estimate = estimate_schedule(25_889, best_config())
    assert estimate.native_nonlinear_products_upper_bound == 233_001
    assert estimate.native_nonlinear_products_upper_bound < 645_221
