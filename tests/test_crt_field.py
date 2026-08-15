from __future__ import annotations

from dataclasses import replace

from ranklock.crt_field import (
    CrtEncodedValue,
    CrtFieldConfig,
    build_mul_witness,
    bounded_quotient_congruences_imply_exact,
    congruences_imply_exact,
    estimate_schedule,
    randomized_self_test,
    verify_mul_witness,
)


def test_bn254_and_bls_scalar_fields_dominate_foreign_square() -> None:
    config = CrtFieldConfig()
    assert config.crt_modulus > config.foreign_modulus**2
    assert config.safety_ratio > 2.39
    assert config.crt_modulus.bit_length() == 509


def test_dual_congruences_prove_exact_foreign_multiplication() -> None:
    config = CrtFieldConfig()
    randomized_self_test(config, cases=200, seed=23)
    witness = build_mul_witness(config.foreign_modulus - 1, config.foreign_modulus - 2, config)
    assert verify_mul_witness(witness, config)
    x, y, z, quotient = (
        witness.x.decode(config),
        witness.y.decode(config),
        witness.z.decode(config),
        witness.quotient.decode(config),
    )
    assert congruences_imply_exact(
        x=x, y=y, z=z, quotient=quotient, config=config
    )


def test_cross_field_residue_or_canonical_byte_substitution_fails() -> None:
    config = CrtFieldConfig()
    witness = build_mul_witness(123456789, 987654321, config)
    bad_residues = (
        (witness.z.residues[0] + 1) % config.native_moduli[0],
        witness.z.residues[1],
    )
    assert not verify_mul_witness(
        replace(witness, z=replace(witness.z, residues=bad_residues)), config
    )
    other = CrtEncodedValue.encode(witness.z.decode(config) + 1, config)
    assert not verify_mul_witness(
        replace(witness, z=replace(witness.z, canonical=other.canonical)), config
    )


def test_crt_schedule_uses_two_native_products_but_requires_dual_proofs() -> None:
    estimate = estimate_schedule(25_889)
    assert estimate.native_multiplications_total == 51_778
    assert estimate.native_multiplications_per_field == 25_889
    assert estimate.proof_fields == 2
    assert estimate.byte_lookup_events_if_byte_range_table == 25_889 * 64


def test_unbound_dual_proofs_can_describe_two_unrelated_multiplications() -> None:
    from ranklock.crt_field import UnboundCrtMulWitness, verify_unbound_congruences

    config = CrtFieldConfig()
    # Each native proof is internally valid, but they encode different integers.
    witness = UnboundCrtMulWitness(
        (
            (2, 3, 6, 0),
            (5, 7, 35, 0),
        )
    )
    assert verify_unbound_congruences(witness, config)
    assert witness.field_tuples[0] != witness.field_tuples[1]


def test_254_bits_is_the_largest_quotient_range_certified_by_crt_bound() -> None:
    config = CrtFieldConfig()
    assert config.minimum_honest_quotient_bits == 254
    assert config.maximum_crt_exact_quotient_bits == 254
    assert config.bounded_quotient_is_crt_exact(254)
    assert config.bounded_quotient_safety_ratio(254) > 1.81
    assert not config.bounded_quotient_is_crt_exact(255)
    assert config.bounded_quotient_safety_ratio(255) < 1.0

    witness = build_mul_witness(
        config.foreign_modulus - 1, config.foreign_modulus - 1, config
    )
    assert bounded_quotient_congruences_imply_exact(
        x=witness.x.decode(config),
        y=witness.y.decode(config),
        z=witness.z.decode(config),
        quotient=witness.quotient.decode(config),
        quotient_bits=254,
        config=config,
    )
    assert not bounded_quotient_congruences_imply_exact(
        x=0, y=0, z=0, quotient=0, quotient_bits=255, config=config
    )
