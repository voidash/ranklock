from dataclasses import replace

import pytest

from ranklock.constraint_backend import (
    ConstraintViolation,
    compile_dual_crt_owner_trace,
    compile_rank5_3x85_trace,
    compile_split_2x127_trace,
)
from ranklock.crt_bridge import build_bound_crt_mul_witness
from ranklock.crt_field import CrtEncodedValue, CrtFieldConfig
from ranklock.canonical_bytes import CanonicalByteWitness
from ranklock.low_rank_field_bridge import build_low_rank_bound_foreign_mul_witness
from ranklock.nonnative_field import BLS12_381_SCALAR_FIELD, best_config
from ranklock.split_limb_field import build_split_limb_mul_witness


def _limb_config():
    return best_config(native_modulus=BLS12_381_SCALAR_FIELD)


def test_rank5_constraint_trace_matches_inventory_and_rejects_bad_product() -> None:
    config = _limb_config()
    witness = build_low_rank_bound_foreign_mul_witness(
        config.foreign_modulus - 31, config.foreign_modulus - 47, config
    )
    report = compile_rank5_3x85_trace(witness, config)
    assert report.native_nonlinear_products == 5
    assert report.logical_lookup_events == 76
    assert report.linear_relation_events == 17
    assert report.estimate_match
    assert report.selectable

    products = list(witness.convolution.point_products)
    products[3] ^= 1
    with pytest.raises(ConstraintViolation):
        compile_rank5_3x85_trace(
            replace(
                witness,
                convolution=replace(
                    witness.convolution, point_products=tuple(products)
                ),
            ),
            config,
        )


def test_split_constraint_trace_matches_inventory_and_rejects_bad_chunk() -> None:
    witness = build_split_limb_mul_witness(2**210 + 17, 2**197 + 29)
    report = compile_split_2x127_trace(witness)
    assert report.native_nonlinear_products == 4
    assert report.logical_lookup_events == 206
    assert report.standalone_linear_constraints == 22
    assert report.embedded_linear_relations == 4
    assert report.linear_relation_events == 26
    assert report.estimate_match
    assert report.selectable

    splits = list(witness.xy_splits)
    splits[2] = replace(splits[2], high=splits[2].high ^ 1)
    with pytest.raises(ConstraintViolation):
        compile_split_2x127_trace(replace(witness, xy_splits=tuple(splits)))


def test_dual_crt_trace_matches_owner_cost_but_remains_unbound() -> None:
    witness = build_bound_crt_mul_witness(2**201 + 7, 2**181 + 13)
    report = compile_dual_crt_owner_trace(witness)
    assert report.native_nonlinear_products == 2
    assert report.logical_lookup_events == 63
    assert report.linear_relation_events == 20
    assert report.estimate_match
    assert not report.selectable
    assert report.cross_field_binding.startswith("MISSING")

    bad_z = replace(
        witness.z,
        residues=(witness.z.residues[0] ^ 1, witness.z.residues[1]),
    )
    with pytest.raises(ConstraintViolation):
        compile_dual_crt_owner_trace(replace(witness, z=bad_z))


def test_rank5_compiler_ignores_unused_quotient_slack_but_not_value_binding() -> None:
    config = _limb_config()
    witness = build_low_rank_bound_foreign_mul_witness(2**190 + 3, 2**173 + 5, config)
    bad_slack = replace(
        witness.bound.quotient,
        slack_limbs=tuple(0 for _ in witness.bound.quotient.slack_limbs),
        carries_le=tuple(0 for _ in witness.bound.quotient.carries_le),
    )
    relaxed = replace(witness, bound=replace(witness.bound, quotient=bad_slack))
    assert compile_rank5_3x85_trace(relaxed, config).estimate_match

    bad_bytes = replace(
        witness.bound.quotient,
        canonical_bytes_be=(witness.bound.quotient.value ^ 1).to_bytes(32, "big"),
    )
    with pytest.raises(ConstraintViolation):
        compile_rank5_3x85_trace(
            replace(witness, bound=replace(witness.bound, quotient=bad_bytes)), config
        )


def test_dual_crt_compiler_rejects_255_bit_quotient_encoding() -> None:
    config = CrtFieldConfig()
    witness = build_bound_crt_mul_witness(7, 11, config)
    value = 1 << 254
    residues = tuple(value % modulus for modulus in config.native_moduli)
    bounded = CanonicalByteWitness(
        value.to_bytes(32, "big"),
        bytes(32),
        tuple(0 for _ in range(33)),
        residues,
    )
    core = replace(
        witness.core,
        quotient=CrtEncodedValue(value.to_bytes(32, "big"), residues),
    )
    with pytest.raises(ConstraintViolation):
        compile_dual_crt_owner_trace(replace(witness, quotient=bounded, core=core))
