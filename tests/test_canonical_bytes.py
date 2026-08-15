from __future__ import annotations

from dataclasses import replace

from ranklock.canonical_bytes import (
    build_canonical_byte_witness,
    estimate_canonical_binding,
    verify_canonical_byte_witness,
)
from ranklock.crt_field import CrtFieldConfig


def test_canonical_byte_witness_binds_range_and_both_residues() -> None:
    config = CrtFieldConfig()
    for value in (0, 1, 2, config.foreign_modulus - 2, config.foreign_modulus - 1):
        witness = build_canonical_byte_witness(value, config)
        assert verify_canonical_byte_witness(witness, config)
        assert witness.value == value


def test_canonical_byte_tampering_fails() -> None:
    config = CrtFieldConfig()
    witness = build_canonical_byte_witness(12345678901234567890, config)
    bad_slack = bytearray(witness.slack_bytes_be)
    bad_slack[-1] ^= 1
    assert not verify_canonical_byte_witness(
        replace(witness, slack_bytes_be=bytes(bad_slack)), config
    )
    carries = list(witness.carries_le)
    carries[1] ^= 1
    assert not verify_canonical_byte_witness(
        replace(witness, carries_le=tuple(carries)), config
    )
    residues = (
        (witness.residues[0] + 1) % config.native_moduli[0],
        witness.residues[1],
    )
    assert not verify_canonical_byte_witness(
        replace(witness, residues=residues), config
    )


def test_complete_crt_binding_inventory_is_not_just_two_products() -> None:
    # z and quotient are fresh for each known multiplication.
    inventory = estimate_canonical_binding(2 * 25_889)
    assert inventory["raw_shared_value_bytes"] == 1_656_896
    assert inventory["byte_lookups"] == 3_313_792
    assert inventory["carry_bit_checks"] == 1_605_118
