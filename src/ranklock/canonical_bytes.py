from __future__ import annotations

"""Canonical-byte binding for dual-field CRT values.

A dual-field proof is meaningful only when both residue encodings refer to one
canonical integer in ``[0,q)``.  This module models a byte-level witness:

* 32 public/shared value bytes;
* 32 slack bytes for ``value + slack = q-1``;
* byte-addition carry bits;
* linear recomposition into each native proof field.

The arithmetic is exact.  The module inventories lookup/Boolean/linear costs
but does not provide the cross-PCS commitment that makes the bytes shared in a
real proof.
"""

from dataclasses import dataclass
from typing import Sequence

from .crt_field import CrtFieldConfig


class CanonicalByteError(ValueError):
    pass


BYTE_WIDTH = 32


@dataclass(frozen=True, slots=True)
class CanonicalByteWitness:
    value_bytes_be: bytes
    slack_bytes_be: bytes
    carries_le: tuple[int, ...]
    residues: tuple[int, int]

    @property
    def value(self) -> int:
        return int.from_bytes(self.value_bytes_be, "big")


@dataclass(frozen=True, slots=True)
class CanonicalByteCost:
    value_byte_lookups: int = BYTE_WIDTH
    slack_byte_lookups: int = BYTE_WIDTH
    carry_bit_checks: int = BYTE_WIDTH - 1
    byte_addition_linear_equations: int = BYTE_WIDTH
    residue_recomposition_linear_equations: int = 2
    schema: str = "ranklock-canonical-byte-cost-v1"

    @property
    def byte_lookups(self) -> int:
        return self.value_byte_lookups + self.slack_byte_lookups

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "value_byte_lookups": self.value_byte_lookups,
            "slack_byte_lookups": self.slack_byte_lookups,
            "byte_lookups_total": self.byte_lookups,
            "carry_bit_checks": self.carry_bit_checks,
            "byte_addition_linear_equations": self.byte_addition_linear_equations,
            "residue_recomposition_linear_equations": self.residue_recomposition_linear_equations,
        }


def _residues_from_bytes(data: bytes, config: CrtFieldConfig) -> tuple[int, int]:
    result = []
    for modulus in config.native_moduli:
        accumulator = 0
        for byte in data:
            accumulator = (accumulator * 256 + byte) % modulus
        result.append(accumulator)
    return tuple(result)  # type: ignore[return-value]


def build_canonical_byte_witness(
    value: int, config: CrtFieldConfig = CrtFieldConfig()
) -> CanonicalByteWitness:
    value = int(value)
    if not 0 <= value < config.foreign_modulus:
        raise CanonicalByteError("value is outside canonical foreign-field range")
    slack = config.foreign_modulus - 1 - value
    value_be = value.to_bytes(BYTE_WIDTH, "big")
    slack_be = slack.to_bytes(BYTE_WIDTH, "big")
    target_le = (config.foreign_modulus - 1).to_bytes(BYTE_WIDTH, "little")
    value_le = tuple(reversed(value_be))
    slack_le = tuple(reversed(slack_be))
    carries = [0]
    for index in range(BYTE_WIDTH):
        total = value_le[index] + slack_le[index] + carries[-1]
        target = target_le[index]
        if (total - target) % 256:
            raise AssertionError("canonical byte addition carry is not integral")
        carries.append((total - target) // 256)
    if carries[-1] != 0 or any(carry not in (0, 1) for carry in carries):
        raise AssertionError("canonical byte addition carries are not bits")
    return CanonicalByteWitness(
        value_be,
        slack_be,
        tuple(carries),
        _residues_from_bytes(value_be, config),
    )


def verify_canonical_byte_witness(
    witness: CanonicalByteWitness, config: CrtFieldConfig = CrtFieldConfig()
) -> bool:
    try:
        if len(witness.value_bytes_be) != BYTE_WIDTH or len(witness.slack_bytes_be) != BYTE_WIDTH:
            return False
        if len(witness.carries_le) != BYTE_WIDTH + 1:
            return False
        if witness.carries_le[0] != 0 or witness.carries_le[-1] != 0:
            return False
        if any(carry not in (0, 1) for carry in witness.carries_le):
            return False
        value_le = tuple(reversed(witness.value_bytes_be))
        slack_le = tuple(reversed(witness.slack_bytes_be))
        target_le = (config.foreign_modulus - 1).to_bytes(BYTE_WIDTH, "little")
        for index in range(BYTE_WIDTH):
            if (
                value_le[index]
                + slack_le[index]
                + witness.carries_le[index]
                != target_le[index] + 256 * witness.carries_le[index + 1]
            ):
                return False
        value = int.from_bytes(witness.value_bytes_be, "big")
        slack = int.from_bytes(witness.slack_bytes_be, "big")
        if value + slack != config.foreign_modulus - 1:
            return False
        if witness.residues != _residues_from_bytes(witness.value_bytes_be, config):
            return False
        return 0 <= value < config.foreign_modulus
    except (CanonicalByteError, ValueError, OverflowError):
        return False


def estimate_canonical_binding(
    values: int, *, cost: CanonicalByteCost = CanonicalByteCost()
) -> dict[str, object]:
    if values <= 0:
        raise CanonicalByteError("value count must be positive")
    return {
        "schema": "ranklock-canonical-byte-schedule-v1",
        "canonical_values": int(values),
        "per_value": cost.document(),
        "byte_lookups": int(values) * cost.byte_lookups,
        "carry_bit_checks": int(values) * cost.carry_bit_checks,
        "byte_addition_linear_equations": int(values)
        * cost.byte_addition_linear_equations,
        "residue_recomposition_linear_equations": int(values)
        * cost.residue_recomposition_linear_equations,
        "raw_shared_value_bytes": int(values) * BYTE_WIDTH,
        "warning": (
            "This inventory does not implement a binding commitment shared by two PCS systems; "
            "lookup arguments may amortize byte/bit checks but add their own proof costs."
        ),
    }
