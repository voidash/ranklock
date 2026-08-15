from __future__ import annotations

"""Complete canonical-binding model for the single-field limb bridge.

The legacy ``nonnative_field`` module proves the arithmetic identity

    x * y = z + quotient * q

for a limb representation, but its schedule only counted multiplication gates
and a few coarse range quantities.  This module adds the missing canonical
32-byte binding and an explicit lookup/linear-constraint inventory.

The witness checks are exact integer checks.  The cost model is a faithful
PLONK/AIR-style inventory under a configurable fixed-width range-lookup model;
it is not a real PCS implementation and does not claim that one lookup event is
one physical row in every backend.
"""

from dataclasses import dataclass
from math import ceil
from typing import Iterable

from .nonnative_field import (
    ForeignMulWitness,
    LimbConfig,
    build_mul_witness as build_arithmetic_mul_witness,
    verify_mul_witness as verify_arithmetic_mul_witness,
)


class FieldBridgeError(ValueError):
    pass


CANONICAL_BYTE_WIDTH = 32


@dataclass(frozen=True, slots=True)
class RangeLookupModel:
    """Logical range-check accounting.

    ``chunk_bits=16`` corresponds to a reusable 2^16 fixed lookup table.  A
    value of ``bits`` bits consumes ``ceil(bits / chunk_bits)`` logical lookup
    events.  Small carries/selectors use one dedicated small-range lookup.
    """

    chunk_bits: int = 16

    def __post_init__(self) -> None:
        if not 1 <= self.chunk_bits <= 20:
            raise FieldBridgeError("range lookup chunk width must be in [1, 20]")

    def chunks(self, bits: int) -> int:
        if bits <= 0:
            raise FieldBridgeError("range width must be positive")
        return ceil(int(bits) / self.chunk_bits)

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-range-lookup-model-v1",
            "chunk_bits": self.chunk_bits,
            "table_rows": 1 << self.chunk_bits,
            "accounting_unit": "logical lookup event",
        }


@dataclass(frozen=True, slots=True)
class CanonicalLimbWitness:
    """One canonical foreign-field value bound to bytes and radix limbs."""

    canonical_bytes_be: bytes
    value_limbs: tuple[int, ...]
    slack_limbs: tuple[int, ...]
    carries_le: tuple[int, ...]

    @property
    def value(self) -> int:
        return int.from_bytes(self.canonical_bytes_be, "big")


@dataclass(frozen=True, slots=True)
class CanonicalGeometry:
    foreign_modulus: int
    limb_bits: int
    limbs: int
    byte_width: int = CANONICAL_BYTE_WIDTH

    def __post_init__(self) -> None:
        if self.foreign_modulus <= 2:
            raise FieldBridgeError("foreign modulus must exceed two")
        if self.limb_bits <= 0 or self.limbs < 2:
            raise FieldBridgeError("invalid canonical limb geometry")
        if self.base**self.limbs <= self.foreign_modulus:
            raise FieldBridgeError("limb geometry cannot encode the foreign field")
        if self.foreign_modulus >= 1 << (8 * self.byte_width):
            raise FieldBridgeError("foreign modulus does not fit canonical bytes")

    @property
    def base(self) -> int:
        return 1 << self.limb_bits

    @property
    def capacity_bits(self) -> int:
        return self.limb_bits * self.limbs

    @classmethod
    def from_limb_config(cls, config: LimbConfig) -> "CanonicalGeometry":
        return cls(config.foreign_modulus, config.limb_bits, config.limbs)

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-canonical-limb-geometry-v1",
            "foreign_modulus": str(self.foreign_modulus),
            "foreign_bits": self.foreign_modulus.bit_length(),
            "limb_bits": self.limb_bits,
            "limbs": self.limbs,
            "capacity_bits": self.capacity_bits,
            "canonical_byte_width": self.byte_width,
        }


def _decompose(value: int, geometry: CanonicalGeometry) -> tuple[int, ...]:
    value = int(value)
    if not 0 <= value < geometry.base**geometry.limbs:
        raise FieldBridgeError("value does not fit canonical limb geometry")
    result: list[int] = []
    for _ in range(geometry.limbs):
        result.append(value % geometry.base)
        value //= geometry.base
    if value:
        raise AssertionError("canonical limb decomposition left a remainder")
    return tuple(result)


def _reconstruct(values: Iterable[int], geometry: CanonicalGeometry) -> int:
    limbs = tuple(int(value) for value in values)
    if len(limbs) != geometry.limbs:
        raise FieldBridgeError("canonical limb count differs from geometry")
    if any(not 0 <= value < geometry.base for value in limbs):
        raise FieldBridgeError("canonical limb is outside radix range")
    return sum(value * geometry.base**index for index, value in enumerate(limbs))


def build_canonical_limb_witness(
    value: int, geometry: CanonicalGeometry
) -> CanonicalLimbWitness:
    value = int(value)
    if not 0 <= value < geometry.foreign_modulus:
        raise FieldBridgeError("value is outside the canonical foreign-field range")
    slack = geometry.foreign_modulus - 1 - value
    value_limbs = _decompose(value, geometry)
    slack_limbs = _decompose(slack, geometry)
    target_limbs = _decompose(geometry.foreign_modulus - 1, geometry)

    carries = [0]
    for value_limb, slack_limb, target_limb in zip(
        value_limbs, slack_limbs, target_limbs, strict=True
    ):
        numerator = value_limb + slack_limb + carries[-1] - target_limb
        if numerator % geometry.base:
            raise AssertionError("canonical limb carry is not integral")
        carries.append(numerator // geometry.base)
    if carries[-1] != 0 or any(carry not in (0, 1) for carry in carries):
        raise AssertionError("canonical limb carries are not Boolean")

    return CanonicalLimbWitness(
        value.to_bytes(geometry.byte_width, "big"),
        value_limbs,
        slack_limbs,
        tuple(carries),
    )


def verify_canonical_limb_witness(
    witness: CanonicalLimbWitness, geometry: CanonicalGeometry
) -> bool:
    try:
        if len(witness.canonical_bytes_be) != geometry.byte_width:
            return False
        if len(witness.value_limbs) != geometry.limbs:
            return False
        if len(witness.slack_limbs) != geometry.limbs:
            return False
        if len(witness.carries_le) != geometry.limbs + 1:
            return False
        if witness.carries_le[0] != 0 or witness.carries_le[-1] != 0:
            return False
        if any(carry not in (0, 1) for carry in witness.carries_le):
            return False

        value = _reconstruct(witness.value_limbs, geometry)
        slack = _reconstruct(witness.slack_limbs, geometry)
        if value != int.from_bytes(witness.canonical_bytes_be, "big"):
            return False
        if value + slack != geometry.foreign_modulus - 1:
            return False

        target_limbs = _decompose(geometry.foreign_modulus - 1, geometry)
        for index in range(geometry.limbs):
            if (
                witness.value_limbs[index]
                + witness.slack_limbs[index]
                + witness.carries_le[index]
                != target_limbs[index]
                + geometry.base * witness.carries_le[index + 1]
            ):
                return False
        return 0 <= value < geometry.foreign_modulus
    except (FieldBridgeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True, slots=True)
class BoundForeignMulWitness:
    """3x85-style arithmetic witness with canonical byte bindings."""

    x: CanonicalLimbWitness
    y: CanonicalLimbWitness
    z: CanonicalLimbWitness
    quotient: CanonicalLimbWitness
    arithmetic: ForeignMulWitness


def build_bound_foreign_mul_witness(
    x: int, y: int, config: LimbConfig
) -> BoundForeignMulWitness:
    geometry = CanonicalGeometry.from_limb_config(config)
    arithmetic = build_arithmetic_mul_witness(x, y, config)
    z = _reconstruct(arithmetic.z_limbs, geometry)
    quotient = _reconstruct(arithmetic.quotient_limbs, geometry)
    return BoundForeignMulWitness(
        build_canonical_limb_witness(x, geometry),
        build_canonical_limb_witness(y, geometry),
        build_canonical_limb_witness(z, geometry),
        build_canonical_limb_witness(quotient, geometry),
        arithmetic,
    )


def verify_bound_foreign_mul_witness(
    witness: BoundForeignMulWitness, config: LimbConfig
) -> bool:
    geometry = CanonicalGeometry.from_limb_config(config)
    try:
        values = (witness.x, witness.y, witness.z, witness.quotient)
        if not all(verify_canonical_limb_witness(value, geometry) for value in values):
            return False
        if not verify_arithmetic_mul_witness(witness.arithmetic, config):
            return False
        return (
            witness.x.value_limbs == witness.arithmetic.x_limbs
            and witness.y.value_limbs == witness.arithmetic.y_limbs
            and witness.z.value_limbs == witness.arithmetic.z_limbs
            and witness.quotient.value_limbs == witness.arithmetic.quotient_limbs
        )
    except (FieldBridgeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True, slots=True)
class CompleteLimbBridgeEstimate:
    foreign_products: int
    config: LimbConfig
    range_model: RangeLookupModel
    fresh_values_per_product: int
    native_nonlinear_products: int
    canonical_serialization_lookup_events: int
    canonical_slack_range_lookup_events: int
    canonical_carry_lookup_events: int
    signed_arithmetic_carry_lookup_events: int
    canonical_linear_equations: int
    arithmetic_linear_equations: int
    schema: str = "ranklock-complete-limb-bridge-estimate-v1"

    @property
    def total_lookup_events(self) -> int:
        return (
            self.canonical_serialization_lookup_events
            + self.canonical_slack_range_lookup_events
            + self.canonical_carry_lookup_events
            + self.signed_arithmetic_carry_lookup_events
        )

    @property
    def total_linear_equations(self) -> int:
        return self.canonical_linear_equations + self.arithmetic_linear_equations

    @property
    def simple_row_equivalent(self) -> int:
        """One logical lookup or nonlinear product per row; linear gates excluded."""

        return self.total_lookup_events + self.native_nonlinear_products

    def document(self) -> dict[str, object]:
        per_product = {
            "native_nonlinear_products": self.native_nonlinear_products
            // self.foreign_products,
            "logical_lookup_events": self.total_lookup_events // self.foreign_products,
            "simple_row_equivalent": self.simple_row_equivalent
            // self.foreign_products,
        }
        return {
            "schema": self.schema,
            "foreign_products": self.foreign_products,
            "config": self.config.document(),
            "range_model": self.range_model.document(),
            "fresh_values_per_product": self.fresh_values_per_product,
            "native_nonlinear_products": self.native_nonlinear_products,
            "canonical_serialization_lookup_events": self.canonical_serialization_lookup_events,
            "canonical_slack_range_lookup_events": self.canonical_slack_range_lookup_events,
            "canonical_carry_lookup_events": self.canonical_carry_lookup_events,
            "signed_arithmetic_carry_lookup_events": self.signed_arithmetic_carry_lookup_events,
            "logical_lookup_events_total": self.total_lookup_events,
            "canonical_linear_equations": self.canonical_linear_equations,
            "arithmetic_linear_equations": self.arithmetic_linear_equations,
            "linear_equations_total": self.total_linear_equations,
            "simple_row_equivalent": self.simple_row_equivalent,
            "per_foreign_product": per_product,
            "scope": (
                "exact canonical witness plus logical range/linear inventory; excludes PCS, "
                "lookup-argument fixed overhead, parser/hash work and conditional disclosure"
            ),
        }


def estimate_complete_limb_bridge(
    foreign_products: int,
    config: LimbConfig,
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    fresh_values_per_product: int = 2,
) -> CompleteLimbBridgeEstimate:
    if foreign_products <= 0:
        raise FieldBridgeError("foreign product count must be positive")
    if fresh_values_per_product <= 0:
        raise FieldBridgeError("fresh-value count must be positive")

    products = int(foreign_products)
    fresh_values = products * int(fresh_values_per_product)
    # A fixed-width tuple table can return the constituent bytes and any
    # limb-boundary pieces for one range-checked chunk.  Thus canonical 32-byte
    # serialization consumes ceil(256/chunk_bits) logical tuple lookups, not one
    # lookup per byte.  The table width/packing remains backend-dependent.
    serialization = fresh_values * range_model.chunks(8 * CANONICAL_BYTE_WIDTH)
    slack_ranges = (
        fresh_values * config.limbs * range_model.chunks(config.limb_bits)
    )
    canonical_carries = fresh_values * (config.limbs - 1)

    internal_signed_carries = 2 * config.limbs - 2
    # Encode each signed carry c by the nonnegative offset c + M, where
    # M is the public absolute bound.  Since 0 <= c+M <= 2M < native_modulus,
    # chunk decomposition is exact and needs no sign-bit multiplication.
    signed_offset_width = (2 * config.carry_abs_bound).bit_length()
    signed_carry_events = products * internal_signed_carries * range_model.chunks(
        signed_offset_width
    )

    canonical_linear = fresh_values * (3 * config.limbs)
    arithmetic_linear = products * (2 * config.limbs - 1)

    return CompleteLimbBridgeEstimate(
        foreign_products=products,
        config=config,
        range_model=range_model,
        fresh_values_per_product=int(fresh_values_per_product),
        native_nonlinear_products=products * config.nonlinear_products_per_mul,
        canonical_serialization_lookup_events=serialization,
        canonical_slack_range_lookup_events=slack_ranges,
        canonical_carry_lookup_events=canonical_carries,
        signed_arithmetic_carry_lookup_events=signed_carry_events,
        canonical_linear_equations=canonical_linear,
        arithmetic_linear_equations=arithmetic_linear,
    )


@dataclass(frozen=True, slots=True)
class ReducedQuotientLimbBridgeEstimate:
    """Logical inventory when only the field output is canonical.

    For canonical ``x,y,z < q`` and an exact integer relation

        x*y = z + quotient*q,

    any nonnegative quotient satisfying the relation is automatically the true
    quotient and is smaller than ``q``.  The circuit therefore needs only a
    bounded limb representation for the internal quotient; a second
    ``value + slack = q-1`` proof is redundant.
    """

    foreign_products: int
    config: LimbConfig
    range_model: RangeLookupModel
    quotient_bits: int
    native_nonlinear_products: int
    output_serialization_lookup_events: int
    output_slack_range_lookup_events: int
    output_carry_lookup_events: int
    quotient_range_lookup_events: int
    signed_arithmetic_carry_lookup_events: int
    output_canonical_linear_equations: int
    quotient_pack_linear_equations: int
    arithmetic_linear_equations: int
    schema: str = "ranklock-reduced-quotient-limb-bridge-estimate-v1"

    @property
    def total_lookup_events(self) -> int:
        return (
            self.output_serialization_lookup_events
            + self.output_slack_range_lookup_events
            + self.output_carry_lookup_events
            + self.quotient_range_lookup_events
            + self.signed_arithmetic_carry_lookup_events
        )

    @property
    def total_linear_equations(self) -> int:
        return (
            self.output_canonical_linear_equations
            + self.quotient_pack_linear_equations
            + self.arithmetic_linear_equations
        )

    @property
    def simple_row_equivalent(self) -> int:
        return self.total_lookup_events + self.native_nonlinear_products

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "foreign_products": self.foreign_products,
            "config": self.config.document(),
            "range_model": self.range_model.document(),
            "quotient_bits": self.quotient_bits,
            "native_nonlinear_products": self.native_nonlinear_products,
            "output_serialization_lookup_events": self.output_serialization_lookup_events,
            "output_slack_range_lookup_events": self.output_slack_range_lookup_events,
            "output_carry_lookup_events": self.output_carry_lookup_events,
            "quotient_range_lookup_events": self.quotient_range_lookup_events,
            "signed_arithmetic_carry_lookup_events": self.signed_arithmetic_carry_lookup_events,
            "logical_lookup_events_total": self.total_lookup_events,
            "output_canonical_linear_equations": self.output_canonical_linear_equations,
            "quotient_pack_linear_equations": self.quotient_pack_linear_equations,
            "arithmetic_linear_equations": self.arithmetic_linear_equations,
            "linear_equations_total": self.total_linear_equations,
            "simple_row_equivalent": self.simple_row_equivalent,
            "per_foreign_product": {
                "native_nonlinear_products": self.native_nonlinear_products
                // self.foreign_products,
                "logical_lookup_events": self.total_lookup_events
                // self.foreign_products,
                "linear_relation_events": self.total_linear_equations
                // self.foreign_products,
                "simple_row_equivalent": self.simple_row_equivalent
                // self.foreign_products,
            },
            "soundness_note": (
                "x,y,z are canonical and the no-wrap carry equations enforce exact "
                "integer equality; a nonnegative bounded quotient is consequently the "
                "unique floor(x*y/q), so a quotient slack proof is redundant"
            ),
            "scope": (
                "exact relation plus logical range/linear inventory; excludes PCS, "
                "lookup-argument fixed overhead, parser/hash work and conditional disclosure"
            ),
        }


def estimate_reduced_quotient_limb_bridge(
    foreign_products: int,
    config: LimbConfig,
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    quotient_bits: int = 254,
) -> ReducedQuotientLimbBridgeEstimate:
    if foreign_products <= 0:
        raise FieldBridgeError("foreign product count must be positive")
    capacity_bits = config.limb_bits * config.limbs
    if not 1 <= quotient_bits <= capacity_bits:
        raise FieldBridgeError("quotient bit bound does not fit limb geometry")
    maximum_honest_quotient = config.foreign_modulus - 2
    if maximum_honest_quotient.bit_length() > quotient_bits:
        raise FieldBridgeError("quotient bound must cover every honest quotient")

    products = int(foreign_products)
    output_serialization = products * range_model.chunks(8 * CANONICAL_BYTE_WIDTH)
    output_slack = products * config.limbs * range_model.chunks(config.limb_bits)
    output_carries = products * (config.limbs - 1)
    quotient_ranges = products * range_model.chunks(quotient_bits)

    internal_signed_carries = 2 * config.limbs - 2
    signed_offset_width = (2 * config.carry_abs_bound).bit_length()
    signed_carries = products * internal_signed_carries * range_model.chunks(
        signed_offset_width
    )

    return ReducedQuotientLimbBridgeEstimate(
        foreign_products=products,
        config=config,
        range_model=range_model,
        quotient_bits=int(quotient_bits),
        native_nonlinear_products=products * config.nonlinear_products_per_mul,
        output_serialization_lookup_events=output_serialization,
        output_slack_range_lookup_events=output_slack,
        output_carry_lookup_events=output_carries,
        quotient_range_lookup_events=quotient_ranges,
        signed_arithmetic_carry_lookup_events=signed_carries,
        output_canonical_linear_equations=products * (3 * config.limbs),
        quotient_pack_linear_equations=products * config.limbs,
        arithmetic_linear_equations=products * (2 * config.limbs - 1),
    )
