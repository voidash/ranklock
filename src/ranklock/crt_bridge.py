from __future__ import annotations

"""Canonical binding and complete logical-cost inventory for dual-field CRT.

The arithmetic core needs one native multiplication in BN254 Fr and one in
BLS12-381 Fr.  Soundness additionally requires both residue traces to refer to
one canonical byte string.  This module makes the existing byte-slack binding
part of the executable witness and exposes two cost views:

* ``explicit_byte_slack`` -- the implemented canonical value/slack witness,
  accounted through packed fixed-width tuple lookups and word carries;
* ``free_shared_table_lower_bound`` -- an intentionally optimistic lower bound
  in which one BLS12-381-side canonical table is shared with the BN254 proof at
  zero cryptographic cost.  This lower bound is not a construction.
"""

from dataclasses import dataclass

from .canonical_bytes import (
    BYTE_WIDTH,
    CanonicalByteWitness,
    build_canonical_byte_witness,
    verify_canonical_byte_witness,
)
from .crt_field import (
    CrtFieldConfig,
    CrtMulWitness,
    build_mul_witness as build_core_mul_witness,
    verify_mul_witness as verify_core_mul_witness,
)
from .field_bridge import RangeLookupModel


class CrtBridgeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BoundCrtMulWitness:
    x: CanonicalByteWitness
    y: CanonicalByteWitness
    z: CanonicalByteWitness
    quotient: CanonicalByteWitness
    core: CrtMulWitness


def build_bound_crt_mul_witness(
    x: int, y: int, config: CrtFieldConfig = CrtFieldConfig()
) -> BoundCrtMulWitness:
    core = build_core_mul_witness(x, y, config)
    values = (
        core.x.decode(config),
        core.y.decode(config),
        core.z.decode(config),
        core.quotient.decode(config),
    )
    bound = tuple(build_canonical_byte_witness(value, config) for value in values)
    return BoundCrtMulWitness(*bound, core)  # type: ignore[arg-type]


def verify_bound_crt_mul_witness(
    witness: BoundCrtMulWitness, config: CrtFieldConfig = CrtFieldConfig()
) -> bool:
    try:
        if not verify_core_mul_witness(witness.core, config):
            return False
        bound_values = (witness.x, witness.y, witness.z, witness.quotient)
        if not all(
            verify_canonical_byte_witness(value, config) for value in bound_values
        ):
            return False
        core_values = (
            witness.core.x,
            witness.core.y,
            witness.core.z,
            witness.core.quotient,
        )
        return all(
            bound.value_bytes_be == core.canonical and bound.residues == core.residues
            for bound, core in zip(bound_values, core_values, strict=True)
        )
    except (CrtBridgeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True, slots=True)
class CrtBridgeScheduleEstimate:
    foreign_products: int
    config: CrtFieldConfig
    range_model: RangeLookupModel
    mode: str
    fresh_values_per_product: int
    native_nonlinear_products: int
    canonical_lookup_events: int
    canonical_linear_equations: int
    residue_recomposition_linear_equations: int
    cross_field_binding_cost_included: bool
    quotient_bits: int | None = None
    schema: str = "ranklock-crt-bridge-schedule-estimate-v1"

    @property
    def total_lookup_events(self) -> int:
        return self.canonical_lookup_events

    @property
    def total_linear_equations(self) -> int:
        return (
            self.canonical_linear_equations
            + self.residue_recomposition_linear_equations
        )

    @property
    def simple_row_equivalent(self) -> int:
        return self.total_lookup_events + self.native_nonlinear_products

    def document(self) -> dict[str, object]:
        warning = None
        if not self.cross_field_binding_cost_included:
            warning = (
                "The common byte-table commitment/equality proof is not included; this is "
                "not a sound end-to-end dual-field construction."
            )
        return {
            "schema": self.schema,
            "foreign_products": self.foreign_products,
            "config": self.config.document(),
            "range_model": self.range_model.document(),
            "mode": self.mode,
            "fresh_values_per_product": self.fresh_values_per_product,
            "native_nonlinear_products": self.native_nonlinear_products,
            "canonical_lookup_events": self.canonical_lookup_events,
            "canonical_linear_equations": self.canonical_linear_equations,
            "residue_recomposition_linear_equations": self.residue_recomposition_linear_equations,
            "linear_equations_total": self.total_linear_equations,
            "cross_field_binding_cost_included": self.cross_field_binding_cost_included,
            "quotient_bits": self.quotient_bits,
            "simple_row_equivalent": self.simple_row_equivalent,
            "per_foreign_product": {
                "native_nonlinear_products": self.native_nonlinear_products
                // self.foreign_products,
                "logical_lookup_events": self.total_lookup_events
                // self.foreign_products,
                "simple_row_equivalent": self.simple_row_equivalent
                // self.foreign_products,
            },
            "warning": warning,
        }


def estimate_explicit_crt_bridge(
    foreign_products: int,
    config: CrtFieldConfig = CrtFieldConfig(),
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    fresh_values_per_product: int = 2,
) -> CrtBridgeScheduleEstimate:
    if foreign_products <= 0:
        raise CrtBridgeError("foreign product count must be positive")
    if fresh_values_per_product <= 0:
        raise CrtBridgeError("fresh-value count must be positive")
    products = int(foreign_products)
    fresh_values = products * int(fresh_values_per_product)

    # Pack the byte witness into fixed-width tuple lookups.  Each table row can
    # expose the underlying bytes while range-checking one chunk.  Canonical
    # addition is performed in the same chunk radix, with one internal carry
    # per boundary.
    words_per_value = range_model.chunks(8 * BYTE_WIDTH)
    lookup_per_value = 2 * words_per_value + (words_per_value - 1)
    linear_per_value = words_per_value
    residue_linear_per_value = 2
    return CrtBridgeScheduleEstimate(
        foreign_products=products,
        config=config,
        range_model=range_model,
        mode="explicit_byte_slack",
        fresh_values_per_product=int(fresh_values_per_product),
        native_nonlinear_products=2 * products,
        canonical_lookup_events=fresh_values * lookup_per_value,
        canonical_linear_equations=fresh_values * linear_per_value,
        residue_recomposition_linear_equations=(
            fresh_values * residue_linear_per_value
        ),
        cross_field_binding_cost_included=False,
    )



def estimate_bounded_quotient_crt_bridge(
    foreign_products: int,
    config: CrtFieldConfig = CrtFieldConfig(),
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    quotient_bits: int = 254,
) -> CrtBridgeScheduleEstimate:
    """Owner-side byte table with canonical ``z`` and bounded quotient."""

    if foreign_products <= 0:
        raise CrtBridgeError("foreign product count must be positive")
    if (config.foreign_modulus - 2).bit_length() > quotient_bits:
        raise CrtBridgeError("quotient bit bound misses an honest quotient")
    if not config.bounded_quotient_is_crt_exact(quotient_bits):
        raise CrtBridgeError("CRT product does not certify this quotient range")

    products = int(foreign_products)
    words = range_model.chunks(8 * BYTE_WIDTH)
    # z: value words + slack words + internal carries. quotient: bounded words.
    output_canonical_lookups = 2 * words + (words - 1)
    quotient_lookups = range_model.chunks(quotient_bits)
    return CrtBridgeScheduleEstimate(
        foreign_products=products,
        config=config,
        range_model=range_model,
        mode="bounded_quotient_owner_side",
        fresh_values_per_product=2,
        native_nonlinear_products=2 * products,
        canonical_lookup_events=products
        * (output_canonical_lookups + quotient_lookups),
        canonical_linear_equations=products * words,
        # z and quotient are each recomposed in both proof fields.
        residue_recomposition_linear_equations=4 * products,
        cross_field_binding_cost_included=False,
        quotient_bits=int(quotient_bits),
        schema="ranklock-crt-bounded-quotient-schedule-estimate-v1",
    )


def estimate_bounded_quotient_free_shared_table_lower_bound(
    foreign_products: int,
    config: CrtFieldConfig = CrtFieldConfig(),
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    quotient_bits: int = 254,
) -> CrtBridgeScheduleEstimate:
    """Optimistic 2x127 owner-table lower bound with bounded quotient."""

    if foreign_products <= 0:
        raise CrtBridgeError("foreign product count must be positive")
    if (config.foreign_modulus - 2).bit_length() > quotient_bits:
        raise CrtBridgeError("quotient bit bound misses an honest quotient")
    if not config.bounded_quotient_is_crt_exact(quotient_bits):
        raise CrtBridgeError("CRT product does not certify this quotient range")

    products = int(foreign_products)
    chunks_per_limb = range_model.chunks(127)
    serialization_chunks = range_model.chunks(8 * BYTE_WIDTH)
    output_lookups = serialization_chunks + 2 * chunks_per_limb + 1
    quotient_lookups = range_model.chunks(quotient_bits)
    return CrtBridgeScheduleEstimate(
        foreign_products=products,
        config=config,
        range_model=range_model,
        mode="bounded_quotient_free_shared_table_lower_bound",
        fresh_values_per_product=2,
        native_nonlinear_products=2 * products,
        canonical_lookup_events=products * (output_lookups + quotient_lookups),
        # z uses six canonical limb equations; quotient uses two byte-to-limb packs.
        canonical_linear_equations=8 * products,
        residue_recomposition_linear_equations=4 * products,
        cross_field_binding_cost_included=False,
        quotient_bits=int(quotient_bits),
        schema="ranklock-crt-bounded-quotient-lower-bound-estimate-v1",
    )

def estimate_free_shared_table_lower_bound(
    foreign_products: int,
    config: CrtFieldConfig = CrtFieldConfig(),
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    fresh_values_per_product: int = 2,
) -> CrtBridgeScheduleEstimate:
    """Optimistic lower bound, not a cryptographic construction.

    One proof field owns a 2x127 canonical byte/limb table.  Under the default
    16-bit model, one value uses sixteen packed serialization lookups, sixteen
    slack-limb chunk lookups and one carry lookup.  The second proof is assumed
    to consume the same table for free.  The missing cross-field commitment is
    precisely the open problem.
    """

    if foreign_products <= 0:
        raise CrtBridgeError("foreign product count must be positive")
    products = int(foreign_products)
    fresh_values = products * int(fresh_values_per_product)
    chunks_per_limb = range_model.chunks(127)
    serialization_chunks = range_model.chunks(8 * BYTE_WIDTH)
    lookup_per_value = serialization_chunks + 2 * chunks_per_limb + 1
    # Two value-limb equations, two slack-limb equations and two canonical
    # addition equations in the owner field.
    linear_per_value = 6
    return CrtBridgeScheduleEstimate(
        foreign_products=products,
        config=config,
        range_model=range_model,
        mode="free_shared_table_lower_bound",
        fresh_values_per_product=int(fresh_values_per_product),
        native_nonlinear_products=2 * products,
        canonical_lookup_events=fresh_values * lookup_per_value,
        canonical_linear_equations=fresh_values * linear_per_value,
        residue_recomposition_linear_equations=2 * fresh_values,
        cross_field_binding_cost_included=False,
    )
