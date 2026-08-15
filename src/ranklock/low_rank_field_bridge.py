from __future__ import annotations

"""Canonical non-native multiplication using rank-(2n-1) convolution."""

from dataclasses import dataclass

from .field_bridge import (
    BoundForeignMulWitness,
    CompleteLimbBridgeEstimate,
    ReducedQuotientLimbBridgeEstimate,
    RangeLookupModel,
    build_bound_foreign_mul_witness,
    estimate_complete_limb_bridge,
    estimate_reduced_quotient_limb_bridge,
    verify_canonical_limb_witness,
    CanonicalGeometry,
)
from .low_rank_convolution import (
    LowRankConvolutionPlan,
    LowRankConvolutionWitness,
    build_low_rank_convolution_witness,
    exact_convolution,
    verify_low_rank_convolution_witness,
)
from .nonnative_field import LimbConfig, decompose, reconstruct


class LowRankFieldBridgeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LowRankBoundForeignMulWitness:
    bound: BoundForeignMulWitness
    convolution: LowRankConvolutionWitness


def build_low_rank_bound_foreign_mul_witness(
    x: int, y: int, config: LimbConfig
) -> LowRankBoundForeignMulWitness:
    bound = build_bound_foreign_mul_witness(x, y, config)
    plan = LowRankConvolutionPlan.consecutive(config.limbs, config.native_modulus)
    convolution = build_low_rank_convolution_witness(
        bound.arithmetic.x_limbs, bound.arithmetic.y_limbs, plan
    )
    return LowRankBoundForeignMulWitness(bound, convolution)


def verify_low_rank_bound_foreign_mul_witness(
    witness: LowRankBoundForeignMulWitness, config: LimbConfig
) -> bool:
    try:
        bound = witness.bound
        geometry = CanonicalGeometry.from_limb_config(config)
        canonical_values = (bound.x, bound.y, bound.z, bound.quotient)
        if not all(
            verify_canonical_limb_witness(value, geometry)
            for value in canonical_values
        ):
            return False
        arithmetic = bound.arithmetic
        if (
            bound.x.value_limbs != arithmetic.x_limbs
            or bound.y.value_limbs != arithmetic.y_limbs
            or bound.z.value_limbs != arithmetic.z_limbs
            or bound.quotient.value_limbs != arithmetic.quotient_limbs
        ):
            return False

        plan = LowRankConvolutionPlan.consecutive(
            config.limbs, config.native_modulus
        )
        if not verify_low_rank_convolution_witness(
            witness.convolution,
            plan,
            limb_upper_bound=config.base,
            require_exact_coefficients=True,
        ):
            return False
        if witness.convolution.left != arithmetic.x_limbs:
            return False
        if witness.convolution.right != arithmetic.y_limbs:
            return False

        n = config.limbs
        if len(arithmetic.carries) != 2 * n:
            return False
        if arithmetic.carries[0] != 0 or arithmetic.carries[-1] != 0:
            return False
        if any(
            abs(int(value)) > config.carry_abs_bound
            for value in arithmetic.carries
        ):
            return False

        modulus_limbs = decompose(config.foreign_modulus, config)
        quotient_product = exact_convolution(
            arithmetic.quotient_limbs, modulus_limbs
        )
        coefficients = witness.convolution.coefficients
        for index in range(2 * n - 1):
            rhs = quotient_product[index] + (
                arithmetic.z_limbs[index] if index < n else 0
            )
            equation = (
                coefficients[index]
                - rhs
                + arithmetic.carries[index]
                - config.base * arithmetic.carries[index + 1]
            )
            if equation != 0:
                return False
            if abs(equation) >= config.native_modulus:
                return False

        x = reconstruct(arithmetic.x_limbs, config)
        y = reconstruct(arithmetic.y_limbs, config)
        z = reconstruct(arithmetic.z_limbs, config)
        quotient = reconstruct(arithmetic.quotient_limbs, config)
        if any(value >= config.foreign_modulus for value in (x, y, z, quotient)):
            return False
        return x * y == z + quotient * config.foreign_modulus
    except (LowRankFieldBridgeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True, slots=True)
class LowRankLimbBridgeEstimate:
    schoolbook: CompleteLimbBridgeEstimate | ReducedQuotientLimbBridgeEstimate
    native_nonlinear_products: int
    convolution_rank: int
    schoolbook_products_avoided: int
    schema: str = "ranklock-low-rank-limb-bridge-estimate-v1"

    @property
    def foreign_products(self) -> int:
        return self.schoolbook.foreign_products

    @property
    def total_lookup_events(self) -> int:
        return self.schoolbook.total_lookup_events

    @property
    def total_linear_equations(self) -> int:
        return self.schoolbook.total_linear_equations

    @property
    def simple_row_equivalent(self) -> int:
        return self.total_lookup_events + self.native_nonlinear_products

    def document(self) -> dict[str, object]:
        document = self.schoolbook.document()
        document.update(
            {
                "schema": self.schema,
                "convolution_method": "fixed-point evaluation/interpolation",
                "convolution_rank_per_foreign_product": self.convolution_rank,
                "schoolbook_products_per_foreign_product": (
                    self.schoolbook.config.nonlinear_products_per_mul
                ),
                "schoolbook_products_avoided": self.schoolbook_products_avoided,
                "native_nonlinear_products": self.native_nonlinear_products,
                "simple_row_equivalent": self.simple_row_equivalent,
                "per_foreign_product": {
                    "native_nonlinear_products": self.convolution_rank,
                    "logical_lookup_events": self.total_lookup_events
                    // self.foreign_products,
                    "simple_row_equivalent": self.simple_row_equivalent
                    // self.foreign_products,
                },
                "soundness_note": (
                    "2n-1 fixed products determine the convolution over the native field; "
                    "bounded canonical limbs make every true coefficient smaller than the "
                    "native modulus, and the existing no-wrap carry bound lifts the final "
                    "field equations to integer equalities"
                ),
            }
        )
        return document


def estimate_low_rank_limb_bridge(
    foreign_products: int,
    config: LimbConfig,
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    fresh_values_per_product: int = 2,
) -> LowRankLimbBridgeEstimate:
    schoolbook = estimate_complete_limb_bridge(
        foreign_products,
        config,
        range_model=range_model,
        fresh_values_per_product=fresh_values_per_product,
    )
    rank = 2 * config.limbs - 1
    products = int(foreign_products)
    return LowRankLimbBridgeEstimate(
        schoolbook=schoolbook,
        native_nonlinear_products=rank * products,
        convolution_rank=rank,
        schoolbook_products_avoided=(
            config.nonlinear_products_per_mul - rank
        )
        * products,
    )


def estimate_low_rank_reduced_quotient_limb_bridge(
    foreign_products: int,
    config: LimbConfig,
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    quotient_bits: int = 254,
) -> LowRankLimbBridgeEstimate:
    """Rank-(2n-1) convolution with a bounded internal quotient.

    The output remains canonical.  The quotient is only range-bound and packed
    into the arithmetic limbs because exact integer equality makes its full
    ``< q`` slack proof redundant.
    """

    reduced = estimate_reduced_quotient_limb_bridge(
        foreign_products,
        config,
        range_model=range_model,
        quotient_bits=quotient_bits,
    )
    rank = 2 * config.limbs - 1
    products = int(foreign_products)
    return LowRankLimbBridgeEstimate(
        schoolbook=reduced,
        native_nonlinear_products=rank * products,
        convolution_rank=rank,
        schoolbook_products_avoided=(
            config.nonlinear_products_per_mul - rank
        )
        * products,
        schema="ranklock-low-rank-reduced-quotient-limb-bridge-estimate-v1",
    )
