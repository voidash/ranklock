from __future__ import annotations

"""Executable constraint ledger for outer-curve proof-point binding.

v0.17 left a 325-coordinate budget per one-sided-SNARK G1 proof element.  The
budget used a single uninstantiated number for all of:

* canonical compressed decoding;
* on-curve enforcement;
* subgroup enforcement;
* binding the scalar transcript view to the final pairing view.

This module replaces that number with an auditable ledger against the concrete
515-bit CP6-style candidate in :mod:`ranklock.outer_curve_candidate`.

The cost accounting is deliberately split into three evidence classes:

``exact logical ledger``
    Native multiplication count plus fixed-width range-lookup events for a
    canonical radix representation.  It is not a concrete PLONK layout.

``optimistic fused ledger``
    Assumes signed-carry checks and linear carry equations are absorbed by a
    custom non-native gate.  It is a lower engineering target, not a gadget.

``standard subgroup estimate``
    Counts a conventional variable-base fixed-scalar Jacobian check.  It is an
    explicit construction cost, not a lower bound against endomorphism-based or
    proof-system-specific subgroup arguments.

The decisive result is scoped: the *current generic public-Fiat--Shamir parser*
does not fit.  A specialised hybrid group/scalar binding gadget remains open.
"""

from dataclasses import dataclass
from math import ceil

from .outer_curve_candidate import (
    BN254_FQ,
    COMPRESSED_G1_BYTES,
    OUTER_Q,
)
from .transcript_mini_lock import TranscriptConstraintScenario
from .fixed_statement_wrapper_candidate import PerDepositCandidateCost


class OuterG1BindingError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OuterFieldLimbGeometry:
    foreign_modulus: int = OUTER_Q
    native_modulus: int = BN254_FQ
    limbs: int = 5
    limb_bits: int = 103
    schema: str = "ranklock-outer-field-limb-geometry-v1"

    def __post_init__(self) -> None:
        if self.limbs < 2 or self.limb_bits <= 0:
            raise OuterG1BindingError("invalid outer-field limb geometry")
        if self.base**self.limbs <= self.foreign_modulus:
            raise OuterG1BindingError("outer-field limbs do not cover the modulus")
        if not self.safe_no_wrap:
            raise OuterG1BindingError("outer-field carry equations can wrap natively")

    @property
    def base(self) -> int:
        return 1 << self.limb_bits

    @property
    def convolution_rank(self) -> int:
        return 2 * self.limbs - 1

    @property
    def coefficient_abs_bound(self) -> int:
        limb_max = self.base - 1
        return 2 * self.limbs * limb_max * limb_max + limb_max

    @property
    def carry_abs_bound(self) -> int:
        bound = 0
        for _ in range(2 * self.limbs - 1):
            bound = ceil((self.coefficient_abs_bound + bound) / self.base)
        return bound

    @property
    def equation_abs_bound(self) -> int:
        return (
            self.coefficient_abs_bound
            + self.carry_abs_bound
            + self.base * self.carry_abs_bound
        )

    @property
    def safe_no_wrap(self) -> bool:
        return self.equation_abs_bound < self.native_modulus

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "foreign_bits": self.foreign_modulus.bit_length(),
            "native_bits": self.native_modulus.bit_length(),
            "limbs": self.limbs,
            "limb_bits": self.limb_bits,
            "capacity_bits": self.limbs * self.limb_bits,
            "convolution_rank": self.convolution_rank,
            "carry_abs_bound_bits": self.carry_abs_bound.bit_length(),
            "equation_abs_bound_bits": self.equation_abs_bound.bit_length(),
            "safe_no_wrap": self.safe_no_wrap,
        }


@dataclass(frozen=True, slots=True)
class LogicalRangeModel:
    chunk_bits: int = 16
    schema: str = "ranklock-outer-binding-range-model-v1"

    def __post_init__(self) -> None:
        if not 1 <= self.chunk_bits <= 20:
            raise OuterG1BindingError("range chunk width must be in [1,20]")

    def chunks(self, bits: int) -> int:
        if bits <= 0:
            raise OuterG1BindingError("range width must be positive")
        return ceil(bits / self.chunk_bits)

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chunk_bits": self.chunk_bits,
            "fixed_table_rows": 1 << self.chunk_bits,
            "accounting_unit": "logical range lookup",
        }


@dataclass(frozen=True, slots=True)
class ForeignMulBindingCost:
    geometry: OuterFieldLimbGeometry
    range_model: LogicalRangeModel
    native_products: int
    output_range_lookups: int
    quotient_range_lookups: int
    signed_carry_lookups: int
    linear_equations: int
    schema: str = "ranklock-outer-foreign-mul-binding-cost-v1"

    @classmethod
    def build(
        cls,
        geometry: OuterFieldLimbGeometry,
        range_model: LogicalRangeModel,
    ) -> "ForeignMulBindingCost":
        limb_chunks = range_model.chunks(geometry.limb_bits)
        output_range = geometry.limbs * limb_chunks + (geometry.limbs - 1)
        quotient_range = range_model.chunks(geometry.foreign_modulus.bit_length())
        signed_width = (2 * geometry.carry_abs_bound).bit_length()
        signed_carries = (2 * geometry.limbs - 2) * range_model.chunks(
            signed_width
        )
        linear = 3 * geometry.limbs + geometry.limbs + (2 * geometry.limbs - 1)
        return cls(
            geometry,
            range_model,
            geometry.convolution_rank,
            output_range,
            quotient_range,
            signed_carries,
            linear,
        )

    @property
    def exact_logical_rows(self) -> int:
        return (
            self.native_products
            + self.output_range_lookups
            + self.quotient_range_lookups
            + self.signed_carry_lookups
        )

    @property
    def optimistic_fused_rows(self) -> int:
        # Signed-carry range checks and linear carry equations are assumed to be
        # absorbed into a dedicated custom gate.  Output/quotient boundedness is
        # still load-bearing and remains explicit.
        return (
            self.native_products
            + self.output_range_lookups
            + self.quotient_range_lookups
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "native_products": self.native_products,
            "output_range_lookups": self.output_range_lookups,
            "quotient_range_lookups": self.quotient_range_lookups,
            "signed_carry_lookups": self.signed_carry_lookups,
            "linear_equations": self.linear_equations,
            "exact_logical_rows": self.exact_logical_rows,
            "optimistic_fused_rows": self.optimistic_fused_rows,
        }


@dataclass(frozen=True, slots=True)
class OnCurveBindingCost:
    geometry: OuterFieldLimbGeometry = OuterFieldLimbGeometry()
    range_model: LogicalRangeModel = LogicalRangeModel()
    foreign_products: int = 3
    schema: str = "ranklock-outer-on-curve-binding-cost-v1"

    def __post_init__(self) -> None:
        if self.foreign_products != 3:
            raise OuterG1BindingError("short-Weierstrass check expects three products")

    @property
    def mul_cost(self) -> ForeignMulBindingCost:
        return ForeignMulBindingCost.build(self.geometry, self.range_model)

    @property
    def canonical_x_rows(self) -> int:
        return (
            self.range_model.chunks(8 * COMPRESSED_G1_BYTES)
            + self.geometry.limbs * self.range_model.chunks(self.geometry.limb_bits)
            + (self.geometry.limbs - 1)
        )

    @property
    def canonical_y_rows(self) -> int:
        return (
            self.geometry.limbs * self.range_model.chunks(self.geometry.limb_bits)
            + (self.geometry.limbs - 1)
        )

    @property
    def compressed_sign_rows(self) -> int:
        # One small lookup can return the low parity bit from the least
        # significant range chunk.  This is still an optimistic packing choice.
        return 1

    @property
    def exact_logical_rows(self) -> int:
        return (
            self.canonical_x_rows
            + self.canonical_y_rows
            + self.compressed_sign_rows
            + self.foreign_products * self.mul_cost.exact_logical_rows
        )

    @property
    def optimistic_fused_rows(self) -> int:
        return (
            self.canonical_x_rows
            + self.canonical_y_rows
            + self.compressed_sign_rows
            + self.foreign_products * self.mul_cost.optimistic_fused_rows
        )

    @property
    def native_products_only(self) -> int:
        return self.foreign_products * self.mul_cost.native_products

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_class": (
                "EXACT logical lookup/product inventory under the stated limb geometry; "
                "not a concrete LVA-WE or PLONK layout"
            ),
            "geometry": self.geometry.document(),
            "range_model": self.range_model.document(),
            "canonical_x_rows": self.canonical_x_rows,
            "canonical_y_rows": self.canonical_y_rows,
            "compressed_sign_rows": self.compressed_sign_rows,
            "foreign_products": self.foreign_products,
            "per_foreign_product": self.mul_cost.document(),
            "native_products_only_unsound_lower_inventory": self.native_products_only,
            "optimistic_fused_rows": self.optimistic_fused_rows,
            "exact_logical_rows": self.exact_logical_rows,
            "excluded": [
                "subgroup membership",
                "cross-gadget scalar/group equality if the backend does not share one typed object",
                "lookup argument fixed overhead",
                "PCS and witness-encryption compilation",
            ],
        }


@dataclass(frozen=True, slots=True)
class StandardSubgroupCheckCost:
    geometry: OuterFieldLimbGeometry = OuterFieldLimbGeometry()
    scalar_bits: int = BN254_FQ.bit_length()
    scalar_hamming_weight: int = BN254_FQ.bit_count()
    jacobian_double_foreign_products: int = 7
    jacobian_add_foreign_products: int = 16
    schema: str = "ranklock-standard-outer-subgroup-check-cost-v1"

    @property
    def doublings(self) -> int:
        return self.scalar_bits - 1

    @property
    def additions(self) -> int:
        return self.scalar_hamming_weight - 1

    @property
    def foreign_products(self) -> int:
        return (
            self.doublings * self.jacobian_double_foreign_products
            + self.additions * self.jacobian_add_foreign_products
        )

    @property
    def native_product_rows(self) -> int:
        return self.foreign_products * self.geometry.convolution_rank

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_class": (
                "EXPLICIT double-and-add Jacobian construction cost; not a lower bound "
                "against specialised endomorphism/subgroup arguments"
            ),
            "scalar_bits": self.scalar_bits,
            "scalar_hamming_weight": self.scalar_hamming_weight,
            "doublings": self.doublings,
            "additions": self.additions,
            "foreign_products_per_double": self.jacobian_double_foreign_products,
            "foreign_products_per_add": self.jacobian_add_foreign_products,
            "foreign_products": self.foreign_products,
            "native_product_rows_before_any_range_checks": self.native_product_rows,
        }


@dataclass(frozen=True, slots=True)
class BindingScenario:
    name: str
    point_rows: int
    security_complete: bool
    assumptions: tuple[str, ...]
    schema: str = "ranklock-outer-binding-scenario-v1"

    @property
    def envelope(self) -> PerDepositCandidateCost:
        return PerDepositCandidateCost(TranscriptConstraintScenario(self.point_rows))

    def document(self) -> dict[str, object]:
        envelope = self.envelope
        return {
            "schema": self.schema,
            "name": self.name,
            "point_rows": self.point_rows,
            "security_complete": self.security_complete,
            "assumptions": list(self.assumptions),
            "wrapper_trace_width": envelope.transcript.wrapper_trace_width,
            "static_plus_future_proof_bytes": (
                envelope.activation_plus_future_proof_bytes
            ),
            "margin_to_one_MiB_bytes": envelope.margin_to_one_mib,
            "fits_one_MiB": envelope.fits_one_mib,
        }


def outer_g1_binding_report() -> dict[str, object]:
    threshold = TranscriptConstraintScenario(0).maximum_point_binding_constraints_per_g1
    exact16 = OnCurveBindingCost(range_model=LogicalRangeModel(16))
    fused16 = OnCurveBindingCost(range_model=LogicalRangeModel(16))
    fused20 = OnCurveBindingCost(range_model=LogicalRangeModel(20))
    subgroup = StandardSubgroupCheckCost()

    scenarios = (
        BindingScenario(
            "16-bit exact canonical/on-curve ledger without subgroup",
            exact16.exact_logical_rows,
            False,
            (
                "one logical lookup or native product consumes one relation coordinate",
                "subgroup check omitted",
            ),
        ),
        BindingScenario(
            "16-bit optimistic fused-carry on-curve ledger without subgroup",
            fused16.optimistic_fused_rows,
            False,
            (
                "signed carry checks and linear equations are fused into a custom gate",
                "subgroup check omitted",
                "no real LVA lookup gadget exists yet",
            ),
        ),
        BindingScenario(
            "20-bit optimistic fused-carry on-curve ledger without subgroup",
            fused20.optimistic_fused_rows,
            False,
            (
                "2^20 fixed range table",
                "signed carry checks and linear equations are fused",
                "subgroup check omitted",
                "no real LVA lookup gadget exists yet",
            ),
        ),
        BindingScenario(
            "standard full subgroup check, native products only",
            exact16.exact_logical_rows + subgroup.native_product_rows,
            True,
            (
                "conventional variable-base [r]P=O double-and-add",
                "range/carry cost of subgroup arithmetic omitted, so this is optimistic",
            ),
        ),
    )

    return {
        "schema": "ranklock-outer-g1-binding-frontier-v1",
        "evidence_class": (
            "CONCRETE outer-curve geometry plus executable cost ledger; no production gadget"
        ),
        "point_binding_threshold_per_G1": threshold,
        "compressed_G1_bytes_corrected": COMPRESSED_G1_BYTES,
        "old_planning_G1_bytes": 64,
        "on_curve_16bit": exact16.document(),
        "on_curve_20bit": fused20.document(),
        "standard_subgroup_check": subgroup.document(),
        "scenarios": [scenario.document() for scenario in scenarios],
        "decision": {
            "generic_full_parser_under_325": False,
            "generic_public_FS_wrapper_size_gate_survives": False,
            "reason": (
                "The exact canonical/on-curve logical ledger already exceeds the 325-row "
                "budget at 16-bit lookup width, and a conventional subgroup check exceeds it "
                "by two orders of magnitude before range checks. The 20-bit fused on-curve "
                "target fits arithmetically but omits subgroup and the cryptographic scalar/"
                "group shared-object gadget, so it is not a secure instantiation."
            ),
            "not_a_universal_impossibility": (
                "A specialised endomorphism/subgroup proof, a native hybrid group/scalar WE "
                "gadget, or a proof system with no point-hashing transcript could change the result."
            ),
        },
        "surviving_research_targets": [
            "construct a hybrid LVA gadget whose group input and transcript encoding are one cryptographic variable",
            "remove point hashing by designing a challenge-oblivious/preprocessing one-sided proof",
            "find an efficient outer-curve subgroup argument compatible with the fixed relation",
        ],
    }
