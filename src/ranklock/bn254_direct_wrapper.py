from __future__ import annotations

"""BN254-native one-sided wrapper route for RankLock.

The v0.17 wrapper selected an outer pairing curve whose scalar field equals the
BN254 *base* field.  That keeps the wrapped RankVM arithmetic native, but the
resulting Cocks--Pinch-style G1 lives over a roughly 515-bit field and has a
large cofactor.  The generic public-Fiat--Shamir parser exceeded the 325-row
per-point envelope before a subgroup check was included.

This module evaluates the opposite trade-off:

* instantiate the one-sided pairing proof directly on BN254;
* run the wrapper circuit over BN254 Fr;
* represent RankVM's BN254 Fq arithmetic non-natively with the exact 3x85,
  rank-5 bridge already present in the repository;
* use canonical **uncompressed** 64-byte G1 encodings in the public transcript;
* exploit BN254 G1's cofactor-one structure, so an affine on-curve point needs
  no separate subgroup multiplication.

The uncompressed format is intentional.  It avoids a square-root/sign gadget:
both affine coordinates are supplied canonically, the curve equation is
checked, and the same typed point is consumed by the transcript and final
pairing layers.

The cost result is an executable logical product/range ledger, not a physical
PLONK layout or an instantiated LVA-WE compiler.
"""

from dataclasses import dataclass
from hashlib import sha256
from math import ceil
from typing import Sequence

from .bn254_real import (
    B,
    CURVE_ORDER,
    FIELD_MODULUS,
    G1,
    Point,
    is_on_curve,
    multiply,
    parse_g1_uncompressed,
    serialize_g1_uncompressed,
)
from .field_bridge import RangeLookupModel
from .fixed_statement_wrapper_candidate import PerDepositCandidateCost
from .low_rank_field_bridge import estimate_low_rank_reduced_quotient_limb_bridge
from .nonnative_field import (
    BN254_SCALAR_FIELD,
    LimbConfig,
    best_config,
    decompose,
)
from .one_sided_wrapper_frontier import OneSidedSnarkProfile
from .transcript_mini_lock import TranscriptConstraintScenario

BN254_G1_COFACTOR = 1
BN254_G1_UNCOMPRESSED_BYTES = 64
BN254_G1_COMPRESSED_BYTES = 32
BN254_G2_COMPRESSED_BYTES = 64
ONE_SIDED_G1_ELEMENTS = 10
ONE_SIDED_SCALAR_ELEMENTS = 20
ONE_SIDED_UNCOMPRESSED_PROOF_BYTES = (
    ONE_SIDED_G1_ELEMENTS * BN254_G1_UNCOMPRESSED_BYTES
    + ONE_SIDED_SCALAR_ELEMENTS * 32
)
KNOWN_FOREIGN_PRODUCTS = 25_889


class Bn254DirectWrapperError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CanonicalUncompressedG1:
    """One canonical affine BN254 G1 element shared by every verifier layer."""

    encoded: bytes

    def __post_init__(self) -> None:
        raw = bytes(self.encoded)
        point = parse_g1_uncompressed(raw)
        if serialize_g1_uncompressed(point) != raw:
            raise Bn254DirectWrapperError("non-canonical BN254 G1 encoding")
        object.__setattr__(self, "encoded", raw)

    @property
    def point(self) -> Point:
        return parse_g1_uncompressed(self.encoded)

    @property
    def transcript_field_elements(self) -> tuple[int, int, int]:
        """Injectively pack affine coordinates into three BN254-Fr elements.

        Each Fq coordinate has three 85-bit limbs.  For limb position ``i`` we
        absorb ``x_i + 2^85 * y_i``.  The result is below 2^170 < Fr, so the
        mapping is native-field canonical and is inverted by quotient/remainder
        at 2^85.  The same bounded limbs are used by the on-curve gadget.
        """

        point = self.point
        x = int(point[0].n)
        y = int(point[1].n)
        config = best_config(
            foreign_modulus=FIELD_MODULUS,
            native_modulus=BN254_SCALAR_FIELD,
        )
        x_limbs = decompose(x, config)
        y_limbs = decompose(y, config)
        packed = tuple(
            x_limb + config.base * y_limb
            for x_limb, y_limb in zip(x_limbs, y_limbs, strict=True)
        )
        if any(not 0 <= value < CURVE_ORDER for value in packed):
            raise AssertionError("paired coordinate limb does not fit BN254 Fr")
        return packed  # type: ignore[return-value]

    @classmethod
    def from_point(cls, point: Point) -> "CanonicalUncompressedG1":
        return cls(serialize_g1_uncompressed(point))


@dataclass(frozen=True, slots=True)
class CanonicalOneSidedProof:
    """Canonical 10-G1/20-Fr public proof object.

    The object is parsed once.  Its exact G1 encodings feed the transcript and
    its parsed points feed the pairing verifier.  This prevents a transcript /
    pairing split-brain at the API boundary.
    """

    g1: tuple[CanonicalUncompressedG1, ...]
    scalars: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.g1) != ONE_SIDED_G1_ELEMENTS:
            raise Bn254DirectWrapperError("one-sided proof must contain ten G1 elements")
        if len(self.scalars) != ONE_SIDED_SCALAR_ELEMENTS:
            raise Bn254DirectWrapperError("one-sided proof must contain twenty scalars")
        values = tuple(int(value) for value in self.scalars)
        if any(not 0 <= value < CURVE_ORDER for value in values):
            raise Bn254DirectWrapperError("one-sided proof scalar is non-canonical")
        object.__setattr__(self, "scalars", values)

    @property
    def pairing_points(self) -> tuple[Point, ...]:
        return tuple(element.point for element in self.g1)

    @property
    def encoded_bytes(self) -> bytes:
        return b"".join(element.encoded for element in self.g1) + b"".join(
            value.to_bytes(32, "big") for value in self.scalars
        )

    def transcript_digest(self, context: bytes) -> bytes:
        context = bytes(context)
        if not context:
            raise Bn254DirectWrapperError("transcript context is empty")
        transcript = bytearray(b"ranklock/bn254-direct-one-sided/v1\x00")
        transcript.extend(len(context).to_bytes(4, "big"))
        transcript.extend(context)
        for element in self.g1:
            for packed in element.transcript_field_elements:
                transcript.extend(packed.to_bytes(32, "big"))
        for value in self.scalars:
            transcript.extend(value.to_bytes(32, "big"))
        return sha256(bytes(transcript)).digest()


@dataclass(frozen=True, slots=True)
class CanonicalCoordinateCost:
    config: LimbConfig
    range_model: RangeLookupModel
    serialized: bool
    schema: str = "ranklock-bn254-coordinate-binding-cost-v1"

    @property
    def serialization_lookups(self) -> int:
        return self.range_model.chunks(256) if self.serialized else 0

    @property
    def slack_range_lookups(self) -> int:
        return self.config.limbs * self.range_model.chunks(self.config.limb_bits)

    @property
    def carry_lookups(self) -> int:
        return self.config.limbs - 1

    @property
    def logical_rows(self) -> int:
        return (
            self.serialization_lookups
            + self.slack_range_lookups
            + self.carry_lookups
        )

    @property
    def linear_equations(self) -> int:
        # Byte/limb packing, slack packing, and canonical addition.
        return 3 * self.config.limbs

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "serialized": self.serialized,
            "serialization_lookups": self.serialization_lookups,
            "slack_range_lookups": self.slack_range_lookups,
            "carry_lookups": self.carry_lookups,
            "logical_rows": self.logical_rows,
            "linear_equations": self.linear_equations,
        }


@dataclass(frozen=True, slots=True)
class InternalForeignProductCost:
    config: LimbConfig
    range_model: RangeLookupModel
    schema: str = "ranklock-bn254-internal-foreign-product-cost-v1"

    @property
    def native_products(self) -> int:
        return 2 * self.config.limbs - 1

    @property
    def output_canonical_cost(self) -> CanonicalCoordinateCost:
        # Internal outputs are canonical and shared between constraints, but are
        # not separately serialized into the public proof.
        return CanonicalCoordinateCost(self.config, self.range_model, False)

    @property
    def quotient_range_lookups(self) -> int:
        return self.range_model.chunks(FIELD_MODULUS.bit_length())

    @property
    def signed_carry_lookups(self) -> int:
        internal = 2 * self.config.limbs - 2
        signed_width = (2 * self.config.carry_abs_bound).bit_length()
        return internal * self.range_model.chunks(signed_width)

    @property
    def logical_rows(self) -> int:
        return (
            self.native_products
            + self.output_canonical_cost.logical_rows
            + self.quotient_range_lookups
            + self.signed_carry_lookups
        )

    @property
    def linear_equations(self) -> int:
        return (
            self.output_canonical_cost.linear_equations
            + self.config.limbs
            + (2 * self.config.limbs - 1)
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "native_products": self.native_products,
            "output_canonical": self.output_canonical_cost.document(),
            "quotient_range_lookups": self.quotient_range_lookups,
            "signed_carry_lookups": self.signed_carry_lookups,
            "logical_rows": self.logical_rows,
            "linear_equations": self.linear_equations,
        }


@dataclass(frozen=True, slots=True)
class Bn254UncompressedPointBindingCost:
    """Exact logical ledger for y^2 = x^3 + 3 over non-native BN254 Fq."""

    range_model: RangeLookupModel = RangeLookupModel(16)
    config: LimbConfig = best_config(
        foreign_modulus=FIELD_MODULUS,
        native_modulus=BN254_SCALAR_FIELD,
    )
    schema: str = "ranklock-bn254-uncompressed-point-binding-v1"

    def __post_init__(self) -> None:
        if self.config.foreign_modulus != FIELD_MODULUS:
            raise Bn254DirectWrapperError("point gadget foreign field is not BN254 Fq")
        if self.config.native_modulus != CURVE_ORDER:
            raise Bn254DirectWrapperError("point gadget native field is not BN254 Fr")

    @property
    def x_cost(self) -> CanonicalCoordinateCost:
        return CanonicalCoordinateCost(self.config, self.range_model, True)

    @property
    def y_cost(self) -> CanonicalCoordinateCost:
        return CanonicalCoordinateCost(self.config, self.range_model, True)

    @property
    def product_cost(self) -> InternalForeignProductCost:
        return InternalForeignProductCost(self.config, self.range_model)

    @property
    def foreign_products(self) -> int:
        # x2=x*x, x3=x2*x, y2=y*y; y2=x3+3 is linear.
        return 3

    @property
    def subgroup_rows(self) -> int:
        # BN254 G1 has cofactor one.  Canonical affine on-curve points are
        # already in the prime-order subgroup.
        return 0

    @property
    def exact_logical_rows(self) -> int:
        return (
            self.x_cost.logical_rows
            + self.y_cost.logical_rows
            + self.foreign_products * self.product_cost.logical_rows
            + self.subgroup_rows
        )

    @property
    def linear_equations(self) -> int:
        return (
            self.x_cost.linear_equations
            + self.y_cost.linear_equations
            + self.foreign_products * self.product_cost.linear_equations
            + 1
        )

    @property
    def threshold(self) -> int:
        return TranscriptConstraintScenario(0).maximum_point_binding_constraints_per_g1

    @property
    def fits_threshold(self) -> bool:
        return self.exact_logical_rows <= self.threshold

    @property
    def envelope(self) -> PerDepositCandidateCost:
        return PerDepositCandidateCost(
            TranscriptConstraintScenario(self.exact_logical_rows)
        )

    def document(self) -> dict[str, object]:
        envelope = self.envelope
        return {
            "schema": self.schema,
            "evidence_class": (
                "EXACT logical range/product inventory under the 3x85 rank-5 bridge; "
                "not a physical lookup layout or LVA-WE key"
            ),
            "native_field": "BN254 Fr",
            "foreign_coordinate_field": "BN254 Fq",
            "config": self.config.document(),
            "range_model": self.range_model.document(),
            "encoding": "canonical 64-byte affine x||y",
            "cofactor": BN254_G1_COFACTOR,
            "external_x": self.x_cost.document(),
            "external_y": self.y_cost.document(),
            "foreign_products": self.foreign_products,
            "per_foreign_product": self.product_cost.document(),
            "subgroup_rows": self.subgroup_rows,
            "exact_logical_rows_per_G1": self.exact_logical_rows,
            "linear_equations_not_charged_as_relation_coordinates": self.linear_equations,
            "point_binding_threshold_per_G1": self.threshold,
            "fits_threshold": self.fits_threshold,
            "wrapper_trace_width": envelope.transcript.wrapper_trace_width,
            "activation_plus_future_proof_bytes": (
                envelope.activation_plus_future_proof_bytes
            ),
            "margin_to_one_MiB_bytes": envelope.margin_to_one_mib,
            "fits_one_MiB": envelope.fits_one_mib,
            "load_bearing_assumptions": [
                "one logical lookup or native product consumes one fixed-relation coordinate",
                "linear packing/carry equations do not consume a 66-byte nonlinear coordinate",
                "one canonical proof object is shared by transcript and pairing gadgets",
                "affine infinity has no accepted encoding",
                "BN254 G1 cofactor is one",
            ],
        }


def _crs_scenario(profile: OneSidedSnarkProfile, name: str, gates: int) -> dict[str, object]:
    return {
        "name": name,
        "circuit_gate_assumption": gates,
        "prover_time_CRS_bytes_compressed": profile.shared_crs_bytes(
            gates,
            g1_bytes=BN254_G1_COMPRESSED_BYTES,
            g2_bytes=BN254_G2_COMPRESSED_BYTES,
            mode="prover_time",
        ),
        "proof_size_CRS_bytes_compressed": profile.shared_crs_bytes(
            gates,
            g1_bytes=BN254_G1_COMPRESSED_BYTES,
            g2_bytes=BN254_G2_COMPRESSED_BYTES,
            mode="proof_size",
        ),
        "combined_prover_MSM_terms": profile.prover_msm_terms(gates),
    }


def bn254_direct_wrapper_report() -> dict[str, object]:
    point16 = Bn254UncompressedPointBindingCost(RangeLookupModel(16))
    point20 = Bn254UncompressedPointBindingCost(RangeLookupModel(20))
    profile = OneSidedSnarkProfile()
    one_product = estimate_low_rank_reduced_quotient_limb_bridge(
        1,
        point16.config,
        range_model=RangeLookupModel(16),
    )
    kernel = estimate_low_rank_reduced_quotient_limb_bridge(
        KNOWN_FOREIGN_PRODUCTS,
        point16.config,
        range_model=RangeLookupModel(16),
    )
    total_events = (
        kernel.native_nonlinear_products
        + kernel.total_lookup_events
        + kernel.total_linear_equations
    )
    return {
        "schema": "ranklock-bn254-direct-wrapper-frontier-v1",
        "evidence_class": (
            "REAL canonical BN254 proof parser + exact integer field bridge + "
            "parameterised wrapper/CRS cost envelope"
        ),
        "architectural_pivot": {
            "old": "native RankVM Fq arithmetic on a large-cofactor CP6-style outer curve",
            "new": "non-native RankVM Fq arithmetic inside a BN254-Fr one-sided wrapper",
            "reason": (
                "BN254 G1 has 32/64-byte encodings and cofactor one; the added field-bridge "
                "cost is reusable prover/CRS work rather than per-proof subgroup parsing"
            ),
        },
        "proof_format": {
            "G1_elements": ONE_SIDED_G1_ELEMENTS,
            "scalar_elements": ONE_SIDED_SCALAR_ELEMENTS,
            "G1_encoding": "canonical uncompressed affine x||y",
            "G1_bytes": BN254_G1_UNCOMPRESSED_BYTES,
            "total_proof_bytes": ONE_SIDED_UNCOMPRESSED_PROOF_BYTES,
            "compressed_transport_variant_bytes": profile.proof_bytes(
                g1_bytes=BN254_G1_COMPRESSED_BYTES,
                scalar_bytes=32,
            ),
            "why_uncompressed": (
                "avoids square-root, sign-selection, and comparator constraints in the static transcript relation"
            ),
        },
        "point_binding_16bit": point16.document(),
        "point_binding_20bit": point20.document(),
        "one_foreign_product_reference": one_product.document(),
        "known_kernel_field_bridge": kernel.document(),
        "reusable_wrapper_CRS_scenarios": [
            _crs_scenario(
                profile,
                "nonlinear rank-5 products only",
                kernel.native_nonlinear_products,
            ),
            _crs_scenario(
                profile,
                "all current field-bridge logical events",
                total_events,
            ),
        ],
        "decision": {
            "CP6_generic_parser_route": "killed in current logical model",
            "BN254_direct_point_binding_gate": "passes",
            "public_Fiat_Shamir_wrapper_route": "survives this gate",
            "reference_rows_per_G1": point16.exact_logical_rows,
            "threshold_rows_per_G1": point16.threshold,
            "one_MiB_margin_bytes": point16.envelope.margin_to_one_mib,
            "breakthrough_target_met": False,
            "why_not_complete": (
                "The complete one-sided proof system, transcript/scalar verifier, LVA-WE compiler, "
                "lookup backend, and malicious activation proof remain uninstantiated."
            ),
        },
        "next_gate": (
            "Compile the actual one-sided verifier transcript and scalar equations over BN254 Fr, "
            "using this canonical 267-row point object, then replace the 1,024 scalar-verifier "
            "allowance with a complete equation inventory."
        ),
    }


def _self_test_parser() -> None:
    points = tuple(
        CanonicalUncompressedG1.from_point(multiply(G1, index + 1, group="g1"))
        for index in range(ONE_SIDED_G1_ELEMENTS)
    )
    proof = CanonicalOneSidedProof(points, tuple(range(ONE_SIDED_SCALAR_ELEMENTS)))
    if len(proof.encoded_bytes) != ONE_SIDED_UNCOMPRESSED_PROOF_BYTES:
        raise AssertionError("unexpected one-sided proof byte size")
    if any(not is_on_curve(point, B) for point in proof.pairing_points):
        raise AssertionError("parsed proof point is off curve")
    if proof.transcript_digest(b"self-test") == proof.transcript_digest(b"other"):
        raise AssertionError("transcript context is not bound")
