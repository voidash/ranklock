from __future__ import annotations

"""Executable backend-independent constraint traces for field bridges.

This module sits between the exact witness models and a concrete PLONK/R1CS
library.  It executes the same relations a backend must enforce and records:

* native multiplication constraints;
* standalone linear constraints;
* linear output forms fused into multiplication gates;
* fixed-width logical tuple/range lookups.

The ledger is deliberately not a proof system: it has transparent witness
access, no polynomial commitment scheme, and no binding or zero-knowledge
claim.  Its purpose is to make the cost inventory executable and to catch
mismatches between witness code and schedule estimates before integrating a
real backend.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable, Sequence

from .canonical_bytes import CanonicalByteWitness, verify_canonical_byte_witness
from .crt_bridge import (
    BoundCrtMulWitness,
    estimate_bounded_quotient_crt_bridge,
)
from .crt_field import CrtFieldConfig
from .field_bridge import (
    CANONICAL_BYTE_WIDTH,
    CanonicalGeometry,
    CanonicalLimbWitness,
    RangeLookupModel,
    verify_canonical_limb_witness,
)
from .low_rank_convolution import (
    LowRankConvolutionPlan,
    interpolation_matrix,
)
from .low_rank_field_bridge import (
    LowRankBoundForeignMulWitness,
    estimate_low_rank_reduced_quotient_limb_bridge,
)
from .nonnative_field import LimbConfig, decompose
from .split_limb_field import (
    ProductSplit,
    SplitLimbConfig,
    SplitLimbMulWitness,
    estimate_split_limb_reduced_quotient_schedule,
)


class ConstraintBackendError(ValueError):
    pass


class ConstraintViolation(ConstraintBackendError):
    """Raised when a concrete witness fails an emitted relation."""


@dataclass(frozen=True, slots=True)
class NativeLedgerReport:
    label: str
    modulus: int
    multiplication_constraints: int
    standalone_linear_constraints: int
    embedded_linear_relations: int
    logical_lookup_events: int
    fixed_boundary_checks: int
    assumptions: tuple[str, ...]
    event_digest: str
    schema: str = "ranklock-native-constraint-ledger-report-v1"

    @property
    def linear_relation_events(self) -> int:
        return self.standalone_linear_constraints + self.embedded_linear_relations

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "label": self.label,
            "modulus": str(self.modulus),
            "multiplication_constraints": self.multiplication_constraints,
            "standalone_linear_constraints": self.standalone_linear_constraints,
            "embedded_linear_relations": self.embedded_linear_relations,
            "linear_relation_events": self.linear_relation_events,
            "logical_lookup_events": self.logical_lookup_events,
            "fixed_boundary_checks": self.fixed_boundary_checks,
            "assumptions": list(self.assumptions),
            "event_digest": self.event_digest,
        }


class NativeConstraintLedger:
    """Concrete relation checker plus deterministic event counter."""

    def __init__(self, label: str, modulus: int) -> None:
        if not label:
            raise ConstraintBackendError("ledger label must be nonempty")
        if modulus <= 2:
            raise ConstraintBackendError("ledger modulus must exceed two")
        self.label = str(label)
        self.modulus = int(modulus)
        self.multiplication_constraints = 0
        self.standalone_linear_constraints = 0
        self.embedded_linear_relations = 0
        self.logical_lookup_events = 0
        self.fixed_boundary_checks = 0
        self.assumptions: list[str] = []
        self._events: list[dict[str, object]] = []

    def _record(self, kind: str, label: str, **payload: object) -> None:
        self._events.append({"kind": kind, "label": label, **payload})

    def assume(self, label: str, predicate: bool, *, detail: str) -> None:
        if not predicate:
            raise ConstraintViolation(f"assumption failed: {label}: {detail}")
        self.assumptions.append(f"{label}: {detail}")
        self._record("assumption", label, detail=detail)

    def fixed(self, label: str, predicate: bool, *, detail: str) -> None:
        if not predicate:
            raise ConstraintViolation(f"fixed boundary failed: {label}: {detail}")
        self.fixed_boundary_checks += 1
        self._record("fixed", label, detail=detail)

    def linear_zero(
        self,
        label: str,
        integer_value: int,
        *,
        require_exact: bool = True,
    ) -> None:
        value = int(integer_value)
        if value % self.modulus != 0:
            raise ConstraintViolation(
                f"linear constraint failed modulo native field: {label}"
            )
        if require_exact and value != 0:
            raise ConstraintViolation(f"exact linear constraint failed: {label}")
        self.standalone_linear_constraints += 1
        self._record(
            "linear",
            label,
            value=str(value),
            require_exact=require_exact,
        )

    def multiply(
        self,
        label: str,
        left: int,
        right: int,
        output: int,
        *,
        require_exact: bool = False,
        embedded_linear_relations: int = 0,
    ) -> None:
        left_i = int(left)
        right_i = int(right)
        output_i = int(output)
        residual = left_i * right_i - output_i
        if residual % self.modulus != 0:
            raise ConstraintViolation(f"multiplication constraint failed: {label}")
        if require_exact and residual != 0:
            raise ConstraintViolation(f"exact multiplication constraint failed: {label}")
        if embedded_linear_relations < 0:
            raise ConstraintBackendError("embedded relation count cannot be negative")
        self.multiplication_constraints += 1
        self.embedded_linear_relations += int(embedded_linear_relations)
        self._record(
            "multiplication",
            label,
            left=str(left_i % self.modulus),
            right=str(right_i % self.modulus),
            output=str(output_i % self.modulus),
            require_exact=require_exact,
            embedded_linear_relations=int(embedded_linear_relations),
        )

    def lookup_unsigned(
        self,
        label: str,
        value: int,
        bits: int,
        range_model: RangeLookupModel,
    ) -> tuple[int, ...]:
        value_i = int(value)
        bits_i = int(bits)
        if bits_i <= 0:
            raise ConstraintBackendError("lookup width must be positive")
        if not 0 <= value_i < (1 << bits_i):
            raise ConstraintViolation(f"unsigned lookup range failed: {label}")

        chunks: list[int] = []
        remaining = value_i
        base = 1 << range_model.chunk_bits
        chunk_count = range_model.chunks(bits_i)
        for index in range(chunk_count):
            width = min(range_model.chunk_bits, bits_i - index * range_model.chunk_bits)
            chunk = remaining % base
            remaining //= base
            if not 0 <= chunk < (1 << width):
                raise ConstraintViolation(f"top-chunk range failed: {label}[{index}]")
            chunks.append(chunk)
            self.logical_lookup_events += 1
            self._record(
                "lookup",
                f"{label}[{index}]",
                value=chunk,
                bits=width,
                table_chunk_bits=range_model.chunk_bits,
            )
        if remaining:
            raise ConstraintViolation(f"lookup decomposition overflow: {label}")
        if sum(chunk << (index * range_model.chunk_bits) for index, chunk in enumerate(chunks)) != value_i:
            raise AssertionError("lookup decomposition did not reconstruct")
        return tuple(chunks)

    def lookup_packed_bytes(
        self,
        label: str,
        data_be: bytes,
        range_model: RangeLookupModel,
        *,
        width: int = CANONICAL_BYTE_WIDTH,
    ) -> tuple[int, ...]:
        data = bytes(data_be)
        if len(data) != width:
            raise ConstraintViolation(f"canonical byte width failed: {label}")
        value = int.from_bytes(data, "big")
        chunks = self.lookup_unsigned(label, value, 8 * width, range_model)
        if value.to_bytes(width, "big") != data:
            raise AssertionError("packed byte lookup changed serialization")
        return chunks

    def lookup_bounded_bytes(
        self,
        label: str,
        data_be: bytes,
        bits: int,
        range_model: RangeLookupModel,
        *,
        width: int = CANONICAL_BYTE_WIDTH,
    ) -> tuple[int, ...]:
        data = bytes(data_be)
        bits_i = int(bits)
        if len(data) != width:
            raise ConstraintViolation(f"bounded byte width failed: {label}")
        if not 1 <= bits_i <= 8 * width:
            raise ConstraintBackendError("bounded byte bit width is invalid")
        value = int.from_bytes(data, "big")
        chunks = self.lookup_unsigned(label, value, bits_i, range_model)
        if value.to_bytes(width, "big") != data:
            raise AssertionError("bounded byte lookup changed serialization")
        return chunks

    def lookup_small(
        self,
        label: str,
        value: int,
        allowed: Iterable[int],
    ) -> None:
        allowed_values = tuple(int(item) for item in allowed)
        value_i = int(value)
        if value_i not in allowed_values:
            raise ConstraintViolation(f"small lookup membership failed: {label}")
        self.logical_lookup_events += 1
        self._record(
            "small_lookup",
            label,
            value=value_i,
            allowed=list(allowed_values),
        )

    def report(self) -> NativeLedgerReport:
        payload = json.dumps(
            self._events, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = hashlib.sha256(
            b"ranklock/native-constraint-ledger/v1\x00" + payload
        ).hexdigest()
        return NativeLedgerReport(
            label=self.label,
            modulus=self.modulus,
            multiplication_constraints=self.multiplication_constraints,
            standalone_linear_constraints=self.standalone_linear_constraints,
            embedded_linear_relations=self.embedded_linear_relations,
            logical_lookup_events=self.logical_lookup_events,
            fixed_boundary_checks=self.fixed_boundary_checks,
            assumptions=tuple(self.assumptions),
            event_digest=digest,
        )


@dataclass(frozen=True, slots=True)
class CompiledBridgeTrace:
    route: str
    native_ledgers: tuple[NativeLedgerReport, ...]
    estimated_native_nonlinear_products: int
    estimated_logical_lookup_events: int
    estimated_linear_relation_events: int
    cross_field_binding: str
    selectable: bool
    warnings: tuple[str, ...]
    schema: str = "ranklock-compiled-field-bridge-trace-v1"

    @property
    def native_nonlinear_products(self) -> int:
        return sum(report.multiplication_constraints for report in self.native_ledgers)

    @property
    def logical_lookup_events(self) -> int:
        return sum(report.logical_lookup_events for report in self.native_ledgers)

    @property
    def standalone_linear_constraints(self) -> int:
        return sum(
            report.standalone_linear_constraints for report in self.native_ledgers
        )

    @property
    def embedded_linear_relations(self) -> int:
        return sum(report.embedded_linear_relations for report in self.native_ledgers)

    @property
    def linear_relation_events(self) -> int:
        return sum(report.linear_relation_events for report in self.native_ledgers)

    @property
    def estimate_match(self) -> bool:
        return (
            self.native_nonlinear_products
            == self.estimated_native_nonlinear_products
            and self.logical_lookup_events == self.estimated_logical_lookup_events
            and self.linear_relation_events == self.estimated_linear_relation_events
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "route": self.route,
            "evidence_class": (
                "REPRODUCED executable constraint trace; transparent witness, no PCS"
            ),
            "native_ledgers": [report.document() for report in self.native_ledgers],
            "native_nonlinear_products": self.native_nonlinear_products,
            "logical_lookup_events": self.logical_lookup_events,
            "standalone_linear_constraints": self.standalone_linear_constraints,
            "embedded_linear_relations": self.embedded_linear_relations,
            "linear_relation_events": self.linear_relation_events,
            "estimated_native_nonlinear_products": self.estimated_native_nonlinear_products,
            "estimated_logical_lookup_events": self.estimated_logical_lookup_events,
            "estimated_linear_relation_events": self.estimated_linear_relation_events,
            "estimate_match": self.estimate_match,
            "cross_field_binding": self.cross_field_binding,
            "selectable": self.selectable,
            "warnings": list(self.warnings),
        }


def _record_canonical_limb_binding(
    ledger: NativeConstraintLedger,
    label: str,
    witness: CanonicalLimbWitness,
    geometry: CanonicalGeometry,
    range_model: RangeLookupModel,
) -> None:
    if not verify_canonical_limb_witness(witness, geometry):
        raise ConstraintViolation(f"canonical limb witness failed: {label}")

    value = witness.value
    slack = geometry.foreign_modulus - 1 - value
    ledger.lookup_packed_bytes(
        f"{label}.canonical_bytes", witness.canonical_bytes_be, range_model
    )

    mask = geometry.base - 1
    for index, limb in enumerate(witness.value_limbs):
        expected = (value >> (index * geometry.limb_bits)) & mask
        ledger.linear_zero(
            f"{label}.value_limb_pack[{index}]", int(limb) - expected
        )
    for index, limb in enumerate(witness.slack_limbs):
        ledger.lookup_unsigned(
            f"{label}.slack_limb[{index}]",
            limb,
            geometry.limb_bits,
            range_model,
        )
        expected = (slack >> (index * geometry.limb_bits)) & mask
        ledger.linear_zero(
            f"{label}.slack_limb_pack[{index}]", int(limb) - expected
        )

    target = geometry.foreign_modulus - 1
    for index in range(geometry.limbs):
        target_limb = (target >> (index * geometry.limb_bits)) & mask
        carry_in = witness.carries_le[index]
        carry_out = witness.carries_le[index + 1]
        ledger.linear_zero(
            f"{label}.canonical_add[{index}]",
            witness.value_limbs[index]
            + witness.slack_limbs[index]
            + carry_in
            - target_limb
            - geometry.base * carry_out,
        )
        if 0 < index + 1 < geometry.limbs:
            ledger.lookup_small(
                f"{label}.canonical_carry[{index + 1}]", carry_out, (0, 1)
            )

    ledger.fixed(
        f"{label}.carry_boundaries",
        witness.carries_le[0] == 0 and witness.carries_le[-1] == 0,
        detail="canonical addition begins and ends with zero carry",
    )



def _record_bounded_limb_binding(
    ledger: NativeConstraintLedger,
    label: str,
    witness: CanonicalLimbWitness,
    geometry: CanonicalGeometry,
    range_model: RangeLookupModel,
    *,
    bits: int,
) -> None:
    """Bind a fixed-width byte value to limbs without a ``< q`` slack proof."""

    if len(witness.canonical_bytes_be) != geometry.byte_width:
        raise ConstraintViolation(f"bounded limb byte width failed: {label}")
    if len(witness.value_limbs) != geometry.limbs:
        raise ConstraintViolation(f"bounded limb count failed: {label}")
    value = int.from_bytes(witness.canonical_bytes_be, "big")
    if not 0 <= value < (1 << bits):
        raise ConstraintViolation(f"bounded limb range failed: {label}")
    ledger.lookup_bounded_bytes(
        f"{label}.bounded_bytes",
        witness.canonical_bytes_be,
        bits,
        range_model,
        width=geometry.byte_width,
    )
    mask = geometry.base - 1
    for index, limb in enumerate(witness.value_limbs):
        expected = (value >> (index * geometry.limb_bits)) & mask
        ledger.linear_zero(
            f"{label}.value_limb_pack[{index}]", int(limb) - expected
        )
    if sum(
        int(limb) * geometry.base**index
        for index, limb in enumerate(witness.value_limbs)
    ) != value:
        raise ConstraintViolation(f"bounded limb reconstruction failed: {label}")

def _interpolate_point_products(
    products: Sequence[int], plan: LowRankConvolutionPlan
) -> tuple[int, ...]:
    matrix = interpolation_matrix(plan.points, plan.native_modulus)
    return tuple(
        sum(weight * int(value) for weight, value in zip(row, products, strict=True))
        % plan.native_modulus
        for row in matrix
    )


def compile_rank5_3x85_trace(
    witness: LowRankBoundForeignMulWitness,
    config: LimbConfig,
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
) -> CompiledBridgeTrace:
    """Compile one multiplication with ``x``/``y`` treated as reused inputs."""

    if config.limbs != 3:
        raise ConstraintBackendError("rank-5 bridge compiler expects three limbs")
    ledger = NativeConstraintLedger("single_field_bls12_381_fr", config.native_modulus)
    bound = witness.bound
    geometry = CanonicalGeometry.from_limb_config(config)

    ledger.assume(
        "x_prebound",
        verify_canonical_limb_witness(bound.x, geometry),
        detail="input x is already constrained by the enclosing trace",
    )
    ledger.assume(
        "y_prebound",
        verify_canonical_limb_witness(bound.y, geometry),
        detail="input y is already constrained by the enclosing trace",
    )
    _record_canonical_limb_binding(ledger, "z", bound.z, geometry, range_model)
    _record_bounded_limb_binding(
        ledger,
        "quotient",
        bound.quotient,
        geometry,
        range_model,
        bits=254,
    )

    arithmetic = bound.arithmetic
    convolution = witness.convolution
    if convolution.left != arithmetic.x_limbs or convolution.right != arithmetic.y_limbs:
        raise ConstraintViolation("low-rank convolution inputs are not the arithmetic limbs")
    if len(convolution.point_products) != 2 * config.limbs - 1:
        raise ConstraintViolation("low-rank point-product count is wrong")
    if (
        bound.x.value_limbs != arithmetic.x_limbs
        or bound.y.value_limbs != arithmetic.y_limbs
        or bound.z.value_limbs != arithmetic.z_limbs
        or bound.quotient.value_limbs != arithmetic.quotient_limbs
    ):
        raise ConstraintViolation("canonical and arithmetic limb tables diverge")

    plan = LowRankConvolutionPlan.consecutive(config.limbs, config.native_modulus)
    for index, point in enumerate(plan.points):
        left_eval = sum(
            limb * pow(point, power, config.native_modulus)
            for power, limb in enumerate(arithmetic.x_limbs)
        ) % config.native_modulus
        right_eval = sum(
            limb * pow(point, power, config.native_modulus)
            for power, limb in enumerate(arithmetic.y_limbs)
        ) % config.native_modulus
        ledger.multiply(
            f"convolution.point_product[{index}]",
            left_eval,
            right_eval,
            convolution.point_products[index],
        )

    coefficients = _interpolate_point_products(convolution.point_products, plan)
    modulus_limbs = decompose(config.foreign_modulus, config)
    quotient_product = [0] * (2 * config.limbs - 1)
    for i, quotient_limb in enumerate(arithmetic.quotient_limbs):
        for j, modulus_limb in enumerate(modulus_limbs):
            quotient_product[i + j] += quotient_limb * modulus_limb

    if len(arithmetic.carries) != 2 * config.limbs:
        raise ConstraintViolation("foreign carry count is wrong")
    ledger.fixed(
        "foreign_carry_boundaries",
        arithmetic.carries[0] == 0 and arithmetic.carries[-1] == 0,
        detail="foreign multiplication carry chain begins and ends at zero",
    )
    signed_width = (2 * config.carry_abs_bound).bit_length()
    for index, carry in enumerate(arithmetic.carries[1:-1], start=1):
        ledger.lookup_unsigned(
            f"foreign_carry_offset[{index}]",
            int(carry) + config.carry_abs_bound,
            signed_width,
            range_model,
        )

    for index, coefficient in enumerate(coefficients):
        rhs = quotient_product[index] + (
            arithmetic.z_limbs[index] if index < config.limbs else 0
        )
        ledger.linear_zero(
            f"foreign_carry_equation[{index}]",
            coefficient
            - rhs
            + arithmetic.carries[index]
            - config.base * arithmetic.carries[index + 1],
        )

    estimate = estimate_low_rank_reduced_quotient_limb_bridge(
        1, config, range_model=range_model
    )
    report = CompiledBridgeTrace(
        route="single_field_3x85_rank5",
        native_ledgers=(ledger.report(),),
        estimated_native_nonlinear_products=estimate.native_nonlinear_products,
        estimated_logical_lookup_events=estimate.total_lookup_events,
        estimated_linear_relation_events=estimate.total_linear_equations,
        cross_field_binding="not applicable: one proof field",
        selectable=True,
        warnings=(
            "Transparent native constraint ledger only; no lookup argument, PCS, degree bound, or proof bytes.",
            "Input x/y canonical costs are amortized as prebound trace values; z is canonical and the internal quotient is only 254-bit bounded.",
        ),
    )
    if not report.estimate_match:
        raise AssertionError("rank-5 compiled trace and schedule estimate diverge")
    return report


def _record_split_range_checks(
    ledger: NativeConstraintLedger,
    label: str,
    split: ProductSplit,
    config: SplitLimbConfig,
    range_model: RangeLookupModel,
) -> None:
    ledger.lookup_unsigned(f"{label}.low", split.low, config.limb_bits, range_model)
    ledger.lookup_unsigned(f"{label}.high", split.high, config.limb_bits, range_model)


def compile_split_2x127_trace(
    witness: SplitLimbMulWitness,
    config: SplitLimbConfig = SplitLimbConfig(),
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
) -> CompiledBridgeTrace:
    """Compile the exact four-product split-limb challenger."""

    ledger = NativeConstraintLedger("single_field_bls12_381_fr", config.native_modulus)
    geometry = config.geometry
    ledger.assume(
        "x_prebound",
        verify_canonical_limb_witness(witness.x, geometry),
        detail="input x is already constrained by the enclosing trace",
    )
    ledger.assume(
        "y_prebound",
        verify_canonical_limb_witness(witness.y, geometry),
        detail="input y is already constrained by the enclosing trace",
    )
    _record_canonical_limb_binding(ledger, "z", witness.z, geometry, range_model)
    _record_bounded_limb_binding(
        ledger,
        "quotient",
        witness.quotient,
        geometry,
        range_model,
        bits=254,
    )

    if len(witness.xy_splits) != 4 or len(witness.quotient_modulus_splits) != 4:
        raise ConstraintViolation("split-product tuple count is wrong")
    pairs = ((0, 0), (0, 1), (1, 0), (1, 1))
    for index, ((i, j), split) in enumerate(zip(pairs, witness.xy_splits, strict=True)):
        _record_split_range_checks(
            ledger, f"xy_split[{index}]", split, config, range_model
        )
        ledger.multiply(
            f"xy_product[{index}]",
            witness.x.value_limbs[i],
            witness.y.value_limbs[j],
            split.low + config.base * split.high,
            require_exact=True,
            embedded_linear_relations=1,
        )

    modulus_limbs = config.modulus_limbs
    for index, ((i, j), split) in enumerate(
        zip(pairs, witness.quotient_modulus_splits, strict=True)
    ):
        _record_split_range_checks(
            ledger, f"quotient_modulus_split[{index}]", split, config, range_model
        )
        ledger.linear_zero(
            f"quotient_modulus_product[{index}]",
            witness.quotient.value_limbs[i] * modulus_limbs[j]
            - split.low
            - config.base * split.high,
        )

    if len(witness.normalized_digits) != 4:
        raise ConstraintViolation("normalized digit count is wrong")
    if witness.normalized_digits[0] != witness.xy_splits[0].low:
        raise ConstraintViolation("normalized digit zero does not alias p00.low")
    for index in range(1, 4):
        chunks = ledger.lookup_unsigned(
            f"normalized_digit[{index}]",
            witness.normalized_digits[index],
            config.limb_bits,
            range_model,
        )
        reconstructed = sum(
            chunk << (position * range_model.chunk_bits)
            for position, chunk in enumerate(chunks)
        )
        ledger.linear_zero(
            f"normalized_digit_pack[{index}]",
            witness.normalized_digits[index] - reconstructed,
        )

    if len(witness.product_carries) != 2 or len(witness.reduction_carries) != 3:
        raise ConstraintViolation("normalization carry count is wrong")
    for index, carry in enumerate(witness.product_carries):
        ledger.lookup_small(f"product_carry[{index}]", carry, (0, 1, 2))
    reduction_ranges = ((0, 1), (0, 1, 2, 3), (0, 1, 2))
    for index, (carry, allowed) in enumerate(
        zip(witness.reduction_carries, reduction_ranges, strict=True)
    ):
        ledger.lookup_small(f"reduction_carry[{index}]", carry, allowed)

    p00, p01, p10, p11 = witness.xy_splits
    d0, d1, d2, d3 = witness.normalized_digits
    c2, c3 = witness.product_carries
    ledger.linear_zero(
        "product_normalize[1]",
        p00.high + p01.low + p10.low - d1 - config.base * c2,
    )
    ledger.linear_zero(
        "product_normalize[2]",
        p01.high + p10.high + p11.low + c2 - d2 - config.base * c3,
    )
    ledger.linear_zero("product_normalize[3]", p11.high + c3 - d3)

    r00, r01, r10, r11 = witness.quotient_modulus_splits
    z0, z1 = witness.z.value_limbs
    rc1, rc2, rc3 = witness.reduction_carries
    ledger.linear_zero(
        "reduction_normalize[0]",
        r00.low + z0 - d0 - config.base * rc1,
    )
    ledger.linear_zero(
        "reduction_normalize[1]",
        r00.high + r01.low + r10.low + z1 + rc1 - d1 - config.base * rc2,
    )
    ledger.linear_zero(
        "reduction_normalize[2]",
        r01.high + r10.high + r11.low + rc2 - d2 - config.base * rc3,
    )
    ledger.linear_zero("reduction_normalize[3]", r11.high + rc3 - d3)

    estimate = estimate_split_limb_reduced_quotient_schedule(
        1, config, range_model=range_model
    )
    report = CompiledBridgeTrace(
        route="single_field_2x127_split",
        native_ledgers=(ledger.report(),),
        estimated_native_nonlinear_products=estimate.native_nonlinear_products,
        estimated_logical_lookup_events=estimate.total_lookup_events,
        estimated_linear_relation_events=estimate.linear_equations,
        cross_field_binding="not applicable: one proof field",
        selectable=True,
        warnings=(
            "Transparent native constraint ledger only; no lookup argument, PCS, degree bound, or proof bytes.",
            "Input x/y canonical costs are amortized as prebound trace values; z is canonical and the internal quotient is only 254-bit bounded.",
        ),
    )
    if not report.estimate_match:
        raise AssertionError("2x127 compiled trace and schedule estimate diverge")
    return report


def _word_canonical_carries(
    witness: CanonicalByteWitness,
    config: CrtFieldConfig,
    range_model: RangeLookupModel,
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    word_bits = range_model.chunk_bits
    words = range_model.chunks(8 * len(witness.value_bytes_be))
    base = 1 << word_bits
    mask = base - 1
    value = int.from_bytes(witness.value_bytes_be, "big")
    slack = int.from_bytes(witness.slack_bytes_be, "big")
    target = config.foreign_modulus - 1
    value_words = tuple((value >> (index * word_bits)) & mask for index in range(words))
    slack_words = tuple((slack >> (index * word_bits)) & mask for index in range(words))
    target_words = tuple((target >> (index * word_bits)) & mask for index in range(words))
    carries = [0]
    for value_word, slack_word, target_word in zip(
        value_words, slack_words, target_words, strict=True
    ):
        numerator = value_word + slack_word + carries[-1] - target_word
        if numerator % base:
            raise ConstraintViolation("word-canonical carry is not integral")
        carries.append(numerator // base)
    if carries[-1] != 0 or any(carry not in (0, 1) for carry in carries):
        raise ConstraintViolation("word-canonical carries are not Boolean")
    return value_words, slack_words, target_words, tuple(carries)


def _record_crt_owner_canonical(
    owner: NativeConstraintLedger,
    other: NativeConstraintLedger,
    label: str,
    witness: CanonicalByteWitness,
    config: CrtFieldConfig,
    range_model: RangeLookupModel,
) -> None:
    if not verify_canonical_byte_witness(witness, config):
        raise ConstraintViolation(f"canonical CRT byte witness failed: {label}")
    value_words, slack_words, target_words, carries = _word_canonical_carries(
        witness, config, range_model
    )
    owner.lookup_packed_bytes(
        f"{label}.value_words", witness.value_bytes_be, range_model
    )
    owner.lookup_packed_bytes(
        f"{label}.slack_words", witness.slack_bytes_be, range_model
    )
    base = 1 << range_model.chunk_bits
    for index in range(len(value_words)):
        owner.linear_zero(
            f"{label}.canonical_add[{index}]",
            value_words[index]
            + slack_words[index]
            + carries[index]
            - target_words[index]
            - base * carries[index + 1],
        )
        if 0 < index + 1 < len(value_words):
            owner.lookup_small(
                f"{label}.canonical_carry[{index + 1}]",
                carries[index + 1],
                (0, 1),
            )
    owner.fixed(
        f"{label}.carry_boundaries",
        carries[0] == 0 and carries[-1] == 0,
        detail="word-canonical addition begins and ends with zero carry",
    )

    value = witness.value
    owner.linear_zero(
        f"{label}.owner_residue_recomposition",
        value - witness.residues[1],
        require_exact=False,
    )
    # This equation is locally valid in the second field, but the bytes used to
    # derive ``value`` are only host-shared in this model.  The missing common
    # commitment/equality proof is deliberately reported by the caller.
    other.linear_zero(
        f"{label}.other_residue_recomposition_unbound",
        value - witness.residues[0],
        require_exact=False,
    )



def _crt_bounded_value_is_consistent(
    witness: CanonicalByteWitness,
    config: CrtFieldConfig,
    *,
    bits: int,
) -> bool:
    try:
        if len(witness.value_bytes_be) != CANONICAL_BYTE_WIDTH:
            return False
        value = int.from_bytes(witness.value_bytes_be, "big")
        if not 0 <= value < (1 << bits):
            return False
        return witness.residues == tuple(
            value % modulus for modulus in config.native_moduli
        )
    except (ValueError, OverflowError):
        return False


def _record_crt_bounded(
    owner: NativeConstraintLedger,
    other: NativeConstraintLedger,
    label: str,
    witness: CanonicalByteWitness,
    config: CrtFieldConfig,
    range_model: RangeLookupModel,
    *,
    bits: int,
) -> None:
    if not _crt_bounded_value_is_consistent(witness, config, bits=bits):
        raise ConstraintViolation(f"bounded CRT value failed: {label}")
    owner.lookup_bounded_bytes(
        f"{label}.bounded_words",
        witness.value_bytes_be,
        bits,
        range_model,
    )
    value = int.from_bytes(witness.value_bytes_be, "big")
    owner.linear_zero(
        f"{label}.owner_residue_recomposition",
        value - witness.residues[1],
        require_exact=False,
    )
    other.linear_zero(
        f"{label}.other_residue_recomposition_unbound",
        value - witness.residues[0],
        require_exact=False,
    )

def compile_dual_crt_owner_trace(
    witness: BoundCrtMulWitness,
    config: CrtFieldConfig = CrtFieldConfig(),
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
) -> CompiledBridgeTrace:
    """Compile the two congruences and owner-side byte table.

    The returned trace intentionally remains non-selectable: the two ledgers
    consume host-equal bytes but have no cryptographic common commitment.
    """

    bn = NativeConstraintLedger("bn254_fr", config.native_moduli[0])
    bls = NativeConstraintLedger("bls12_381_fr_owner", config.native_moduli[1])
    bound_values = (witness.x, witness.y, witness.z, witness.quotient)
    core_values = (
        witness.core.x,
        witness.core.y,
        witness.core.z,
        witness.core.quotient,
    )
    for label, bound, core in zip(
        ("x", "y", "z", "quotient"), bound_values, core_values, strict=True
    ):
        if label == "quotient":
            valid = _crt_bounded_value_is_consistent(bound, config, bits=254)
        else:
            valid = verify_canonical_byte_witness(bound, config)
        if not valid:
            raise ConstraintViolation(f"CRT value binding failed: {label}")
        if bound.value_bytes_be != core.canonical or bound.residues != core.residues:
            raise ConstraintViolation(f"CRT core and byte binding diverge: {label}")

    bn.assume(
        "x_y_prebound",
        True,
        detail="x/y canonical encodings are reused from the enclosing trace",
    )
    bls.assume(
        "x_y_prebound",
        True,
        detail="x/y canonical encodings are reused from the enclosing trace",
    )
    _record_crt_owner_canonical(bls, bn, "z", witness.z, config, range_model)
    _record_crt_bounded(
        bls,
        bn,
        "quotient",
        witness.quotient,
        config,
        range_model,
        bits=254,
    )

    q = config.foreign_modulus
    for index, (ledger, modulus) in enumerate(
        zip((bn, bls), config.native_moduli, strict=True)
    ):
        ledger.multiply(
            "foreign_product_congruence",
            witness.core.x.residues[index],
            witness.core.y.residues[index],
            witness.core.z.residues[index]
            + witness.core.quotient.residues[index] * (q % modulus),
        )

    estimate = estimate_bounded_quotient_crt_bridge(
        1, config, range_model=range_model
    )
    report = CompiledBridgeTrace(
        route="dual_field_crt_bounded_quotient_owner_side",
        native_ledgers=(bn.report(), bls.report()),
        estimated_native_nonlinear_products=estimate.native_nonlinear_products,
        estimated_logical_lookup_events=estimate.total_lookup_events,
        estimated_linear_relation_events=estimate.total_linear_equations,
        cross_field_binding=(
            "MISSING: host-equal canonical words are used in both ledgers, but no common "
            "PCS commitment or verified equality proof binds them"
        ),
        selectable=False,
        warnings=(
            "Not a sound end-to-end dual-field construction.",
            "Transparent native constraint ledgers only; no PCS, degree bound, or conditional-lock conjunction.",
        ),
    )
    if not report.estimate_match:
        raise AssertionError("dual-field compiled trace and schedule estimate diverge")
    return report
