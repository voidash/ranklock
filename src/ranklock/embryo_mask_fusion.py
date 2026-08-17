from __future__ import annotations

"""Mask-carrying DFB/Embryo prototype with exact retained-byte accounting.

The standalone DFB API publishes one CRT output mask for every affine output.
For the 3,077-output Embryo instance this dominates the retained object.  This
module co-designs Embryo's affine intercepts with the already-generated DFB
body readouts so that:

* every nonterminal monomial-chain mask is zero in the BN254 field;
* terminal masks are aggregated once per final Jacobian polynomial; and
* the curve-check aggregate mask is made zero by choosing its random secret.

The evaluator consumes raw DFB output labels, reconstructs them over the CRT,
reduces them to BN254, and cancels only 3 x 256 final polynomial masks.  A
strict no-CRT-wrap check is enforced for *every* canonical future BN254 input;
without it the apparent fusion is algebraically wrong.

This is an executable correctness/storage prototype.  It deliberately does not
claim that correlating Embryo intercept lifts with DFB readouts preserves the
paper's selective-privacy proof.  The adaptive/two-instance proof and the
reference implementation's biased Z_p sampler remain separate security gates.
"""

from dataclasses import dataclass
from hashlib import sha256
from math import ceil
from time import perf_counter
from typing import Sequence

import numpy as np

from .bn254_real import (
    CURVE_ORDER,
    FIELD_MODULUS,
    FQ,
    G1,
    Point,
    add,
    double,
    eq_points,
    multiply,
    point_at_infinity,
)
from .dfb_real import (
    BitReader,
    BitWriter,
    BodyMaterial,
    ChunkMaterial,
    CoordinateMaterial,
    DfbDecodeState,
    DfbGeneration,
    DfbProgram,
    ExtractMaterial,
    ExtractStageMaterial,
    FoldMaterial,
    DfbLabelEvaluation,
    DfbProfile,
    DeterministicRng,
    FIRST_90_PRIMES,
    bind_input_values,
    evaluate_program_labels,
    generate_program_template,
    parse_input_labels,
    reconstruct_crt_columns,
)
from .embryo_real import (
    EMBRYO_MAPS,
    EMBRYO_SCALAR_DIMENSION,
    EMBRYO_TOTAL_DIMENSION,
    EMBRYO_X_DIMENSION,
    EMBRYO_X_SCALAR_DIMENSION,
    EMBRYO_Y_DIMENSION,
    EMBRYO_Y_SCALAR_DIMENSION,
    AffineEncoding,
    ChainPlan,
    ConditionalMapSecret,
    EmbryoError,
    EmbryoEvaluationResult,
    EmbryoGarbling,
    GlobalPolynomialPlan,
    LocalPolynomialPlan,
    Monomial,
    _affine_ints,
    _derive_curve_key,
    _find_nonexceptional_input,
    _jacobian_to_point,
    _prf_field,
    _random_nonzero_field,
    _sample_constrained_phi_scalars,
    _unmask_scalar_encodings,
    conditional_jacobian_polynomials,
)
from .bounded_mpc_embryo import (
    SignedBoundedEmbryoManifest,
    UnsignedBoundedEmbryoManifest,
)


FIRST_91_PRIMES: tuple[int, ...] = FIRST_90_PRIMES + (467,)
FUSED_FIELD_BITS = FIELD_MODULUS.bit_length()
FUSED_MAP_MASKS = 3 * EMBRYO_MAPS
CURRENT_MANIFEST_BYTES = 748
PRACTICAL_TARGET_BYTES = 1 << 20


class MaskFusionError(EmbryoError):
    pass


@dataclass(frozen=True, slots=True)
class FusedMaskState:
    """One BN254 mask per final X/Y/Z polynomial; curve mask is forced to zero."""

    map_coordinate_masks: tuple[int, ...]
    curve_mask: int = 0

    def __post_init__(self) -> None:
        if len(self.map_coordinate_masks) != FUSED_MAP_MASKS:
            raise MaskFusionError(
                f"expected {FUSED_MAP_MASKS} map-coordinate masks, "
                f"got {len(self.map_coordinate_masks)}"
            )
        if any(not 0 <= value < FIELD_MODULUS for value in self.map_coordinate_masks):
            raise MaskFusionError("non-canonical fused map mask")
        if self.curve_mask % FIELD_MODULUS:
            raise MaskFusionError("the fixed fused profile requires a zero curve mask")

    @property
    def bit_length(self) -> int:
        return len(self.map_coordinate_masks) * FUSED_FIELD_BITS

    @property
    def encoded_bytes(self) -> bytes:
        writer = BitWriter()
        for value in self.map_coordinate_masks:
            writer.write(value, FUSED_FIELD_BITS)
        if writer.total_bits != self.bit_length:
            raise MaskFusionError("fused-mask bit accounting drift")
        return writer.finish()

    @property
    def sha256(self) -> str:
        return sha256(self.encoded_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class FusedLiftMetadata:
    readouts_x: tuple[int, ...]
    readouts_y: tuple[int, ...]
    intercept_lifts_x: tuple[int, ...]
    intercept_lifts_y: tuple[int, ...]
    individual_masks_x: tuple[int, ...]
    individual_masks_y: tuple[int, ...]
    no_wrap_limit: int

    @property
    def nonzero_individual_masks(self) -> int:
        return sum(value != 0 for value in self.individual_masks_x) + sum(
            value != 0 for value in self.individual_masks_y
        )


@dataclass(frozen=True, slots=True)
class RetainedObjectAccounting:
    prime_count: int
    crt_bits: int
    program_bytes_per_slot: int
    fused_mask_bytes_per_slot: int
    complete_slot_bytes: int
    slot_count: int
    slots_bytes: int
    manifest_and_positive_lock_bytes: int
    complete_retained_bytes: int
    target_bytes: int
    margin_bytes: int
    target_met: bool

    def document(self) -> dict[str, int | bool]:
        return {
            "prime_count": self.prime_count,
            "crt_bits": self.crt_bits,
            "program_bytes_per_slot": self.program_bytes_per_slot,
            "fused_mask_bytes_per_slot": self.fused_mask_bytes_per_slot,
            "complete_slot_bytes": self.complete_slot_bytes,
            "slot_count": self.slot_count,
            "slots_bytes": self.slots_bytes,
            "manifest_and_positive_lock_bytes": self.manifest_and_positive_lock_bytes,
            "complete_retained_bytes": self.complete_retained_bytes,
            "target_bytes": self.target_bytes,
            "margin_bytes": self.margin_bytes,
            "target_met": self.target_met,
        }


@dataclass(slots=True)
class MaskFusedExecution:
    garbling: EmbryoGarbling
    generation: DfbGeneration
    label_evaluation: DfbLabelEvaluation
    mask_state: FusedMaskState
    lift_metadata: FusedLiftMetadata
    result: EmbryoEvaluationResult
    accounting: RetainedObjectAccounting
    timings: dict[str, float]

    @property
    def retained_slot_bytes(self) -> bytes:
        return serialize_fused_slot(self.generation.program, self.mask_state)


@dataclass(frozen=True, slots=True)
class FusedRetainedObject:
    manifest: SignedBoundedEmbryoManifest
    slots: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if len(self.slots) != self.manifest.unsigned.slot_count:
            raise MaskFusionError("retained-object slot count mismatch")
        for descriptor, artifact in zip(
            self.manifest.unsigned.slots, self.slots, strict=True
        ):
            if len(artifact) != descriptor.artifact_length:
                raise MaskFusionError("retained-object slot length mismatch")
            root = sha256(
                b"ranklock/bounded-embryo-artifact-root/v1\x00"
                + descriptor.slot_id.to_bytes(4, "big")
                + bytes(artifact)
            ).digest()
            if root != descriptor.artifact_root:
                raise MaskFusionError("retained-object slot root mismatch")

    @property
    def encoded(self) -> bytes:
        return self.manifest.encoded + b"".join(self.slots)

    @property
    def encoded_bytes(self) -> int:
        return len(self.encoded)


def parse_fused_retained_object(
    raw: bytes, *, profile: DfbProfile
) -> FusedRetainedObject:
    raw = bytes(raw)
    unsigned, body_end = UnsignedBoundedEmbryoManifest.parse_body(raw)
    manifest_end = body_end + unsigned.contributor_count * 64 + 32
    if manifest_end > len(raw):
        raise MaskFusionError("truncated fused retained-object manifest")
    manifest = SignedBoundedEmbryoManifest.parse(raw[:manifest_end])
    cursor = manifest_end
    slots: list[bytes] = []
    for descriptor in manifest.unsigned.slots:
        end = cursor + descriptor.artifact_length
        if end > len(raw):
            raise MaskFusionError("truncated fused retained-object slot")
        artifact = raw[cursor:end]
        parse_fused_slot(artifact, profile=profile)
        slots.append(artifact)
        cursor = end
    if cursor != len(raw):
        raise MaskFusionError("fused retained object has trailing bytes")
    result = FusedRetainedObject(manifest=manifest, slots=tuple(slots))
    if result.encoded != raw:
        raise MaskFusionError("non-canonical fused retained-object encoding")
    return result


@dataclass(frozen=True, slots=True)
class PublicEmbryoLayout:
    map_plans: tuple[
        tuple[GlobalPolynomialPlan, GlobalPolynomialPlan, GlobalPolynomialPlan], ...
    ]
    curve_plan: GlobalPolynomialPlan


@dataclass(frozen=True, slots=True)
class PublicFusedEvaluation:
    output_point: Point
    recovered_curve_secret: int
    curve_check_valid: bool
    maps_evaluated: int


@dataclass(slots=True)
class FusedSlotReplay:
    label_evaluation: DfbLabelEvaluation
    raw_x: tuple[int, ...]
    raw_y: tuple[int, ...]
    result: PublicFusedEvaluation


@dataclass(frozen=True, slots=True)
class _FusedPolynomial:
    encoding: AffineEncoding
    mask: int
    next_prf_index: int
    individual_masks_x: tuple[int, ...]
    individual_masks_y: tuple[int, ...]


def parse_fused_mask_state(raw: bytes) -> FusedMaskState:
    total_bits = FUSED_MAP_MASKS * FUSED_FIELD_BITS
    if len(raw) != ceil(total_bits / 8):
        raise MaskFusionError(
            f"fused mask state must be exactly {ceil(total_bits / 8)} bytes"
        )
    reader = BitReader(raw, total_bits=total_bits)
    values = tuple(reader.read(FUSED_FIELD_BITS) for _ in range(FUSED_MAP_MASKS))
    reader.finish()
    if any(value >= FIELD_MODULUS for value in values):
        raise MaskFusionError("non-canonical BN254 value in fused mask state")
    state = FusedMaskState(values)
    if state.encoded_bytes != bytes(raw):
        raise MaskFusionError("non-canonical fused mask encoding")
    return state


def serialize_fused_slot(program: DfbProgram, mask_state: FusedMaskState) -> bytes:
    """Canonical retained slot: compact DFB program followed by final masks."""

    if program.dimensions != (EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION):
        raise MaskFusionError("fused slot has unexpected Embryo dimensions")
    return program.encoded + mask_state.encoded_bytes


def parse_fused_slot(
    raw: bytes, *, profile: DfbProfile
) -> tuple[DfbProgram, FusedMaskState]:
    program_bits = sum(
        compact_coordinate_program_bits(profile, dimension)
        for dimension in (EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION)
    )
    program_bytes = ceil(program_bits / 8)
    mask_bytes = ceil(FUSED_MAP_MASKS * FUSED_FIELD_BITS / 8)
    if len(raw) != program_bytes + mask_bytes:
        raise MaskFusionError(
            f"fused slot must be exactly {program_bytes + mask_bytes} bytes"
        )
    program = parse_compact_program(
        raw[:program_bytes],
        dimensions=(EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION),
        profile=profile,
    )
    state = parse_fused_mask_state(raw[program_bytes:])
    if serialize_fused_slot(program, state) != bytes(raw):
        raise MaskFusionError("non-canonical fused slot encoding")
    return program, state


def _rho_shares(constant: int, count: int, rng: DeterministicRng) -> tuple[int, ...]:
    if count <= 0:
        raise MaskFusionError("polynomial must contain a monomial")
    values: list[int] = []
    running = 0
    for _ in range(count - 1):
        value = rng.below(FIELD_MODULUS)
        values.append(value)
        running = (running + value) % FIELD_MODULUS
    values.append((constant - running) % FIELD_MODULUS)
    return tuple(values)


def _garble_fused_polynomial(
    *,
    constant: int,
    monomials: Sequence[Monomial],
    readouts_x: Sequence[int],
    readouts_y: Sequence[int],
    rng: DeterministicRng,
    prf_key: bytes | None,
    prf_index: int,
) -> _FusedPolynomial:
    if not monomials:
        raise MaskFusionError("fused polynomial needs at least one monomial")
    x_count = sum(variable == "x" for m in monomials for variable in m.variables)
    y_count = sum(variable == "y" for m in monomials for variable in m.variables)
    if len(readouts_x) != x_count or len(readouts_y) != y_count:
        raise MaskFusionError("fused polynomial readout slice has the wrong shape")

    if prf_key is None:
        prfs_x = [0] * x_count
        prfs_y = [0] * y_count
        next_prf = prf_index
    else:
        prfs_x = [_prf_field(prf_key, prf_index + index) for index in range(x_count)]
        prf_index += x_count
        prfs_y = [_prf_field(prf_key, prf_index + index) for index in range(y_count)]
        prf_index += y_count
        next_prf = prf_index

    readouts = {
        "x": [int(value) % FIELD_MODULUS for value in readouts_x],
        "y": [int(value) % FIELD_MODULUS for value in readouts_y],
    }
    prfs = {"x": prfs_x, "y": prfs_y}
    rho_values = _rho_shares(constant % FIELD_MODULUS, len(monomials), rng)
    counters = {"x": 0, "y": 0}
    a_values: dict[str, list[int]] = {"x": [], "y": []}
    b_values: dict[str, list[int]] = {"x": [], "y": []}
    masks: dict[str, list[int]] = {"x": [], "y": []}
    plans: list[ChainPlan] = []
    terminal_masks: list[int] = []

    for monomial, rho in zip(monomials, rho_values, strict=True):
        previous_b: int | None = None
        entries: list[tuple[str, int]] = []
        degree = len(monomial.variables)
        for position, variable in enumerate(monomial.variables):
            local_index = counters[variable]
            counters[variable] += 1
            prf = prfs[variable][local_index]
            readout = readouts[variable][local_index]
            terminal = position == degree - 1
            if terminal:
                core_b = rho
            else:
                # After PRF removal the raw DFB field label has additive mask
                # R - PRF - b.  Choose b to make that mask exactly zero.
                core_b = (readout - prf) % FIELD_MODULUS
            a = (
                monomial.coefficient % FIELD_MODULUS
                if position == 0
                else (-int(previous_b)) % FIELD_MODULUS
            )
            transmitted_b = (core_b + prf) % FIELD_MODULUS
            individual_mask = (readout - transmitted_b) % FIELD_MODULUS
            if not terminal and individual_mask:
                raise MaskFusionError("nonterminal mask did not cancel")
            if terminal:
                terminal_masks.append(individual_mask)

            output_index = len(a_values[variable])
            a_values[variable].append(a)
            b_values[variable].append(transmitted_b)
            masks[variable].append(individual_mask)
            entries.append((variable, output_index))
            previous_b = core_b
        plans.append(ChainPlan(entries=tuple(entries)))

    if counters != {"x": x_count, "y": y_count}:
        raise MaskFusionError("fused polynomial counter drift")
    polynomial_mask = sum(terminal_masks) % FIELD_MODULUS
    return _FusedPolynomial(
        encoding=AffineEncoding(
            a_x=tuple(a_values["x"]),
            b_x=tuple(b_values["x"]),
            a_y=tuple(a_values["y"]),
            b_y=tuple(b_values["y"]),
            plan=LocalPolynomialPlan(
                chains=tuple(plans), x_count=x_count, y_count=y_count
            ),
        ),
        mask=polynomial_mask,
        next_prf_index=next_prf,
        individual_masks_x=tuple(masks["x"]),
        individual_masks_y=tuple(masks["y"]),
    )


def _curve_terminal_readout_sum(
    readouts_x: Sequence[int], readouts_y: Sequence[int]
) -> int:
    # Curve support is delta*y*y - delta*x*x*x.  The terminal entries are the
    # final y and final x entries of the complete fixed-dimension vectors.
    return (int(readouts_x[-1]) + int(readouts_y[-1])) % FIELD_MODULUS


def garble_mask_fused_embryo(
    hidden_scalar: int,
    *,
    readouts_x: Sequence[int],
    readouts_y: Sequence[int],
    seed: bytes,
) -> tuple[EmbryoGarbling, FusedMaskState, tuple[int, ...], tuple[int, ...]]:
    if len(readouts_x) != EMBRYO_X_DIMENSION or len(readouts_y) != EMBRYO_Y_DIMENSION:
        raise MaskFusionError("DFB readout vector does not match Embryo dimensions")
    hidden_scalar %= CURVE_ORDER
    rng = DeterministicRng(seed, domain=b"ranklock/embryo-mask-fusion/rng/v1\x00")
    curve_delta = _random_nonzero_field(rng)
    curve_constant = _curve_terminal_readout_sum(readouts_x, readouts_y)
    curve_secret = (curve_constant + 3 * curve_delta) % FIELD_MODULUS
    key = _derive_curve_key(curve_secret)
    phi_scalars = _sample_constrained_phi_scalars(rng)

    a_x: list[int] = []
    b_x: list[int] = []
    a_y: list[int] = []
    b_y: list[int] = []
    masks_x: list[int] = []
    masks_y: list[int] = []
    plans: list[tuple[GlobalPolynomialPlan, GlobalPolynomialPlan, GlobalPolynomialPlan]] = []
    secrets: list[ConditionalMapSecret] = []
    final_masks: list[int] = []
    prf_index = 0

    for map_index, phi_scalar in enumerate(phi_scalars):
        phi = multiply(G1, phi_scalar, group="g1")
        phi_x, phi_y = _affine_ints(phi)
        secret = ConditionalMapSecret(
            bit=(hidden_scalar >> map_index) & 1,
            phi_scalar=phi_scalar,
            phi_x=phi_x,
            phi_y=phi_y,
            jacobian_scale=_random_nonzero_field(rng),
        )
        secrets.append(secret)
        coordinate_plans: list[GlobalPolynomialPlan] = []
        for constant, monomials in conditional_jacobian_polynomials(secret):
            x_count = sum(v == "x" for m in monomials for v in m.variables)
            y_count = sum(v == "y" for m in monomials for v in m.variables)
            x_start = len(a_x)
            y_start = len(a_y)
            fused = _garble_fused_polynomial(
                constant=constant,
                monomials=monomials,
                readouts_x=readouts_x[x_start : x_start + x_count],
                readouts_y=readouts_y[y_start : y_start + y_count],
                rng=rng,
                prf_key=key,
                prf_index=prf_index,
            )
            prf_index = fused.next_prf_index
            encoding = fused.encoding
            a_x.extend(encoding.a_x)
            b_x.extend(encoding.b_x)
            a_y.extend(encoding.a_y)
            b_y.extend(encoding.b_y)
            masks_x.extend(fused.individual_masks_x)
            masks_y.extend(fused.individual_masks_y)
            final_masks.append(fused.mask)
            coordinate_plans.append(
                GlobalPolynomialPlan(local=encoding.plan, x_start=x_start, y_start=y_start)
            )
        plans.append(tuple(coordinate_plans))  # type: ignore[arg-type]

    if len(a_x) != EMBRYO_X_SCALAR_DIMENSION or len(a_y) != EMBRYO_Y_SCALAR_DIMENSION:
        raise MaskFusionError("unexpected scalar dimensions in fused garbling")
    if prf_index != EMBRYO_SCALAR_DIMENSION:
        raise MaskFusionError("fused PRF schedule does not cover 12x256 entries")

    curve_x_start = len(a_x)
    curve_y_start = len(a_y)
    curve_monomials = (
        Monomial(curve_delta, ("y", "y")),
        Monomial(-curve_delta, ("x", "x", "x")),
    )
    curve = _garble_fused_polynomial(
        constant=curve_constant,
        monomials=curve_monomials,
        readouts_x=readouts_x[curve_x_start:],
        readouts_y=readouts_y[curve_y_start:],
        rng=rng,
        prf_key=None,
        prf_index=prf_index,
    )
    if curve.mask:
        raise MaskFusionError("curve-check aggregate mask was not eliminated")
    a_x.extend(curve.encoding.a_x)
    b_x.extend(curve.encoding.b_x)
    a_y.extend(curve.encoding.a_y)
    b_y.extend(curve.encoding.b_y)
    masks_x.extend(curve.individual_masks_x)
    masks_y.extend(curve.individual_masks_y)
    curve_plan = GlobalPolynomialPlan(
        local=curve.encoding.plan, x_start=curve_x_start, y_start=curve_y_start
    )

    if len(a_x) != EMBRYO_X_DIMENSION or len(a_y) != EMBRYO_Y_DIMENSION:
        raise MaskFusionError("unexpected complete dimensions in fused garbling")
    if len(final_masks) != FUSED_MAP_MASKS:
        raise MaskFusionError("one fused mask was not produced per map coordinate")
    weighted_phi = sum(
        pow(2, index, CURVE_ORDER) * scalar
        for index, scalar in enumerate(phi_scalars)
    )
    if weighted_phi % CURVE_ORDER:
        raise MaskFusionError("fused phi points violate the weighted-zero constraint")

    garbling = EmbryoGarbling(
        hidden_scalar=hidden_scalar,
        curve_delta=curve_delta,
        curve_secret=curve_secret,
        prf_key=key,
        a_x=tuple(a_x),
        b_x=tuple(b_x),
        a_y=tuple(a_y),
        b_y=tuple(b_y),
        map_plans=tuple(plans),
        curve_plan=curve_plan,
        maps=tuple(secrets),
        seed_digest=sha256(seed).hexdigest(),
    )
    return garbling, FusedMaskState(tuple(final_masks)), tuple(masks_x), tuple(masks_y)


def _readouts_from_zero_template(
    generation: DfbGeneration,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if generation.effective_coefficients is None:
        raise MaskFusionError("zero-template coefficient metadata is unavailable")
    outputs: list[tuple[int, ...]] = []
    for state in generation.decode_state.coordinates:
        matrix = np.stack(state.output_masks)
        outputs.append(tuple(reconstruct_crt_columns(matrix, generation.program.profile)))
    if len(outputs) != 2:
        raise MaskFusionError("Embryo needs exactly two DFB coordinates")
    return outputs[0], outputs[1]


def _derive_lifts(
    *,
    readouts: Sequence[int],
    a_values: Sequence[int],
    b_values: Sequence[int],
    primorial: int,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if not (len(readouts) == len(a_values) == len(b_values)):
        raise MaskFusionError("lift vectors have inconsistent dimensions")
    maximum_product = (FIELD_MODULUS - 1) ** 2
    safe_limit = primorial - 1 - maximum_product
    lifts: list[int] = []
    masks: list[int] = []
    for readout, a, transmitted_b in zip(readouts, a_values, b_values, strict=True):
        readout = int(readout)
        if readout > safe_limit:
            raise MaskFusionError(
                "DFB readout can wrap for a future canonical BN254 input; resample setup"
            )
        mask = (readout % FIELD_MODULUS - int(transmitted_b)) % FIELD_MODULUS
        lift = readout - mask
        if lift < 0 or lift % FIELD_MODULUS != int(transmitted_b) % FIELD_MODULUS:
            raise MaskFusionError("failed to derive a canonical correlated intercept lift")
        if readout + (int(a) % FIELD_MODULUS) * (FIELD_MODULUS - 1) >= primorial:
            raise MaskFusionError("actual affine slope exceeds the no-wrap envelope")
        lifts.append(lift)
        masks.append(mask)
    return tuple(lifts), tuple(masks)



def compact_coordinate_program_bits(profile: DfbProfile, dimension: int) -> int:
    """Program bits with one canonical CRT integer per body join.

    The standard serializer spends ``sum(ceil(log2 p_i))`` bits on every
    residue tuple.  Every canonical tuple is equivalently one value in
    ``Z_M``, so the compact format spends exactly ``bit_length(M)`` bits.
    Header/scaling material is byte-for-byte unchanged.
    """

    if dimension <= 0:
        raise MaskFusionError("compact DFB dimension must be positive")
    fixed = (
        profile.chunk_join_bits
        + profile.extract_join_bits
        + profile.fold_join_bits
    )
    return fixed + dimension * profile.primorial.bit_length()


def _stage_widths(profile: DfbProfile) -> tuple[tuple[int, int], ...]:
    remaining = profile.ell
    stages: list[tuple[int, int]] = []
    for index, width in enumerate(profile.sub_widths):
        upcast = width if index == len(profile.sub_widths) - 1 else remaining
        stages.append((width, upcast))
        remaining -= width
    return tuple(stages)


def _write_compact_coordinate(
    writer: BitWriter, coordinate: CoordinateMaterial, profile: DfbProfile
) -> None:
    if len(coordinate.chunks) != profile.num_chunks:
        raise MaskFusionError("compact DFB chunk count mismatch")
    for chunk in coordinate.chunks:
        if chunk.scale.shape != (profile.chunk_size - 1, 2):
            raise MaskFusionError("compact DFB chunk scale shape mismatch")
        for diff in chunk.scale:
            writer.write_bool(diff)
        writer.write_wide(chunk.pin, profile.ell)

    stages = _stage_widths(profile)
    if len(coordinate.extracts) != len(profile.primes):
        raise MaskFusionError("compact DFB extract prime count mismatch")
    for extract in coordinate.extracts:
        if len(extract.stages) != len(stages):
            raise MaskFusionError("compact DFB extract stage count mismatch")
        for material, (width, upcast) in zip(extract.stages, stages, strict=True):
            if material.width != width or material.upcast_width != upcast:
                raise MaskFusionError("compact DFB extract stage width mismatch")
            if material.scale.shape != (width - 1, 2):
                raise MaskFusionError("compact DFB extract scale shape mismatch")
            for diff in material.scale:
                writer.write_bool(diff)
            writer.write_wide(material.pin, upcast)

    if len(coordinate.folds) != len(profile.primes):
        raise MaskFusionError("compact DFB fold prime count mismatch")
    for fold in coordinate.folds:
        if fold.diffs.shape != (profile.fold_bits, 2):
            raise MaskFusionError("compact DFB fold shape mismatch")
        for diff in fold.diffs:
            writer.write_bool(diff)

    flattened: list[np.ndarray] = []
    for body in coordinate.bodies:
        values = np.concatenate(body.batches)
        if values.shape != (coordinate.dimension,):
            raise MaskFusionError("compact DFB body dimension mismatch")
        flattened.append(values)
    residue_matrix = np.stack(flattened)
    crt_values = reconstruct_crt_columns(residue_matrix, profile)
    width = profile.primorial.bit_length()
    for value in crt_values:
        if not 0 <= value < profile.primorial:
            raise MaskFusionError("non-canonical compact CRT join")
        writer.write(value, width)


def serialize_compact_program(
    coordinates: Sequence[CoordinateMaterial], profile: DfbProfile
) -> DfbProgram:
    writer = BitWriter()
    for coordinate in coordinates:
        _write_compact_coordinate(writer, coordinate, profile)
    expected = sum(
        compact_coordinate_program_bits(profile, coordinate.dimension)
        for coordinate in coordinates
    )
    if writer.total_bits != expected:
        raise MaskFusionError(
            f"compact DFB bit accounting mismatch: {writer.total_bits} != {expected}"
        )
    return DfbProgram(
        profile=profile,
        coordinates=tuple(coordinates),
        encoded=writer.finish(),
        bit_length=expected,
    )


def _read_compact_coordinate(
    reader: BitReader, dimension: int, profile: DfbProfile
) -> CoordinateMaterial:
    chunks: list[ChunkMaterial] = []
    for _ in range(profile.num_chunks):
        scale = np.stack(
            [reader.read_bool() for _ in range(profile.chunk_size - 1)]
        )
        chunks.append(ChunkMaterial(scale=scale, pin=reader.read_wide(profile.ell)))

    stages = _stage_widths(profile)
    extracts: list[ExtractMaterial] = []
    for _ in profile.primes:
        parsed_stages: list[ExtractStageMaterial] = []
        for width, upcast in stages:
            scale = np.stack([reader.read_bool() for _ in range(width - 1)])
            parsed_stages.append(
                ExtractStageMaterial(
                    width=width,
                    upcast_width=upcast,
                    scale=scale,
                    pin=reader.read_wide(upcast),
                )
            )
        extracts.append(ExtractMaterial(stages=tuple(parsed_stages)))

    folds = tuple(
        FoldMaterial(
            diffs=(
                np.stack([reader.read_bool() for _ in range(profile.fold_bits)])
                if profile.fold_bits
                else np.empty((0, 2), dtype=np.uint64)
            )
        )
        for _ in profile.primes
    )

    width = profile.primorial.bit_length()
    crt_values = [reader.read(width) for _ in range(dimension)]
    if any(value >= profile.primorial for value in crt_values):
        raise MaskFusionError("non-canonical compact CRT join value")
    bodies: list[BodyMaterial] = []
    for prime in profile.primes:
        residues = np.array([value % prime for value in crt_values], dtype=np.uint64)
        batches = tuple(
            residues[start : min(start + profile.batch_size, dimension)].copy()
            for start in range(0, dimension, profile.batch_size)
        )
        bodies.append(BodyMaterial(batches=batches))
    return CoordinateMaterial(
        dimension=dimension,
        chunks=tuple(chunks),
        extracts=tuple(extracts),
        folds=folds,
        bodies=tuple(bodies),
    )


def parse_compact_program(
    raw: bytes, *, dimensions: Sequence[int], profile: DfbProfile
) -> DfbProgram:
    dims = tuple(int(value) for value in dimensions)
    if any(value <= 0 for value in dims):
        raise MaskFusionError("compact DFB dimensions must be positive")
    total_bits = sum(compact_coordinate_program_bits(profile, value) for value in dims)
    reader = BitReader(raw, total_bits=total_bits)
    coordinates = tuple(
        _read_compact_coordinate(reader, dimension, profile) for dimension in dims
    )
    reader.finish()
    canonical = serialize_compact_program(coordinates, profile)
    if canonical.encoded != bytes(raw):
        raise MaskFusionError("non-canonical compact DFB program encoding")
    return canonical


def _patch_program_slopes(
    template: DfbGeneration,
    *,
    slopes: Sequence[Sequence[int]],
    intercept_lifts: Sequence[Sequence[int]],
) -> DfbGeneration:
    profile = template.program.profile
    if len(slopes) != len(template.program.coordinates):
        raise MaskFusionError("one slope vector is required per DFB coordinate")
    coordinates: list[CoordinateMaterial] = []
    effective: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
    for coordinate, a_values, b_values in zip(
        template.program.coordinates, slopes, intercept_lifts, strict=True
    ):
        if len(a_values) != coordinate.dimension or len(b_values) != coordinate.dimension:
            raise MaskFusionError("patched affine dimensions do not match DFB program")
        bodies: list[BodyMaterial] = []
        for prime, body in zip(profile.primes, coordinate.bodies, strict=True):
            patched_batches: list[np.ndarray] = []
            start = 0
            for batch in body.batches:
                end = start + len(batch)
                slope_residues = np.array(
                    [int(value) % prime for value in a_values[start:end]], dtype=np.uint64
                )
                patched_batches.append(
                    (batch.astype(np.uint64) + slope_residues) % np.uint64(prime)
                )
                start = end
            if start != coordinate.dimension:
                raise MaskFusionError("patched body batches do not cover dimension")
            bodies.append(BodyMaterial(batches=tuple(patched_batches)))
        coordinates.append(
            CoordinateMaterial(
                dimension=coordinate.dimension,
                chunks=coordinate.chunks,
                extracts=coordinate.extracts,
                folds=coordinate.folds,
                bodies=tuple(bodies),
            )
        )
        effective.append((tuple(map(int, a_values)), tuple(map(int, b_values))))

    serialized = serialize_compact_program(coordinates, profile)
    parsed = parse_compact_program(
        serialized.encoded, dimensions=serialized.dimensions, profile=profile
    )
    return DfbGeneration(
        program=parsed,
        # Retained only inside the test fixture to prove the correlation; the
        # complete retained slot intentionally omits this standalone state.
        decode_state=template.decode_state,
        input_encodings=template.input_encodings,
        garbler_hash_blocks=template.garbler_hash_blocks,
        effective_coefficients=tuple(effective),
        field_modulus=FIELD_MODULUS,
        statistical_security_bits=0,
    )


def build_mask_fused_template(
    *,
    hidden_scalar: int,
    profile: DfbProfile | None = None,
    dfb_seed: bytes,
    garbling_seed: bytes,
) -> tuple[EmbryoGarbling, DfbGeneration, FusedMaskState, FusedLiftMetadata]:
    if profile is None:
        profile = DfbProfile(primes=FIRST_91_PRIMES)
    zero_coefficients = (
        ((0,) * EMBRYO_X_DIMENSION, (0,) * EMBRYO_X_DIMENSION),
        ((0,) * EMBRYO_Y_DIMENSION, (0,) * EMBRYO_Y_DIMENSION),
    )
    zero_template = generate_program_template(
        coefficients=zero_coefficients,
        profile=profile,
        seed=dfb_seed,
        field_modulus=None,
        statistical_security_bits=0,
    )
    readouts_x, readouts_y = _readouts_from_zero_template(zero_template)
    garbling, mask_state, planned_masks_x, planned_masks_y = garble_mask_fused_embryo(
        hidden_scalar,
        readouts_x=readouts_x,
        readouts_y=readouts_y,
        seed=garbling_seed,
    )
    lifts_x, masks_x = _derive_lifts(
        readouts=readouts_x,
        a_values=garbling.a_x,
        b_values=garbling.b_x,
        primorial=profile.primorial,
    )
    lifts_y, masks_y = _derive_lifts(
        readouts=readouts_y,
        a_values=garbling.a_y,
        b_values=garbling.b_y,
        primorial=profile.primorial,
    )
    if masks_x != planned_masks_x or masks_y != planned_masks_y:
        raise MaskFusionError("integer lift masks disagree with field fusion plan")
    generation = _patch_program_slopes(
        zero_template,
        slopes=(garbling.a_x, garbling.a_y),
        intercept_lifts=(lifts_x, lifts_y),
    )
    metadata = FusedLiftMetadata(
        readouts_x=readouts_x,
        readouts_y=readouts_y,
        intercept_lifts_x=lifts_x,
        intercept_lifts_y=lifts_y,
        individual_masks_x=masks_x,
        individual_masks_y=masks_y,
        no_wrap_limit=profile.primorial - 1 - (FIELD_MODULUS - 1) ** 2,
    )
    return garbling, generation, mask_state, metadata



def _local_plan_for_support(monomials: Sequence[Monomial]) -> LocalPolynomialPlan:
    counters = {"x": 0, "y": 0}
    chains: list[ChainPlan] = []
    for monomial in monomials:
        entries: list[tuple[str, int]] = []
        for variable in monomial.variables:
            index = counters[variable]
            counters[variable] += 1
            entries.append((variable, index))
        chains.append(ChainPlan(entries=tuple(entries)))
    return LocalPolynomialPlan(
        chains=tuple(chains), x_count=counters["x"], y_count=counters["y"]
    )


def build_public_embryo_layout() -> PublicEmbryoLayout:
    """Build the fixed support/offset layout without any generator secrets."""

    # Coefficients/constants are irrelevant to the plan; only variable support
    # and monomial order matter.
    supports = (
        (
            Monomial(0, ("x",)),
            Monomial(0, ("y",)),
            Monomial(0, ("x", "x")),
        ),
        (
            Monomial(0, ("y",)),
            Monomial(0, ("x", "x")),
            Monomial(0, ("y", "y")),
            Monomial(0, ("x", "y")),
        ),
        (Monomial(0, ("x",)),),
    )
    x_cursor = 0
    y_cursor = 0
    maps: list[tuple[GlobalPolynomialPlan, GlobalPolynomialPlan, GlobalPolynomialPlan]] = []
    for _ in range(EMBRYO_MAPS):
        coordinates: list[GlobalPolynomialPlan] = []
        for monomials in supports:
            local = _local_plan_for_support(monomials)
            coordinates.append(
                GlobalPolynomialPlan(local=local, x_start=x_cursor, y_start=y_cursor)
            )
            x_cursor += local.x_count
            y_cursor += local.y_count
        maps.append(tuple(coordinates))  # type: ignore[arg-type]
    if (x_cursor, y_cursor) != (
        EMBRYO_X_SCALAR_DIMENSION,
        EMBRYO_Y_SCALAR_DIMENSION,
    ):
        raise MaskFusionError("public Embryo scalar layout dimension drift")
    curve_local = _local_plan_for_support(
        (Monomial(0, ("y", "y")), Monomial(0, ("x", "x", "x")))
    )
    curve = GlobalPolynomialPlan(
        local=curve_local, x_start=x_cursor, y_start=y_cursor
    )
    x_cursor += curve_local.x_count
    y_cursor += curve_local.y_count
    if (x_cursor, y_cursor) != (EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION):
        raise MaskFusionError("public Embryo complete layout dimension drift")
    return PublicEmbryoLayout(map_plans=tuple(maps), curve_plan=curve)


def _public_unmask_scalar_encodings(
    layout: PublicEmbryoLayout,
    x_values: Sequence[int],
    y_values: Sequence[int],
    key: bytes,
) -> tuple[list[int], list[int]]:
    x_unmasked = list(x_values)
    y_unmasked = list(y_values)
    index = 0
    for coordinate_plans in layout.map_plans:
        for plan in coordinate_plans:
            for position in range(plan.x_start, plan.x_stop):
                x_unmasked[position] = (
                    x_unmasked[position] - _prf_field(key, index)
                ) % FIELD_MODULUS
                index += 1
            for position in range(plan.y_start, plan.y_stop):
                y_unmasked[position] = (
                    y_unmasked[position] - _prf_field(key, index)
                ) % FIELD_MODULUS
                index += 1
    if index != EMBRYO_SCALAR_DIMENSION:
        raise MaskFusionError("public fused PRF schedule drift")
    return x_unmasked, y_unmasked


def evaluate_public_mask_fused_outputs(
    *,
    mask_state: FusedMaskState,
    input_point: Point,
    raw_x: Sequence[int],
    raw_y: Sequence[int],
    layout: PublicEmbryoLayout | None = None,
) -> PublicFusedEvaluation:
    """Evaluate from public retained data only.

    No hidden scalar, phi point, Jacobian scale, affine coefficient or
    generator random tape is supplied to this function.
    """

    if layout is None:
        layout = build_public_embryo_layout()
    if len(raw_x) != EMBRYO_X_DIMENSION or len(raw_y) != EMBRYO_Y_DIMENSION:
        raise MaskFusionError("public raw encoding vector has the wrong dimension")
    x, y = _affine_ints(input_point)
    x_field = [int(value) % FIELD_MODULUS for value in raw_x]
    y_field = [int(value) % FIELD_MODULUS for value in raw_y]
    curve_secret = (
        layout.curve_plan.evaluate(x_field, y_field, x, y) - mask_state.curve_mask
    ) % FIELD_MODULUS
    curve_valid = (y * y - x * x * x - 3) % FIELD_MODULUS == 0
    key = _derive_curve_key(curve_secret)
    x_values, y_values = _public_unmask_scalar_encodings(
        layout, x_field, y_field, key
    )

    points: list[Point] = []
    mask_index = 0
    for coordinate_plans in layout.map_plans:
        jacobian: list[int] = []
        for plan in coordinate_plans:
            value = plan.evaluate(x_values, y_values, x, y)
            value = (
                value - mask_state.map_coordinate_masks[mask_index]
            ) % FIELD_MODULUS
            mask_index += 1
            jacobian.append(value)
        points.append(_jacobian_to_point(*jacobian))
    if mask_index != FUSED_MAP_MASKS:
        raise MaskFusionError("public evaluation did not consume every final mask")

    accumulator = point_at_infinity(FQ)
    for point in reversed(points):
        accumulator = double(accumulator, group="g1")
        accumulator = add(accumulator, point, group="g1")
    return PublicFusedEvaluation(
        output_point=accumulator,
        recovered_curve_secret=curve_secret,
        curve_check_valid=curve_valid,
        maps_evaluated=len(points),
    )


def replay_fused_slot(
    *,
    program: DfbProgram,
    mask_state: FusedMaskState,
    input_point: Point,
    x_input_labels: bytes,
    y_input_labels: bytes,
) -> FusedSlotReplay:
    """Replay a parsed retained slot with future externally supplied labels."""

    profile = program.profile
    x, y = _affine_ints(input_point)
    generation = DfbGeneration(
        program=program,
        decode_state=DfbDecodeState(coordinates=()),
        input_encodings=(
            parse_input_labels(x_input_labels, profile=profile),
            parse_input_labels(y_input_labels, profile=profile),
        ),
        garbler_hash_blocks=0,
        effective_coefficients=None,
        field_modulus=FIELD_MODULUS,
        statistical_security_bits=0,
    )
    labels = evaluate_program_labels(generation, values=(x, y))
    raw_x = tuple(reconstruct_crt_columns(labels.label_residues[0], profile))
    raw_y = tuple(reconstruct_crt_columns(labels.label_residues[1], profile))
    result = evaluate_public_mask_fused_outputs(
        mask_state=mask_state,
        input_point=input_point,
        raw_x=raw_x,
        raw_y=raw_y,
    )
    return FusedSlotReplay(
        label_evaluation=labels, raw_x=raw_x, raw_y=raw_y, result=result
    )


def evaluate_mask_fused_outputs(
    garbling: EmbryoGarbling,
    *,
    mask_state: FusedMaskState,
    input_point: Point,
    raw_x: Sequence[int],
    raw_y: Sequence[int],
) -> EmbryoEvaluationResult:
    if len(raw_x) != EMBRYO_X_DIMENSION or len(raw_y) != EMBRYO_Y_DIMENSION:
        raise MaskFusionError("raw fused encoding vector has the wrong dimension")
    x, y = _affine_ints(input_point)
    x_field = [int(value) % FIELD_MODULUS for value in raw_x]
    y_field = [int(value) % FIELD_MODULUS for value in raw_y]
    curve_secret = (
        garbling.curve_plan.evaluate(x_field, y_field, x, y) - mask_state.curve_mask
    ) % FIELD_MODULUS
    curve_valid = (y * y - x * x * x - 3) % FIELD_MODULUS == 0
    candidate_key = _derive_curve_key(curve_secret)
    x_values, y_values = _unmask_scalar_encodings(
        garbling, x_field, y_field, candidate_key
    )

    map_points: list[Point] = []
    mask_index = 0
    for secret, coordinate_plans in zip(garbling.maps, garbling.map_plans, strict=True):
        jacobian_values: list[int] = []
        for plan in coordinate_plans:
            value = plan.evaluate(x_values, y_values, x, y)
            value = (value - mask_state.map_coordinate_masks[mask_index]) % FIELD_MODULUS
            mask_index += 1
            jacobian_values.append(value)
        point = _jacobian_to_point(*jacobian_values)
        phi = multiply(G1, secret.phi_scalar, group="g1")
        expected = add(phi, input_point, group="g1") if secret.bit else phi
        if not eq_points(point, expected):
            raise MaskFusionError("mask-fused conditional Jacobian map failed")
        map_points.append(point)
    if mask_index != FUSED_MAP_MASKS:
        raise MaskFusionError("mask-fused evaluation did not consume every final mask")

    accumulator = point_at_infinity(FQ)
    for point in reversed(map_points):
        accumulator = double(accumulator, group="g1")
        accumulator = add(accumulator, point, group="g1")
    expected_output = multiply(input_point, garbling.hidden_scalar, group="g1")
    return EmbryoEvaluationResult(
        input_point=input_point,
        output_point=accumulator,
        expected_point=expected_output,
        recovered_curve_secret=curve_secret,
        curve_check_valid=curve_valid,
        map_points_verified=len(map_points),
        output_matches=eq_points(accumulator, expected_output),
    )


def account_retained_object(
    *,
    program_bytes_per_slot: int,
    fused_mask_bytes_per_slot: int,
    profile: DfbProfile,
    slot_count: int = 2,
    manifest_and_positive_lock_bytes: int = CURRENT_MANIFEST_BYTES,
    target_bytes: int = PRACTICAL_TARGET_BYTES,
) -> RetainedObjectAccounting:
    complete_slot = program_bytes_per_slot + fused_mask_bytes_per_slot
    slots_bytes = slot_count * complete_slot
    complete = slots_bytes + manifest_and_positive_lock_bytes
    margin = target_bytes - complete
    return RetainedObjectAccounting(
        prime_count=len(profile.primes),
        crt_bits=profile.crt_bits,
        program_bytes_per_slot=program_bytes_per_slot,
        fused_mask_bytes_per_slot=fused_mask_bytes_per_slot,
        complete_slot_bytes=complete_slot,
        slot_count=slot_count,
        slots_bytes=slots_bytes,
        manifest_and_positive_lock_bytes=manifest_and_positive_lock_bytes,
        complete_retained_bytes=complete,
        target_bytes=target_bytes,
        margin_bytes=margin,
        target_met=margin >= 0,
    )


def execute_mask_fused_embryo(
    *,
    hidden_scalar: int,
    profile: DfbProfile | None = None,
    dfb_seed: bytes,
    garbling_seed: bytes,
    input_scalar_start: int = 1_234_567,
) -> MaskFusedExecution:
    if profile is None:
        profile = DfbProfile(primes=FIRST_91_PRIMES)
    timings: dict[str, float] = {}
    start = perf_counter()
    garbling, template, mask_state, metadata = build_mask_fused_template(
        hidden_scalar=hidden_scalar,
        profile=profile,
        dfb_seed=dfb_seed,
        garbling_seed=garbling_seed,
    )
    timings["generate_fused_template_seconds"] = perf_counter() - start

    _, input_point = _find_nonexceptional_input(garbling, input_scalar_start)
    x, y = _affine_ints(input_point)
    generation = bind_input_values(template, values=(x, y))

    start = perf_counter()
    labels = evaluate_program_labels(generation, values=(x, y))
    timings["dfb_raw_label_evaluation_seconds"] = perf_counter() - start

    start = perf_counter()
    raw_x = reconstruct_crt_columns(labels.label_residues[0], profile)
    raw_y = reconstruct_crt_columns(labels.label_residues[1], profile)
    timings["crt_reconstruct_seconds"] = perf_counter() - start

    # Prove the load-bearing no-wrap claim against the actual emitted labels.
    for raw, readout, slope in zip(
        raw_x, metadata.readouts_x, garbling.a_x, strict=True
    ):
        expected = int(readout) + int(slope) * x
        if expected >= profile.primorial or raw != expected:
            raise MaskFusionError("x-coordinate raw label crossed the CRT modulus")
    for raw, readout, slope in zip(
        raw_y, metadata.readouts_y, garbling.a_y, strict=True
    ):
        expected = int(readout) + int(slope) * y
        if expected >= profile.primorial or raw != expected:
            raise MaskFusionError("y-coordinate raw label crossed the CRT modulus")

    start = perf_counter()
    result = evaluate_mask_fused_outputs(
        garbling,
        mask_state=mask_state,
        input_point=input_point,
        raw_x=raw_x,
        raw_y=raw_y,
    )
    timings["embryo_fused_evaluation_seconds"] = perf_counter() - start
    if not result.curve_check_valid or result.recovered_curve_secret != garbling.curve_secret:
        raise MaskFusionError("fused curve check failed to recover its key")
    if not result.output_matches:
        raise MaskFusionError("fused Embryo output differs from direct [r]A")

    accounting = account_retained_object(
        program_bytes_per_slot=len(generation.program.encoded),
        fused_mask_bytes_per_slot=len(mask_state.encoded_bytes),
        profile=profile,
    )
    return MaskFusedExecution(
        garbling=garbling,
        generation=generation,
        label_evaluation=labels,
        mask_state=mask_state,
        lift_metadata=metadata,
        result=result,
        accounting=accounting,
        timings=timings,
    )
