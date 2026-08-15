from __future__ import annotations

"""Executable Embryo application layered over :mod:`ranklock.dfb_real`.

The module instantiates the Section 7.2 information-theoretic garbling for
private BN254 scalar multiplication:

* a five-element sum-of-monomials encoding of the curve check,
* 256 randomized conditional-addition maps with the fixed 12-element encoding
  shape from Appendix C,
* PRF masking keyed by the curve-check secret, and
* two real DFB affine-switch executions for the input point's x/y coordinates.

The generated ``DfbProgram`` is a real, canonical join-payload artifact.  The
standalone DFB output masks remain in ``DfbDecodeState``.  This file therefore
proves the switch execution and the Embryo polynomial semantics, but it does
not yet prove that those per-output masks can be omitted from the retained
RankLock object; that requires the application-level label-flow fusion called
out in the checkpoint report.

Research code only; neither the Python ECC nor the PRF instantiation is
constant-time.
"""

from dataclasses import dataclass
from hashlib import sha256
from time import perf_counter
from typing import Iterable, Sequence

import numpy as np

from .bn254_real import (
    B,
    CURVE_ORDER,
    FIELD_MODULUS,
    FQ,
    G1,
    Point,
    add,
    affine,
    double,
    eq_points,
    is_inf,
    is_on_curve,
    multiply,
    point_at_infinity,
)
from .dfb_real import (
    DfbDecodeState,
    DfbError,
    DfbEvaluation,
    DfbGeneration,
    DfbProfile,
    DeterministicRng,
    FIRST_90_PRIMES,
    bind_input_values,
    evaluate_program,
    generate_program_template,
    reconstruct_crt_columns,
    verify_affine_residues,
)


EMBRYO_MAPS = 256
EMBRYO_SCALAR_DIMENSION = 12 * EMBRYO_MAPS
EMBRYO_CURVE_DIMENSION = 5
EMBRYO_TOTAL_DIMENSION = EMBRYO_SCALAR_DIMENSION + EMBRYO_CURVE_DIMENSION
EMBRYO_X_SCALAR_DIMENSION = 7 * EMBRYO_MAPS
EMBRYO_Y_SCALAR_DIMENSION = 5 * EMBRYO_MAPS
EMBRYO_X_DIMENSION = EMBRYO_X_SCALAR_DIMENSION + 3
EMBRYO_Y_DIMENSION = EMBRYO_Y_SCALAR_DIMENSION + 2


class EmbryoError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Monomial:
    coefficient: int
    variables: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.variables or any(variable not in ("x", "y") for variable in self.variables):
            raise EmbryoError("monomial variables must be a non-empty x/y sequence")


@dataclass(frozen=True, slots=True)
class ChainPlan:
    entries: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class LocalPolynomialPlan:
    chains: tuple[ChainPlan, ...]
    x_count: int
    y_count: int

    def evaluate(self, x_encodings: Sequence[int], y_encodings: Sequence[int], x: int, y: int) -> int:
        if len(x_encodings) != self.x_count or len(y_encodings) != self.y_count:
            raise EmbryoError("polynomial encoding slice has the wrong length")
        inputs = {"x": x % FIELD_MODULUS, "y": y % FIELD_MODULUS}
        encodings = {"x": x_encodings, "y": y_encodings}
        total = 0
        for chain in self.chains:
            suffix = 1
            chain_total = 0
            for variable, index in reversed(chain.entries):
                chain_total = (chain_total + int(encodings[variable][index]) * suffix) % FIELD_MODULUS
                suffix = suffix * inputs[variable] % FIELD_MODULUS
            total = (total + chain_total) % FIELD_MODULUS
        return total


@dataclass(frozen=True, slots=True)
class GlobalPolynomialPlan:
    local: LocalPolynomialPlan
    x_start: int
    y_start: int

    @property
    def x_stop(self) -> int:
        return self.x_start + self.local.x_count

    @property
    def y_stop(self) -> int:
        return self.y_start + self.local.y_count

    def evaluate(self, x_values: Sequence[int], y_values: Sequence[int], x: int, y: int) -> int:
        return self.local.evaluate(
            x_values[self.x_start : self.x_stop],
            y_values[self.y_start : self.y_stop],
            x,
            y,
        )


@dataclass(frozen=True, slots=True)
class AffineEncoding:
    a_x: tuple[int, ...]
    b_x: tuple[int, ...]
    a_y: tuple[int, ...]
    b_y: tuple[int, ...]
    plan: LocalPolynomialPlan


@dataclass(frozen=True, slots=True)
class ConditionalMapSecret:
    bit: int
    phi_scalar: int
    phi_x: int
    phi_y: int
    jacobian_scale: int


@dataclass(frozen=True, slots=True)
class EmbryoGarbling:
    hidden_scalar: int
    curve_delta: int
    curve_secret: int
    prf_key: bytes
    a_x: tuple[int, ...]
    b_x: tuple[int, ...]
    a_y: tuple[int, ...]
    b_y: tuple[int, ...]
    map_plans: tuple[tuple[GlobalPolynomialPlan, GlobalPolynomialPlan, GlobalPolynomialPlan], ...]
    curve_plan: GlobalPolynomialPlan
    maps: tuple[ConditionalMapSecret, ...]
    seed_digest: str

    @property
    def dimensions(self) -> tuple[int, int]:
        return len(self.a_x), len(self.a_y)


@dataclass(frozen=True, slots=True)
class EmbryoEvaluationResult:
    input_point: Point
    output_point: Point
    expected_point: Point
    recovered_curve_secret: int
    curve_check_valid: bool
    map_points_verified: int
    output_matches: bool


@dataclass(slots=True)
class EmbryoExecution:
    garbling: EmbryoGarbling
    dfb_generation: DfbGeneration
    dfb_evaluation: DfbEvaluation
    result: EmbryoEvaluationResult
    timings: dict[str, float]

    @property
    def program_bytes(self) -> int:
        return len(self.dfb_generation.program.encoded)

    @property
    def decoder_bytes(self) -> int:
        return len(self.dfb_generation.decode_state.canonical_bytes(self.dfb_generation.program.profile))


def _field(value: int) -> int:
    return value % FIELD_MODULUS


def _random_field(rng: DeterministicRng) -> int:
    return rng.below(FIELD_MODULUS)


def _random_nonzero_field(rng: DeterministicRng) -> int:
    return rng.nonzero_below(FIELD_MODULUS)


def _uniform_hash_to_field(domain: bytes, key: bytes, index: int) -> int:
    limit = (1 << 256) - ((1 << 256) % FIELD_MODULUS)
    attempt = 0
    while True:
        digest = sha256(
            domain
            + len(key).to_bytes(2, "big")
            + key
            + index.to_bytes(16, "big")
            + attempt.to_bytes(4, "big")
        ).digest()
        value = int.from_bytes(digest, "big")
        if value < limit:
            return value % FIELD_MODULUS
        attempt += 1


def _derive_curve_key(curve_secret: int) -> bytes:
    return sha256(
        b"ranklock/embryo/curve-key/v1\x00" + curve_secret.to_bytes(32, "big")
    ).digest()


def _prf_field(key: bytes, index: int) -> int:
    return _uniform_hash_to_field(b"ranklock/embryo/prf/v1\x00", key, index)


def garble_sum_of_monomials(
    *,
    constant: int,
    monomials: Sequence[Monomial],
    rng: DeterministicRng,
) -> AffineEncoding:
    """The degree-many affine encoding from the Sum-of-Monomials PGS.

    For one monomial ``c*x_1*...*x_d`` choose chain masks and affine
    encodings ``c*x_1-r_1, r_1*x_2-r_2, ..., r_(d-1)*x_d+rho``.
    Weighted suffix evaluation telescopes to the monomial plus ``rho``.  The
    rho values are additive shares of the polynomial constant term.
    """

    if not monomials:
        raise EmbryoError("sum-of-monomials encoding needs at least one monomial")
    constant %= FIELD_MODULUS
    rho_values: list[int] = []
    running = 0
    for _ in monomials[:-1]:
        rho = _random_field(rng)
        rho_values.append(rho)
        running = (running + rho) % FIELD_MODULUS
    rho_values.append((constant - running) % FIELD_MODULUS)

    a_values: dict[str, list[int]] = {"x": [], "y": []}
    b_values: dict[str, list[int]] = {"x": [], "y": []}
    plans: list[ChainPlan] = []

    for monomial, rho in zip(monomials, rho_values, strict=True):
        coefficient = monomial.coefficient % FIELD_MODULUS
        degree = len(monomial.variables)
        masks = [_random_field(rng) for _ in range(max(0, degree - 1))]
        entries: list[tuple[str, int]] = []
        for position, variable in enumerate(monomial.variables):
            if degree == 1:
                a = coefficient
                b = rho
            elif position == 0:
                a = coefficient
                b = -masks[0]
            elif position == degree - 1:
                a = masks[position - 1]
                b = rho
            else:
                a = masks[position - 1]
                b = -masks[position]
            index = len(a_values[variable])
            a_values[variable].append(a % FIELD_MODULUS)
            b_values[variable].append(b % FIELD_MODULUS)
            entries.append((variable, index))
        plans.append(ChainPlan(entries=tuple(entries)))

    return AffineEncoding(
        a_x=tuple(a_values["x"]),
        b_x=tuple(b_values["x"]),
        a_y=tuple(a_values["y"]),
        b_y=tuple(b_values["y"]),
        plan=LocalPolynomialPlan(
            chains=tuple(plans),
            x_count=len(a_values["x"]),
            y_count=len(a_values["y"]),
        ),
    )


def conditional_jacobian_polynomials(secret: ConditionalMapSecret) -> tuple[tuple[int, tuple[Monomial, ...]], ...]:
    """Return the fixed-support X/Y/Z polynomials of Lemma B.5."""

    d = secret.bit
    fx = secret.phi_x
    fy = secret.phi_y
    scale = secret.jacobian_scale
    s2 = scale * scale % FIELD_MODULUS
    s3 = s2 * scale % FIELD_MODULUS

    x_constant = ((1 - d) * fx + d * 6) * s2
    x_monomials = (
        Monomial(d * fx * fx * s2, ("x",)),
        Monomial(-2 * d * fy * s2, ("y",)),
        Monomial(d * fx * s2, ("x", "x")),
    )

    y_constant = ((1 - d) * fy + d * 9 * fy) * s3
    y_monomials = (
        Monomial(-d * (fy * fy + 9) * s3, ("y",)),
        Monomial(3 * d * fx * fy * s3, ("x", "x")),
        Monomial(d * fy * s3, ("y", "y")),
        Monomial(-3 * d * fx * fx * s3, ("x", "y")),
    )

    z_constant = ((1 - d) - d * fx) * scale
    z_monomials = (Monomial(d * scale, ("x",)),)
    return (
        (x_constant % FIELD_MODULUS, x_monomials),
        (y_constant % FIELD_MODULUS, y_monomials),
        (z_constant % FIELD_MODULUS, z_monomials),
    )


def _eval_polynomial_direct(constant: int, monomials: Sequence[Monomial], x: int, y: int) -> int:
    inputs = {"x": x % FIELD_MODULUS, "y": y % FIELD_MODULUS}
    total = constant % FIELD_MODULUS
    for monomial in monomials:
        term = monomial.coefficient % FIELD_MODULUS
        for variable in monomial.variables:
            term = term * inputs[variable] % FIELD_MODULUS
        total = (total + term) % FIELD_MODULUS
    return total


def _jacobian_to_point(x: int, y: int, z: int) -> Point:
    z %= FIELD_MODULUS
    if z == 0:
        return point_at_infinity(FQ)
    inverse = pow(z, FIELD_MODULUS - 2, FIELD_MODULUS)
    inverse2 = inverse * inverse % FIELD_MODULUS
    inverse3 = inverse2 * inverse % FIELD_MODULUS
    point = (FQ(x * inverse2), FQ(y * inverse3), FQ.one())
    if not is_on_curve(point, B):
        raise EmbryoError("conditional map produced an off-curve Jacobian point")
    return point


def _affine_ints(point: Point) -> tuple[int, int]:
    coords = affine(point)
    if coords is None:
        raise EmbryoError("point at infinity has no affine coordinates")
    x, y = coords
    if not isinstance(x, FQ) or not isinstance(y, FQ):
        raise EmbryoError("expected a G1 point")
    return x.n, y.n


def _sample_constrained_phi_scalars(rng: DeterministicRng) -> tuple[int, ...]:
    while True:
        scalars = [rng.nonzero_below(CURVE_ORDER) for _ in range(EMBRYO_MAPS - 1)]
        weighted = 0
        power = 1
        for scalar in scalars:
            weighted = (weighted + power * scalar) % CURVE_ORDER
            power = (power * 2) % CURVE_ORDER
        last = (-weighted * pow(power, -1, CURVE_ORDER)) % CURVE_ORDER
        if last:
            scalars.append(last)
            return tuple(scalars)


def garble_embryo(
    hidden_scalar: int,
    *,
    seed: bytes = b"ranklock-embryo-real-default-seed",
) -> EmbryoGarbling:
    hidden_scalar %= CURVE_ORDER
    rng = DeterministicRng(seed, domain=b"ranklock/embryo/garbling-rng/v1\x00")
    curve_delta = _random_nonzero_field(rng)
    curve_secret = _random_field(rng)
    key = _derive_curve_key(curve_secret)
    phi_scalars = _sample_constrained_phi_scalars(rng)

    a_x: list[int] = []
    b_x: list[int] = []
    a_y: list[int] = []
    b_y: list[int] = []
    plans: list[tuple[GlobalPolynomialPlan, GlobalPolynomialPlan, GlobalPolynomialPlan]] = []
    secrets: list[ConditionalMapSecret] = []
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
            encoding = garble_sum_of_monomials(constant=constant, monomials=monomials, rng=rng)
            x_start = len(a_x)
            y_start = len(a_y)
            a_x.extend(encoding.a_x)
            a_y.extend(encoding.a_y)
            for value in encoding.b_x:
                b_x.append((value + _prf_field(key, prf_index)) % FIELD_MODULUS)
                prf_index += 1
            for value in encoding.b_y:
                b_y.append((value + _prf_field(key, prf_index)) % FIELD_MODULUS)
                prf_index += 1
            coordinate_plans.append(
                GlobalPolynomialPlan(local=encoding.plan, x_start=x_start, y_start=y_start)
            )
        plans.append(tuple(coordinate_plans))  # type: ignore[arg-type]

    if len(a_x) != EMBRYO_X_SCALAR_DIMENSION or len(a_y) != EMBRYO_Y_SCALAR_DIMENSION:
        raise EmbryoError(f"unexpected scalar encoding dimensions: x={len(a_x)} y={len(a_y)}")
    if prf_index != EMBRYO_SCALAR_DIMENSION:
        raise EmbryoError("PRF mask count does not match the 12x256 encoding dimension")

    curve_encoding = garble_sum_of_monomials(
        constant=curve_secret - 3 * curve_delta,
        monomials=(
            Monomial(curve_delta, ("y", "y")),
            Monomial(-curve_delta, ("x", "x", "x")),
        ),
        rng=rng,
    )
    curve_x_start = len(a_x)
    curve_y_start = len(a_y)
    a_x.extend(curve_encoding.a_x)
    b_x.extend(curve_encoding.b_x)
    a_y.extend(curve_encoding.a_y)
    b_y.extend(curve_encoding.b_y)
    curve_plan = GlobalPolynomialPlan(
        local=curve_encoding.plan,
        x_start=curve_x_start,
        y_start=curve_y_start,
    )

    if len(a_x) != EMBRYO_X_DIMENSION or len(a_y) != EMBRYO_Y_DIMENSION:
        raise EmbryoError(f"unexpected full encoding dimensions: x={len(a_x)} y={len(a_y)}")
    weighted_phi = sum((pow(2, index, CURVE_ORDER) * scalar) for index, scalar in enumerate(phi_scalars))
    if weighted_phi % CURVE_ORDER:
        raise EmbryoError("sampled phi points do not satisfy the weighted zero constraint")

    return EmbryoGarbling(
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


def _find_nonexceptional_input(garbling: EmbryoGarbling, start_scalar: int = 1) -> tuple[int, Point]:
    scalar = start_scalar % CURVE_ORDER or 1
    while True:
        point = multiply(G1, scalar, group="g1")
        x, _ = _affine_ints(point)
        valid = True
        for secret in garbling.maps:
            if secret.bit and (secret.phi_x == x or (secret.phi_scalar + scalar) % CURVE_ORDER == 0):
                valid = False
                break
        if valid:
            return scalar, point
        scalar = (scalar + 1) % CURVE_ORDER or 1


def _unmask_scalar_encodings(
    garbling: EmbryoGarbling,
    x_values: Sequence[int],
    y_values: Sequence[int],
    key: bytes,
) -> tuple[list[int], list[int]]:
    x_unmasked = list(x_values)
    y_unmasked = list(y_values)
    index = 0
    for coordinate_plans in garbling.map_plans:
        for plan in coordinate_plans:
            for position in range(plan.x_start, plan.x_stop):
                x_unmasked[position] = (x_unmasked[position] - _prf_field(key, index)) % FIELD_MODULUS
                index += 1
            for position in range(plan.y_start, plan.y_stop):
                y_unmasked[position] = (y_unmasked[position] - _prf_field(key, index)) % FIELD_MODULUS
                index += 1
    if index != EMBRYO_SCALAR_DIMENSION:
        raise EmbryoError("PRF unmask schedule drift")
    return x_unmasked, y_unmasked


def evaluate_embryo_outputs(
    garbling: EmbryoGarbling,
    *,
    input_point: Point,
    x_encodings: Sequence[int],
    y_encodings: Sequence[int],
) -> EmbryoEvaluationResult:
    if len(x_encodings) != EMBRYO_X_DIMENSION or len(y_encodings) != EMBRYO_Y_DIMENSION:
        raise EmbryoError("Embryo encoding vector has the wrong dimension")
    x, y = _affine_ints(input_point)
    curve_secret = garbling.curve_plan.evaluate(x_encodings, y_encodings, x, y)
    valid = (y * y - x * x * x - 3) % FIELD_MODULUS == 0
    candidate_key = _derive_curve_key(curve_secret)
    x_values, y_values = _unmask_scalar_encodings(
        garbling, x_encodings, y_encodings, candidate_key
    )

    map_points: list[Point] = []
    for secret, coordinate_plans in zip(garbling.maps, garbling.map_plans, strict=True):
        jacobian = tuple(
            plan.evaluate(x_values, y_values, x, y) for plan in coordinate_plans
        )
        point = _jacobian_to_point(*jacobian)
        phi = multiply(G1, secret.phi_scalar, group="g1")
        expected = add(phi, input_point, group="g1") if secret.bit else phi
        if not eq_points(point, expected):
            raise EmbryoError("conditional Jacobian map failed")
        map_points.append(point)

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
        curve_check_valid=valid,
        map_points_verified=len(map_points),
        output_matches=eq_points(accumulator, expected_output),
    )


def execute_embryo(
    *,
    hidden_scalar: int,
    garbling_seed: bytes = b"ranklock-embryo-real-garbling-v1",
    dfb_seed: bytes = b"ranklock-embryo-real-dfb-v1",
    input_scalar_start: int = 1_234_567,
    profile: DfbProfile | None = None,
    statistical_security_bits: int = 128,
) -> EmbryoExecution:
    if profile is None:
        profile = DfbProfile(primes=FIRST_90_PRIMES)
    profile.require_statistical_smudging(FIELD_MODULUS, statistical_security_bits)
    timings: dict[str, float] = {}
    start = perf_counter()
    garbling = garble_embryo(hidden_scalar, seed=garbling_seed)
    timings["embryo_garble_seconds"] = perf_counter() - start

    _, input_point = _find_nonexceptional_input(garbling, input_scalar_start)
    x, y = _affine_ints(input_point)
    start = perf_counter()
    template = generate_program_template(
        coefficients=((garbling.a_x, garbling.b_x), (garbling.a_y, garbling.b_y)),
        profile=profile,
        seed=dfb_seed,
        field_modulus=FIELD_MODULUS,
        statistical_security_bits=statistical_security_bits,
    )
    timings["dfb_generate_serialize_parse_seconds"] = perf_counter() - start
    generation = bind_input_values(template, values=(x, y))
    timings["input_binding_seconds"] = perf_counter() - start - timings["dfb_generate_serialize_parse_seconds"]

    if generation.program.dimensions != (EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION):
        raise EmbryoError("serialized DFB dimensions do not match Embryo")
    start = perf_counter()
    evaluation = evaluate_program(generation, values=(x, y))
    timings["dfb_evaluate_seconds"] = perf_counter() - start
    if generation.effective_coefficients is None:
        raise EmbryoError("DFB smudging metadata is unavailable")
    verify_affine_residues(
        evaluation,
        values=(x, y),
        coefficients=generation.effective_coefficients,
        profile=profile,
    )

    start = perf_counter()
    x_encoded = [value % FIELD_MODULUS for value in reconstruct_crt_columns(evaluation.decoded_residues[0], profile)]
    y_encoded = [value % FIELD_MODULUS for value in reconstruct_crt_columns(evaluation.decoded_residues[1], profile)]
    timings["crt_reconstruct_seconds"] = perf_counter() - start

    start = perf_counter()
    result = evaluate_embryo_outputs(
        garbling,
        input_point=input_point,
        x_encodings=x_encoded,
        y_encodings=y_encoded,
    )
    timings["embryo_eval_seconds"] = perf_counter() - start
    if not result.curve_check_valid or result.recovered_curve_secret != garbling.curve_secret:
        raise EmbryoError("curve check did not recover the embedded secret")
    if not result.output_matches:
        raise EmbryoError("Embryo output does not equal hidden-scalar multiplication")
    return EmbryoExecution(
        garbling=garbling,
        dfb_generation=generation,
        dfb_evaluation=evaluation,
        result=result,
        timings=timings,
    )


def direct_conditional_map_check(secret: ConditionalMapSecret, input_point: Point) -> bool:
    x, y = _affine_ints(input_point)
    values = [
        _eval_polynomial_direct(constant, monomials, x, y)
        for constant, monomials in conditional_jacobian_polynomials(secret)
    ]
    got = _jacobian_to_point(*values)
    phi = multiply(G1, secret.phi_scalar, group="g1")
    expected = add(phi, input_point, group="g1") if secret.bit else phi
    return eq_points(got, expected)
