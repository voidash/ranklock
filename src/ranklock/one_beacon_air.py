from __future__ import annotations

"""Legacy polynomial/AIR algebra utilities and an unsafe convenience proof.

SECURITY WARNING: the convenience prover in this module takes the beacon point
before constructing commitments, despite the historical name.  It therefore
does not enforce commitment-before-challenge timing.  Use
:mod:`ranklock.phased_air` for the protocol-correct construction.  The
polynomial helpers remain shared infrastructure.

This is an exponent-space KZG model, not production cryptography.
"""

from dataclasses import dataclass, replace
import hashlib
import json
from typing import Mapping, Sequence

from .field import BN254_BASE_FIELD, polynomial_evaluate
from .kzg_we_model import GroupElement
from .ppe_normal_form import (
    FormalKzgSrs,
    PairingProductEquation,
    kzg_opening_equation_g1,
)


class OneBeaconAirError(ValueError):
    pass


def _trim(values: Sequence[int], modulus: int) -> tuple[int, ...]:
    result = [int(value) % modulus for value in values]
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return tuple(result or (0,))


def poly_add(left: Sequence[int], right: Sequence[int], modulus: int) -> tuple[int, ...]:
    size = max(len(left), len(right))
    return _trim(
        [
            (left[index] if index < len(left) else 0)
            + (right[index] if index < len(right) else 0)
            for index in range(size)
        ],
        modulus,
    )


def poly_sub(left: Sequence[int], right: Sequence[int], modulus: int) -> tuple[int, ...]:
    size = max(len(left), len(right))
    return _trim(
        [
            (left[index] if index < len(left) else 0)
            - (right[index] if index < len(right) else 0)
            for index in range(size)
        ],
        modulus,
    )


def poly_scale(polynomial: Sequence[int], scalar: int, modulus: int) -> tuple[int, ...]:
    return _trim([int(scalar) * int(value) for value in polynomial], modulus)


def poly_mul(left: Sequence[int], right: Sequence[int], modulus: int) -> tuple[int, ...]:
    result = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[i + j] = (result[i + j] + int(a) * int(b)) % modulus
    return _trim(result, modulus)


def poly_shift(polynomial: Sequence[int], offset: int, modulus: int) -> tuple[int, ...]:
    """Return f(X+offset) using the binomial theorem."""

    offset %= modulus
    result = (0,)
    power = (1,)
    base = (offset, 1)
    for coefficient in polynomial:
        result = poly_add(result, poly_scale(power, coefficient, modulus), modulus)
        power = poly_mul(power, base, modulus)
    return _trim(result, modulus)


def vanishing_polynomial(points: Sequence[int], modulus: int) -> tuple[int, ...]:
    if not points:
        raise OneBeaconAirError("vanishing domain is empty")
    result = (1,)
    seen: set[int] = set()
    for raw_point in points:
        point = int(raw_point) % modulus
        if point in seen:
            raise OneBeaconAirError("vanishing domain contains duplicates")
        seen.add(point)
        result = poly_mul(result, (-point % modulus, 1), modulus)
    return result


def poly_divmod(
    numerator: Sequence[int], denominator: Sequence[int], modulus: int
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    numerator_work = list(_trim(numerator, modulus))
    denominator = _trim(denominator, modulus)
    if denominator == (0,):
        raise OneBeaconAirError("division by zero polynomial")
    if len(numerator_work) < len(denominator):
        return (0,), tuple(numerator_work)
    quotient = [0] * (len(numerator_work) - len(denominator) + 1)
    denominator_inverse = pow(denominator[-1], -1, modulus)
    while len(numerator_work) >= len(denominator) and any(numerator_work):
        degree = len(numerator_work) - len(denominator)
        coefficient = numerator_work[-1] * denominator_inverse % modulus
        quotient[degree] = coefficient
        for index, value in enumerate(denominator):
            numerator_work[degree + index] = (
                numerator_work[degree + index] - coefficient * value
            ) % modulus
        while len(numerator_work) > 1 and numerator_work[-1] == 0:
            numerator_work.pop()
    return _trim(quotient, modulus), _trim(numerator_work, modulus)


def interpolate(points: Sequence[int], values: Sequence[int], modulus: int) -> tuple[int, ...]:
    if len(points) != len(values) or not points:
        raise OneBeaconAirError("interpolation point/value shape mismatch")
    result = (0,)
    normalized_points = tuple(int(point) % modulus for point in points)
    if len(set(normalized_points)) != len(normalized_points):
        raise OneBeaconAirError("interpolation points must be distinct")
    for i, (point_i, value_i) in enumerate(zip(normalized_points, values, strict=True)):
        basis = (1,)
        denominator = 1
        for j, point_j in enumerate(normalized_points):
            if i == j:
                continue
            basis = poly_mul(basis, (-point_j % modulus, 1), modulus)
            denominator = denominator * (point_i - point_j) % modulus
        basis = poly_scale(basis, int(value_i) * pow(denominator, -1, modulus), modulus)
        result = poly_add(result, basis, modulus)
    return _trim(result, modulus)


@dataclass(frozen=True, slots=True)
class LocalAirTrace:
    a: tuple[int, ...]
    b: tuple[int, ...]
    c: tuple[int, ...]
    state: tuple[int, ...]
    delta: int
    modulus: int = BN254_BASE_FIELD

    def __post_init__(self) -> None:
        lengths = {len(self.a), len(self.b), len(self.c), len(self.state)}
        if len(lengths) != 1 or next(iter(lengths)) < 2:
            raise OneBeaconAirError("AIR columns must have the same length >=2")
        for name in ("a", "b", "c", "state"):
            object.__setattr__(
                self, name, tuple(int(value) % self.modulus for value in getattr(self, name))
            )
        object.__setattr__(self, "delta", int(self.delta) % self.modulus)

    @property
    def rows(self) -> int:
        return len(self.a)

    def validate(self) -> None:
        for index, (a, b, c) in enumerate(zip(self.a, self.b, self.c, strict=True)):
            if a * b % self.modulus != c:
                raise OneBeaconAirError(f"multiplication constraint fails at row {index}")
        for index in range(self.rows - 1):
            if (self.state[index] + self.delta) % self.modulus != self.state[index + 1]:
                raise OneBeaconAirError(f"transition constraint fails at row {index}")


@dataclass(frozen=True, slots=True)
class PolynomialOpening:
    value: int
    proof: GroupElement


@dataclass(frozen=True, slots=True)
class OneBeaconAirProof:
    rows: int
    beacon_point: int
    commitments: Mapping[str, GroupElement]
    openings_at_zeta: Mapping[str, PolynomialOpening]
    state_at_next: PolynomialOpening
    modulus: int = BN254_BASE_FIELD
    schema: str = "ranklock-one-beacon-local-air-proof-v1"

    @property
    def digest(self) -> bytes:
        document = {
            "schema": self.schema,
            "rows": self.rows,
            "beacon_point": str(self.beacon_point),
            "commitments": {
                key: value.encode().hex() for key, value in sorted(self.commitments.items())
            },
            "openings": {
                key: {"value": str(value.value), "proof": value.proof.encode().hex()}
                for key, value in sorted(self.openings_at_zeta.items())
            },
            "state_at_next": {
                "value": str(self.state_at_next.value),
                "proof": self.state_at_next.proof.encode().hex(),
            },
        }
        return hashlib.sha256(
            b"ranklock/one-beacon-air-proof/v1\x00"
            + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).digest()


@dataclass(frozen=True, slots=True)
class OneBeaconAirProverOutput:
    proof: OneBeaconAirProof
    polynomials: Mapping[str, tuple[int, ...]]


def prove_local_air(
    trace: LocalAirTrace,
    *,
    beacon_point: int,
    srs: FormalKzgSrs,
) -> OneBeaconAirProverOutput:
    trace.validate()
    if srs.modulus != trace.modulus:
        raise OneBeaconAirError("AIR and KZG fields differ")
    domain = tuple(range(trace.rows))
    active_transition_domain = domain[:-1]
    polynomials: dict[str, tuple[int, ...]] = {
        "a": interpolate(domain, trace.a, trace.modulus),
        "b": interpolate(domain, trace.b, trace.modulus),
        "c": interpolate(domain, trace.c, trace.modulus),
        "state": interpolate(domain, trace.state, trace.modulus),
    }
    multiplication_residual = poly_sub(
        poly_mul(polynomials["a"], polynomials["b"], trace.modulus),
        polynomials["c"],
        trace.modulus,
    )
    q_mul, remainder = poly_divmod(
        multiplication_residual,
        vanishing_polynomial(domain, trace.modulus),
        trace.modulus,
    )
    if remainder != (0,):
        raise OneBeaconAirError("multiplication residual is not divisible by row domain")

    transition_residual = poly_sub(
        poly_sub(
            poly_shift(polynomials["state"], 1, trace.modulus),
            polynomials["state"],
            trace.modulus,
        ),
        (trace.delta,),
        trace.modulus,
    )
    q_transition, remainder = poly_divmod(
        transition_residual,
        vanishing_polynomial(active_transition_domain, trace.modulus),
        trace.modulus,
    )
    if remainder != (0,):
        raise OneBeaconAirError("transition residual is not divisible by active domain")
    polynomials["q_mul"] = q_mul
    polynomials["q_transition"] = q_transition

    zeta = int(beacon_point) % trace.modulus
    if zeta in domain or (zeta + 1) % trace.modulus in domain:
        raise OneBeaconAirError("beacon point collides with AIR evaluation domain")
    commitments = {name: srs.commit_g1(poly) for name, poly in polynomials.items()}
    openings: dict[str, PolynomialOpening] = {}
    for name, poly in polynomials.items():
        value, opening = srs.opening_g1(poly, zeta)
        openings[name] = PolynomialOpening(value, opening)
    state_next_value, state_next_proof = srs.opening_g1(
        polynomials["state"], (zeta + 1) % trace.modulus
    )
    proof = OneBeaconAirProof(
        rows=trace.rows,
        beacon_point=zeta,
        commitments=commitments,
        openings_at_zeta=openings,
        state_at_next=PolynomialOpening(state_next_value, state_next_proof),
        modulus=trace.modulus,
    )
    return OneBeaconAirProverOutput(proof, polynomials)


def _opening_equations(
    proof: OneBeaconAirProof, srs: FormalKzgSrs
) -> tuple[PairingProductEquation, ...]:
    expected_names = {"a", "b", "c", "state", "q_mul", "q_transition"}
    if set(proof.commitments) != expected_names or set(proof.openings_at_zeta) != expected_names:
        raise OneBeaconAirError("AIR proof polynomial set differs")
    equations: list[PairingProductEquation] = []
    for name in sorted(expected_names):
        opening = proof.openings_at_zeta[name]
        equations.append(
            kzg_opening_equation_g1(
                commitment=proof.commitments[name],
                value=opening.value,
                opening=opening.proof,
                point=proof.beacon_point,
                srs=srs,
                label=f"open-{name}",
            )
        )
    equations.append(
        kzg_opening_equation_g1(
            commitment=proof.commitments["state"],
            value=proof.state_at_next.value,
            opening=proof.state_at_next.proof,
            point=(proof.beacon_point + 1) % proof.modulus,
            srs=srs,
            label="open-state-next",
        )
    )
    return tuple(equations)


def verify_local_air(
    proof: OneBeaconAirProof,
    *,
    delta: int,
    srs: FormalKzgSrs,
) -> bool:
    try:
        if proof.modulus != srs.modulus or proof.rows < 2:
            return False
        if not all(equation.verify() for equation in _opening_equations(proof, srs)):
            return False
        values = proof.openings_at_zeta
        zeta = proof.beacon_point % proof.modulus
        domain = tuple(range(proof.rows))
        active = domain[:-1]
        z_rows = polynomial_evaluate(
            vanishing_polynomial(domain, proof.modulus), zeta, proof.modulus
        )
        z_transition = polynomial_evaluate(
            vanishing_polynomial(active, proof.modulus), zeta, proof.modulus
        )
        multiplication_left = (
            values["a"].value * values["b"].value - values["c"].value
        ) % proof.modulus
        multiplication_right = z_rows * values["q_mul"].value % proof.modulus
        if multiplication_left != multiplication_right:
            return False
        transition_left = (
            proof.state_at_next.value - values["state"].value - int(delta)
        ) % proof.modulus
        transition_right = z_transition * values["q_transition"].value % proof.modulus
        return transition_left == transition_right
    except (OneBeaconAirError, ValueError, KeyError, OverflowError):
        return False


def air_cost_inventory(proof: OneBeaconAirProof) -> dict[str, object]:
    return {
        "schema": "ranklock-one-beacon-air-cost-v1",
        "rows": proof.rows,
        "trace_column_commitments": 4,
        "quotient_commitments": 2,
        "unbatched_kzg_openings": 7,
        "random_beacons": 1,
        "fiat_shamir_hashes_inside_lock": 0,
        "local_constraint_templates": 2,
        "proof_shape_independent_of_rows": True,
        "remaining_full_rankvm_gap": "memory/permutation argument and field-compatible real PCS",
    }
