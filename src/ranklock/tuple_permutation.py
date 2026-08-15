from __future__ import annotations

"""Legacy tuple-permutation algebra and verifier.

SECURITY WARNING: :func:`respond_tuple_permutation` receives ``zeta`` before it
commits ``Z`` and ``Q``.  A non-permutation can therefore pass with a quotient
tailored to that single point; the exploit is executable in
``tests/test_phased_permutation.py``.  Use
:mod:`ranklock.phased_permutation` for the timing-correct two-beacon protocol.

The data structures and opening-equation verifier here are intentionally kept
as a low-level algebra backend.
"""

from dataclasses import dataclass, replace
import hashlib
from typing import Mapping, Sequence

from .field import BN254_BASE_FIELD, polynomial_evaluate
from .generic_air import GenericAirError
from .kzg_we_model import GroupElement
from .one_beacon_air import (
    PolynomialOpening,
    interpolate,
    poly_add,
    poly_divmod,
    poly_mul,
    poly_scale,
    poly_shift,
    poly_sub,
    vanishing_polynomial,
)
from .ppe_normal_form import FormalKzgSrs, PairingProductEquation, kzg_opening_equation_g1


class TuplePermutationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class TuplePermutationPhaseOne:
    rows: int
    width: int
    left_commitments: tuple[GroupElement, ...]
    right_commitments: tuple[GroupElement, ...]
    transcript_digest: bytes
    modulus: int = BN254_BASE_FIELD


@dataclass(frozen=True, slots=True)
class TuplePermutationState:
    phase_one: TuplePermutationPhaseOne
    left_columns: tuple[tuple[int, ...], ...]
    right_columns: tuple[tuple[int, ...], ...]
    left_polynomials: tuple[tuple[int, ...], ...]
    right_polynomials: tuple[tuple[int, ...], ...]


@dataclass(frozen=True, slots=True)
class TuplePermutationProof:
    phase_one: TuplePermutationPhaseOne
    eta: int
    beta: int
    zeta: int
    commitment_z: GroupElement
    commitment_q: GroupElement
    left_openings: tuple[PolynomialOpening, ...]
    right_openings: tuple[PolynomialOpening, ...]
    z_opening: PolynomialOpening
    q_opening: PolynomialOpening
    z_next: PolynomialOpening
    z_zero: PolynomialOpening
    z_end: PolynomialOpening


def _transpose(rows: Sequence[Sequence[int]]) -> tuple[tuple[int, ...], ...]:
    rows = tuple(tuple(int(value) for value in row) for row in rows)
    if not rows or not rows[0]:
        raise TuplePermutationError("tuple sequence is empty")
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        raise TuplePermutationError("tuple sequence rows have different widths")
    return tuple(tuple(row[index] for row in rows) for index in range(width))


def commit_tuple_sequences(
    left_rows: Sequence[Sequence[int]],
    right_rows: Sequence[Sequence[int]],
    *,
    srs: FormalKzgSrs,
) -> TuplePermutationState:
    if len(left_rows) != len(right_rows) or len(left_rows) < 2:
        raise TuplePermutationError("tuple sequences must have equal row count >=2")
    left_columns = _transpose(left_rows)
    right_columns = _transpose(right_rows)
    if len(left_columns) != len(right_columns):
        raise TuplePermutationError("tuple sequences have different widths")
    modulus = srs.modulus
    domain = tuple(range(len(left_rows)))
    left_columns = tuple(tuple(value % modulus for value in column) for column in left_columns)
    right_columns = tuple(tuple(value % modulus for value in column) for column in right_columns)
    left_polynomials = tuple(interpolate(domain, column, modulus) for column in left_columns)
    right_polynomials = tuple(interpolate(domain, column, modulus) for column in right_columns)
    left_commitments = tuple(srs.commit_g1(polynomial) for polynomial in left_polynomials)
    right_commitments = tuple(srs.commit_g1(polynomial) for polynomial in right_polynomials)
    digest = hashlib.sha256()
    digest.update(b"ranklock/tuple-permutation/phase-one/v1\x00")
    digest.update(len(left_rows).to_bytes(8, "big"))
    digest.update(len(left_columns).to_bytes(4, "big"))
    for commitment in left_commitments + right_commitments:
        digest.update(commitment.encode())
    phase = TuplePermutationPhaseOne(
        len(left_rows), len(left_columns), left_commitments, right_commitments, digest.digest(), modulus
    )
    return TuplePermutationState(
        phase, left_columns, right_columns, left_polynomials, right_polynomials
    )


def _compress_columns(
    columns: Sequence[Sequence[int]], eta: int, modulus: int
) -> tuple[int, ...]:
    rows = len(columns[0])
    result = [0] * rows
    power = 1
    for column in columns:
        for row, value in enumerate(column):
            result[row] = (result[row] + power * int(value)) % modulus
        power = power * eta % modulus
    return tuple(result)


def _compress_polynomials(
    polynomials: Sequence[Sequence[int]], eta: int, modulus: int
) -> tuple[int, ...]:
    result = (0,)
    power = 1
    for polynomial in polynomials:
        result = poly_add(result, poly_scale(polynomial, power, modulus), modulus)
        power = power * eta % modulus
    return result


def _grand_product(left: Sequence[int], right: Sequence[int], beta: int, modulus: int) -> tuple[int, ...]:
    z = [1]
    for l_value, r_value in zip(left, right, strict=True):
        denominator = (int(r_value) + beta) % modulus
        if denominator == 0:
            raise TuplePermutationError("beta hits a compressed right-tuple pole")
        z.append(
            z[-1]
            * ((int(l_value) + beta) % modulus)
            * pow(denominator, -1, modulus)
            % modulus
        )
    return tuple(z)


def respond_tuple_permutation(
    state: TuplePermutationState,
    *,
    eta: int,
    beta: int,
    zeta: int,
    srs: FormalKzgSrs,
) -> TuplePermutationProof:
    modulus = srs.modulus
    if state.phase_one.modulus != modulus:
        raise TuplePermutationError("tuple permutation and SRS fields differ")
    eta %= modulus
    beta %= modulus
    zeta %= modulus
    rows = state.phase_one.rows
    domain = tuple(range(rows))
    z_domain = tuple(range(rows + 1))
    if zeta in z_domain or (zeta + 1) % modulus in z_domain:
        raise TuplePermutationError("zeta collides with tuple-permutation domain")
    left_values = _compress_columns(state.left_columns, eta, modulus)
    right_values = _compress_columns(state.right_columns, eta, modulus)
    left_polynomial = _compress_polynomials(state.left_polynomials, eta, modulus)
    right_polynomial = _compress_polynomials(state.right_polynomials, eta, modulus)
    z_values = _grand_product(left_values, right_values, beta, modulus)
    z_polynomial = interpolate(z_domain, z_values, modulus)
    residual = poly_sub(
        poly_mul(
            poly_shift(z_polynomial, 1, modulus),
            poly_add(right_polynomial, (beta,), modulus),
            modulus,
        ),
        poly_mul(
            z_polynomial,
            poly_add(left_polynomial, (beta,), modulus),
            modulus,
        ),
        modulus,
    )
    q_polynomial, remainder = poly_divmod(
        residual, vanishing_polynomial(domain, modulus), modulus
    )
    if remainder != (0,):
        raise TuplePermutationError("tuple grand-product recurrence is not divisible")
    commitment_z = srs.commit_g1(z_polynomial)
    commitment_q = srs.commit_g1(q_polynomial)
    left_openings = tuple(
        PolynomialOpening(*srs.opening_g1(polynomial, zeta))
        for polynomial in state.left_polynomials
    )
    right_openings = tuple(
        PolynomialOpening(*srs.opening_g1(polynomial, zeta))
        for polynomial in state.right_polynomials
    )
    z_opening = PolynomialOpening(*srs.opening_g1(z_polynomial, zeta))
    q_opening = PolynomialOpening(*srs.opening_g1(q_polynomial, zeta))
    z_next = PolynomialOpening(*srs.opening_g1(z_polynomial, (zeta + 1) % modulus))
    z_zero = PolynomialOpening(*srs.opening_g1(z_polynomial, 0))
    z_end = PolynomialOpening(*srs.opening_g1(z_polynomial, rows))
    return TuplePermutationProof(
        state.phase_one,
        eta,
        beta,
        zeta,
        commitment_z,
        commitment_q,
        left_openings,
        right_openings,
        z_opening,
        q_opening,
        z_next,
        z_zero,
        z_end,
    )


def _opening_equations(
    proof: TuplePermutationProof, srs: FormalKzgSrs
) -> tuple[PairingProductEquation, ...]:
    if len(proof.left_openings) != proof.phase_one.width or len(proof.right_openings) != proof.phase_one.width:
        raise TuplePermutationError("tuple opening width differs")
    equations: list[PairingProductEquation] = []
    for side, commitments, openings in (
        ("left", proof.phase_one.left_commitments, proof.left_openings),
        ("right", proof.phase_one.right_commitments, proof.right_openings),
    ):
        for index, (commitment, opening) in enumerate(zip(commitments, openings, strict=True)):
            equations.append(
                kzg_opening_equation_g1(
                    commitment=commitment,
                    value=opening.value,
                    opening=opening.proof,
                    point=proof.zeta,
                    srs=srs,
                    label=f"tuple-{side}-{index}",
                )
            )
    for label, commitment, point, opening in (
        ("tuple-z", proof.commitment_z, proof.zeta, proof.z_opening),
        ("tuple-q", proof.commitment_q, proof.zeta, proof.q_opening),
        ("tuple-z-next", proof.commitment_z, proof.zeta + 1, proof.z_next),
        ("tuple-z-zero", proof.commitment_z, 0, proof.z_zero),
        ("tuple-z-end", proof.commitment_z, proof.phase_one.rows, proof.z_end),
    ):
        equations.append(
            kzg_opening_equation_g1(
                commitment=commitment,
                value=opening.value,
                opening=opening.proof,
                point=point % srs.modulus,
                srs=srs,
                label=label,
            )
        )
    return tuple(equations)


def _compress_openings(openings: Sequence[PolynomialOpening], eta: int, modulus: int) -> int:
    value = 0
    power = 1
    for opening in openings:
        value = (value + power * opening.value) % modulus
        power = power * eta % modulus
    return value


def verify_tuple_permutation(proof: TuplePermutationProof, *, srs: FormalKzgSrs) -> bool:
    try:
        if proof.phase_one.modulus != srs.modulus or proof.phase_one.rows < 2:
            return False
        if not all(equation.verify() for equation in _opening_equations(proof, srs)):
            return False
        modulus = srs.modulus
        left = _compress_openings(proof.left_openings, proof.eta, modulus)
        right = _compress_openings(proof.right_openings, proof.eta, modulus)
        recurrence_left = (
            proof.z_next.value * (right + proof.beta)
            - proof.z_opening.value * (left + proof.beta)
        ) % modulus
        vanishing = polynomial_evaluate(
            vanishing_polynomial(tuple(range(proof.phase_one.rows)), modulus),
            proof.zeta,
            modulus,
        )
        if recurrence_left != vanishing * proof.q_opening.value % modulus:
            return False
        return proof.z_zero.value % modulus == 1 and proof.z_end.value % modulus == 1
    except (TuplePermutationError, GenericAirError, ValueError, OverflowError):
        return False


def tuple_permutation_cost(rows: int, width: int) -> dict[str, object]:
    if rows < 2 or width < 1:
        raise TuplePermutationError("rows/width outside tuple-permutation bounds")
    return {
        "schema": "ranklock-two-beacon-tuple-permutation-cost-v1",
        "rows": rows,
        "tuple_width": width,
        "phase_one_component_commitments": 2 * width,
        "phase_two_commitments": 2,
        "unbatched_openings": 2 * width + 5,
        "beacons": 2,
        "proof_shape_independent_of_rows": True,
        "compression_soundness": "O(width/p)",
        "grand_product_soundness": "O(rows/p)",
    }
