from __future__ import annotations

"""Challenge-timing-correct tuple permutation argument.

The legacy :mod:`ranklock.tuple_permutation` helper accepts ``eta``, ``beta``
and ``zeta`` in one call and only then commits the grand-product and quotient
polynomials.  That ordering is unsound: once ``zeta`` is known, a prover can
commit a constant quotient tailored to that single point.

This module enforces the actual protocol schedule:

1. commit every tuple component column;
2. beacon one derives ``eta`` and ``beta``;
3. commit the grand-product ``Z`` and recurrence quotient ``Q``;
4. beacon two derives ``zeta``;
5. open all committed polynomials.

The implementation remains an exponent-space KZG model.  It validates protocol
shape and challenge timing; it is not production cryptography.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Sequence

from .beacon import derive_field_challenge
from .one_beacon_air import (
    PolynomialOpening,
    interpolate,
    poly_add,
    poly_divmod,
    poly_mul,
    poly_shift,
    poly_sub,
    vanishing_polynomial,
)
from .ppe_normal_form import FormalKzgSrs
from .tuple_permutation import (
    TuplePermutationError,
    TuplePermutationPhaseOne,
    TuplePermutationProof,
    TuplePermutationState,
    _compress_columns,
    _compress_polynomials,
    _grand_product,
    verify_tuple_permutation,
)


@dataclass(frozen=True, slots=True)
class TuplePermutationPhaseTwo:
    phase_one: TuplePermutationPhaseOne
    beacon_one: bytes
    eta: int
    beta: int
    commitment_z: object
    commitment_q: object
    transcript_digest: bytes
    modulus: int
    schema: str = "ranklock-tuple-permutation-phase-two-v1"


@dataclass(frozen=True, slots=True)
class TuplePermutationCommittedPhaseTwo:
    phase: TuplePermutationPhaseTwo
    state: TuplePermutationState
    z_polynomial: tuple[int, ...]
    q_polynomial: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PhasedTuplePermutationProof:
    phase_two: TuplePermutationPhaseTwo
    beacon_two: bytes
    proof: TuplePermutationProof
    schema: str = "ranklock-phased-tuple-permutation-proof-v1"


def phase_one_digest(phase: TuplePermutationPhaseOne) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"ranklock/tuple-permutation/phase-one/v1\x00")
    digest.update(int(phase.rows).to_bytes(8, "big"))
    digest.update(int(phase.width).to_bytes(4, "big"))
    for commitment in phase.left_commitments + phase.right_commitments:
        digest.update(commitment.encode())
    return digest.digest()


def challenges_for_phase_one(
    phase: TuplePermutationPhaseOne, beacon_one: bytes
) -> tuple[int, int]:
    expected = phase_one_digest(phase)
    if phase.transcript_digest != expected:
        raise TuplePermutationError("tuple phase-one transcript digest mismatch")
    eta = derive_field_challenge(
        beacon=beacon_one,
        transcript_digest=expected,
        label=b"tuple-eta",
        modulus=phase.modulus,
    )
    beta = derive_field_challenge(
        beacon=beacon_one,
        transcript_digest=expected,
        label=b"tuple-beta",
        modulus=phase.modulus,
    )
    return eta, beta


def _phase_two_digest(
    *,
    phase_one: TuplePermutationPhaseOne,
    beacon_one: bytes,
    eta: int,
    beta: int,
    commitment_z: object,
    commitment_q: object,
    modulus: int,
) -> bytes:
    document = {
        "schema": "ranklock-tuple-permutation-phase-two-v1",
        "phase_one_digest": phase_one.transcript_digest.hex(),
        "beacon_one": bytes(beacon_one).hex(),
        "eta": str(int(eta) % modulus),
        "beta": str(int(beta) % modulus),
        "commitment_z": commitment_z.encode().hex(),
        "commitment_q": commitment_q.encode().hex(),
        "modulus": str(modulus),
    }
    return hashlib.sha256(
        b"ranklock/tuple-permutation/phase-two/v1\x00"
        + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).digest()


def _build_phase_two(
    state: TuplePermutationState,
    *,
    beacon_one: bytes,
    z_polynomial: Sequence[int],
    q_polynomial: Sequence[int],
    srs: FormalKzgSrs,
) -> TuplePermutationCommittedPhaseTwo:
    if state.phase_one.modulus != srs.modulus:
        raise TuplePermutationError("tuple permutation and SRS fields differ")
    eta, beta = challenges_for_phase_one(state.phase_one, beacon_one)
    z_polynomial = tuple(int(value) % srs.modulus for value in z_polynomial)
    q_polynomial = tuple(int(value) % srs.modulus for value in q_polynomial)
    if not z_polynomial or not q_polynomial:
        raise TuplePermutationError("phase-two polynomials must be non-empty")
    commitment_z = srs.commit_g1(z_polynomial)
    commitment_q = srs.commit_g1(q_polynomial)
    digest = _phase_two_digest(
        phase_one=state.phase_one,
        beacon_one=beacon_one,
        eta=eta,
        beta=beta,
        commitment_z=commitment_z,
        commitment_q=commitment_q,
        modulus=srs.modulus,
    )
    phase = TuplePermutationPhaseTwo(
        state.phase_one,
        bytes(beacon_one),
        eta,
        beta,
        commitment_z,
        commitment_q,
        digest,
        srs.modulus,
    )
    return TuplePermutationCommittedPhaseTwo(
        phase, state, z_polynomial, q_polynomial
    )


def commit_tuple_permutation_phase_two(
    state: TuplePermutationState,
    *,
    beacon_one: bytes,
    srs: FormalKzgSrs,
) -> TuplePermutationCommittedPhaseTwo:
    """Commit a valid grand product and quotient after beacon one."""

    modulus = srs.modulus
    eta, beta = challenges_for_phase_one(state.phase_one, beacon_one)
    rows = state.phase_one.rows
    domain = tuple(range(rows))
    z_domain = tuple(range(rows + 1))
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
        raise TuplePermutationError(
            "tuple grand-product recurrence is not divisible"
        )
    return _build_phase_two(
        state,
        beacon_one=beacon_one,
        z_polynomial=z_polynomial,
        q_polynomial=q_polynomial,
        srs=srs,
    )


def commit_arbitrary_tuple_phase_two(
    state: TuplePermutationState,
    *,
    beacon_one: bytes,
    z_polynomial: Sequence[int],
    q_polynomial: Sequence[int],
    srs: FormalKzgSrs,
) -> TuplePermutationCommittedPhaseTwo:
    """Adversarial-test helper that skips recurrence divisibility checks."""

    return _build_phase_two(
        state,
        beacon_one=beacon_one,
        z_polynomial=z_polynomial,
        q_polynomial=q_polynomial,
        srs=srs,
    )


def challenge_for_phase_two(
    phase: TuplePermutationPhaseTwo, beacon_two: bytes
) -> int:
    expected_eta, expected_beta = challenges_for_phase_one(
        phase.phase_one, phase.beacon_one
    )
    if phase.eta != expected_eta or phase.beta != expected_beta:
        raise TuplePermutationError("phase-two tuple challenges mismatch")
    expected_digest = _phase_two_digest(
        phase_one=phase.phase_one,
        beacon_one=phase.beacon_one,
        eta=phase.eta,
        beta=phase.beta,
        commitment_z=phase.commitment_z,
        commitment_q=phase.commitment_q,
        modulus=phase.modulus,
    )
    if phase.transcript_digest != expected_digest:
        raise TuplePermutationError("tuple phase-two transcript digest mismatch")
    z_domain = set(range(phase.phase_one.rows + 1))
    forbidden = z_domain | {(value - 1) % phase.modulus for value in z_domain}
    return derive_field_challenge(
        beacon=beacon_two,
        transcript_digest=phase.transcript_digest,
        label=b"tuple-zeta",
        modulus=phase.modulus,
        forbidden=forbidden,
    )


def open_committed_tuple_permutation(
    state: TuplePermutationCommittedPhaseTwo,
    *,
    beacon_two: bytes,
    srs: FormalKzgSrs,
) -> PhasedTuplePermutationProof:
    if state.phase.modulus != srs.modulus:
        raise TuplePermutationError("tuple phase two and SRS fields differ")
    zeta = challenge_for_phase_two(state.phase, beacon_two)
    left_openings = tuple(
        PolynomialOpening(*srs.opening_g1(polynomial, zeta))
        for polynomial in state.state.left_polynomials
    )
    right_openings = tuple(
        PolynomialOpening(*srs.opening_g1(polynomial, zeta))
        for polynomial in state.state.right_polynomials
    )
    z_opening = PolynomialOpening(*srs.opening_g1(state.z_polynomial, zeta))
    q_opening = PolynomialOpening(*srs.opening_g1(state.q_polynomial, zeta))
    z_next = PolynomialOpening(
        *srs.opening_g1(state.z_polynomial, (zeta + 1) % srs.modulus)
    )
    z_zero = PolynomialOpening(*srs.opening_g1(state.z_polynomial, 0))
    z_end = PolynomialOpening(
        *srs.opening_g1(state.z_polynomial, state.phase.phase_one.rows)
    )
    proof = TuplePermutationProof(
        state.phase.phase_one,
        state.phase.eta,
        state.phase.beta,
        zeta,
        state.phase.commitment_z,
        state.phase.commitment_q,
        left_openings,
        right_openings,
        z_opening,
        q_opening,
        z_next,
        z_zero,
        z_end,
    )
    return PhasedTuplePermutationProof(state.phase, bytes(beacon_two), proof)


def verify_phased_tuple_permutation(
    phased: PhasedTuplePermutationProof, *, srs: FormalKzgSrs
) -> bool:
    try:
        phase = phased.phase_two
        if phase.modulus != srs.modulus:
            return False
        if phase.phase_one.transcript_digest != phase_one_digest(phase.phase_one):
            return False
        eta, beta = challenges_for_phase_one(phase.phase_one, phase.beacon_one)
        if phase.eta != eta or phase.beta != beta:
            return False
        if phase.transcript_digest != _phase_two_digest(
            phase_one=phase.phase_one,
            beacon_one=phase.beacon_one,
            eta=phase.eta,
            beta=phase.beta,
            commitment_z=phase.commitment_z,
            commitment_q=phase.commitment_q,
            modulus=phase.modulus,
        ):
            return False
        expected_zeta = challenge_for_phase_two(phase, phased.beacon_two)
        proof = phased.proof
        if (
            proof.phase_one != phase.phase_one
            or proof.eta != phase.eta
            or proof.beta != phase.beta
            or proof.zeta != expected_zeta
            or proof.commitment_z != phase.commitment_z
            or proof.commitment_q != phase.commitment_q
        ):
            return False
        return verify_tuple_permutation(proof, srs=srs)
    except (TuplePermutationError, ValueError, KeyError, OverflowError):
        return False
