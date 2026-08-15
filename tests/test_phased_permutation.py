from __future__ import annotations

from dataclasses import replace

from ranklock.field import polynomial_evaluate
from ranklock.one_beacon_air import (
    PolynomialOpening,
    poly_add,
    poly_mul,
    poly_shift,
    poly_sub,
    vanishing_polynomial,
)
from ranklock.phased_permutation import (
    challenge_for_phase_two,
    commit_arbitrary_tuple_phase_two,
    commit_tuple_permutation_phase_two,
    open_committed_tuple_permutation,
    verify_phased_tuple_permutation,
)
from ranklock.ppe_normal_form import FormalKzgSrs
from ranklock.tuple_permutation import (
    TuplePermutationProof,
    _compress_polynomials,
    commit_tuple_sequences,
    verify_tuple_permutation,
)


def _legacy_late_bound_nonpermutation(
    *,
    srs: FormalKzgSrs,
    eta: int,
    beta: int,
    zeta: int,
) -> TuplePermutationProof:
    left = ((1, 2), (3, 4), (5, 6), (7, 8))
    # Not a permutation: the final tuple was changed.
    right = ((1, 2), (3, 4), (5, 6), (7, 9))
    state = commit_tuple_sequences(left, right, srs=srs)
    modulus = srs.modulus
    left_poly = _compress_polynomials(state.left_polynomials, eta, modulus)
    right_poly = _compress_polynomials(state.right_polynomials, eta, modulus)
    z_poly = (1,)
    residual = poly_sub(
        poly_mul(
            poly_shift(z_poly, 1, modulus),
            poly_add(right_poly, (beta,), modulus),
            modulus,
        ),
        poly_mul(z_poly, poly_add(left_poly, (beta,), modulus), modulus),
        modulus,
    )
    z_h = polynomial_evaluate(
        vanishing_polynomial(tuple(range(state.phase_one.rows)), modulus),
        zeta,
        modulus,
    )
    q_at_zeta = polynomial_evaluate(residual, zeta, modulus) * pow(
        z_h, -1, modulus
    ) % modulus
    q_poly = (q_at_zeta,)
    left_openings = tuple(
        PolynomialOpening(*srs.opening_g1(polynomial, zeta))
        for polynomial in state.left_polynomials
    )
    right_openings = tuple(
        PolynomialOpening(*srs.opening_g1(polynomial, zeta))
        for polynomial in state.right_polynomials
    )
    z_opening = PolynomialOpening(*srs.opening_g1(z_poly, zeta))
    q_opening = PolynomialOpening(*srs.opening_g1(q_poly, zeta))
    return TuplePermutationProof(
        state.phase_one,
        eta,
        beta,
        zeta,
        srs.commit_g1(z_poly),
        srs.commit_g1(q_poly),
        left_openings,
        right_openings,
        z_opening,
        q_opening,
        PolynomialOpening(*srs.opening_g1(z_poly, zeta + 1)),
        PolynomialOpening(*srs.opening_g1(z_poly, 0)),
        PolynomialOpening(*srs.opening_g1(z_poly, state.phase_one.rows)),
    )


def test_legacy_tuple_permutation_has_late_binding_forgery() -> None:
    srs = FormalKzgSrs(tau=701)
    forged = _legacy_late_bound_nonpermutation(
        srs=srs, eta=31, beta=37, zeta=101
    )
    assert verify_tuple_permutation(forged, srs=srs)


def test_phased_tuple_permutation_accepts_real_permutation_and_binds_beacons() -> None:
    srs = FormalKzgSrs(tau=709)
    left = ((1, 10, 100), (2, 20, 200), (3, 30, 300), (4, 40, 400))
    right = (left[2], left[0], left[3], left[1])
    phase_one = commit_tuple_sequences(left, right, srs=srs)
    phase_two = commit_tuple_permutation_phase_two(
        phase_one, beacon_one=bytes.fromhex("31" * 32), srs=srs
    )
    proof = open_committed_tuple_permutation(
        phase_two, beacon_two=bytes.fromhex("32" * 32), srs=srs
    )
    assert verify_phased_tuple_permutation(proof, srs=srs)
    assert not verify_phased_tuple_permutation(
        replace(proof, beacon_two=bytes.fromhex("33" * 32)), srs=srs
    )
    assert not verify_phased_tuple_permutation(
        replace(
            proof,
            phase_two=replace(
                proof.phase_two, beacon_one=bytes.fromhex("34" * 32)
            ),
        ),
        srs=srs,
    )


def test_phase_two_quotient_tailored_to_guessed_zeta_fails() -> None:
    srs = FormalKzgSrs(tau=719)
    left = ((1, 2), (3, 4), (5, 6), (7, 8))
    right = ((1, 2), (3, 4), (5, 6), (7, 9))
    state = commit_tuple_sequences(left, right, srs=srs)
    beacon_one = bytes.fromhex("41" * 32)
    # Build an arbitrary phase-two commitment that is only correct at a guessed point.
    # The actual point will be derived later from beacon two.
    from ranklock.phased_permutation import challenges_for_phase_one

    eta, beta = challenges_for_phase_one(state.phase_one, beacon_one)
    modulus = srs.modulus
    guessed_zeta = 127
    left_poly = _compress_polynomials(state.left_polynomials, eta, modulus)
    right_poly = _compress_polynomials(state.right_polynomials, eta, modulus)
    z_poly = (1,)
    residual = poly_sub(
        poly_mul(
            poly_shift(z_poly, 1, modulus),
            poly_add(right_poly, (beta,), modulus),
            modulus,
        ),
        poly_mul(z_poly, poly_add(left_poly, (beta,), modulus), modulus),
        modulus,
    )
    z_h = polynomial_evaluate(
        vanishing_polynomial(tuple(range(state.phase_one.rows)), modulus),
        guessed_zeta,
        modulus,
    )
    q_poly = (
        polynomial_evaluate(residual, guessed_zeta, modulus)
        * pow(z_h, -1, modulus)
        % modulus,
    )
    phase_two = commit_arbitrary_tuple_phase_two(
        state,
        beacon_one=beacon_one,
        z_polynomial=z_poly,
        q_polynomial=q_poly,
        srs=srs,
    )
    beacon_two = bytes.fromhex("42" * 32)
    actual_zeta = challenge_for_phase_two(phase_two.phase, beacon_two)
    assert actual_zeta != guessed_zeta
    proof = open_committed_tuple_permutation(
        phase_two, beacon_two=beacon_two, srs=srs
    )
    assert not verify_phased_tuple_permutation(proof, srs=srs)
