from __future__ import annotations

from dataclasses import replace

from ranklock.generic_air import (
    AirConstraint,
    Current,
    GenericAirProgram,
    GenericAirProof,
    GenericAirTrace,
    program_digest,
    verify_generic_air,
)
from ranklock.one_beacon_air import PolynomialOpening, interpolate, vanishing_polynomial
from ranklock.phased_air import (
    challenge_for_phase,
    commit_air,
    commit_arbitrary_air_polynomials,
    open_committed_air,
    verify_phased_air,
)
from ranklock.ppe_normal_form import FormalKzgSrs
from ranklock.field import polynomial_evaluate


def _program() -> GenericAirProgram:
    a = Current("a")
    b = Current("b")
    c = Current("c")
    return GenericAirProgram(
        ("a", "b", "c"),
        (AirConstraint("mul", a * b - c, (0, 1, 2, 3)),),
    )


def _valid_trace() -> GenericAirTrace:
    return GenericAirTrace(
        {
            "a": (2, 3, 5, 7),
            "b": (11, 13, 17, 19),
            "c": (22, 39, 85, 133),
        }
    )


def _legacy_late_binding_forgery(program: GenericAirProgram, zeta: int, srs: FormalKzgSrs) -> GenericAirProof:
    rows = 4
    domain = tuple(range(rows))
    columns = {
        "a": interpolate(domain, (1, 2, 3, 4), srs.modulus),
        "b": interpolate(domain, (5, 6, 7, 8), srs.modulus),
        # Deliberately false on every row.
        "c": interpolate(domain, (0, 0, 0, 0), srs.modulus),
    }
    residual = program.constraints[0].expression.poly(columns, srs.modulus)
    z_h = polynomial_evaluate(vanishing_polynomial(domain, srs.modulus), zeta, srs.modulus)
    q_at_zeta = polynomial_evaluate(residual, zeta, srs.modulus) * pow(z_h, -1, srs.modulus) % srs.modulus
    polynomials = {**columns, "q:mul": (q_at_zeta,)}
    commitments = {name: srs.commit_g1(poly) for name, poly in polynomials.items()}
    openings = {}
    for name, polynomial in polynomials.items():
        value, proof = srs.opening_g1(polynomial, zeta)
        openings[name] = PolynomialOpening(value, proof)
    return GenericAirProof(
        program_digest(program), rows, zeta, commitments, openings, {}, {}, srs.modulus
    )


def test_legacy_helper_has_a_real_late_binding_attack() -> None:
    srs = FormalKzgSrs(tau=601)
    forged = _legacy_late_binding_forgery(_program(), 101, srs)
    assert verify_generic_air(_program(), forged, srs=srs)


def test_phased_air_accepts_valid_trace_and_binds_beacon() -> None:
    srs = FormalKzgSrs(tau=607)
    state = commit_air(_program(), _valid_trace(), srs=srs)
    proof = open_committed_air(
        state, beacon=bytes.fromhex("11" * 32), program=_program(), srs=srs
    )
    assert verify_phased_air(_program(), proof, srs=srs)
    assert not verify_phased_air(
        _program(), replace(proof, beacon=bytes.fromhex("12" * 32)), srs=srs
    )


def test_precommitted_quotient_tailored_to_wrong_zeta_fails() -> None:
    program = _program()
    srs = FormalKzgSrs(tau=613)
    guessed_zeta = 109
    legacy = _legacy_late_binding_forgery(program, guessed_zeta, srs)
    # Reuse the exact forged polynomials by recovering their formal exponents is not
    # possible in a real group; in this explicit formal model we reconstruct the same
    # polynomial choices directly.
    domain = (0, 1, 2, 3)
    columns = {
        "a": interpolate(domain, (1, 2, 3, 4), srs.modulus),
        "b": interpolate(domain, (5, 6, 7, 8), srs.modulus),
        "c": interpolate(domain, (0, 0, 0, 0), srs.modulus),
    }
    residual = program.constraints[0].expression.poly(columns, srs.modulus)
    z_h = polynomial_evaluate(vanishing_polynomial(domain, srs.modulus), guessed_zeta, srs.modulus)
    tailored_q = polynomial_evaluate(residual, guessed_zeta, srs.modulus) * pow(z_h, -1, srs.modulus) % srs.modulus
    state = commit_arbitrary_air_polynomials(
        program,
        rows=4,
        polynomials={**columns, "q:mul": (tailored_q,)},
        srs=srs,
    )
    beacon = bytes.fromhex("22" * 32)
    actual_zeta = challenge_for_phase(state.phase, beacon, program=program)
    assert actual_zeta != guessed_zeta
    proof = open_committed_air(state, beacon=beacon, program=program, srs=srs)
    assert not verify_phased_air(program, proof, srs=srs)
