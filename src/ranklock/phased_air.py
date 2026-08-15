from __future__ import annotations

"""Timing-correct one-beacon AIR protocol model.

The inherited ``generic_air.prove_generic_air`` helper receives zeta before it
constructs commitments.  That is convenient for honest tests but does not model
the security-critical timing requirement.  This module separates:

1. trace/quotient commitment;
2. external beacon challenge derivation;
3. polynomial openings.

The verifier recomputes the challenge from the committed transcript.  The model
still uses formal exponent-space KZG and is not production cryptography.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping

from .beacon import derive_field_challenge
from .generic_air import (
    AirConstraint,
    GenericAirError,
    GenericAirProgram,
    GenericAirProof,
    GenericAirTrace,
    program_digest,
    verify_generic_air,
)
from .kzg_we_model import GroupElement
from .one_beacon_air import PolynomialOpening, interpolate, poly_divmod, vanishing_polynomial
from .ppe_normal_form import FormalKzgSrs


@dataclass(frozen=True, slots=True)
class AirCommitmentPhase:
    program_digest: bytes
    rows: int
    commitments: Mapping[str, GroupElement]
    transcript_digest: bytes
    modulus: int
    schema: str = "ranklock-air-commitment-phase-v1"


@dataclass(frozen=True, slots=True)
class AirCommittedState:
    phase: AirCommitmentPhase
    polynomials: Mapping[str, tuple[int, ...]]


@dataclass(frozen=True, slots=True)
class PhasedAirProof:
    phase: AirCommitmentPhase
    beacon: bytes
    proof: GenericAirProof
    schema: str = "ranklock-phased-air-proof-v1"


def _validate_program_trace(
    program: GenericAirProgram, trace: GenericAirTrace, srs: FormalKzgSrs
) -> int:
    if trace.modulus != program.modulus or srs.modulus != program.modulus:
        raise GenericAirError("AIR program, trace, and PCS fields differ")
    if set(trace.columns) != set(program.columns):
        raise GenericAirError("AIR trace column set differs from program")
    rows = trace.rows
    if rows < 2:
        raise GenericAirError("AIR trace must have at least two rows")
    for constraint in program.constraints:
        if max(constraint.active_rows) >= rows:
            raise GenericAirError("AIR active row exceeds trace")
        if constraint.expression.next_columns and max(constraint.active_rows) >= rows - 1:
            raise GenericAirError("next-row constraint is active on the last row")
    for boundary in program.boundaries:
        if boundary.row >= rows:
            raise GenericAirError("AIR boundary row exceeds trace")
    return rows


def _phase_digest(
    *,
    program_hash: bytes,
    rows: int,
    commitments: Mapping[str, GroupElement],
    modulus: int,
) -> bytes:
    document = {
        "schema": "ranklock-air-commitment-phase-v1",
        "program_digest": program_hash.hex(),
        "rows": rows,
        "modulus": str(modulus),
        "commitments": {
            name: element.encode().hex() for name, element in sorted(commitments.items())
        },
    }
    return hashlib.sha256(
        b"ranklock/air/commitment-phase/v1\x00"
        + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).digest()


def commit_air(
    program: GenericAirProgram,
    trace: GenericAirTrace,
    *,
    srs: FormalKzgSrs,
) -> AirCommittedState:
    rows = _validate_program_trace(program, trace, srs)
    domain = tuple(range(rows))
    polynomials: dict[str, tuple[int, ...]] = {
        name: interpolate(domain, trace.columns[name], program.modulus)
        for name in program.columns
    }
    for constraint in program.constraints:
        residual = constraint.expression.poly(polynomials, program.modulus)
        quotient, remainder = poly_divmod(
            residual,
            vanishing_polynomial(constraint.active_rows, program.modulus),
            program.modulus,
        )
        if remainder != (0,):
            raise GenericAirError(f"AIR constraint {constraint.label} does not hold on its domain")
        polynomials[f"q:{constraint.label}"] = quotient
    commitments = {name: srs.commit_g1(poly) for name, poly in polynomials.items()}
    p_digest = program_digest(program)
    phase = AirCommitmentPhase(
        p_digest,
        rows,
        commitments,
        _phase_digest(
            program_hash=p_digest,
            rows=rows,
            commitments=commitments,
            modulus=program.modulus,
        ),
        program.modulus,
    )
    return AirCommittedState(phase, polynomials)


def commit_arbitrary_air_polynomials(
    program: GenericAirProgram,
    *,
    rows: int,
    polynomials: Mapping[str, tuple[int, ...]],
    srs: FormalKzgSrs,
) -> AirCommittedState:
    """Adversarial-test helper: commit exact polynomials without validity checks."""

    expected = set(program.columns) | {
        f"q:{constraint.label}" for constraint in program.constraints
    }
    if set(polynomials) != expected or rows < 2:
        raise GenericAirError("arbitrary AIR polynomial set/row count differs")
    commitments = {name: srs.commit_g1(poly) for name, poly in polynomials.items()}
    p_digest = program_digest(program)
    return AirCommittedState(
        AirCommitmentPhase(
            p_digest,
            rows,
            commitments,
            _phase_digest(
                program_hash=p_digest,
                rows=rows,
                commitments=commitments,
                modulus=program.modulus,
            ),
            program.modulus,
        ),
        dict(polynomials),
    )


def challenge_for_phase(
    phase: AirCommitmentPhase,
    beacon: bytes,
    *,
    program: GenericAirProgram,
) -> int:
    forbidden = set(range(phase.rows)) | {
        boundary.row for boundary in program.boundaries
    }
    # Next-row openings also use zeta+1.
    forbidden |= {(value - 1) % phase.modulus for value in tuple(forbidden)}
    return derive_field_challenge(
        beacon=beacon,
        transcript_digest=phase.transcript_digest,
        label=b"air-zeta",
        modulus=phase.modulus,
        forbidden=forbidden,
    )


def open_committed_air(
    state: AirCommittedState,
    *,
    beacon: bytes,
    program: GenericAirProgram,
    srs: FormalKzgSrs,
) -> PhasedAirProof:
    if state.phase.program_digest != program_digest(program):
        raise GenericAirError("committed AIR program differs")
    if state.phase.modulus != srs.modulus:
        raise GenericAirError("committed AIR field differs")
    zeta = challenge_for_phase(state.phase, beacon, program=program)
    current: dict[str, PolynomialOpening] = {}
    for name, polynomial in state.polynomials.items():
        value, proof = srs.opening_g1(polynomial, zeta)
        current[name] = PolynomialOpening(value, proof)
    next_names = sorted(
        set().union(*(constraint.expression.next_columns for constraint in program.constraints))
    )
    next_openings: dict[str, PolynomialOpening] = {}
    for name in next_names:
        value, proof = srs.opening_g1(
            state.polynomials[name], (zeta + 1) % state.phase.modulus
        )
        next_openings[name] = PolynomialOpening(value, proof)
    boundary_openings: dict[str, PolynomialOpening] = {}
    for boundary in program.boundaries:
        value, proof = srs.opening_g1(state.polynomials[boundary.column], boundary.row)
        boundary_openings[boundary.label] = PolynomialOpening(value, proof)
    generic = GenericAirProof(
        state.phase.program_digest,
        state.phase.rows,
        zeta,
        state.phase.commitments,
        current,
        next_openings,
        boundary_openings,
        state.phase.modulus,
    )
    return PhasedAirProof(state.phase, bytes(beacon), generic)


def verify_phased_air(
    program: GenericAirProgram,
    phased: PhasedAirProof,
    *,
    srs: FormalKzgSrs,
) -> bool:
    try:
        expected_digest = _phase_digest(
            program_hash=program_digest(program),
            rows=phased.phase.rows,
            commitments=phased.phase.commitments,
            modulus=phased.phase.modulus,
        )
        if phased.phase.transcript_digest != expected_digest:
            return False
        if phased.proof.commitments != phased.phase.commitments:
            return False
        if phased.proof.zeta != challenge_for_phase(
            phased.phase, phased.beacon, program=program
        ):
            return False
        return verify_generic_air(program, phased.proof, srs=srs)
    except (GenericAirError, ValueError, KeyError, OverflowError):
        return False
