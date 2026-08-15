from __future__ import annotations

"""Unified second-beacon opening schedule for the phased memory argument.

The v0.13 protocol opened AIR polynomials from beacon one and permutation
polynomials from beacon two.  AIR commitments and quotients are already fixed
before beacon one, so the AIR opening can be delayed.  This module derives one
shared ``zeta`` after the tuple grand-product and quotient are committed, then
opens both proof components at the same point.

After publishing all claimed opening values, a third independent beacon derives
same-point batching coefficients.  In the current sorted-memory skeleton this
reduces every KZG opening to four aggregate instances at points:

    zeta, zeta + 1, 0, rows.

This is a formal exponent-space KZG model.  It establishes transcript timing and
an exact conjunction inventory; it is not a static conditional-disclosure
construction because KZG-WE encapsulation still depends on the future aggregate
statements.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping, Sequence

from .beacon import derive_field_challenge
from .generic_air import GenericAirProof, verify_generic_air
from .kzg_we_conjunction import (
    KzgOpeningStatement,
    KzgOpeningWitness,
    aggregate_same_point,
)
from .memory_air import SortedMemoryAir
from .one_beacon_air import PolynomialOpening
from .phased_memory import (
    ACCESS_COLUMNS,
    PhasedMemoryCommittedState,
    _right_commitments_match_air,
)
from .phased_permutation import (
    TuplePermutationCommittedPhaseTwo,
    commit_tuple_permutation_phase_two,
)
from .ppe_normal_form import FormalKzgSrs
from .tuple_permutation import TuplePermutationProof, verify_tuple_permutation


class UnifiedMemoryOpeningError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class UnifiedMemoryPhaseTwo:
    committed: PhasedMemoryCommittedState
    tuple_phase_two: TuplePermutationCommittedPhaseTwo
    beacon_one: bytes
    transcript_digest: bytes
    schema: str = "ranklock-unified-memory-phase-two-v1"


@dataclass(frozen=True, slots=True)
class UnifiedMemoryProof:
    phase_two: UnifiedMemoryPhaseTwo
    beacon_two: bytes
    zeta: int
    air: GenericAirProof
    permutation: TuplePermutationProof
    schema: str = "ranklock-unified-memory-proof-v1"


@dataclass(frozen=True, slots=True)
class OpeningClaim:
    label: str
    commitment: object
    point: int
    value: int
    witness: object

    def statement(self) -> KzgOpeningStatement:
        return KzgOpeningStatement(self.commitment, self.point, self.value)

    def opening_witness(self) -> KzgOpeningWitness:
        return KzgOpeningWitness(self.witness)


@dataclass(frozen=True, slots=True)
class OpeningValuePublication:
    claims: tuple[OpeningClaim, ...]
    digest: bytes
    schema: str = "ranklock-opening-value-publication-v1"


@dataclass(frozen=True, slots=True)
class BatchedOpeningConjunction:
    statements: tuple[KzgOpeningStatement, ...]
    witnesses: tuple[KzgOpeningWitness, ...]
    points: tuple[int, ...]
    group_sizes: tuple[int, ...]
    value_publication_digest: bytes
    beacon_three: bytes
    schema: str = "ranklock-batched-opening-conjunction-v1"



def _combined_digest(
    committed: PhasedMemoryCommittedState,
    tuple_phase_two: TuplePermutationCommittedPhaseTwo,
    beacon_one: bytes,
) -> bytes:
    document = {
        "schema": "ranklock-unified-memory-phase-two-v1",
        "air_phase": committed.air_phase.phase.transcript_digest.hex(),
        "tuple_phase_one": committed.permutation_phase_one.phase_one.transcript_digest.hex(),
        "tuple_phase_two": tuple_phase_two.phase.transcript_digest.hex(),
        "beacon_one": bytes(beacon_one).hex(),
        "rows": committed.sorted_air.trace.rows,
    }
    return hashlib.sha256(
        b"ranklock/unified-memory/phase-two/v1\x00"
        + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).digest()



def commit_unified_memory_phase_two(
    committed: PhasedMemoryCommittedState,
    *,
    beacon_one: bytes,
    srs: FormalKzgSrs,
) -> UnifiedMemoryPhaseTwo:
    if not _right_commitments_match_air(
        committed.permutation_phase_one, committed.air_phase
    ):
        raise UnifiedMemoryOpeningError("memory components do not share access commitments")
    tuple_phase_two = commit_tuple_permutation_phase_two(
        committed.permutation_phase_one, beacon_one=beacon_one, srs=srs
    )
    return UnifiedMemoryPhaseTwo(
        committed,
        tuple_phase_two,
        bytes(beacon_one),
        _combined_digest(committed, tuple_phase_two, beacon_one),
    )



def shared_zeta(
    phase_two: UnifiedMemoryPhaseTwo, beacon_two: bytes, *, srs: FormalKzgSrs
) -> int:
    expected = _combined_digest(
        phase_two.committed, phase_two.tuple_phase_two, phase_two.beacon_one
    )
    if phase_two.transcript_digest != expected:
        raise UnifiedMemoryOpeningError("unified phase-two transcript mismatch")
    rows = phase_two.committed.sorted_air.trace.rows
    forbidden = set(range(rows + 1))
    forbidden |= {(value - 1) % srs.modulus for value in forbidden}
    return derive_field_challenge(
        beacon=beacon_two,
        transcript_digest=phase_two.transcript_digest,
        label=b"unified-memory-zeta",
        modulus=srs.modulus,
        forbidden=forbidden,
    )



def _open_air_at(
    sorted_air: SortedMemoryAir,
    state,
    zeta: int,
    *,
    srs: FormalKzgSrs,
) -> GenericAirProof:
    program = sorted_air.program
    current: dict[str, PolynomialOpening] = {}
    for name, polynomial in state.polynomials.items():
        current[name] = PolynomialOpening(*srs.opening_g1(polynomial, zeta))
    next_names = sorted(
        set().union(*(constraint.expression.next_columns for constraint in program.constraints))
    )
    next_openings = {
        name: PolynomialOpening(
            *srs.opening_g1(state.polynomials[name], (zeta + 1) % srs.modulus)
        )
        for name in next_names
    }
    boundaries = {
        boundary.label: PolynomialOpening(
            *srs.opening_g1(state.polynomials[boundary.column], boundary.row)
        )
        for boundary in program.boundaries
    }
    return GenericAirProof(
        state.phase.program_digest,
        state.phase.rows,
        zeta,
        state.phase.commitments,
        current,
        next_openings,
        boundaries,
        state.phase.modulus,
    )



def _open_tuple_at(
    state: TuplePermutationCommittedPhaseTwo,
    zeta: int,
    *,
    srs: FormalKzgSrs,
) -> TuplePermutationProof:
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
    return TuplePermutationProof(
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



def open_unified_memory(
    phase_two: UnifiedMemoryPhaseTwo,
    *,
    beacon_two: bytes,
    srs: FormalKzgSrs,
) -> UnifiedMemoryProof:
    zeta = shared_zeta(phase_two, beacon_two, srs=srs)
    air = _open_air_at(
        phase_two.committed.sorted_air,
        phase_two.committed.air_phase,
        zeta,
        srs=srs,
    )
    permutation = _open_tuple_at(phase_two.tuple_phase_two, zeta, srs=srs)
    return UnifiedMemoryProof(phase_two, bytes(beacon_two), zeta, air, permutation)



def verify_unified_memory(proof: UnifiedMemoryProof, *, srs: FormalKzgSrs) -> bool:
    try:
        expected_zeta = shared_zeta(proof.phase_two, proof.beacon_two, srs=srs)
        if proof.zeta != expected_zeta:
            return False
        if proof.air.zeta != expected_zeta or proof.permutation.zeta != expected_zeta:
            return False
        try:
            expected_access_commitments = tuple(
                proof.air.commitments[name] for name in ACCESS_COLUMNS
            )
        except KeyError:
            return False
        if proof.permutation.phase_one.right_commitments != expected_access_commitments:
            return False
        return verify_generic_air(
            proof.phase_two.committed.sorted_air.program, proof.air, srs=srs
        ) and verify_tuple_permutation(proof.permutation, srs=srs)
    except (UnifiedMemoryOpeningError, ValueError, KeyError, OverflowError):
        return False



def opening_claims(proof: UnifiedMemoryProof) -> tuple[OpeningClaim, ...]:
    program = proof.phase_two.committed.sorted_air.program
    claims: list[OpeningClaim] = []
    for name, opening in proof.air.current_openings.items():
        claims.append(
            OpeningClaim(
                f"air-current:{name}",
                proof.air.commitments[name],
                proof.zeta,
                opening.value,
                opening.proof,
            )
        )
    for name, opening in proof.air.next_openings.items():
        claims.append(
            OpeningClaim(
                f"air-next:{name}",
                proof.air.commitments[name],
                (proof.zeta + 1) % proof.air.modulus,
                opening.value,
                opening.proof,
            )
        )
    boundary_by_label = {boundary.label: boundary for boundary in program.boundaries}
    for label, opening in proof.air.boundary_openings.items():
        boundary = boundary_by_label[label]
        claims.append(
            OpeningClaim(
                f"air-boundary:{label}",
                proof.air.commitments[boundary.column],
                boundary.row,
                opening.value,
                opening.proof,
            )
        )
    phase_one = proof.permutation.phase_one
    for side, commitments, openings in (
        ("left", phase_one.left_commitments, proof.permutation.left_openings),
        ("right", phase_one.right_commitments, proof.permutation.right_openings),
    ):
        for index, (commitment, opening) in enumerate(
            zip(commitments, openings, strict=True)
        ):
            claims.append(
                OpeningClaim(
                    f"perm-{side}:{index}",
                    commitment,
                    proof.zeta,
                    opening.value,
                    opening.proof,
                )
            )
    for label, commitment, point, opening in (
        ("perm-z", proof.permutation.commitment_z, proof.zeta, proof.permutation.z_opening),
        ("perm-q", proof.permutation.commitment_q, proof.zeta, proof.permutation.q_opening),
        (
            "perm-z-next",
            proof.permutation.commitment_z,
            (proof.zeta + 1) % proof.air.modulus,
            proof.permutation.z_next,
        ),
        ("perm-z-zero", proof.permutation.commitment_z, 0, proof.permutation.z_zero),
        (
            "perm-z-end",
            proof.permutation.commitment_z,
            phase_one.rows,
            proof.permutation.z_end,
        ),
    ):
        claims.append(
            OpeningClaim(label, commitment, point, opening.value, opening.proof)
        )
    return tuple(claims)



def publish_opening_values(proof: UnifiedMemoryProof) -> OpeningValuePublication:
    claims = opening_claims(proof)
    document = [
        {
            "label": claim.label,
            "commitment": claim.commitment.encode().hex(),
            "point": str(claim.point % proof.air.modulus),
            "value": str(claim.value % proof.air.modulus),
        }
        for claim in claims
    ]
    digest = hashlib.sha256(
        b"ranklock/opening-values/v1\x00"
        + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).digest()
    return OpeningValuePublication(claims, digest)



def _batch_rho(
    publication: OpeningValuePublication,
    point: int,
    beacon_three: bytes,
    *,
    modulus: int,
) -> int:
    return derive_field_challenge(
        beacon=beacon_three,
        transcript_digest=publication.digest,
        label=b"opening-batch-rho" + int(point % modulus).to_bytes(32, "big"),
        modulus=modulus,
        forbidden={0},
    )



def batch_published_openings(
    publication: OpeningValuePublication,
    *,
    beacon_three: bytes,
    srs: FormalKzgSrs,
) -> BatchedOpeningConjunction:
    groups: dict[int, list[OpeningClaim]] = {}
    for claim in publication.claims:
        groups.setdefault(claim.point % srs.modulus, []).append(claim)
    statements: list[KzgOpeningStatement] = []
    witnesses: list[KzgOpeningWitness] = []
    points: list[int] = []
    sizes: list[int] = []
    for point in sorted(groups):
        claims = groups[point]
        rho = _batch_rho(
            publication, point, beacon_three, modulus=srs.modulus
        )
        statement, witness = aggregate_same_point(
            tuple(claim.statement() for claim in claims),
            tuple(claim.opening_witness() for claim in claims),
            rho=rho,
            srs=srs,
        )
        statements.append(statement)
        witnesses.append(witness)
        points.append(point)
        sizes.append(len(claims))
    return BatchedOpeningConjunction(
        tuple(statements),
        tuple(witnesses),
        tuple(points),
        tuple(sizes),
        publication.digest,
        bytes(beacon_three),
    )



def unified_opening_inventory(
    proof: UnifiedMemoryProof, batched: BatchedOpeningConjunction
) -> dict[str, object]:
    claims = opening_claims(proof)
    return {
        "schema": "ranklock-unified-memory-opening-inventory-v1",
        "raw_kzg_openings": len(claims),
        "distinct_evaluation_points": len(set(claim.point for claim in claims)),
        "batched_kzg_openings": len(batched.statements),
        "batch_group_sizes": list(batched.group_sizes),
        "points": [str(point) for point in batched.points],
        "external_beacons": 3,
        "kzg_we_ciphertext_group_elements_after_batching": len(batched.statements),
        "kzg_we_decryption_pairings_after_batching": len(batched.statements),
        "static_encapsulation_supported": False,
        "remaining_barrier": "aggregate KZG statements are created after the trace and value-binding beacon",
    }
