from __future__ import annotations

"""Challenge-timing model for batched same-point KZG openings.

A random linear combination reduces many same-point KZG equations to one, but
only if the batching scalar is sampled *after* the individual claimed values
are fixed.  If the scalar is already known, false values can cancel in the
aggregate.

This module provides both the forgery-prone known-challenge verifier and a
three-phase model:

1. polynomial commitments are fixed;
2. individual values are published and transcript-bound;
3. an external beacon derives ``rho`` and one aggregate opening is supplied.

It remains a formal exponent-space KZG model.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Sequence

from .beacon import derive_field_challenge
from .kzg_we_model import GroupElement
from .one_beacon_air import poly_add, poly_scale
from .ppe_normal_form import FormalKzgSrs, kzg_opening_equation_g1


class BatchedOpeningError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OpeningValuePhase:
    commitments: tuple[GroupElement, ...]
    point: int
    values: tuple[int, ...]
    transcript_digest: bytes
    modulus: int
    schema: str = "ranklock-kzg-opening-value-phase-v1"


@dataclass(frozen=True, slots=True)
class BatchedOpeningProof:
    value_phase: OpeningValuePhase
    beacon: bytes
    rho: int
    opening: GroupElement
    schema: str = "ranklock-batched-kzg-opening-proof-v1"


def _weighted_scalars(values: Sequence[int], rho: int, modulus: int) -> int:
    result = 0
    power = 1
    for value in values:
        result = (result + power * int(value)) % modulus
        power = power * rho % modulus
    return result


def _weighted_commitments(
    commitments: Sequence[GroupElement], rho: int, modulus: int
) -> GroupElement:
    if not commitments:
        raise BatchedOpeningError("empty commitment batch")
    result = GroupElement("G1", 0, modulus)
    power = 1
    for commitment in commitments:
        if commitment.group != "G1" or commitment.modulus != modulus:
            raise BatchedOpeningError("batched commitment is incompatible")
        result = result + commitment.scale(power)
        power = power * rho % modulus
    return result


def _aggregate_polynomial(
    polynomials: Sequence[Sequence[int]], rho: int, modulus: int
) -> tuple[int, ...]:
    if not polynomials:
        raise BatchedOpeningError("empty polynomial batch")
    result = (0,)
    power = 1
    for polynomial in polynomials:
        result = poly_add(result, poly_scale(polynomial, power, modulus), modulus)
        power = power * rho % modulus
    return result


def value_phase_digest(
    *,
    commitments: Sequence[GroupElement],
    point: int,
    values: Sequence[int],
    modulus: int,
) -> bytes:
    document = {
        "schema": "ranklock-kzg-opening-value-phase-v1",
        "commitments": [commitment.encode().hex() for commitment in commitments],
        "point": str(int(point) % modulus),
        "values": [str(int(value) % modulus) for value in values],
        "modulus": str(modulus),
    }
    return hashlib.sha256(
        b"ranklock/kzg/opening-value-phase/v1\x00"
        + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).digest()


def commit_opening_values(
    *,
    commitments: Sequence[GroupElement],
    point: int,
    values: Sequence[int],
    modulus: int,
) -> OpeningValuePhase:
    commitments = tuple(commitments)
    values = tuple(int(value) % modulus for value in values)
    if not commitments or len(commitments) != len(values):
        raise BatchedOpeningError("commitment/value batch size differs")
    if any(commitment.group != "G1" or commitment.modulus != modulus for commitment in commitments):
        raise BatchedOpeningError("value phase contains incompatible commitment")
    return OpeningValuePhase(
        commitments,
        int(point) % modulus,
        values,
        value_phase_digest(
            commitments=commitments,
            point=point,
            values=values,
            modulus=modulus,
        ),
        modulus,
    )


def batching_challenge(phase: OpeningValuePhase, beacon: bytes) -> int:
    expected = value_phase_digest(
        commitments=phase.commitments,
        point=phase.point,
        values=phase.values,
        modulus=phase.modulus,
    )
    if phase.transcript_digest != expected:
        raise BatchedOpeningError("opening-value phase digest mismatch")
    return derive_field_challenge(
        beacon=beacon,
        transcript_digest=phase.transcript_digest,
        label=b"kzg-batch-rho",
        modulus=phase.modulus,
        forbidden=(0,),
    )


def prove_batched_opening(
    polynomials: Sequence[Sequence[int]],
    *,
    point: int,
    beacon: bytes,
    srs: FormalKzgSrs,
) -> BatchedOpeningProof:
    polynomials = tuple(tuple(int(value) % srs.modulus for value in poly) for poly in polynomials)
    commitments = tuple(srs.commit_g1(poly) for poly in polynomials)
    values = tuple(srs.opening_g1(poly, point)[0] for poly in polynomials)
    phase = commit_opening_values(
        commitments=commitments,
        point=point,
        values=values,
        modulus=srs.modulus,
    )
    rho = batching_challenge(phase, beacon)
    aggregate = _aggregate_polynomial(polynomials, rho, srs.modulus)
    _value, opening = srs.opening_g1(aggregate, point)
    return BatchedOpeningProof(phase, bytes(beacon), rho, opening)


def prove_with_claimed_values(
    polynomials: Sequence[Sequence[int]],
    *,
    point: int,
    claimed_values: Sequence[int],
    beacon: bytes,
    srs: FormalKzgSrs,
) -> BatchedOpeningProof:
    """Adversarial helper: bind arbitrary values, then open the true aggregate."""

    polynomials = tuple(tuple(int(value) % srs.modulus for value in poly) for poly in polynomials)
    commitments = tuple(srs.commit_g1(poly) for poly in polynomials)
    phase = commit_opening_values(
        commitments=commitments,
        point=point,
        values=claimed_values,
        modulus=srs.modulus,
    )
    rho = batching_challenge(phase, beacon)
    aggregate = _aggregate_polynomial(polynomials, rho, srs.modulus)
    _value, opening = srs.opening_g1(aggregate, point)
    return BatchedOpeningProof(phase, bytes(beacon), rho, opening)


def verify_known_rho_aggregate(
    *,
    commitments: Sequence[GroupElement],
    point: int,
    claimed_values: Sequence[int],
    rho: int,
    opening: GroupElement,
    srs: FormalKzgSrs,
) -> bool:
    try:
        commitment = _weighted_commitments(commitments, rho, srs.modulus)
        value = _weighted_scalars(claimed_values, rho, srs.modulus)
        return kzg_opening_equation_g1(
            commitment=commitment,
            value=value,
            opening=opening,
            point=point,
            srs=srs,
            label="known-rho-batch",
        ).verify()
    except (BatchedOpeningError, ValueError, OverflowError):
        return False


def verify_batched_opening(
    proof: BatchedOpeningProof, *, srs: FormalKzgSrs
) -> bool:
    try:
        phase = proof.value_phase
        if phase.modulus != srs.modulus:
            return False
        if phase.transcript_digest != value_phase_digest(
            commitments=phase.commitments,
            point=phase.point,
            values=phase.values,
            modulus=phase.modulus,
        ):
            return False
        expected_rho = batching_challenge(phase, proof.beacon)
        if proof.rho != expected_rho:
            return False
        return verify_known_rho_aggregate(
            commitments=phase.commitments,
            point=phase.point,
            claimed_values=phase.values,
            rho=proof.rho,
            opening=proof.opening,
            srs=srs,
        )
    except (BatchedOpeningError, ValueError, KeyError, OverflowError):
        return False


def batching_cost_inventory(openings: int) -> dict[str, object]:
    if openings < 1:
        raise BatchedOpeningError("opening count must be positive")
    return {
        "schema": "ranklock-kzg-batching-cost-v1",
        "individual_same_point_openings": int(openings),
        "batched_openings": 1,
        "pairing_product_equations": 1,
        "additional_value_publication_phase": True,
        "additional_external_beacon": 1,
        "security_condition": (
            "rho must be unpredictable until commitments and every claimed value are bound"
        ),
    }
