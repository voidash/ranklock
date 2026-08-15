from __future__ import annotations

"""Constraint and retained-material envelope for the one-sided FS transcript.

The one-sided wrapper has a compact public proof (10 G1 elements and 20 field
scalars), but a static witness-encryption relation must also enforce the exact
Fiat--Shamir transcript.  This module answers the first concrete feasibility
question: can a circuit-friendly transcript and the remaining scalar verifier
fit inside the v0.15 fixed-relation byte envelope?

The Poseidon2 profile is a planning instantiation over a BN254-style scalar field:
width 3, rate 2, x^5 S-box, 8 full rounds and 56 partial rounds.  One x^5 S-box
is conservatively counted as three multiplication constraints.  Linear layers
are counted as free in the multiplication-coordinate model.

The result is a *cost envelope*, not a cryptographic construction.  In
particular, the point-encoding/canonicality cost and the conversion from
multiplication constraints to LVA-WE key elements must be instantiated by the
real outer-curve and gadget compiler.
"""

from dataclasses import dataclass
from hashlib import sha256
from math import ceil
from typing import Sequence

MIB = 1 << 20
RELATION_CAP_BYTES = MIB
PROJECTIVE_STATIC_BYTES = 112_746
PROJECTIVE_INPUT_RELATION_WIDTH = 264
REFERENCE_BYTES_PER_SCALAR_COORDINATE = 66
REFERENCE_FIXED_KEY_BYTES = 130
REFERENCE_MAX_TRACE_WIDTH = 13_912
ONE_SIDED_PROOF_BYTES = 1_280


class TranscriptMiniLockError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Poseidon2ConstraintProfile:
    state_width: int = 3
    rate: int = 2
    full_rounds: int = 8
    partial_rounds: int = 56
    sbox_degree: int = 5
    multiplications_per_sbox: int = 3
    schema: str = "ranklock-poseidon2-constraint-profile-v1"

    def __post_init__(self) -> None:
        if self.state_width <= 1 or self.rate <= 0 or self.rate >= self.state_width:
            raise TranscriptMiniLockError("invalid Poseidon2 width/rate")
        if self.full_rounds <= 0 or self.partial_rounds <= 0:
            raise TranscriptMiniLockError("invalid Poseidon2 round count")
        if self.sbox_degree != 5 or self.multiplications_per_sbox < 3:
            raise TranscriptMiniLockError("profile expects the x^5 S-box")

    @property
    def sboxes_per_permutation(self) -> int:
        return self.full_rounds * self.state_width + self.partial_rounds

    @property
    def multiplication_constraints_per_permutation(self) -> int:
        return self.sboxes_per_permutation * self.multiplications_per_sbox

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state_width": self.state_width,
            "rate": self.rate,
            "full_rounds": self.full_rounds,
            "partial_rounds": self.partial_rounds,
            "sbox": "x^5",
            "sboxes_per_permutation": self.sboxes_per_permutation,
            "multiplication_constraints_per_sbox": self.multiplications_per_sbox,
            "multiplication_constraints_per_permutation": (
                self.multiplication_constraints_per_permutation
            ),
            "cost_boundary": (
                "Linear layers are free in this multiplication-coordinate envelope; "
                "the final backend must account for them if they are not free."
            ),
        }


@dataclass(frozen=True, slots=True)
class TranscriptInventory:
    proof_g1_elements: int = 10
    hashed_g1_elements: int | None = None
    proof_scalar_elements: int = 20
    challenge_hash_calls: int = 8
    challenge_scalars: int = 10
    g1_encoding_field_elements: int = 3
    context_digest_field_elements: int = 1
    domain_separator_field_elements: int = 8
    schema: str = "ranklock-one-sided-transcript-inventory-v1"

    def __post_init__(self) -> None:
        for value in (
            self.proof_g1_elements,
            self.proof_scalar_elements,
            self.challenge_hash_calls,
            self.challenge_scalars,
            self.g1_encoding_field_elements,
            self.context_digest_field_elements,
            self.domain_separator_field_elements,
        ):
            if value < 0:
                raise TranscriptMiniLockError("negative transcript inventory count")
        if self.hashed_g1_elements is not None:
            if self.hashed_g1_elements < 0 or self.hashed_g1_elements > self.proof_g1_elements:
                raise TranscriptMiniLockError("invalid hashed G1 element count")

    @property
    def effective_hashed_g1_elements(self) -> int:
        return (
            self.proof_g1_elements
            if self.hashed_g1_elements is None
            else self.hashed_g1_elements
        )

    @property
    def absorbed_field_elements(self) -> int:
        return (
            self.effective_hashed_g1_elements * self.g1_encoding_field_elements
            + self.proof_scalar_elements
            + self.context_digest_field_elements
            + self.domain_separator_field_elements
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proof_G1_elements": self.proof_g1_elements,
            "hashed_G1_elements": self.effective_hashed_g1_elements,
            "proof_scalar_elements": self.proof_scalar_elements,
            "challenge_hash_calls": self.challenge_hash_calls,
            "challenge_scalars": self.challenge_scalars,
            "G1_encoding_field_elements": self.g1_encoding_field_elements,
            "context_digest_field_elements": self.context_digest_field_elements,
            "domain_separator_field_elements": self.domain_separator_field_elements,
            "absorbed_field_elements": self.absorbed_field_elements,
        }


@dataclass(frozen=True, slots=True)
class TranscriptConstraintScenario:
    point_binding_constraints_per_g1: int
    scalar_verifier_constraints: int = 1_024
    fixed_wrapper_constraints: int = 512
    profile: Poseidon2ConstraintProfile = Poseidon2ConstraintProfile()
    inventory: TranscriptInventory = TranscriptInventory()
    concrete_permutation_count: int | None = None
    schema: str = "ranklock-transcript-constraint-scenario-v1"

    def __post_init__(self) -> None:
        if self.point_binding_constraints_per_g1 < 0:
            raise TranscriptMiniLockError("negative point-binding cost")
        if self.scalar_verifier_constraints < 0 or self.fixed_wrapper_constraints < 0:
            raise TranscriptMiniLockError("negative wrapper cost")
        if self.concrete_permutation_count is not None and self.concrete_permutation_count < 0:
            raise TranscriptMiniLockError("negative concrete permutation count")

    @property
    def absorb_permutations(self) -> int:
        return ceil(self.inventory.absorbed_field_elements / self.profile.rate)

    @property
    def conservative_squeeze_permutations(self) -> int:
        # Count one fresh permutation per challenge-generating transcript call.
        # A concrete duplex schedule may reuse capacity and reduce this number.
        return self.inventory.challenge_hash_calls

    @property
    def total_permutations(self) -> int:
        if self.concrete_permutation_count is not None:
            return self.concrete_permutation_count
        return self.absorb_permutations + self.conservative_squeeze_permutations

    @property
    def hash_constraints(self) -> int:
        return (
            self.total_permutations
            * self.profile.multiplication_constraints_per_permutation
        )

    @property
    def point_binding_constraints(self) -> int:
        return (
            self.point_binding_constraints_per_g1
            * self.inventory.proof_g1_elements
        )

    @property
    def wrapper_trace_width(self) -> int:
        return (
            self.hash_constraints
            + self.point_binding_constraints
            + self.scalar_verifier_constraints
            + self.fixed_wrapper_constraints
        )

    @property
    def fits_reference_trace_width(self) -> bool:
        return self.wrapper_trace_width <= REFERENCE_MAX_TRACE_WIDTH

    @property
    def retained_bytes_without_runtime_proof(self) -> int:
        return (
            PROJECTIVE_STATIC_BYTES
            + REFERENCE_FIXED_KEY_BYTES
            + REFERENCE_BYTES_PER_SCALAR_COORDINATE
            * (PROJECTIVE_INPUT_RELATION_WIDTH + self.wrapper_trace_width)
        )

    @property
    def retained_plus_runtime_proof_bytes(self) -> int:
        return self.retained_bytes_without_runtime_proof + ONE_SIDED_PROOF_BYTES

    @property
    def fits_one_mib(self) -> bool:
        return self.retained_plus_runtime_proof_bytes <= RELATION_CAP_BYTES

    @property
    def maximum_point_binding_constraints_per_g1(self) -> int:
        available = (
            REFERENCE_MAX_TRACE_WIDTH
            - self.hash_constraints
            - self.scalar_verifier_constraints
            - self.fixed_wrapper_constraints
        )
        if self.inventory.proof_g1_elements == 0:
            return 0
        return max(0, available // self.inventory.proof_g1_elements)

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_class": "PARAMETERISED COST ENVELOPE; not a gadget construction",
            "point_binding_constraints_per_G1": self.point_binding_constraints_per_g1,
            "scalar_verifier_constraints": self.scalar_verifier_constraints,
            "fixed_wrapper_constraints": self.fixed_wrapper_constraints,
            "absorb_permutations": self.absorb_permutations,
            "conservative_squeeze_permutations": self.conservative_squeeze_permutations,
            "concrete_permutation_count": self.concrete_permutation_count,
            "total_permutations": self.total_permutations,
            "hash_constraints": self.hash_constraints,
            "point_binding_constraints": self.point_binding_constraints,
            "wrapper_trace_width": self.wrapper_trace_width,
            "reference_max_trace_width": REFERENCE_MAX_TRACE_WIDTH,
            "maximum_point_binding_constraints_per_G1": (
                self.maximum_point_binding_constraints_per_g1
            ),
            "fits_reference_trace_width": self.fits_reference_trace_width,
            "retained_bytes_without_runtime_proof": (
                self.retained_bytes_without_runtime_proof
            ),
            "runtime_one_sided_proof_bytes": ONE_SIDED_PROOF_BYTES,
            "retained_plus_runtime_proof_bytes": (
                self.retained_plus_runtime_proof_bytes
            ),
            "one_MiB_cap_bytes": RELATION_CAP_BYTES,
            "fits_one_MiB": self.fits_one_mib,
        }


def canonical_transcript_digest(
    context: bytes,
    proof_g1: Sequence[bytes],
    proof_scalars: Sequence[int],
) -> bytes:
    """Bind the exact planned proof inventory for regression tests.

    SHA-256 is used only as an executable canonical-encoding oracle.  It is not
    the proposed in-relation hash and does not alter the Poseidon2 cost model.
    """

    context = bytes(context)
    if not context:
        raise TranscriptMiniLockError("transcript context is empty")
    if len(proof_g1) != 10 or len(proof_scalars) != 20:
        raise TranscriptMiniLockError("one-sided proof inventory mismatch")
    transcript = bytearray(b"ranklock/one-sided/transcript-binding/v1\x00")
    transcript.extend(len(context).to_bytes(4, "big"))
    transcript.extend(context)
    for encoded in proof_g1:
        encoded = bytes(encoded)
        if len(encoded) != 64:
            raise TranscriptMiniLockError("planning G1 encoding must be 64 bytes")
        transcript.extend(encoded)
    for scalar in proof_scalars:
        value = int(scalar)
        if value < 0 or value >= 1 << 256:
            raise TranscriptMiniLockError("planning scalar is outside 256 bits")
        transcript.extend(value.to_bytes(32, "big"))
    return sha256(bytes(transcript)).digest()


def transcript_mini_lock_frontier() -> dict[str, object]:
    profile = Poseidon2ConstraintProfile()
    inventory = TranscriptInventory()
    scenarios = tuple(
        TranscriptConstraintScenario(value, profile=profile, inventory=inventory)
        for value in (200, 300, 400)
    )
    return {
        "schema": "ranklock-transcript-mini-lock-frontier-v1",
        "profile": profile.document(),
        "inventory": inventory.document(),
        "scenarios": [scenario.document() for scenario in scenarios],
        "best_surviving_reference_scenario": scenarios[1].document(),
        "decision": (
            "The reference byte envelope survives at 300 point-binding constraints per "
            "G1 element and fails at 400. The real outer-curve encoding gadget therefore "
            "has a hard planning threshold of 325 constraints per G1 element under the "
            "current scalar-verifier and fixed-overhead allowances."
        ),
        "open_gates": [
            "instantiate the actual outer curve and canonical compressed-point gadget",
            "compile every scalar verifier equation rather than reserve 1,024 constraints",
            "replace the 66-byte scalar-coordinate proxy with the real LVA-WE gadget key",
            "prove Fiat-Shamir domain separation and adaptive knowledge soundness",
        ],
        "breakthrough_target_met": False,
    }
