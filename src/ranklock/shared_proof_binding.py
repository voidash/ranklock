from __future__ import annotations

"""Canonical shared-object binding between transcript hashing and pairings.

Composed conditional-verification gadgets are vulnerable to a split-brain bug if
one byte string is hashed into Fiat--Shamir while a different group element is
fed to the final pairing equation.  The correct interface parses one canonical
proof object once and gives both subrelations access to that same typed value.

This module uses real BN254 G1 encodings to reproduce the split-brain failure and
to enforce the repaired interface.  It does not estimate the final in-circuit
cost of canonical decompression or subgroup checks on the eventual outer curve.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .bn254_real import Point, compress_g1, decompress_g1


class SharedProofBindingError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CanonicalG1ProofElement:
    encoded: bytes
    schema: str = "ranklock-canonical-g1-proof-element-v1"

    def __post_init__(self) -> None:
        raw = bytes(self.encoded)
        point = decompress_g1(raw)
        if compress_g1(point) != raw:
            raise SharedProofBindingError("G1 proof element is not canonically encoded")
        object.__setattr__(self, "encoded", raw)

    @property
    def point(self) -> Point:
        return decompress_g1(self.encoded)

    @property
    def transcript_bytes(self) -> bytes:
        return self.encoded


@dataclass(frozen=True, slots=True)
class SharedOneSidedProof:
    group_elements: tuple[CanonicalG1ProofElement, ...]
    scalars: tuple[int, ...]
    context: bytes
    schema: str = "ranklock-shared-one-sided-proof-v1"

    def __post_init__(self) -> None:
        if len(self.group_elements) != 10 or len(self.scalars) != 20:
            raise SharedProofBindingError("one-sided proof inventory mismatch")
        if not self.context:
            raise SharedProofBindingError("proof context is empty")
        for scalar in self.scalars:
            if not 0 <= int(scalar) < 1 << 256:
                raise SharedProofBindingError("proof scalar is outside 256 bits")

    @property
    def transcript_digest(self) -> bytes:
        transcript = bytearray(b"ranklock/shared-proof/transcript/v1\x00")
        transcript.extend(len(self.context).to_bytes(4, "big"))
        transcript.extend(self.context)
        for element in self.group_elements:
            transcript.extend(element.transcript_bytes)
        for scalar in self.scalars:
            transcript.extend(int(scalar).to_bytes(32, "big"))
        return sha256(bytes(transcript)).digest()

    @property
    def pairing_points(self) -> tuple[Point, ...]:
        # These points are obtained from the exact objects hashed above.  There
        # is no second independently supplied pairing witness.
        return tuple(element.point for element in self.group_elements)


@dataclass(frozen=True, slots=True)
class SplitBrainProofView:
    transcript_group_encodings: tuple[bytes, ...]
    pairing_group_encodings: tuple[bytes, ...]
    scalars: tuple[int, ...]
    context: bytes
    schema: str = "ranklock-split-brain-proof-view-v1"

    @property
    def transcript_digest(self) -> bytes:
        transcript = bytearray(b"ranklock/shared-proof/transcript/v1\x00")
        transcript.extend(len(self.context).to_bytes(4, "big"))
        transcript.extend(self.context)
        for encoded in self.transcript_group_encodings:
            transcript.extend(bytes(encoded))
        for scalar in self.scalars:
            transcript.extend(int(scalar).to_bytes(32, "big"))
        return sha256(bytes(transcript)).digest()

    @property
    def pairing_points(self) -> tuple[Point, ...]:
        return tuple(decompress_g1(bytes(value)) for value in self.pairing_group_encodings)

    @property
    def split_brain_present(self) -> bool:
        return tuple(map(bytes, self.transcript_group_encodings)) != tuple(
            map(bytes, self.pairing_group_encodings)
        )


def build_shared_proof(
    group_encodings: Sequence[bytes],
    scalars: Sequence[int],
    *,
    context: bytes,
) -> SharedOneSidedProof:
    return SharedOneSidedProof(
        tuple(CanonicalG1ProofElement(bytes(value)) for value in group_encodings),
        tuple(int(value) for value in scalars),
        bytes(context),
    )


def shared_binding_frontier() -> dict[str, object]:
    return {
        "schema": "ranklock-shared-proof-binding-frontier-v1",
        "evidence_class": "REAL canonical BN254 parsing and executable split-brain regression",
        "required_interface": (
            "parse each proof element once; transcript and pairing gadgets consume the same typed object"
        ),
        "separate_hash_and_pairing_witnesses_allowed": False,
        "split_brain_attack_reproduced": True,
        "canonical_parse_can_remove_a_separate_equality_proof": True,
        "cost_not_yet_known": [
            "canonical outer-curve point decompression",
            "subgroup validation",
            "compressed sign-bit binding",
            "cost of exposing the same typed variable to the LVA hash and pairing gadgets",
        ],
        "effect_on_325_constraint_threshold": (
            "positive but unquantified; no lower point-binding scenario is claimed until the real compiler shares variables"
        ),
        "breakthrough_target_met": False,
    }
