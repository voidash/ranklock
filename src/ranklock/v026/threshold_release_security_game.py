"""Exact combinatorial security game for the v0.26 ACK release threshold.

This module proves only the threshold arithmetic that follows from
``f < t <= n - f``.  It deliberately treats positive-lock hiding/correctness,
pre-erasure corruption, artifact availability, authenticated delivery, and exact
Bitcoin witness binding as assumptions.  Those assumptions are not converted into
facts by successful Python execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256

from .threshold_signature_release import ThresholdReleasePolicy

_MAX_ALTERNATIVES = 64
_GAME_DOMAIN = b"ranklock/v026/threshold-release-static-game/v1\x00"
_EVIDENCE_DOMAIN = b"ranklock/v026/threshold-release-static-evidence/v1\x00"


class ThresholdReleaseSecurityGameError(ValueError):
    """The threshold-release security game or its evidence is malformed."""


def _strict_int(value: int, name: str) -> int:
    if type(value) is not int:
        raise ThresholdReleaseSecurityGameError(f"{name} must be an integer")
    return value


def _u(value: int, width: int, name: str) -> bytes:
    value = _strict_int(value, name)
    if not 0 <= value < 1 << (8 * width):
        raise ThresholdReleaseSecurityGameError(f"{name} does not fit u{width * 8}")
    return value.to_bytes(width, "big")


def _hash(domain: bytes, *parts: bytes) -> bytes:
    digest = sha256(domain)
    for part in parts:
        encoded = bytes(part)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.digest()


def _exact_schema(actual: str, expected: str) -> None:
    if actual != expected:
        raise ThresholdReleaseSecurityGameError(f"unknown schema {actual!r}")


class StaticReleaseWorldKind(Enum):
    """Canonical worlds in the fixed-coalition threshold game."""

    PRE_PROOF_CORRUPT_EXPOSURE = "pre-proof-corrupt-exposure"
    INVALID_PROOF_CORRUPT_EXPOSURE = "invalid-proof-corrupt-exposure"
    VALID_PROOF_MAXIMUM_WITHHOLDING = "valid-proof-maximum-withholding"


class StaticReleaseAssumption(Enum):
    """External assumptions required to interpret the arithmetic as security."""

    HONEST_POSITIVE_LOCK_HIDING = (
        "honest-positive-lock-hiding-over-complete-public-side-information"
    )
    HONEST_POSITIVE_LOCK_CORRECTNESS = "honest-positive-lock-valid-proof-correctness"
    DISTINCT_PARTICIPANT_CONTROL_DOMAINS = (
        "participant-identity-and-release-key-control-domain-independence"
    )
    CUMULATIVE_STATIC_CORRUPTION = "cumulative-static-pre-erasure-corruption-bound"
    HONEST_ARTIFACT_AVAILABILITY = "honest-retained-artifact-and-delivery-availability"
    EXACT_ACK_AUTHENTICATION = "exact-ack-template-key-and-witness-authentication"


_CANONICAL_ASSUMPTIONS = tuple(StaticReleaseAssumption)


@dataclass(frozen=True, slots=True)
class StaticReleaseWorldV1:
    """One cardinality-complete fixed-coalition game world."""

    alternative_index: int
    corrupt_count: int
    kind: StaticReleaseWorldKind
    corrupt_signatures_available: int
    honest_signatures_available: int
    threshold: int
    ack_quorum_available: bool
    schema: str = "ranklock-v026-static-release-world-v1"

    def __post_init__(self) -> None:
        _exact_schema(self.schema, "ranklock-v026-static-release-world-v1")
        for attribute, label in (
            (self.alternative_index, "alternative index"),
            (self.corrupt_count, "corrupt count"),
            (self.corrupt_signatures_available, "corrupt signature count"),
            (self.honest_signatures_available, "honest signature count"),
            (self.threshold, "threshold"),
        ):
            if _strict_int(attribute, label) < 0:
                raise ThresholdReleaseSecurityGameError(f"{label} must be nonnegative")
        if not isinstance(self.kind, StaticReleaseWorldKind):
            raise ThresholdReleaseSecurityGameError("world kind is invalid")
        if type(self.ack_quorum_available) is not bool:
            raise ThresholdReleaseSecurityGameError(
                "ACK quorum availability must be boolean"
            )
        if self.threshold == 0:
            raise ThresholdReleaseSecurityGameError("threshold must be positive")
        total = self.corrupt_signatures_available + self.honest_signatures_available
        if self.ack_quorum_available != (total >= self.threshold):
            raise ThresholdReleaseSecurityGameError(
                "ACK quorum flag disagrees with the available signature count"
            )

    @property
    def available_signature_count(self) -> int:
        return self.corrupt_signatures_available + self.honest_signatures_available

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.alternative_index, 4, "alternative index")
            + _u(self.corrupt_count, 2, "corrupt count")
            + _u(list(StaticReleaseWorldKind).index(self.kind), 1, "world kind")
            + _u(
                self.corrupt_signatures_available,
                2,
                "corrupt signature count",
            )
            + _u(
                self.honest_signatures_available,
                2,
                "honest signature count",
            )
            + _u(self.threshold, 2, "threshold")
            + bytes((int(self.ack_quorum_available),))
        )


@dataclass(frozen=True, slots=True)
class MobilePreErasureCorruptionWitnessV1:
    """Sequential pre-erasure corruption that defeats a simultaneous bound."""

    alternative_index: int
    participant_sequence: tuple[int, ...]
    maximum_simultaneous_corruptions: int
    accumulated_signature_count: int
    threshold: int
    schema: str = "ranklock-v026-mobile-pre-erasure-corruption-witness-v1"

    def __post_init__(self) -> None:
        _exact_schema(
            self.schema,
            "ranklock-v026-mobile-pre-erasure-corruption-witness-v1",
        )
        _u(self.alternative_index, 4, "alternative index")
        if type(self.participant_sequence) is not tuple:
            raise ThresholdReleaseSecurityGameError(
                "mobile corruption sequence must be an immutable tuple"
            )
        if not self.participant_sequence:
            raise ThresholdReleaseSecurityGameError(
                "mobile corruption sequence must be nonempty"
            )
        if any(
            type(index) is not int or index < 0 for index in self.participant_sequence
        ):
            raise ThresholdReleaseSecurityGameError(
                "mobile corruption sequence has an invalid participant"
            )
        if len(set(self.participant_sequence)) != len(self.participant_sequence):
            raise ThresholdReleaseSecurityGameError(
                "mobile corruption sequence must use distinct participants"
            )
        if (
            _strict_int(
                self.maximum_simultaneous_corruptions,
                "maximum simultaneous corruption count",
            )
            != 1
        ):
            raise ThresholdReleaseSecurityGameError(
                "canonical mobile witness corrupts exactly one participant at a time"
            )
        if _strict_int(
            self.accumulated_signature_count,
            "accumulated signature count",
        ) != len(self.participant_sequence):
            raise ThresholdReleaseSecurityGameError(
                "accumulated signature count disagrees with corruption sequence"
            )
        if _strict_int(self.threshold, "threshold") <= 0:
            raise ThresholdReleaseSecurityGameError("threshold must be positive")
        if self.accumulated_signature_count < self.threshold:
            raise ThresholdReleaseSecurityGameError(
                "mobile corruption witness does not reach the threshold"
            )

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.alternative_index, 4, "alternative index")
            + _u(len(self.participant_sequence), 2, "sequence length")
            + b"".join(
                _u(index, 2, "participant index") for index in self.participant_sequence
            )
            + _u(
                self.maximum_simultaneous_corruptions,
                2,
                "maximum simultaneous corruption count",
            )
            + _u(
                self.accumulated_signature_count,
                2,
                "accumulated signature count",
            )
            + _u(self.threshold, 2, "threshold")
        )


@dataclass(frozen=True, slots=True)
class ControlDomainCollapseWitnessV1:
    """One control domain owning ``t`` distinct keys defeats the roster count."""

    alternative_index: int
    aliased_participant_indices: tuple[int, ...]
    compromised_control_domain_count: int
    accumulated_signature_count: int
    threshold: int
    schema: str = "ranklock-v026-control-domain-collapse-witness-v1"

    def __post_init__(self) -> None:
        _exact_schema(
            self.schema,
            "ranklock-v026-control-domain-collapse-witness-v1",
        )
        _u(self.alternative_index, 4, "alternative index")
        if (
            type(self.aliased_participant_indices) is not tuple
            or not self.aliased_participant_indices
        ):
            raise ThresholdReleaseSecurityGameError(
                "aliased participant indices must be a nonempty immutable tuple"
            )
        if any(
            type(index) is not int or index < 0
            for index in self.aliased_participant_indices
        ):
            raise ThresholdReleaseSecurityGameError(
                "control-domain witness has an invalid participant"
            )
        if len(set(self.aliased_participant_indices)) != len(
            self.aliased_participant_indices
        ):
            raise ThresholdReleaseSecurityGameError(
                "control-domain witness must use distinct participant rows"
            )
        if (
            _strict_int(
                self.compromised_control_domain_count,
                "compromised control-domain count",
            )
            != 1
        ):
            raise ThresholdReleaseSecurityGameError(
                "canonical control-domain witness compromises exactly one domain"
            )
        if _strict_int(
            self.accumulated_signature_count,
            "accumulated signature count",
        ) != len(self.aliased_participant_indices):
            raise ThresholdReleaseSecurityGameError(
                "signature count disagrees with aliased participant rows"
            )
        if _strict_int(self.threshold, "threshold") <= 0:
            raise ThresholdReleaseSecurityGameError("threshold must be positive")
        if self.accumulated_signature_count < self.threshold:
            raise ThresholdReleaseSecurityGameError(
                "control-domain witness does not reach the threshold"
            )

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.alternative_index, 4, "alternative index")
            + _u(
                len(self.aliased_participant_indices),
                2,
                "aliased participant count",
            )
            + b"".join(
                _u(index, 2, "participant index")
                for index in self.aliased_participant_indices
            )
            + _u(
                self.compromised_control_domain_count,
                2,
                "compromised control-domain count",
            )
            + _u(
                self.accumulated_signature_count,
                2,
                "accumulated signature count",
            )
            + _u(self.threshold, 2, "threshold")
        )


@dataclass(frozen=True, slots=True)
class HonestArtifactLossWitnessV1:
    """Smallest extra honest-artifact outage that defeats valid-proof liveness."""

    alternative_index: int
    corrupt_count: int
    unavailable_honest_count: int
    available_signature_count: int
    threshold: int
    schema: str = "ranklock-v026-honest-artifact-loss-witness-v1"

    def __post_init__(self) -> None:
        _exact_schema(
            self.schema,
            "ranklock-v026-honest-artifact-loss-witness-v1",
        )
        _u(self.alternative_index, 4, "alternative index")
        for attribute, label in (
            (self.corrupt_count, "corrupt count"),
            (self.unavailable_honest_count, "unavailable honest count"),
            (self.available_signature_count, "available signature count"),
            (self.threshold, "threshold"),
        ):
            if _strict_int(attribute, label) < 0:
                raise ThresholdReleaseSecurityGameError(f"{label} must be nonnegative")
        if self.unavailable_honest_count == 0:
            raise ThresholdReleaseSecurityGameError(
                "artifact-loss witness must remove at least one honest artifact"
            )
        if self.threshold == 0:
            raise ThresholdReleaseSecurityGameError("threshold must be positive")
        if self.available_signature_count >= self.threshold:
            raise ThresholdReleaseSecurityGameError(
                "artifact-loss witness does not defeat the threshold"
            )

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.alternative_index, 4, "alternative index")
            + _u(self.corrupt_count, 2, "corrupt count")
            + _u(
                self.unavailable_honest_count,
                2,
                "unavailable honest count",
            )
            + _u(
                self.available_signature_count,
                2,
                "available signature count",
            )
            + _u(self.threshold, 2, "threshold")
        )


def _canonical_worlds(
    policy: ThresholdReleasePolicy,
    alternative_count: int,
) -> tuple[StaticReleaseWorldV1, ...]:
    worlds: list[StaticReleaseWorldV1] = []
    for alternative_index in range(alternative_count):
        for corrupt_count in range(policy.max_corrupt + 1):
            for kind in StaticReleaseWorldKind:
                if kind is StaticReleaseWorldKind.VALID_PROOF_MAXIMUM_WITHHOLDING:
                    corrupt_available = 0
                    honest_available = policy.participant_count - corrupt_count
                else:
                    corrupt_available = corrupt_count
                    honest_available = 0
                worlds.append(
                    StaticReleaseWorldV1(
                        alternative_index,
                        corrupt_count,
                        kind,
                        corrupt_available,
                        honest_available,
                        policy.threshold,
                        corrupt_available + honest_available >= policy.threshold,
                    )
                )
    return tuple(worlds)


def _canonical_mobile_witnesses(
    policy: ThresholdReleasePolicy,
    alternative_count: int,
) -> tuple[MobilePreErasureCorruptionWitnessV1, ...]:
    if policy.max_corrupt == 0:
        return ()
    sequence = tuple(range(policy.threshold))
    return tuple(
        MobilePreErasureCorruptionWitnessV1(
            alternative_index,
            sequence,
            1,
            policy.threshold,
            policy.threshold,
        )
        for alternative_index in range(alternative_count)
    )


def _canonical_artifact_loss_witnesses(
    policy: ThresholdReleasePolicy,
    alternative_count: int,
) -> tuple[HonestArtifactLossWitnessV1, ...]:
    slack = policy.participant_count - policy.max_corrupt - policy.threshold
    unavailable = slack + 1
    available = policy.participant_count - policy.max_corrupt - unavailable
    return tuple(
        HonestArtifactLossWitnessV1(
            alternative_index,
            policy.max_corrupt,
            unavailable,
            available,
            policy.threshold,
        )
        for alternative_index in range(alternative_count)
    )


def _canonical_control_domain_witnesses(
    policy: ThresholdReleasePolicy,
    alternative_count: int,
) -> tuple[ControlDomainCollapseWitnessV1, ...]:
    aliased_indices = tuple(range(policy.threshold))
    return tuple(
        ControlDomainCollapseWitnessV1(
            alternative_index,
            aliased_indices,
            1,
            policy.threshold,
            policy.threshold,
        )
        for alternative_index in range(alternative_count)
    )


@dataclass(frozen=True, slots=True)
class ConditionalStaticThresholdEvidenceV1:
    """Complete fixed-coalition arithmetic, with cryptographic claims withheld."""

    policy: ThresholdReleasePolicy
    alternative_count: int
    worlds: tuple[StaticReleaseWorldV1, ...]
    assumptions: tuple[StaticReleaseAssumption, ...]
    mobile_corruption_witnesses: tuple[MobilePreErasureCorruptionWitnessV1, ...]
    control_domain_witnesses: tuple[ControlDomainCollapseWitnessV1, ...]
    artifact_loss_witnesses: tuple[HonestArtifactLossWitnessV1, ...]
    schema: str = "ranklock-v026-conditional-static-threshold-evidence-v1"

    def __post_init__(self) -> None:
        _exact_schema(
            self.schema,
            "ranklock-v026-conditional-static-threshold-evidence-v1",
        )
        if not isinstance(self.policy, ThresholdReleasePolicy):
            raise ThresholdReleaseSecurityGameError("threshold policy is invalid")
        alternative_count = _strict_int(self.alternative_count, "alternative count")
        if not 1 <= alternative_count <= _MAX_ALTERNATIVES:
            raise ThresholdReleaseSecurityGameError(
                f"alternative count must be in 1..{_MAX_ALTERNATIVES}"
            )
        if type(self.worlds) is not tuple or self.worlds != _canonical_worlds(
            self.policy,
            alternative_count,
        ):
            raise ThresholdReleaseSecurityGameError(
                "static release worlds are incomplete or noncanonical"
            )
        if self.assumptions != _CANONICAL_ASSUMPTIONS:
            raise ThresholdReleaseSecurityGameError(
                "static release assumptions are incomplete or noncanonical"
            )
        if (
            type(self.mobile_corruption_witnesses) is not tuple
            or self.mobile_corruption_witnesses
            != _canonical_mobile_witnesses(self.policy, alternative_count)
        ):
            raise ThresholdReleaseSecurityGameError(
                "mobile-corruption witnesses are incomplete or noncanonical"
            )
        if (
            type(self.control_domain_witnesses) is not tuple
            or self.control_domain_witnesses
            != _canonical_control_domain_witnesses(self.policy, alternative_count)
        ):
            raise ThresholdReleaseSecurityGameError(
                "control-domain witnesses are incomplete or noncanonical"
            )
        if (
            type(self.artifact_loss_witnesses) is not tuple
            or self.artifact_loss_witnesses
            != _canonical_artifact_loss_witnesses(self.policy, alternative_count)
        ):
            raise ThresholdReleaseSecurityGameError(
                "artifact-loss witnesses are incomplete or noncanonical"
            )

    @property
    def availability_slack(self) -> int:
        return (
            self.policy.participant_count
            - self.policy.max_corrupt
            - self.policy.threshold
        )

    @property
    def conditional_static_exposure_safety_established(self) -> bool:
        return all(
            not world.ack_quorum_available
            for world in self.worlds
            if world.kind
            in (
                StaticReleaseWorldKind.PRE_PROOF_CORRUPT_EXPOSURE,
                StaticReleaseWorldKind.INVALID_PROOF_CORRUPT_EXPOSURE,
            )
        )

    @property
    def conditional_static_valid_proof_availability_established(self) -> bool:
        return all(
            world.ack_quorum_available
            for world in self.worlds
            if world.kind is StaticReleaseWorldKind.VALID_PROOF_MAXIMUM_WITHHOLDING
        )

    @property
    def mobile_pre_erasure_corruption_resistance_established(self) -> bool:
        return False

    @property
    def participant_control_domain_independence_established(self) -> bool:
        return False

    @property
    def positive_lock_hiding_established(self) -> bool:
        return False

    @property
    def production_release_theorem_established(self) -> bool:
        return False

    @property
    def funding_eligible(self) -> bool:
        return False

    @property
    def encoded(self) -> bytes:
        return (
            self.policy.digest
            + _u(self.alternative_count, 4, "alternative count")
            + _u(len(self.worlds), 4, "world count")
            + b"".join(world.encoded for world in self.worlds)
            + _u(len(self.assumptions), 2, "assumption count")
            + b"".join(
                _hash(_GAME_DOMAIN, assumption.value.encode("ascii"))
                for assumption in self.assumptions
            )
            + _u(
                len(self.mobile_corruption_witnesses),
                4,
                "mobile witness count",
            )
            + b"".join(witness.encoded for witness in self.mobile_corruption_witnesses)
            + _u(
                len(self.control_domain_witnesses),
                4,
                "control-domain witness count",
            )
            + b"".join(witness.encoded for witness in self.control_domain_witnesses)
            + _u(
                len(self.artifact_loss_witnesses),
                4,
                "artifact-loss witness count",
            )
            + b"".join(witness.encoded for witness in self.artifact_loss_witnesses)
        )

    @property
    def digest(self) -> bytes:
        return _hash(_EVIDENCE_DOMAIN, self.encoded)


def evaluate_conditional_static_threshold_release(
    policy: ThresholdReleasePolicy,
    *,
    alternative_count: int,
) -> ConditionalStaticThresholdEvidenceV1:
    """Evaluate every coalition cardinality in the fixed-coalition game.

    The result establishes the exact arithmetic for the supplied policy.  It does
    not establish any assumption in :class:`StaticReleaseAssumption` and therefore
    cannot authorize funding.
    """

    alternative_count = _strict_int(alternative_count, "alternative count")
    if not 1 <= alternative_count <= _MAX_ALTERNATIVES:
        raise ThresholdReleaseSecurityGameError(
            f"alternative count must be in 1..{_MAX_ALTERNATIVES}"
        )
    if not isinstance(policy, ThresholdReleasePolicy):
        raise ThresholdReleaseSecurityGameError("threshold policy is invalid")
    return ConditionalStaticThresholdEvidenceV1(
        policy,
        alternative_count,
        _canonical_worlds(policy, alternative_count),
        _CANONICAL_ASSUMPTIONS,
        _canonical_mobile_witnesses(policy, alternative_count),
        _canonical_control_domain_witnesses(policy, alternative_count),
        _canonical_artifact_loss_witnesses(policy, alternative_count),
    )
