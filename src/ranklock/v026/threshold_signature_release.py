"""Research-only threshold release of exact ACK BIP340 signatures.

Every participant contributes a distinct release key and an independently scaled
positive-lock artifact for every counterproof alternative.  After the exact graph
is known, each ``(participant, alternative)`` lock hides only that alternative's
raw 64-byte BIP340 ACK signature.  Signature metadata is reconstructed from the
exact bound template.  Lock context commits to the setup, ordered roster, exact
counterproof/proof statement, ACK template, and ACK sighash.

This deliberately is not DKG, FROST, or threshold Schnorr.  It is variable-time
Python/BN254 research code.  Setup abort handling, independent randomness/custody,
erasure, qualified toxic-waste disposal, durable witness-selection adoption,
runtime delivery, and Bitcoin integration remain unverified; every assessment is
funding-ineligible.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256

from ..babe_positive_lock import (
    BabePositiveLockError,
    BabePositiveLockV2,
    PositiveGroth16Proof,
    PositiveGroth16VerifyingKey,
    setup_babe_positive_lock_v2,
    statement_digest,
    unlock_babe_positive_lock_v2,
)
from ..bip340 import BIP340Error, lift_x, public_key, sign, verify
from ..bn254_real import CURVE_ORDER, compress_g2, decompress_g2, multiply
from ..real_secp import N as SECP_ORDER
from ..split_scalar_lock import ScaleKnowledgeProof, SplitScalarLockError

_HASH_BYTES = 32
_PUBKEY_BYTES = 32
_SIGNATURE_BYTES = 64
_G2_BYTES = 64
_MAX_PARTICIPANTS = 64

_POLICY_DOMAIN = b"ranklock/v026/ack-threshold/policy/v2\x00"
_SIDE_INFORMATION_DOMAIN = b"ranklock/v026/ack-threshold/side-information/v1\x00"
_PROOF_STATEMENT_DOMAIN = b"ranklock/v026/ack-threshold/proof-statement/v3\x00"
_TEMPLATE_DOMAIN = b"ranklock/v026/ack-threshold/templates/v3\x00"
_SCALE_DOMAIN = b"ranklock/v026/ack-threshold/alternative-scale/v2\x00"
_ALT_CONTRIBUTION_DOMAIN = (
    b"ranklock/v026/ack-threshold/alternative-contribution/v2\x00"
)
_CONTRIBUTION_SIGN_DOMAIN = b"ranklock/v026/ack-threshold/contribution-sign/v2\x00"
_CONTRIBUTION_DOMAIN = b"ranklock/v026/ack-threshold/contribution/v2\x00"
_ROSTER_DOMAIN = b"ranklock/v026/ack-threshold/roster/v2\x00"
_LOCK_CONTEXT_DOMAIN = b"ranklock/v026/ack-threshold/lock-context/v2\x00"
_LOCK_ROW_SIGN_DOMAIN = b"ranklock/v026/ack-threshold/lock-row-sign/v2\x00"
_LOCK_ROW_DOMAIN = b"ranklock/v026/ack-threshold/lock-row/v2\x00"
_LOCK_SET_DOMAIN = b"ranklock/v026/ack-threshold/lock-set/v2\x00"
_CAPSULE_DOMAIN = b"ranklock/v026/ack-threshold/capsule/v2\x00"
_WITNESS_SELECTION_DOMAIN = b"ranklock/v026/ack-threshold/witness-selection/v2\x00"
_KNOWN_TOXIC_VK_POINTS_DOMAIN = b"ranklock/v026/known-toxic-vk-points/v1\x00"
_KNOWN_TOXIC_VK_POINTS_FINGERPRINT = bytes.fromhex(
    "34454a055efc1fe5c431b095b25686f640cc8251597d5d958c661535129ac56e"
)


class ThresholdSignatureReleaseError(ValueError):
    """Invalid data or an unavailable threshold release."""


class WitnessSelectionConflictError(ThresholdSignatureReleaseError):
    """A different witness capsule was already adopted for the same ACK subject."""


def _strict_int(value: int, name: str) -> int:
    if type(value) is not int:
        raise ThresholdSignatureReleaseError(f"{name} must be an integer")
    return value


def _u(value: int, width: int, name: str) -> bytes:
    value = _strict_int(value, name)
    if not 0 <= value < 1 << (8 * width):
        raise ThresholdSignatureReleaseError(f"{name} does not fit u{width * 8}")
    return value.to_bytes(width, "big")


def _fixed(value: bytes, width: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise ThresholdSignatureReleaseError(f"{name} must be immutable bytes")
    if len(value) != width:
        raise ThresholdSignatureReleaseError(f"{name} must be {width} bytes")
    return value


def _digest(value: bytes, name: str) -> bytes:
    value = _fixed(value, _HASH_BYTES, name)
    if value == bytes(_HASH_BYTES):
        raise ThresholdSignatureReleaseError(f"{name} must not be a zero placeholder")
    return value


def _pubkey(value: bytes, name: str) -> bytes:
    value = _fixed(value, _PUBKEY_BYTES, name)
    try:
        lift_x(int.from_bytes(value, "big"))
    except BIP340Error as exc:
        raise ThresholdSignatureReleaseError(
            f"{name} is not a valid x-only key"
        ) from exc
    return value


def _secret(value: int, name: str) -> int:
    value = _strict_int(value, name)
    if not 0 < value < SECP_ORDER:
        raise ThresholdSignatureReleaseError(
            f"{name} is not a canonical secp256k1 scalar"
        )
    return value


def _scale(value: int) -> int:
    value = _strict_int(value, "positive-lock scale")
    if not 0 < value < CURVE_ORDER:
        raise ThresholdSignatureReleaseError(
            "positive-lock scale is not canonical BN254 Fr"
        )
    return value


def _hash(domain: bytes, *parts: bytes) -> bytes:
    result = sha256(domain)
    for part in parts:
        part = bytes(part)
        result.update(len(part).to_bytes(8, "big"))
        result.update(part)
    return result.digest()


def _public_inputs_encoded(public_inputs: Sequence[int]) -> bytes:
    values = tuple(public_inputs)
    encoded = _u(len(values), 4, "public-input count")
    for index, value in enumerate(values):
        value = _strict_int(value, f"public input {index}")
        if not 0 <= value < CURVE_ORDER:
            raise ThresholdSignatureReleaseError(
                f"public input {index} is non-canonical"
            )
        encoded += value.to_bytes(32, "big")
    return encoded


def _ensure_not_known_toxic_vk(vk: PositiveGroth16VerifyingKey) -> None:
    points = vk.alpha_g1 + vk.beta_g2 + vk.gamma_g2 + vk.delta_g2 + b"".join(vk.ic_g1)
    fingerprint = sha256(_KNOWN_TOXIC_VK_POINTS_DOMAIN + points).digest()
    if fingerprint == _KNOWN_TOXIC_VK_POINTS_FINGERPRINT:
        raise ThresholdSignatureReleaseError(
            "known-toxic deterministic Groth16 fixture is forbidden"
        )


def _counterproof_digest_limbs(counterproof_template_digest: bytes) -> tuple[int, int]:
    digest = _digest(counterproof_template_digest, "counterproof-template digest")
    return (
        int.from_bytes(digest[:16], "big"),
        int.from_bytes(digest[16:], "big"),
    )


def _bound_public_inputs(
    public_inputs: Sequence[int], counterproof_template_digest: bytes
) -> tuple[int, ...]:
    """Append the exact digest as two injective 128-bit BN254 input limbs."""

    base_inputs = tuple(public_inputs)
    _public_inputs_encoded(base_inputs)
    return base_inputs + _counterproof_digest_limbs(counterproof_template_digest)


@dataclass(frozen=True, slots=True)
class ThresholdReleasePolicy:
    participant_count: int
    threshold: int
    max_corrupt: int
    schema: str = "ranklock-v026-threshold-release-policy-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-threshold-release-policy-v2":
            raise ThresholdSignatureReleaseError("unknown threshold policy schema")
        n = _strict_int(self.participant_count, "participant count")
        t = _strict_int(self.threshold, "threshold")
        f = _strict_int(self.max_corrupt, "maximum corruption count")
        if not 2 <= n <= _MAX_PARTICIPANTS:
            raise ThresholdSignatureReleaseError(
                f"participant count must be in 2..{_MAX_PARTICIPANTS}"
            )
        if not 0 <= f < t:
            raise ThresholdSignatureReleaseError("threshold policy requires f < t")
        if t > n - f:
            raise ThresholdSignatureReleaseError("threshold policy requires t <= n - f")

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.participant_count, 2, "participant count")
            + _u(self.threshold, 2, "threshold")
            + _u(self.max_corrupt, 2, "maximum corruption count")
        )

    @property
    def digest(self) -> bytes:
        return _hash(_POLICY_DOMAIN, self.encoded)


@dataclass(frozen=True, slots=True)
class BabePublicSideInformationProfileV2:
    """Exact fixed public artifacts covered by the BABE hiding assumption.

    The per-participant artifact, scale proof, release key, roster, ACK template,
    and lock bytes are bound separately by the contribution and lock contexts.  This
    profile covers the fixed proof-system and projectivizer material that was
    previously only described in prose.  Digests bind bytes; they do not qualify the
    ceremony, circuit, CRS, or implementation.
    """

    relation_circuit_digest: bytes
    complete_crs_digest: bytes
    proving_key_digest: bytes
    projectivizer_digest: bytes
    ceremony_transcript_digest: bytes
    schema: str = "ranklock-v026-babe-public-side-information-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-babe-public-side-information-v2":
            raise ThresholdSignatureReleaseError(
                "unknown BABE public-side-information schema"
            )
        values = tuple(
            _digest(getattr(self, attribute), label)
            for attribute, label in (
                ("relation_circuit_digest", "relation-circuit digest"),
                ("complete_crs_digest", "complete-CRS digest"),
                ("proving_key_digest", "proving-key digest"),
                ("projectivizer_digest", "projectivizer digest"),
                ("ceremony_transcript_digest", "ceremony-transcript digest"),
            )
        )
        if len(set(values)) != len(values):
            raise ThresholdSignatureReleaseError(
                "BABE public-side-information artifact digests must be distinct"
            )

    @property
    def encoded(self) -> bytes:
        return (
            self.relation_circuit_digest
            + self.complete_crs_digest
            + self.proving_key_digest
            + self.projectivizer_digest
            + self.ceremony_transcript_digest
        )

    @property
    def digest(self) -> bytes:
        return _hash(_SIDE_INFORMATION_DOMAIN, self.encoded)


def exact_proof_statement_digest(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Sequence[int],
    *,
    counterproof_template_digest: bytes,
    side_information_profile: BabePublicSideInformationProfileV2,
) -> bytes:
    """Digest the VK's exact base-input-plus-two-CP-limb statement layout.

    This establishes only that concrete public-input layout.  It does not prove
    that an independently supplied circuit assigns any further semantics to the
    base inputs or the two appended limbs.
    """

    _ensure_not_known_toxic_vk(vk)
    if not isinstance(side_information_profile, BabePublicSideInformationProfileV2):
        raise ThresholdSignatureReleaseError(
            "BABE public-side-information profile has the wrong type"
        )
    bound_inputs = _bound_public_inputs(public_inputs, counterproof_template_digest)
    if len(bound_inputs) + 1 != len(vk.ic_g1):
        raise ThresholdSignatureReleaseError(
            "Groth16 VK was not compiled for the exact "
            "base-input-plus-two-counterproof-limb layout"
        )
    return _hash(
        _PROOF_STATEMENT_DOMAIN,
        vk.digest,
        side_information_profile.digest,
        _public_inputs_encoded(bound_inputs),
    )


@dataclass(frozen=True, slots=True)
class ExactAckTemplate:
    alternative_index: int
    counterproof_template_digest: bytes
    proof_statement_digest: bytes
    ack_template_digest: bytes
    ack_sighash: bytes
    schema: str = "ranklock-v026-exact-ack-template-v2"

    def __post_init__(self) -> None:
        _u(self.alternative_index, 4, "alternative index")
        _digest(self.counterproof_template_digest, "counterproof-template digest")
        _digest(self.proof_statement_digest, "proof-statement digest")
        _digest(self.ack_template_digest, "ACK-template digest")
        _digest(self.ack_sighash, "ACK sighash")

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.alternative_index, 4, "alternative index")
            + self.counterproof_template_digest
            + self.proof_statement_digest
            + self.ack_template_digest
            + self.ack_sighash
        )


@dataclass(frozen=True, slots=True)
class ExactAckTemplateVector:
    setup_intent_digest: bytes
    graph_template_digest: bytes
    side_information_profile: BabePublicSideInformationProfileV2
    templates: tuple[ExactAckTemplate, ...]
    schema: str = "ranklock-v026-exact-ack-template-vector-v3"

    def __post_init__(self) -> None:
        _digest(self.setup_intent_digest, "setup-intent digest")
        _digest(self.graph_template_digest, "graph-template digest")
        if self.schema != "ranklock-v026-exact-ack-template-vector-v3":
            raise ThresholdSignatureReleaseError("unknown ACK template-vector schema")
        if not isinstance(
            self.side_information_profile,
            BabePublicSideInformationProfileV2,
        ):
            raise ThresholdSignatureReleaseError(
                "ACK templates have an invalid BABE public-side-information profile"
            )
        if type(self.templates) is not tuple or not self.templates:
            raise ThresholdSignatureReleaseError(
                "ACK template vector must be a nonempty tuple"
            )
        _u(len(self.templates), 4, "alternative count")
        if not all(isinstance(item, ExactAckTemplate) for item in self.templates):
            raise ThresholdSignatureReleaseError(
                "ACK template vector contains an invalid item"
            )
        if tuple(item.alternative_index for item in self.templates) != tuple(
            range(len(self.templates))
        ):
            raise ThresholdSignatureReleaseError(
                "ACK alternatives must be contiguous and ordered"
            )
        for attribute in (
            "counterproof_template_digest",
            "proof_statement_digest",
            "ack_template_digest",
            "ack_sighash",
        ):
            values = tuple(getattr(item, attribute) for item in self.templates)
            if len(set(values)) != len(values):
                raise ThresholdSignatureReleaseError(
                    f"{attribute} values must be distinct"
                )

    @property
    def encoded(self) -> bytes:
        return (
            self.setup_intent_digest
            + self.graph_template_digest
            + self.side_information_profile.digest
            + _u(len(self.templates), 4, "alternative count")
            + b"".join(item.encoded for item in self.templates)
        )

    @property
    def digest(self) -> bytes:
        return _hash(_TEMPLATE_DOMAIN, self.encoded)


def _scale_transcript(
    *,
    setup_intent_digest: bytes,
    participant_index: int,
    participant_identity_pubkey: bytes,
    release_pubkey: bytes,
    alternative_index: int,
    retained_artifact_digest: bytes,
    r_delta_g2: bytes,
) -> bytes:
    return _hash(
        _SCALE_DOMAIN,
        setup_intent_digest,
        _u(participant_index, 2, "participant index"),
        participant_identity_pubkey,
        release_pubkey,
        _u(alternative_index, 4, "alternative index"),
        retained_artifact_digest,
        r_delta_g2,
    )


@dataclass(frozen=True, slots=True)
class PreliminaryAlternativeContribution:
    alternative_index: int
    release_pubkey: bytes
    retained_artifact_digest: bytes
    r_delta_g2: bytes
    scale_proof: ScaleKnowledgeProof
    schema: str = "ranklock-v026-preliminary-alternative-contribution-v2"

    def __post_init__(self) -> None:
        _u(self.alternative_index, 4, "alternative index")
        _pubkey(self.release_pubkey, "alternative release key")
        _digest(self.retained_artifact_digest, "retained-artifact digest")
        _fixed(self.r_delta_g2, _G2_BYTES, "scaled delta G2")
        try:
            decompress_g2(self.r_delta_g2)
        except (ValueError, ZeroDivisionError, OverflowError) as exc:
            raise ThresholdSignatureReleaseError("scaled delta G2 is invalid") from exc
        if not isinstance(self.scale_proof, ScaleKnowledgeProof):
            raise ThresholdSignatureReleaseError("scale proof has the wrong type")

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.alternative_index, 4, "alternative index")
            + self.release_pubkey
            + self.retained_artifact_digest
            + self.r_delta_g2
            + self.scale_proof.encoded
        )

    @property
    def digest(self) -> bytes:
        return _hash(_ALT_CONTRIBUTION_DOMAIN, self.encoded)


@dataclass(frozen=True, slots=True)
class PreliminaryReleaseContribution:
    setup_intent_digest: bytes
    participant_index: int
    participant_identity_pubkey: bytes
    alternatives: tuple[PreliminaryAlternativeContribution, ...]
    participant_signature: bytes
    schema: str = "ranklock-v026-preliminary-release-contribution-v2"

    def __post_init__(self) -> None:
        _digest(self.setup_intent_digest, "setup-intent digest")
        _u(self.participant_index, 2, "participant index")
        _pubkey(self.participant_identity_pubkey, "participant identity key")
        if type(self.alternatives) is not tuple or not self.alternatives:
            raise ThresholdSignatureReleaseError(
                "alternative contributions must be nonempty"
            )
        if not all(
            isinstance(item, PreliminaryAlternativeContribution)
            for item in self.alternatives
        ):
            raise ThresholdSignatureReleaseError("invalid alternative contribution")
        if tuple(item.alternative_index for item in self.alternatives) != tuple(
            range(len(self.alternatives))
        ):
            raise ThresholdSignatureReleaseError(
                "alternative contributions must be contiguous and ordered"
            )
        release_keys = tuple(item.release_pubkey for item in self.alternatives)
        if len(set(release_keys)) != len(release_keys):
            raise ThresholdSignatureReleaseError(
                "participant alternative release keys must be distinct"
            )
        if self.participant_identity_pubkey in release_keys:
            raise ThresholdSignatureReleaseError(
                "identity and alternative release keys must be distinct"
            )
        artifacts = tuple(item.retained_artifact_digest for item in self.alternatives)
        scales = tuple(item.r_delta_g2 for item in self.alternatives)
        if len(set(artifacts)) != len(artifacts) or len(set(scales)) != len(scales):
            raise ThresholdSignatureReleaseError(
                "each alternative requires an independent artifact and scale anchor"
            )
        _fixed(self.participant_signature, _SIGNATURE_BYTES, "participant signature")

    @property
    def unsigned_encoded(self) -> bytes:
        return (
            self.setup_intent_digest
            + _u(self.participant_index, 2, "participant index")
            + self.participant_identity_pubkey
            + _u(len(self.alternatives), 4, "alternative count")
            + b"".join(item.encoded for item in self.alternatives)
        )

    @property
    def signature_message(self) -> bytes:
        return _hash(_CONTRIBUTION_SIGN_DOMAIN, self.unsigned_encoded)

    @property
    def encoded(self) -> bytes:
        return self.unsigned_encoded + self.participant_signature

    @property
    def digest(self) -> bytes:
        return _hash(_CONTRIBUTION_DOMAIN, self.encoded)

    def verify(self, vk: PositiveGroth16VerifyingKey) -> bool:
        if not verify(
            self.signature_message,
            self.participant_identity_pubkey,
            self.participant_signature,
        ):
            return False
        return all(
            item.scale_proof.verify(
                delta_g2=vk.delta_g2,
                r_delta_g2=item.r_delta_g2,
                transcript=_scale_transcript(
                    setup_intent_digest=self.setup_intent_digest,
                    participant_index=self.participant_index,
                    participant_identity_pubkey=self.participant_identity_pubkey,
                    release_pubkey=item.release_pubkey,
                    alternative_index=item.alternative_index,
                    retained_artifact_digest=item.retained_artifact_digest,
                    r_delta_g2=item.r_delta_g2,
                ),
            )
            for item in self.alternatives
        )

    @classmethod
    def create(
        cls,
        *,
        setup_intent_digest: bytes,
        participant_index: int,
        participant_identity_secret: int,
        release_secrets: Sequence[int],
        retained_artifact_digests: Sequence[bytes],
        scales: Sequence[int],
        vk: PositiveGroth16VerifyingKey,
        scale_proof_nonces: Sequence[int],
        signature_aux_rand: bytes,
    ) -> PreliminaryReleaseContribution:
        _ensure_not_known_toxic_vk(vk)
        setup_intent_digest = _digest(setup_intent_digest, "setup-intent digest")
        participant_index = _strict_int(participant_index, "participant index")
        _u(participant_index, 2, "participant index")
        identity_secret = _secret(
            participant_identity_secret, "participant identity secret"
        )
        _fixed(
            signature_aux_rand,
            _HASH_BYTES,
            "participant-signature auxiliary randomness",
        )
        artifacts = tuple(retained_artifact_digests)
        release_secret_values = tuple(release_secrets)
        scale_values = tuple(scales)
        proof_nonces = tuple(scale_proof_nonces)
        if (
            not artifacts
            or len(artifacts) != len(release_secret_values)
            or len(artifacts) != len(scale_values)
            or len(artifacts) != len(proof_nonces)
        ):
            raise ThresholdSignatureReleaseError(
                "release-secret, artifact, scale, and proof-nonce vectors must have one equal nonzero length"
            )
        identity_pubkey = public_key(identity_secret)
        alternatives: list[PreliminaryAlternativeContribution] = []
        try:
            delta = decompress_g2(vk.delta_g2)
            for alternative_index, (
                release_secret,
                artifact,
                scale_value,
                proof_nonce,
            ) in enumerate(
                zip(
                    release_secret_values,
                    artifacts,
                    scale_values,
                    proof_nonces,
                    strict=True,
                )
            ):
                release_secret = _secret(
                    release_secret,
                    f"release secret {alternative_index}",
                )
                release_pubkey = public_key(release_secret)
                artifact = _digest(
                    artifact, f"retained-artifact digest {alternative_index}"
                )
                scale_value = _scale(scale_value)
                r_delta = compress_g2(multiply(delta, scale_value, group="g2"))
                transcript = _scale_transcript(
                    setup_intent_digest=setup_intent_digest,
                    participant_index=participant_index,
                    participant_identity_pubkey=identity_pubkey,
                    release_pubkey=release_pubkey,
                    alternative_index=alternative_index,
                    retained_artifact_digest=artifact,
                    r_delta_g2=r_delta,
                )
                proof = ScaleKnowledgeProof.create(
                    scale=scale_value,
                    delta_g2=vk.delta_g2,
                    r_delta_g2=r_delta,
                    transcript=transcript,
                    nonce=_strict_int(
                        proof_nonce, f"scale-proof nonce {alternative_index}"
                    ),
                )
                alternatives.append(
                    PreliminaryAlternativeContribution(
                        alternative_index,
                        release_pubkey,
                        artifact,
                        r_delta,
                        proof,
                    )
                )
            unsigned = (
                setup_intent_digest
                + _u(participant_index, 2, "participant index")
                + identity_pubkey
                + _u(len(alternatives), 4, "alternative count")
                + b"".join(item.encoded for item in alternatives)
            )
            participant_signature = sign(
                _hash(_CONTRIBUTION_SIGN_DOMAIN, unsigned),
                identity_secret,
                signature_aux_rand,
            )
        except (BIP340Error, SplitScalarLockError, ValueError) as exc:
            raise ThresholdSignatureReleaseError(
                "failed to create preliminary contribution"
            ) from exc
        result = cls(
            setup_intent_digest,
            participant_index,
            identity_pubkey,
            tuple(alternatives),
            participant_signature,
        )
        if not result.verify(vk):  # pragma: no cover
            raise ThresholdSignatureReleaseError(
                "created preliminary contribution is invalid"
            )
        return result


@dataclass(frozen=True, slots=True)
class PreliminaryContributionRoster:
    policy: ThresholdReleasePolicy
    contributions: tuple[PreliminaryReleaseContribution, ...]
    schema: str = "ranklock-v026-preliminary-release-roster-v2"

    def __post_init__(self) -> None:
        if not isinstance(self.policy, ThresholdReleasePolicy):
            raise ThresholdSignatureReleaseError("threshold policy has the wrong type")
        if (
            type(self.contributions) is not tuple
            or len(self.contributions) != self.policy.participant_count
        ):
            raise ThresholdSignatureReleaseError(
                "contribution count does not match policy"
            )
        if not all(
            isinstance(item, PreliminaryReleaseContribution)
            for item in self.contributions
        ):
            raise ThresholdSignatureReleaseError(
                "roster contains an invalid contribution"
            )
        if tuple(item.participant_index for item in self.contributions) != tuple(
            range(self.policy.participant_count)
        ):
            raise ThresholdSignatureReleaseError(
                "contributions must be contiguous and ordered"
            )
        if len({item.setup_intent_digest for item in self.contributions}) != 1:
            raise ThresholdSignatureReleaseError(
                "contributions bind different setup intents"
            )
        alternative_counts = {len(item.alternatives) for item in self.contributions}
        if len(alternative_counts) != 1:
            raise ThresholdSignatureReleaseError(
                "contributions have different alternative counts"
            )
        identity_keys = tuple(
            item.participant_identity_pubkey for item in self.contributions
        )
        release_keys = tuple(
            alternative.release_pubkey
            for contribution in self.contributions
            for alternative in contribution.alternatives
        )
        if len(set(identity_keys)) != len(identity_keys):
            raise ThresholdSignatureReleaseError("identity keys must be distinct")
        if len(set(release_keys)) != len(release_keys):
            raise ThresholdSignatureReleaseError(
                "participant/alternative release keys must be globally distinct"
            )
        if set(identity_keys) & set(release_keys):
            raise ThresholdSignatureReleaseError(
                "identity and release key subjects must not alias"
            )
        artifacts = tuple(
            alternative.retained_artifact_digest
            for contribution in self.contributions
            for alternative in contribution.alternatives
        )
        scale_anchors = tuple(
            alternative.r_delta_g2
            for contribution in self.contributions
            for alternative in contribution.alternatives
        )
        if len(set(artifacts)) != len(artifacts) or len(set(scale_anchors)) != len(
            scale_anchors
        ):
            raise ThresholdSignatureReleaseError(
                "every participant/alternative needs a distinct artifact and scale anchor"
            )

    @property
    def setup_intent_digest(self) -> bytes:
        return self.contributions[0].setup_intent_digest

    @property
    def alternative_count(self) -> int:
        return len(self.contributions[0].alternatives)

    @property
    def encoded(self) -> bytes:
        return (
            self.policy.encoded
            + self.setup_intent_digest
            + _u(self.alternative_count, 4, "alternative count")
            + b"".join(item.encoded for item in self.contributions)
        )

    @property
    def digest(self) -> bytes:
        return _hash(_ROSTER_DOMAIN, self.encoded)

    def verify(self, vk: PositiveGroth16VerifyingKey) -> bool:
        return all(item.verify(vk) for item in self.contributions)


@dataclass(frozen=True, slots=True)
class ExactAckSignature:
    alternative_index: int
    counterproof_template_digest: bytes
    proof_statement_digest: bytes
    ack_template_digest: bytes
    ack_sighash: bytes
    signature: bytes
    schema: str = "ranklock-v026-exact-ack-signature-v2"

    def __post_init__(self) -> None:
        _u(self.alternative_index, 4, "alternative index")
        _digest(self.counterproof_template_digest, "counterproof-template digest")
        _digest(self.proof_statement_digest, "proof-statement digest")
        _digest(self.ack_template_digest, "ACK-template digest")
        _digest(self.ack_sighash, "ACK sighash")
        _fixed(self.signature, _SIGNATURE_BYTES, "ACK signature")

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.alternative_index, 4, "alternative index")
            + self.counterproof_template_digest
            + self.proof_statement_digest
            + self.ack_template_digest
            + self.ack_sighash
            + self.signature
        )

    @classmethod
    def create(
        cls,
        template: ExactAckTemplate,
        *,
        release_secret: int,
        auxiliary_randomness: bytes,
    ) -> ExactAckSignature:
        release_secret = _secret(release_secret, "release secret")
        _fixed(auxiliary_randomness, _HASH_BYTES, "ACK auxiliary randomness")
        try:
            signature = sign(template.ack_sighash, release_secret, auxiliary_randomness)
        except BIP340Error as exc:
            raise ThresholdSignatureReleaseError(
                "failed to sign exact ACK sighash"
            ) from exc
        return cls.from_locked_payload(template, signature)

    @classmethod
    def from_locked_payload(
        cls,
        template: ExactAckTemplate,
        raw_signature: bytes,
    ) -> ExactAckSignature:
        """Reconstruct exact metadata from the bound template and raw signature."""

        if not isinstance(template, ExactAckTemplate):
            raise ThresholdSignatureReleaseError("ACK template has the wrong type")
        signature = _fixed(raw_signature, _SIGNATURE_BYTES, "raw ACK signature")
        return cls(
            template.alternative_index,
            template.counterproof_template_digest,
            template.proof_statement_digest,
            template.ack_template_digest,
            template.ack_sighash,
            signature,
        )

    def verify_exact(self, template: ExactAckTemplate, release_pubkey: bytes) -> bool:
        return (
            self.alternative_index == template.alternative_index
            and self.counterproof_template_digest
            == template.counterproof_template_digest
            and self.proof_statement_digest == template.proof_statement_digest
            and self.ack_template_digest == template.ack_template_digest
            and self.ack_sighash == template.ack_sighash
            and verify(template.ack_sighash, release_pubkey, self.signature)
        )


@dataclass(frozen=True, slots=True)
class ExactAckSignatureVector:
    signatures: tuple[ExactAckSignature, ...]
    schema: str = "ranklock-v026-exact-ack-signature-vector-v2"

    def __post_init__(self) -> None:
        if type(self.signatures) is not tuple or not self.signatures:
            raise ThresholdSignatureReleaseError(
                "signature vector must be a nonempty tuple"
            )
        if tuple(item.alternative_index for item in self.signatures) != tuple(
            range(len(self.signatures))
        ):
            raise ThresholdSignatureReleaseError(
                "signature alternatives must be contiguous and ordered"
            )

    @classmethod
    def create(
        cls,
        templates: ExactAckTemplateVector,
        *,
        release_secrets: Sequence[int],
        auxiliary_randomness: Sequence[bytes],
    ) -> ExactAckSignatureVector:
        secrets = tuple(release_secrets)
        randomness = tuple(auxiliary_randomness)
        if len(secrets) != len(templates.templates) or len(randomness) != len(
            templates.templates
        ):
            raise ThresholdSignatureReleaseError(
                "ACK release-secret and randomness counts do not match alternatives"
            )
        return cls(
            tuple(
                ExactAckSignature.create(
                    template,
                    release_secret=secrets[index],
                    auxiliary_randomness=randomness[index],
                )
                for index, template in enumerate(templates.templates)
            )
        )


def _lock_context(
    roster: PreliminaryContributionRoster,
    templates: ExactAckTemplateVector,
    contribution: PreliminaryReleaseContribution,
    alternative: PreliminaryAlternativeContribution,
) -> bytes:
    return _hash(
        _LOCK_CONTEXT_DOMAIN,
        roster.setup_intent_digest,
        roster.digest,
        templates.digest,
        contribution.digest,
        alternative.digest,
        templates.templates[alternative.alternative_index].encoded,
    )


@dataclass(frozen=True, slots=True)
class LockedAlternativeAckSignature:
    alternative_index: int
    alternative_contribution_digest: bytes
    positive_lock: BabePositiveLockV2
    schema: str = "ranklock-v026-locked-alternative-ack-signature-v2"

    def __post_init__(self) -> None:
        _u(self.alternative_index, 4, "alternative index")
        _digest(self.alternative_contribution_digest, "alternative-contribution digest")
        if not isinstance(self.positive_lock, BabePositiveLockV2):
            raise ThresholdSignatureReleaseError("positive lock has the wrong type")

    @property
    def encoded(self) -> bytes:
        encoded_lock = self.positive_lock.encoded
        return (
            _u(self.alternative_index, 4, "alternative index")
            + self.alternative_contribution_digest
            + _u(len(encoded_lock), 4, "positive-lock length")
            + encoded_lock
        )


@dataclass(frozen=True, slots=True)
class LockedParticipantAckSignatures:
    participant_index: int
    contribution_digest: bytes
    template_vector_digest: bytes
    alternative_locks: tuple[LockedAlternativeAckSignature, ...]
    participant_signature: bytes
    schema: str = "ranklock-v026-locked-participant-ack-signatures-v2"

    def __post_init__(self) -> None:
        _u(self.participant_index, 2, "participant index")
        _digest(self.contribution_digest, "contribution digest")
        _digest(self.template_vector_digest, "template-vector digest")
        if type(self.alternative_locks) is not tuple or not self.alternative_locks:
            raise ThresholdSignatureReleaseError("alternative locks must be nonempty")
        if tuple(item.alternative_index for item in self.alternative_locks) != tuple(
            range(len(self.alternative_locks))
        ):
            raise ThresholdSignatureReleaseError(
                "alternative locks must be contiguous and ordered"
            )
        _fixed(self.participant_signature, _SIGNATURE_BYTES, "participant signature")

    @property
    def unsigned_encoded(self) -> bytes:
        return (
            _u(self.participant_index, 2, "participant index")
            + self.contribution_digest
            + self.template_vector_digest
            + _u(len(self.alternative_locks), 4, "alternative-lock count")
            + b"".join(item.encoded for item in self.alternative_locks)
        )

    @property
    def signature_message(self) -> bytes:
        return _hash(_LOCK_ROW_SIGN_DOMAIN, self.unsigned_encoded)

    @property
    def encoded(self) -> bytes:
        return self.unsigned_encoded + self.participant_signature

    @property
    def digest(self) -> bytes:
        return _hash(_LOCK_ROW_DOMAIN, self.encoded)

    @classmethod
    def create(
        cls,
        *,
        roster: PreliminaryContributionRoster,
        templates: ExactAckTemplateVector,
        participant_index: int,
        participant_identity_secret: int,
        release_secrets: Sequence[int],
        scales: Sequence[int],
        vk: PositiveGroth16VerifyingKey,
        public_inputs_by_alternative: Sequence[Sequence[int]],
        auxiliary_randomness: Sequence[bytes],
        row_signature_aux_rand: bytes,
    ) -> LockedParticipantAckSignatures:
        participant_index = _strict_int(participant_index, "participant index")
        if not 0 <= participant_index < len(roster.contributions):
            raise ThresholdSignatureReleaseError("participant is outside the roster")
        contribution = roster.contributions[participant_index]
        identity_secret = _secret(
            participant_identity_secret, "participant identity secret"
        )
        if public_key(identity_secret) != contribution.participant_identity_pubkey:
            raise ThresholdSignatureReleaseError(
                "identity secret does not match contribution"
            )
        release_secret_values = tuple(release_secrets)
        scale_values = tuple(scales)
        input_vectors = tuple(tuple(values) for values in public_inputs_by_alternative)
        randomness = tuple(auxiliary_randomness)
        count = len(templates.templates)
        if (
            count != len(contribution.alternatives)
            or len(release_secret_values) != count
            or len(scale_values) != count
            or len(input_vectors) != count
            or len(randomness) != count
        ):
            raise ThresholdSignatureReleaseError(
                "lock inputs do not match alternative count"
            )
        _fixed(
            row_signature_aux_rand, _HASH_BYTES, "row-signature auxiliary randomness"
        )
        signature_vector = ExactAckSignatureVector.create(
            templates,
            release_secrets=release_secret_values,
            auxiliary_randomness=randomness,
        )
        locks: list[LockedAlternativeAckSignature] = []
        for index, (
            alternative,
            release_secret,
            scale_value,
            public_inputs,
            exact_signature,
        ) in enumerate(
            zip(
                contribution.alternatives,
                release_secret_values,
                scale_values,
                input_vectors,
                signature_vector.signatures,
                strict=True,
            )
        ):
            release_secret = _secret(
                release_secret,
                f"release secret {index}",
            )
            if public_key(release_secret) != alternative.release_pubkey:
                raise ThresholdSignatureReleaseError(
                    f"release secret {index} does not match its alternative contribution"
                )
            scale_value = _scale(scale_value)
            expected_proof_digest = exact_proof_statement_digest(
                vk,
                public_inputs,
                counterproof_template_digest=templates.templates[
                    index
                ].counterproof_template_digest,
                side_information_profile=templates.side_information_profile,
            )
            if (
                expected_proof_digest
                != templates.templates[index].proof_statement_digest
            ):
                raise ThresholdSignatureReleaseError(
                    "template binds another proof statement"
                )
            try:
                lock = setup_babe_positive_lock_v2(
                    vk,
                    _bound_public_inputs(
                        public_inputs,
                        templates.templates[index].counterproof_template_digest,
                    ),
                    exact_signature.signature,
                    scale=scale_value,
                    session_context=_lock_context(
                        roster, templates, contribution, alternative
                    ),
                )
            except BabePositiveLockError as exc:
                raise ThresholdSignatureReleaseError(
                    "failed to lock exact ACK signature"
                ) from exc
            if lock.r_delta_g2 != alternative.r_delta_g2:
                raise ThresholdSignatureReleaseError(
                    "lock scale does not match preliminary anchor"
                )
            locks.append(LockedAlternativeAckSignature(index, alternative.digest, lock))
        unsigned = (
            _u(participant_index, 2, "participant index")
            + contribution.digest
            + templates.digest
            + _u(len(locks), 4, "alternative-lock count")
            + b"".join(item.encoded for item in locks)
        )
        try:
            participant_signature = sign(
                _hash(_LOCK_ROW_SIGN_DOMAIN, unsigned),
                identity_secret,
                row_signature_aux_rand,
            )
        except BIP340Error as exc:
            raise ThresholdSignatureReleaseError("failed to sign locked row") from exc
        return cls(
            participant_index,
            contribution.digest,
            templates.digest,
            tuple(locks),
            participant_signature,
        )


@dataclass(frozen=True, slots=True)
class ParticipantAckSignatureRelease:
    participant_index: int
    alternative_index: int
    locked_set_digest: bytes
    exact_signature: ExactAckSignature
    schema: str = "ranklock-v026-participant-ack-signature-release-v2"

    def __post_init__(self) -> None:
        _u(self.participant_index, 2, "participant index")
        _u(self.alternative_index, 4, "alternative index")
        _digest(self.locked_set_digest, "locked-set digest")
        if not isinstance(self.exact_signature, ExactAckSignature):
            raise ThresholdSignatureReleaseError("exact signature has the wrong type")


@dataclass(frozen=True, slots=True)
class IndexedAckSignature:
    participant_index: int
    release_pubkey: bytes
    exact_signature: ExactAckSignature
    schema: str = "ranklock-v026-indexed-ack-signature-v2"

    def __post_init__(self) -> None:
        _u(self.participant_index, 2, "participant index")
        _pubkey(self.release_pubkey, "release key")
        if not isinstance(self.exact_signature, ExactAckSignature):
            raise ThresholdSignatureReleaseError("exact signature has the wrong type")
        if not verify(
            self.exact_signature.ack_sighash,
            self.release_pubkey,
            self.exact_signature.signature,
        ):
            raise ThresholdSignatureReleaseError("indexed ACK signature is invalid")

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.participant_index, 2, "participant index")
            + self.release_pubkey
            + self.exact_signature.encoded
        )


@dataclass(frozen=True, slots=True)
class ThresholdRecoveryCapsule:
    locked_set_digest: bytes
    roster_digest: bytes
    template_vector_digest: bytes
    alternative_index: int
    selected_participant_indices: tuple[int, ...]
    signatures: tuple[IndexedAckSignature, ...]
    schema: str = "ranklock-v026-threshold-recovery-capsule-v2"

    def __post_init__(self) -> None:
        _digest(self.locked_set_digest, "locked-set digest")
        _digest(self.roster_digest, "roster digest")
        _digest(self.template_vector_digest, "template-vector digest")
        _u(self.alternative_index, 4, "alternative index")
        if (
            type(self.selected_participant_indices) is not tuple
            or not self.selected_participant_indices
        ):
            raise ThresholdSignatureReleaseError(
                "selected participant subset must be nonempty"
            )
        if self.selected_participant_indices != tuple(
            sorted(self.selected_participant_indices)
        ):
            raise ThresholdSignatureReleaseError(
                "selected participant subset is not ordered"
            )
        if len(set(self.selected_participant_indices)) != len(
            self.selected_participant_indices
        ):
            raise ThresholdSignatureReleaseError(
                "selected participant subset is duplicated"
            )
        if type(self.signatures) is not tuple:
            raise ThresholdSignatureReleaseError("indexed signatures must be a tuple")
        if (
            tuple(item.participant_index for item in self.signatures)
            != self.selected_participant_indices
        ):
            raise ThresholdSignatureReleaseError(
                "signature order differs from selected participants"
            )
        if any(
            item.exact_signature.alternative_index != self.alternative_index
            for item in self.signatures
        ):
            raise ThresholdSignatureReleaseError("capsule mixes ACK alternatives")

    @property
    def encoded(self) -> bytes:
        return (
            self.locked_set_digest
            + self.roster_digest
            + self.template_vector_digest
            + _u(self.alternative_index, 4, "alternative index")
            + _u(len(self.selected_participant_indices), 2, "selected count")
            + b"".join(
                _u(index, 2, "participant index")
                for index in self.selected_participant_indices
            )
            + b"".join(item.encoded for item in self.signatures)
        )

    @property
    def digest(self) -> bytes:
        return _hash(_CAPSULE_DOMAIN, self.encoded)


@dataclass(frozen=True, slots=True)
class LockedAckSignatureSet:
    roster: PreliminaryContributionRoster
    templates: ExactAckTemplateVector
    rows: tuple[LockedParticipantAckSignatures, ...]
    schema: str = "ranklock-v026-locked-ack-signature-set-v2"

    def __post_init__(self) -> None:
        if self.templates.setup_intent_digest != self.roster.setup_intent_digest:
            raise ThresholdSignatureReleaseError("templates bind another setup intent")
        if len(self.templates.templates) != self.roster.alternative_count:
            raise ThresholdSignatureReleaseError(
                "template count differs from preliminary alternatives"
            )
        if (
            type(self.rows) is not tuple
            or len(self.rows) != self.roster.policy.participant_count
        ):
            raise ThresholdSignatureReleaseError(
                "locked-row count does not match policy"
            )
        if tuple(item.participant_index for item in self.rows) != tuple(
            range(self.roster.policy.participant_count)
        ):
            raise ThresholdSignatureReleaseError(
                "locked rows must be contiguous and ordered"
            )
        if len({item.digest for item in self.rows}) != len(self.rows):
            raise ThresholdSignatureReleaseError("locked rows must be distinct")

    @property
    def encoded(self) -> bytes:
        return (
            self.roster.digest
            + self.templates.digest
            + _u(len(self.rows), 2, "locked-row count")
            + b"".join(item.encoded for item in self.rows)
        )

    @property
    def digest(self) -> bytes:
        return _hash(_LOCK_SET_DOMAIN, self.encoded)

    def validate(
        self,
        vk: PositiveGroth16VerifyingKey,
        public_inputs_by_alternative: Sequence[Sequence[int]],
    ) -> None:
        _ensure_not_known_toxic_vk(vk)
        input_vectors = tuple(tuple(values) for values in public_inputs_by_alternative)
        if len(input_vectors) != len(self.templates.templates):
            raise ThresholdSignatureReleaseError(
                "public-input vectors do not match alternatives"
            )
        if not self.roster.verify(vk):
            raise ThresholdSignatureReleaseError("preliminary roster is invalid")
        for index, (template, public_inputs) in enumerate(
            zip(self.templates.templates, input_vectors, strict=True)
        ):
            if template.proof_statement_digest != exact_proof_statement_digest(
                vk,
                public_inputs,
                counterproof_template_digest=template.counterproof_template_digest,
                side_information_profile=self.templates.side_information_profile,
            ):
                raise ThresholdSignatureReleaseError(
                    f"alternative {index} binds another proof statement"
                )
        for row, contribution in zip(self.rows, self.roster.contributions, strict=True):
            if row.contribution_digest != contribution.digest:
                raise ThresholdSignatureReleaseError(
                    "locked row binds another contribution"
                )
            if row.template_vector_digest != self.templates.digest:
                raise ThresholdSignatureReleaseError(
                    "locked row binds another template vector"
                )
            if len(row.alternative_locks) != len(contribution.alternatives):
                raise ThresholdSignatureReleaseError(
                    "locked row has wrong alternative count"
                )
            for lock, alternative, public_inputs in zip(
                row.alternative_locks,
                contribution.alternatives,
                input_vectors,
                strict=True,
            ):
                if lock.alternative_contribution_digest != alternative.digest:
                    raise ThresholdSignatureReleaseError(
                        "lock binds another alternative contribution"
                    )
                try:
                    template = self.templates.templates[alternative.alternative_index]
                    expected_statement = statement_digest(
                        vk,
                        _bound_public_inputs(
                            public_inputs,
                            template.counterproof_template_digest,
                        ),
                        session_context=_lock_context(
                            self.roster, self.templates, contribution, alternative
                        ),
                    )
                except BabePositiveLockError as exc:
                    raise ThresholdSignatureReleaseError(
                        "failed to validate lock statement"
                    ) from exc
                if lock.positive_lock.vk_digest != vk.digest:
                    raise ThresholdSignatureReleaseError(
                        "lock binds another verifying key"
                    )
                if lock.positive_lock.statement_digest != expected_statement:
                    raise ThresholdSignatureReleaseError(
                        "lock binds another statement context"
                    )
                if lock.positive_lock.r_delta_g2 != alternative.r_delta_g2:
                    raise ThresholdSignatureReleaseError(
                        "lock binds another scale anchor"
                    )
            if not verify(
                row.signature_message,
                contribution.participant_identity_pubkey,
                row.participant_signature,
            ):
                raise ThresholdSignatureReleaseError("locked-row signature is invalid")

    def unlock_participant(
        self,
        participant_index: int,
        alternative_index: int,
        *,
        vk: PositiveGroth16VerifyingKey,
        public_inputs_by_alternative: Sequence[Sequence[int]],
        proof: PositiveGroth16Proof,
        r_a_g1: bytes,
    ) -> ParticipantAckSignatureRelease:
        participant_index = _strict_int(participant_index, "participant index")
        alternative_index = _strict_int(alternative_index, "alternative index")
        if not 0 <= participant_index < len(self.rows):
            raise ThresholdSignatureReleaseError(
                "participant is outside the locked set"
            )
        if not 0 <= alternative_index < len(self.templates.templates):
            raise ThresholdSignatureReleaseError(
                "alternative is outside the locked set"
            )
        input_vectors = tuple(tuple(values) for values in public_inputs_by_alternative)
        self.validate(vk, input_vectors)
        row = self.rows[participant_index]
        contribution = self.roster.contributions[participant_index]
        alternative = contribution.alternatives[alternative_index]
        lock = row.alternative_locks[alternative_index].positive_lock
        template = self.templates.templates[alternative_index]
        try:
            payload = unlock_babe_positive_lock_v2(
                vk,
                _bound_public_inputs(
                    input_vectors[alternative_index],
                    template.counterproof_template_digest,
                ),
                proof,
                lock,
                r_a_g1,
                session_context=_lock_context(
                    self.roster, self.templates, contribution, alternative
                ),
            )
            exact_signature = ExactAckSignature.from_locked_payload(template, payload)
        except (BabePositiveLockError, ThresholdSignatureReleaseError) as exc:
            raise ThresholdSignatureReleaseError(
                "proof did not release this exact ACK signature"
            ) from exc
        if not exact_signature.verify_exact(template, alternative.release_pubkey):
            raise ThresholdSignatureReleaseError("released ACK signature is not exact")
        return ParticipantAckSignatureRelease(
            participant_index,
            alternative_index,
            self.digest,
            exact_signature,
        )


def recover_threshold_capsule(
    locked_set: LockedAckSignatureSet,
    alternative_index: int,
    releases: Sequence[ParticipantAckSignatureRelease],
) -> ThresholdRecoveryCapsule:
    """Select the lowest exactly-t indices within the supplied valid set.

    Local sorting is not global canonicality.  A durable first-writer-wins store
    must adopt the resulting witness-selection capsule before publication.  This
    model deliberately does not claim an ACK txid/wtxid or descendant identity.
    """

    alternative_index = _strict_int(alternative_index, "alternative index")
    if not 0 <= alternative_index < len(locked_set.templates.templates):
        raise ThresholdSignatureReleaseError("alternative is outside the locked set")
    supplied = tuple(releases)
    indices = tuple(item.participant_index for item in supplied)
    if len(set(indices)) != len(indices):
        raise ThresholdSignatureReleaseError("duplicate participant release")
    template = locked_set.templates.templates[alternative_index]
    verified: dict[int, ExactAckSignature] = {}
    for release in supplied:
        if release.alternative_index != alternative_index:
            raise ThresholdSignatureReleaseError(
                "release belongs to another ACK alternative"
            )
        if (
            not 0
            <= release.participant_index
            < locked_set.roster.policy.participant_count
        ):
            raise ThresholdSignatureReleaseError(
                "release participant is outside the roster"
            )
        if release.locked_set_digest != locked_set.digest:
            raise ThresholdSignatureReleaseError("release binds another locked set")
        contribution = locked_set.roster.contributions[release.participant_index]
        release_pubkey = contribution.alternatives[alternative_index].release_pubkey
        if not release.exact_signature.verify_exact(template, release_pubkey):
            raise ThresholdSignatureReleaseError(
                "release signature is non-exact or invalid"
            )
        verified[release.participant_index] = release.exact_signature
    threshold = locked_set.roster.policy.threshold
    if len(verified) < threshold:
        raise ThresholdSignatureReleaseError("fewer than threshold valid releases")
    selected = tuple(sorted(verified)[:threshold])
    signatures = tuple(
        IndexedAckSignature(
            participant_index,
            locked_set.roster.contributions[participant_index]
            .alternatives[alternative_index]
            .release_pubkey,
            verified[participant_index],
        )
        for participant_index in selected
    )
    return ThresholdRecoveryCapsule(
        locked_set.digest,
        locked_set.roster.digest,
        locked_set.templates.digest,
        alternative_index,
        selected,
        signatures,
    )


def _participant_bitmap(participant_count: int, selected: tuple[int, ...]) -> bytes:
    result = bytearray((participant_count + 7) // 8)
    for participant_index in selected:
        if not 0 <= participant_index < participant_count:
            raise ThresholdSignatureReleaseError(
                "selected participant is outside the roster"
            )
        byte_index, bit_index = divmod(participant_index, 8)
        result[byte_index] |= 1 << bit_index
    return bytes(result)


@dataclass(frozen=True, slots=True)
class AckWitnessSelection:
    """Exact locally selected witness capsule, without Bitcoin parent identity."""

    locked_set_digest: bytes
    alternative_index: int
    participant_bitmap: bytes
    capsule_digest: bytes
    selected_signatures_digest: bytes
    schema: str = "ranklock-v026-ack-witness-selection-v2"

    def __post_init__(self) -> None:
        _digest(self.locked_set_digest, "locked-set digest")
        _u(self.alternative_index, 4, "alternative index")
        if (
            not isinstance(self.participant_bitmap, bytes)
            or not self.participant_bitmap
        ):
            raise ThresholdSignatureReleaseError(
                "participant bitmap must be nonempty bytes"
            )
        _digest(self.capsule_digest, "capsule digest")
        _digest(self.selected_signatures_digest, "signature-set digest")

    @property
    def subject(self) -> tuple[bytes, int]:
        return self.locked_set_digest, self.alternative_index

    @property
    def encoded(self) -> bytes:
        return (
            self.locked_set_digest
            + _u(self.alternative_index, 4, "alternative index")
            + _u(len(self.participant_bitmap), 2, "bitmap length")
            + self.participant_bitmap
            + self.capsule_digest
            + self.selected_signatures_digest
        )

    @classmethod
    def create(
        cls,
        locked_set: LockedAckSignatureSet,
        capsule: ThresholdRecoveryCapsule,
    ) -> AckWitnessSelection:
        if capsule.locked_set_digest != locked_set.digest:
            raise ThresholdSignatureReleaseError("capsule binds another locked set")
        if capsule.roster_digest != locked_set.roster.digest:
            raise ThresholdSignatureReleaseError("capsule binds another roster")
        if capsule.template_vector_digest != locked_set.templates.digest:
            raise ThresholdSignatureReleaseError(
                "capsule binds another template vector"
            )
        if not 0 <= capsule.alternative_index < len(locked_set.templates.templates):
            raise ThresholdSignatureReleaseError(
                "capsule alternative is outside the locked set"
            )
        if (
            len(capsule.selected_participant_indices)
            != locked_set.roster.policy.threshold
        ):
            raise ThresholdSignatureReleaseError(
                "capsule does not have exactly threshold signers"
            )
        template = locked_set.templates.templates[capsule.alternative_index]
        if len(capsule.signatures) != locked_set.roster.policy.threshold:
            raise ThresholdSignatureReleaseError(
                "capsule signature count is not threshold"
            )
        for item in capsule.signatures:
            if (
                not 0
                <= item.participant_index
                < locked_set.roster.policy.participant_count
            ):
                raise ThresholdSignatureReleaseError(
                    "capsule signer is outside the roster"
                )
            release_pubkey = (
                locked_set.roster.contributions[item.participant_index]
                .alternatives[capsule.alternative_index]
                .release_pubkey
            )
            if (
                item.release_pubkey != release_pubkey
                or not item.exact_signature.verify_exact(
                    template,
                    release_pubkey,
                )
            ):
                raise ThresholdSignatureReleaseError(
                    "capsule contains an invalid signature"
                )
        return cls(
            locked_set.digest,
            capsule.alternative_index,
            _participant_bitmap(
                locked_set.roster.policy.participant_count,
                capsule.selected_participant_indices,
            ),
            capsule.digest,
            _hash(
                _WITNESS_SELECTION_DOMAIN,
                b"".join(item.encoded for item in capsule.signatures),
            ),
        )


class WitnessSelectionDisposition(Enum):
    ADOPTED = "adopted"
    EXACT_REPLAY = "exact-replay"


@dataclass(slots=True)
class FirstWriterWitnessSelectionModel:
    """In-memory specification of capsule selection, not durable Bitcoin CAS."""

    locked_set: LockedAckSignatureSet
    _adopted: dict[tuple[bytes, int], AckWitnessSelection] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    def adopt(
        self,
        capsule: ThresholdRecoveryCapsule,
    ) -> tuple[WitnessSelectionDisposition, AckWitnessSelection]:
        selection = AckWitnessSelection.create(self.locked_set, capsule)
        existing = self._adopted.get(selection.subject)
        if existing is None:
            self._adopted[selection.subject] = selection
            return WitnessSelectionDisposition.ADOPTED, selection
        if existing.encoded == selection.encoded:
            return WitnessSelectionDisposition.EXACT_REPLAY, existing
        raise WitnessSelectionConflictError(
            "a different witness capsule is already adopted"
        )

    def adopted(self, alternative_index: int) -> AckWitnessSelection | None:
        alternative_index = _strict_int(alternative_index, "alternative index")
        if not 0 <= alternative_index < len(self.locked_set.templates.templates):
            raise ThresholdSignatureReleaseError("alternative is outside the graph")
        return self._adopted.get((self.locked_set.digest, alternative_index))


@dataclass(frozen=True, slots=True)
class ThresholdSignatureReleaseResearchAssessment:
    policy: ThresholdReleasePolicy
    lock_granularity: str
    funding_eligible: bool
    unverified_blockers: tuple[str, ...]
    schema: str = "ranklock-v026-threshold-signature-release-assessment-v4"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-threshold-signature-release-assessment-v4":
            raise ThresholdSignatureReleaseError(
                "unknown threshold release assessment schema"
            )
        if (
            self.lock_granularity
            != "one-independent-positive-lock-per-participant-alternative"
        ):
            raise ThresholdSignatureReleaseError("unknown lock granularity")
        if self.funding_eligible:
            raise ThresholdSignatureReleaseError(
                "research assessment must remain funding-ineligible"
            )
        if type(self.unverified_blockers) is not tuple or not self.unverified_blockers:
            raise ThresholdSignatureReleaseError("assessment must enumerate blockers")


def assess_threshold_signature_release(
    policy: ThresholdReleasePolicy,
) -> ThresholdSignatureReleaseResearchAssessment:
    return ThresholdSignatureReleaseResearchAssessment(
        policy,
        "one-independent-positive-lock-per-participant-alternative",
        False,
        (
            "UNVERIFIED: setup abort handling and restart semantics are not implemented",
            "UNVERIFIED: per-alternative scale randomness, retained-artifact custody, and erasure are not attested",
            "UNVERIFIED: release signing-key plaintext and post-setup key erasure are not attested",
            "UNVERIFIED: distinct participant keys are not evidence of independent control domains or custody",
            "UNVERIFIED: evaluator-output availability and authenticated runtime delivery are absent",
            "UNVERIFIED: qualified CRS generation, toxic-waste disposal, and qualification evidence are absent",
            "UNVERIFIED: BABE Construction 1 has a GGM-plus-ROM extractable-WE proof, but its applicability to the exact v2 encoding, complete CRS, proving key, retained artifacts, and transcript has no independent equivalence review",
            "INCOMPATIBLE: deployed SP1 6.2.4 gnark Groth16 samples fresh prover randomness r and s and does not instantiate BABE's deterministic non-zero-knowledge R-prime relation",
            "INCOMPATIBLE: the deployed SP1 universal Groth16 VK accepts five public inputs while the current base-plus-two-counterproof-limb profile requires seven",
            "INCOMPATIBLE: deployed counterproof public values contain only the operator key and game index, not the selected commitment or exact ACK template digest",
            "UNVERIFIED: the Python locked set and capsule are not canonically projected into the Rust selected-commitment ACK subject, and runtime adoption is absent",
            "UNVERIFIED: Python secp256k1 and BN254 code is variable-time research code",
            "UNVERIFIED: BN254 concrete security and the local subgroup and pairing implementation are not approved against a production funds-at-risk target",
            "UNVERIFIED: f must be a cumulative pre-erasure corruption bound; a merely simultaneous mobile bound can accumulate t signatures",
            "UNVERIFIED: Python ACK templates are not derived from exact Rust serialization and sighash bytes, and Bitcoin execution is not bound to this locked set",
            "UNVERIFIED: no production theorem or ceremony qualifies funds",
        ),
    )
