from __future__ import annotations

"""Non-equivocating activation evidence for an external active-MPC ceremony.

This module does *not* implement malicious-secure MPC.  It defines the evidence
boundary an actual MPC backend must cross before its output can be activated:

* every registered participant commits to one private view and outbound-message
  transcript before an external beacon is fixed;
* the beacon is bound to the intended chain and a height after the commitment
  cutoff;
* all participants sign the same final transcript root and exact artifact;
* an independent verifier signs the certificate after replaying the backend's
  transcript checker;
* aborts, missing receipts, stale beacons and equivocation cannot activate.

Only digests of private MPC views appear here.  Secret shares and entropy are
never publicly revealed.  A signed certificate authenticates what was checked;
it does not substitute for a proven and audited MPC implementation.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from .bip340 import public_key, sign, verify
from .bitcoin_spv import (
    BitcoinCoreBlockObservation,
    BitcoinCoreSpvObservation,
    BitcoinCoreSpvReader,
    BitcoinSpvInclusionProof,
    verify_active_chain_block,
    verify_spv_inclusion_with_core,
)


class CeremonyEvidenceError(ValueError):
    pass


_DESCRIPTOR_DOMAIN = b"ranklock/mpc-session-descriptor/v1\x00"
_COMMITMENT_DOMAIN = b"ranklock/mpc-participant-commitment/v1\x00"
_COMMITMENT_SET_DOMAIN = b"ranklock/mpc-commitment-set/v1\x00"
_COMMITMENT_ANCHOR_DOMAIN = b"ranklock/mpc-commitment-publication-anchor/v1\x00"
_TRANSCRIPT_DOMAIN = b"ranklock/mpc-transcript-root/v1\x00"
_RECEIPT_DOMAIN = b"ranklock/mpc-participant-receipt/v1\x00"
_VERIFIER_DOMAIN = b"ranklock/mpc-independent-verifier/v1\x00"
_CORE_OBSERVATION_DOMAIN = b"ranklock/mpc-ceremony-core-observation/v1\x00"


def _digest(value: bytes, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != 32:
        raise CeremonyEvidenceError(f"{name} must be 32 bytes")
    if raw == bytes(32):
        raise CeremonyEvidenceError(f"{name} must be nonzero")
    return raw


def _lp(value: bytes, width: int = 2) -> bytes:
    raw = bytes(value)
    if len(raw) >= 1 << (8 * width):
        raise CeremonyEvidenceError("length-prefixed value is too long")
    return len(raw).to_bytes(width, "big") + raw


def _rpc_hash(value: object, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise CeremonyEvidenceError(f"Bitcoin Core returned malformed {name}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise CeremonyEvidenceError(
            f"Bitcoin Core returned non-hexadecimal {name}"
        ) from exc


@dataclass(frozen=True, slots=True)
class CeremonyParticipant:
    participant_id: bytes
    signing_pubkey: bytes

    def __post_init__(self) -> None:
        if not self.participant_id or len(bytes(self.participant_id)) > 64:
            raise CeremonyEvidenceError("participant id must contain 1..64 bytes")
        if len(bytes(self.signing_pubkey)) != 32:
            raise CeremonyEvidenceError("participant signing key must be 32 bytes")

    @property
    def canonical_bytes(self) -> bytes:
        return _lp(self.participant_id, 1) + bytes(self.signing_pubkey)


@dataclass(frozen=True, slots=True)
class MpcSessionDescriptor:
    session_id: bytes
    context_digest: bytes
    chain_genesis_hash: bytes
    source_archive_digest: bytes
    implementation_digest: bytes
    circuit_digest: bytes
    parameter_digest: bytes
    protocol_security_reference_digest: bytes
    commitment_cutoff_height: int
    participants: tuple[CeremonyParticipant, ...]
    corruption_threshold: int
    schema: str = "ranklock-mpc-session-descriptor-v1"

    def __post_init__(self) -> None:
        for name in (
            "session_id",
            "context_digest",
            "chain_genesis_hash",
            "source_archive_digest",
            "implementation_digest",
            "circuit_digest",
            "parameter_digest",
            "protocol_security_reference_digest",
        ):
            _digest(getattr(self, name), name.replace("_", " "))
        if not 0 <= int(self.commitment_cutoff_height) < 2**64:
            raise CeremonyEvidenceError("commitment cutoff height is invalid")
        if len(self.participants) < 2:
            raise CeremonyEvidenceError("ceremony requires at least two participants")
        ids = [bytes(participant.participant_id) for participant in self.participants]
        keys = [bytes(participant.signing_pubkey) for participant in self.participants]
        if len(ids) != len(set(ids)) or len(keys) != len(set(keys)):
            raise CeremonyEvidenceError("participant ids and keys must be unique")
        if tuple(sorted(ids)) != tuple(ids):
            raise CeremonyEvidenceError("participants must be ordered by participant id")
        if not 0 <= int(self.corruption_threshold) < len(self.participants):
            raise CeremonyEvidenceError("invalid corruption threshold")

    @property
    def canonical_bytes(self) -> bytes:
        return (
            bytes(self.session_id)
            + bytes(self.context_digest)
            + bytes(self.chain_genesis_hash)
            + bytes(self.source_archive_digest)
            + bytes(self.implementation_digest)
            + bytes(self.circuit_digest)
            + bytes(self.parameter_digest)
            + bytes(self.protocol_security_reference_digest)
            + int(self.commitment_cutoff_height).to_bytes(8, "big")
            + int(self.corruption_threshold).to_bytes(2, "big")
            + len(self.participants).to_bytes(2, "big")
            + b"".join(participant.canonical_bytes for participant in self.participants)
        )

    @property
    def digest(self) -> bytes:
        return sha256(_DESCRIPTOR_DOMAIN + self.canonical_bytes).digest()


@dataclass(frozen=True, slots=True)
class ParticipantCommitment:
    participant_id: bytes
    descriptor_digest: bytes
    private_view_commitment: bytes
    outbound_messages_root: bytes
    local_randomness_commitment: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not self.participant_id or len(bytes(self.participant_id)) > 64:
            raise CeremonyEvidenceError("commitment participant id is invalid")
        for name in (
            "descriptor_digest",
            "private_view_commitment",
            "outbound_messages_root",
            "local_randomness_commitment",
        ):
            _digest(getattr(self, name), name.replace("_", " "))
        if len(bytes(self.signature)) != 64:
            raise CeremonyEvidenceError("commitment signature must be 64 bytes")

    @property
    def unsigned_bytes(self) -> bytes:
        return (
            _lp(self.participant_id, 1)
            + bytes(self.descriptor_digest)
            + bytes(self.private_view_commitment)
            + bytes(self.outbound_messages_root)
            + bytes(self.local_randomness_commitment)
        )

    @property
    def signing_message(self) -> bytes:
        return sha256(_COMMITMENT_DOMAIN + self.unsigned_bytes).digest()

    @property
    def canonical_bytes(self) -> bytes:
        return self.unsigned_bytes + bytes(self.signature)

    @classmethod
    def issue(
        cls,
        *,
        participant_id: bytes,
        descriptor_digest: bytes,
        private_view_commitment: bytes,
        outbound_messages_root: bytes,
        local_randomness_commitment: bytes,
        participant_secret: int,
    ) -> "ParticipantCommitment":
        placeholder = cls(
            participant_id=bytes(participant_id),
            descriptor_digest=bytes(descriptor_digest),
            private_view_commitment=bytes(private_view_commitment),
            outbound_messages_root=bytes(outbound_messages_root),
            local_randomness_commitment=bytes(local_randomness_commitment),
            signature=bytes(64),
        )
        return cls(
            participant_id=placeholder.participant_id,
            descriptor_digest=placeholder.descriptor_digest,
            private_view_commitment=placeholder.private_view_commitment,
            outbound_messages_root=placeholder.outbound_messages_root,
            local_randomness_commitment=placeholder.local_randomness_commitment,
            signature=sign(placeholder.signing_message, participant_secret),
        )


def commitment_set_digest(
    *,
    descriptor: MpcSessionDescriptor,
    commitments: Iterable[ParticipantCommitment],
) -> bytes:
    rows = tuple(sorted(commitments, key=lambda item: bytes(item.participant_id)))
    if not rows:
        raise CeremonyEvidenceError("commitment set is empty")
    return sha256(
        _COMMITMENT_SET_DOMAIN
        + descriptor.digest
        + len(rows).to_bytes(2, "big")
        + b"".join(_lp(row.canonical_bytes, 2) for row in rows)
    ).digest()


@dataclass(frozen=True, slots=True)
class CommitmentPublicationAnchor:
    """Locally verifiable publication proof for the complete signed set.

    ``inclusion_proof`` verifies the canonical transaction, exact OP_RETURN
    commitment, Merkle inclusion and header proof of work.  Membership of the
    header in the canonical best chain is deliberately a separate Bitcoin-Core
    cross-check required by the deployment policy.
    """

    chain_genesis_hash: bytes
    block_height: int
    commitment_set_digest: bytes
    inclusion_proof: BitcoinSpvInclusionProof
    schema: str = "ranklock-mpc-commitment-publication-anchor-v2"

    def __post_init__(self) -> None:
        _digest(self.chain_genesis_hash, "commitment anchor chain genesis hash")
        _digest(self.commitment_set_digest, "commitment set digest")
        if not 0 <= int(self.block_height) < 2**64:
            raise CeremonyEvidenceError("commitment anchor height is invalid")
        if not isinstance(self.inclusion_proof, BitcoinSpvInclusionProof):
            raise CeremonyEvidenceError("commitment inclusion proof is invalid")

    @property
    def block_hash(self) -> bytes:
        return self.inclusion_proof.block_hash

    @property
    def publication_txid(self) -> bytes:
        return self.inclusion_proof.publication_txid

    @property
    def inclusion_evidence_digest(self) -> bytes:
        return self.inclusion_proof.digest

    @property
    def canonical_bytes(self) -> bytes:
        proof = self.inclusion_proof.canonical_bytes
        return (
            bytes(self.chain_genesis_hash)
            + int(self.block_height).to_bytes(8, "big")
            + bytes(self.commitment_set_digest)
            + len(proof).to_bytes(4, "big")
            + proof
        )

    @property
    def digest(self) -> bytes:
        return sha256(_COMMITMENT_ANCHOR_DOMAIN + self.canonical_bytes).digest()

    def verify(self) -> bool:
        return self.inclusion_proof.verify(
            commitment_digest=self.commitment_set_digest
        )

    def verify_with_core(
        self,
        reader: BitcoinCoreSpvReader,
        *,
        minimum_confirmations: int,
    ) -> BitcoinCoreSpvObservation:
        return verify_spv_inclusion_with_core(
            reader,
            proof=self.inclusion_proof,
            chain_genesis_hash=self.chain_genesis_hash,
            block_height=self.block_height,
            commitment_digest=self.commitment_set_digest,
            minimum_confirmations=minimum_confirmations,
        )


@dataclass(frozen=True, slots=True)
class ExternalBeacon:
    chain_genesis_hash: bytes
    block_height: int
    block_hash: bytes

    def __post_init__(self) -> None:
        _digest(self.chain_genesis_hash, "beacon chain genesis hash")
        _digest(self.block_hash, "beacon block hash")
        if not 0 <= int(self.block_height) < 2**64:
            raise CeremonyEvidenceError("beacon height is invalid")

    @property
    def canonical_bytes(self) -> bytes:
        return (
            bytes(self.chain_genesis_hash)
            + int(self.block_height).to_bytes(8, "big")
            + bytes(self.block_hash)
        )

    def verify_with_core(
        self,
        reader: BitcoinCoreSpvReader,
        *,
        minimum_confirmations: int,
    ) -> BitcoinCoreBlockObservation:
        return verify_active_chain_block(
            reader,
            chain_genesis_hash=self.chain_genesis_hash,
            block_height=self.block_height,
            expected_block_hash=self.block_hash,
            minimum_confirmations=minimum_confirmations,
        )


@dataclass(frozen=True, slots=True)
class CeremonyCoreObservation:
    """Auditable point-in-time binding of one ceremony to Core's active chain."""

    commitment_anchor: BitcoinCoreSpvObservation
    beacon: BitcoinCoreBlockObservation
    best_block_hash: bytes
    minimum_confirmations: int
    observed_at_unix: int
    schema: str = "ranklock-mpc-ceremony-core-observation-v1"

    def __post_init__(self) -> None:
        _digest(self.best_block_hash, "best block hash")
        if (
            self.commitment_anchor.chain_genesis_hash
            != self.beacon.chain_genesis_hash
        ):
            raise CeremonyEvidenceError(
                "ceremony Core observations use different chains"
            )
        if not 1 <= int(self.minimum_confirmations) < 2**31:
            raise CeremonyEvidenceError("minimum confirmation depth is invalid")
        if not 0 <= int(self.observed_at_unix) < 2**64:
            raise CeremonyEvidenceError("observation time is invalid")
        if (
            self.commitment_anchor.confirmations < self.minimum_confirmations
            or self.beacon.confirmations < self.minimum_confirmations
        ):
            raise CeremonyEvidenceError(
                "ceremony Core observation is below the required depth"
            )

    @property
    def canonical_bytes(self) -> bytes:
        return (
            self.commitment_anchor.canonical_bytes
            + self.beacon.canonical_bytes
            + bytes(self.best_block_hash)
            + int(self.minimum_confirmations).to_bytes(4, "big")
            + int(self.observed_at_unix).to_bytes(8, "big")
        )

    @property
    def digest(self) -> bytes:
        return sha256(
            _CORE_OBSERVATION_DOMAIN + self.canonical_bytes
        ).digest()


@dataclass(frozen=True, slots=True)
class ParticipantReceipt:
    participant_id: bytes
    descriptor_digest: bytes
    transcript_root: bytes
    artifact_digest: bytes
    artifact_bytes: int
    completed: bool
    signature: bytes

    def __post_init__(self) -> None:
        if not self.participant_id or len(bytes(self.participant_id)) > 64:
            raise CeremonyEvidenceError("receipt participant id is invalid")
        for name in ("descriptor_digest", "transcript_root", "artifact_digest"):
            _digest(getattr(self, name), name.replace("_", " "))
        if not 0 < int(self.artifact_bytes) < 2**64:
            raise CeremonyEvidenceError("receipt artifact length is invalid")
        if len(bytes(self.signature)) != 64:
            raise CeremonyEvidenceError("receipt signature must be 64 bytes")

    @property
    def signing_message(self) -> bytes:
        return sha256(
            _RECEIPT_DOMAIN
            + _lp(self.participant_id, 1)
            + bytes(self.descriptor_digest)
            + bytes(self.transcript_root)
            + bytes(self.artifact_digest)
            + int(self.artifact_bytes).to_bytes(8, "big")
            + bytes((1 if self.completed else 0,))
        ).digest()

    @classmethod
    def issue(
        cls,
        *,
        participant_id: bytes,
        descriptor_digest: bytes,
        transcript_root: bytes,
        artifact_digest: bytes,
        artifact_bytes: int,
        completed: bool,
        participant_secret: int,
    ) -> "ParticipantReceipt":
        placeholder = cls(
            participant_id=bytes(participant_id),
            descriptor_digest=bytes(descriptor_digest),
            transcript_root=bytes(transcript_root),
            artifact_digest=bytes(artifact_digest),
            artifact_bytes=int(artifact_bytes),
            completed=bool(completed),
            signature=bytes(64),
        )
        return cls(
            participant_id=placeholder.participant_id,
            descriptor_digest=placeholder.descriptor_digest,
            transcript_root=placeholder.transcript_root,
            artifact_digest=placeholder.artifact_digest,
            artifact_bytes=placeholder.artifact_bytes,
            completed=placeholder.completed,
            signature=sign(placeholder.signing_message, participant_secret),
        )


def compute_transcript_root(
    *,
    descriptor: MpcSessionDescriptor,
    commitments: Iterable[ParticipantCommitment],
    commitment_anchor: CommitmentPublicationAnchor,
    beacon: ExternalBeacon,
    backend_transcript_digest: bytes,
    artifact_digest: bytes,
    artifact_bytes: int,
) -> bytes:
    rows = sorted(commitments, key=lambda item: bytes(item.participant_id))
    commitment_bytes = b"".join(
        _lp(row.participant_id, 1)
        + row.private_view_commitment
        + row.outbound_messages_root
        + row.local_randomness_commitment
        for row in rows
    )
    return sha256(
        _TRANSCRIPT_DOMAIN
        + descriptor.digest
        + len(rows).to_bytes(2, "big")
        + commitment_bytes
        + commitment_anchor.canonical_bytes
        + beacon.canonical_bytes
        + _digest(backend_transcript_digest, "backend transcript digest")
        + _digest(artifact_digest, "artifact digest")
        + int(artifact_bytes).to_bytes(8, "big")
    ).digest()


@dataclass(frozen=True, slots=True)
class CeremonyCertificate:
    descriptor: MpcSessionDescriptor
    commitments: tuple[ParticipantCommitment, ...]
    commitment_anchor: CommitmentPublicationAnchor
    beacon: ExternalBeacon
    backend_transcript_digest: bytes
    artifact_digest: bytes
    artifact_bytes: int
    transcript_root: bytes
    receipts: tuple[ParticipantReceipt, ...]
    independent_verifier_pubkey: bytes
    independent_verifier_signature: bytes
    schema: str = "ranklock-mpc-ceremony-certificate-v2"

    def __post_init__(self) -> None:
        for name in ("backend_transcript_digest", "artifact_digest", "transcript_root"):
            _digest(getattr(self, name), name.replace("_", " "))
        if not 0 < int(self.artifact_bytes) < 2**64:
            raise CeremonyEvidenceError("certificate artifact length is invalid")
        if len(bytes(self.independent_verifier_pubkey)) != 32:
            raise CeremonyEvidenceError("independent verifier key must be 32 bytes")
        if len(bytes(self.independent_verifier_signature)) != 64:
            raise CeremonyEvidenceError("independent verifier signature must be 64 bytes")

    @property
    def verifier_message(self) -> bytes:
        return sha256(
            _VERIFIER_DOMAIN
            + self.descriptor.digest
            + self.commitment_anchor.canonical_bytes
            + self.beacon.canonical_bytes
            + bytes(self.backend_transcript_digest)
            + bytes(self.transcript_root)
            + bytes(self.artifact_digest)
            + int(self.artifact_bytes).to_bytes(8, "big")
            + bytes(self.independent_verifier_pubkey)
        ).digest()

    def verify(self, *, approved_independent_verifiers: Iterable[bytes]) -> bool:
        participants = {bytes(item.participant_id): item for item in self.descriptor.participants}
        if (
            self.commitment_anchor.chain_genesis_hash
            != self.descriptor.chain_genesis_hash
            or self.commitment_anchor.block_height
            > self.descriptor.commitment_cutoff_height
            or not self.commitment_anchor.verify()
        ):
            return False
        if self.beacon.chain_genesis_hash != self.descriptor.chain_genesis_hash:
            return False
        if self.beacon.block_height <= self.descriptor.commitment_cutoff_height:
            return False
        if len(self.commitments) != len(participants) or len(self.receipts) != len(participants):
            return False

        commitments: dict[bytes, ParticipantCommitment] = {}
        for row in self.commitments:
            pid = bytes(row.participant_id)
            participant = participants.get(pid)
            if participant is None or pid in commitments:
                return False
            if row.descriptor_digest != self.descriptor.digest:
                return False
            if not verify(row.signing_message, participant.signing_pubkey, row.signature):
                return False
            commitments[pid] = row
        # Reusing any private-view/randomness commitment across participants is
        # an unambiguous setup fault.  Outbound roots may coincide only with an
        # empty/protocol-defined transcript, so they are not globally unique.
        if len({row.private_view_commitment for row in commitments.values()}) != len(participants):
            return False
        if len({row.local_randomness_commitment for row in commitments.values()}) != len(participants):
            return False
        if self.commitment_anchor.commitment_set_digest != commitment_set_digest(
            descriptor=self.descriptor, commitments=commitments.values()
        ):
            return False

        expected_root = compute_transcript_root(
            descriptor=self.descriptor,
            commitments=commitments.values(),
            commitment_anchor=self.commitment_anchor,
            beacon=self.beacon,
            backend_transcript_digest=self.backend_transcript_digest,
            artifact_digest=self.artifact_digest,
            artifact_bytes=self.artifact_bytes,
        )
        if expected_root != self.transcript_root:
            return False

        receipts: dict[bytes, ParticipantReceipt] = {}
        for row in self.receipts:
            pid = bytes(row.participant_id)
            participant = participants.get(pid)
            if participant is None or pid in receipts:
                return False
            if (
                not row.completed
                or row.descriptor_digest != self.descriptor.digest
                or row.transcript_root != self.transcript_root
                or row.artifact_digest != self.artifact_digest
                or row.artifact_bytes != self.artifact_bytes
            ):
                return False
            if not verify(row.signing_message, participant.signing_pubkey, row.signature):
                return False
            receipts[pid] = row

        approved = {bytes(key) for key in approved_independent_verifiers}
        return (
            bytes(self.independent_verifier_pubkey) in approved
            and bytes(self.independent_verifier_pubkey)
            not in {participant.signing_pubkey for participant in participants.values()}
            and verify(
                self.verifier_message,
                self.independent_verifier_pubkey,
                self.independent_verifier_signature,
            )
        )

    def verify_with_core(
        self,
        *,
        approved_independent_verifiers: Iterable[bytes],
        bitcoin_core: BitcoinCoreSpvReader,
        minimum_confirmations: int,
        observed_at_unix: int = 0,
    ) -> bool:
        try:
            self.observe_with_core(
                approved_independent_verifiers=approved_independent_verifiers,
                bitcoin_core=bitcoin_core,
                minimum_confirmations=minimum_confirmations,
                observed_at_unix=observed_at_unix,
            )
        except Exception:
            return False
        return True

    def observe_with_core(
        self,
        *,
        approved_independent_verifiers: Iterable[bytes],
        bitcoin_core: BitcoinCoreSpvReader,
        minimum_confirmations: int,
        observed_at_unix: int,
    ) -> CeremonyCoreObservation:
        """Verify the complete ceremony against one stable Core snapshot.

        Each signed block is checked independently and the best-chain tip is
        required to remain unchanged across the whole sequence.  The exact
        observations are returned so a later funding attestation can commit to
        what Core actually reported, rather than merely recording a boolean.
        """

        approved = tuple(bytes(key) for key in approved_independent_verifiers)
        if not self.verify(approved_independent_verifiers=approved):
            raise CeremonyEvidenceError("ceremony certificate verification failed")
        depth = int(minimum_confirmations)
        if not 1 <= depth < 2**31:
            raise CeremonyEvidenceError("minimum confirmation depth is invalid")

        tip_before = _rpc_hash(
            bitcoin_core.call("getbestblockhash"), "pre-check best block hash"
        )
        anchor = self.commitment_anchor.verify_with_core(
            bitcoin_core, minimum_confirmations=depth
        )
        beacon = self.beacon.verify_with_core(
            bitcoin_core, minimum_confirmations=depth
        )

        # Recheck both signed heights after both detailed checks.  This closes
        # the gap where an anchor could be displaced between its local check
        # and the later beacon check while each individual read looked stable.
        anchor_final = verify_active_chain_block(
            bitcoin_core,
            chain_genesis_hash=self.descriptor.chain_genesis_hash,
            block_height=self.commitment_anchor.block_height,
            expected_block_hash=self.commitment_anchor.block_hash,
            minimum_confirmations=depth,
        )
        beacon_final = verify_active_chain_block(
            bitcoin_core,
            chain_genesis_hash=self.descriptor.chain_genesis_hash,
            block_height=self.beacon.block_height,
            expected_block_hash=self.beacon.block_hash,
            minimum_confirmations=depth,
        )
        tip_after = _rpc_hash(
            bitcoin_core.call("getbestblockhash"), "post-check best block hash"
        )
        if tip_after != tip_before:
            raise CeremonyEvidenceError(
                "Bitcoin best chain changed during ceremony verification"
            )
        if (
            anchor_final.block_hash != anchor.block_hash
            or beacon_final.block_hash != beacon.block_hash
            or anchor_final.confirmations != anchor.confirmations
            or beacon_final.confirmations != beacon.confirmations
        ):
            raise CeremonyEvidenceError(
                "Bitcoin Core observations changed during ceremony verification"
            )
        return CeremonyCoreObservation(
            commitment_anchor=anchor,
            beacon=beacon,
            best_block_hash=tip_after,
            minimum_confirmations=depth,
            observed_at_unix=int(observed_at_unix),
        )

    @classmethod
    def assemble(
        cls,
        *,
        descriptor: MpcSessionDescriptor,
        commitments: tuple[ParticipantCommitment, ...],
        commitment_anchor: CommitmentPublicationAnchor,
        beacon: ExternalBeacon,
        backend_transcript_digest: bytes,
        artifact_digest: bytes,
        artifact_bytes: int,
        participant_secrets: dict[bytes, int],
        independent_verifier_secret: int,
    ) -> "CeremonyCertificate":
        root = compute_transcript_root(
            descriptor=descriptor,
            commitments=commitments,
            commitment_anchor=commitment_anchor,
            beacon=beacon,
            backend_transcript_digest=backend_transcript_digest,
            artifact_digest=artifact_digest,
            artifact_bytes=artifact_bytes,
        )
        receipts = tuple(
            ParticipantReceipt.issue(
                participant_id=participant.participant_id,
                descriptor_digest=descriptor.digest,
                transcript_root=root,
                artifact_digest=artifact_digest,
                artifact_bytes=artifact_bytes,
                completed=True,
                participant_secret=participant_secrets[bytes(participant.participant_id)],
            )
            for participant in descriptor.participants
        )
        placeholder = cls(
            descriptor=descriptor,
            commitments=commitments,
            commitment_anchor=commitment_anchor,
            beacon=beacon,
            backend_transcript_digest=bytes(backend_transcript_digest),
            artifact_digest=bytes(artifact_digest),
            artifact_bytes=int(artifact_bytes),
            transcript_root=root,
            receipts=receipts,
            independent_verifier_pubkey=public_key(independent_verifier_secret),
            independent_verifier_signature=bytes(64),
        )
        return cls(
            descriptor=placeholder.descriptor,
            commitments=placeholder.commitments,
            commitment_anchor=placeholder.commitment_anchor,
            beacon=placeholder.beacon,
            backend_transcript_digest=placeholder.backend_transcript_digest,
            artifact_digest=placeholder.artifact_digest,
            artifact_bytes=placeholder.artifact_bytes,
            transcript_root=placeholder.transcript_root,
            receipts=placeholder.receipts,
            independent_verifier_pubkey=placeholder.independent_verifier_pubkey,
            independent_verifier_signature=sign(
                placeholder.verifier_message, independent_verifier_secret
            ),
        )
