from __future__ import annotations

"""Fail-closed qualification wrapper for an external malicious-secure MPC backend.

This module deliberately does not implement MPC.  It binds three independent
claims that must all exist before the funding gate may accept
``malicious-mpc-execution`` evidence:

* a complete non-equivocating ceremony certificate;
* an exact backend/security-proof/build identity;
* signed results from a verifier that is neither a setup participant nor the
  ceremony-transcript verifier.

A ceremony certificate alone is therefore never promoted into an MPC claim.
The independent verifier remains responsible for actually replaying the
backend's malicious-security checker and validating the referenced reports.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable

from .bip340 import public_key, sign, verify
from .deployment_policy import ROLE_ACTIVE_MPC, SecurityAttestation
from .bitcoin_spv import BitcoinCoreSpvReader
from .setup_ceremony_evidence import (
    CeremonyCertificate,
    CeremonyCoreObservation,
)


class MpcQualificationError(ValueError):
    pass


_STATEMENT_DOMAIN = b"ranklock/mpc-qualification-statement/v1\x00"
_CERTIFICATE_DOMAIN = b"ranklock/mpc-qualification-certificate/v1\x00"
_EVIDENCE_DOMAIN = b"ranklock/mpc-qualification-evidence/v1\x00"
_FUNDING_EVIDENCE_DOMAIN = b"ranklock/mpc-funding-evidence/v2\x00"


def _digest(value: bytes, name: str) -> bytes:
    raw = bytes(value)
    if len(raw) != 32:
        raise MpcQualificationError(f"{name} must be 32 bytes")
    if raw == bytes(32):
        raise MpcQualificationError(f"{name} must be nonzero")
    return raw


def ceremony_certificate_digest(certificate: CeremonyCertificate) -> bytes:
    """Digest every activation-relevant field of a ceremony certificate."""

    return sha256(
        b"ranklock/mpc-ceremony-certificate-digest/v1\x00"
        + certificate.descriptor.digest
        + certificate.commitment_anchor.canonical_bytes
        + certificate.beacon.canonical_bytes
        + certificate.transcript_root
        + certificate.backend_transcript_digest
        + certificate.artifact_digest
        + int(certificate.artifact_bytes).to_bytes(8, "big")
        + certificate.independent_verifier_pubkey
        + certificate.independent_verifier_signature
    ).digest()


@dataclass(frozen=True, slots=True)
class MpcQualificationStatement:
    deployment_digest: bytes
    deployment_context_digest: bytes
    chain_genesis_hash: bytes
    descriptor_digest: bytes
    ceremony_certificate_digest: bytes
    transcript_root: bytes
    artifact_digest: bytes
    artifact_bytes: int
    backend_implementation_digest: bytes
    protocol_security_reference_digest: bytes
    reproducible_backend_build_digest: bytes
    malicious_security_test_report_digest: bytes
    transcript_replay_report_digest: bytes
    secret_erasure_report_digest: bytes
    schema: str = "ranklock-mpc-qualification-statement-v1"

    def __post_init__(self) -> None:
        for name in (
            "deployment_digest",
            "deployment_context_digest",
            "chain_genesis_hash",
            "descriptor_digest",
            "ceremony_certificate_digest",
            "transcript_root",
            "artifact_digest",
            "backend_implementation_digest",
            "protocol_security_reference_digest",
            "reproducible_backend_build_digest",
            "malicious_security_test_report_digest",
            "transcript_replay_report_digest",
            "secret_erasure_report_digest",
        ):
            _digest(getattr(self, name), name.replace("_", " "))
        if not 0 < int(self.artifact_bytes) < 2**64:
            raise MpcQualificationError("artifact length is invalid")

    @property
    def canonical_bytes(self) -> bytes:
        return (
            bytes(self.deployment_digest)
            + bytes(self.deployment_context_digest)
            + bytes(self.chain_genesis_hash)
            + bytes(self.descriptor_digest)
            + bytes(self.ceremony_certificate_digest)
            + bytes(self.transcript_root)
            + bytes(self.artifact_digest)
            + int(self.artifact_bytes).to_bytes(8, "big")
            + bytes(self.backend_implementation_digest)
            + bytes(self.protocol_security_reference_digest)
            + bytes(self.reproducible_backend_build_digest)
            + bytes(self.malicious_security_test_report_digest)
            + bytes(self.transcript_replay_report_digest)
            + bytes(self.secret_erasure_report_digest)
        )

    @property
    def digest(self) -> bytes:
        return sha256(_STATEMENT_DOMAIN + self.canonical_bytes).digest()


@dataclass(frozen=True, slots=True)
class MpcQualificationCertificate:
    statement: MpcQualificationStatement
    verifier_pubkey: bytes
    issued_at_unix: int
    expires_at_unix: int
    signature: bytes
    schema: str = "ranklock-mpc-qualification-certificate-v1"

    def __post_init__(self) -> None:
        if len(bytes(self.verifier_pubkey)) != 32:
            raise MpcQualificationError("MPC verifier key must be 32 bytes")
        if len(bytes(self.signature)) != 64:
            raise MpcQualificationError("MPC verifier signature must be 64 bytes")
        if not 0 <= int(self.issued_at_unix) < 2**64:
            raise MpcQualificationError("MPC certificate issue time is invalid")
        if not 0 <= int(self.expires_at_unix) < 2**64:
            raise MpcQualificationError("MPC certificate expiry time is invalid")
        if self.expires_at_unix <= self.issued_at_unix:
            raise MpcQualificationError("MPC certificate expiry must follow issue time")

    @property
    def signing_message(self) -> bytes:
        return sha256(
            _CERTIFICATE_DOMAIN
            + self.statement.digest
            + int(self.issued_at_unix).to_bytes(8, "big")
            + int(self.expires_at_unix).to_bytes(8, "big")
            + bytes(self.verifier_pubkey)
        ).digest()

    @property
    def evidence_digest(self) -> bytes:
        return sha256(
            _EVIDENCE_DOMAIN
            + self.statement.digest
            + bytes(self.verifier_pubkey)
            + int(self.issued_at_unix).to_bytes(8, "big")
            + int(self.expires_at_unix).to_bytes(8, "big")
            + bytes(self.signature)
        ).digest()

    def verify(
        self,
        *,
        ceremony: CeremonyCertificate,
        approved_ceremony_verifiers: Iterable[bytes],
        approved_mpc_verifiers: Iterable[bytes],
        now_unix: int,
    ) -> bool:
        descriptor = ceremony.descriptor
        participant_keys = {bytes(row.signing_pubkey) for row in descriptor.participants}
        approved_mpc = {bytes(key) for key in approved_mpc_verifiers}
        # RankLock's target is security with all but one setup participant corrupt.
        threshold_is_target = descriptor.corruption_threshold == len(descriptor.participants) - 1
        statement_matches = (
            self.statement.descriptor_digest == descriptor.digest
            and self.statement.deployment_context_digest
            == descriptor.context_digest
            and self.statement.chain_genesis_hash
            == descriptor.chain_genesis_hash
            and self.statement.ceremony_certificate_digest
            == ceremony_certificate_digest(ceremony)
            and self.statement.transcript_root == ceremony.transcript_root
            and self.statement.artifact_digest == ceremony.artifact_digest
            and self.statement.artifact_bytes == ceremony.artifact_bytes
            and self.statement.backend_implementation_digest
            == descriptor.implementation_digest
            and self.statement.protocol_security_reference_digest
            == descriptor.protocol_security_reference_digest
        )
        return (
            threshold_is_target
            and statement_matches
            and ceremony.verify(
                approved_independent_verifiers=approved_ceremony_verifiers
            )
            and bytes(self.verifier_pubkey) in approved_mpc
            and bytes(self.verifier_pubkey) not in participant_keys
            and bytes(self.verifier_pubkey) != ceremony.independent_verifier_pubkey
            and self.issued_at_unix <= int(now_unix) < self.expires_at_unix
            and verify(self.signing_message, self.verifier_pubkey, self.signature)
        )

    def verify_for_funding(
        self,
        *,
        ceremony: CeremonyCertificate,
        approved_ceremony_verifiers: Iterable[bytes],
        approved_mpc_verifiers: Iterable[bytes],
        bitcoin_core: BitcoinCoreSpvReader,
        minimum_confirmations: int,
        now_unix: int,
    ) -> bool:
        return bool(
            self.verify(
                ceremony=ceremony,
                approved_ceremony_verifiers=approved_ceremony_verifiers,
                approved_mpc_verifiers=approved_mpc_verifiers,
                now_unix=now_unix,
            )
            and ceremony.verify_with_core(
                approved_independent_verifiers=approved_ceremony_verifiers,
                bitcoin_core=bitcoin_core,
                minimum_confirmations=minimum_confirmations,
            )
        )

    @classmethod
    def issue(
        cls,
        *,
        statement: MpcQualificationStatement,
        verifier_secret: int,
        issued_at_unix: int,
        expires_at_unix: int,
    ) -> "MpcQualificationCertificate":
        placeholder = cls(
            statement=statement,
            verifier_pubkey=public_key(verifier_secret),
            issued_at_unix=int(issued_at_unix),
            expires_at_unix=int(expires_at_unix),
            signature=bytes(64),
        )
        return cls(
            statement=statement,
            verifier_pubkey=placeholder.verifier_pubkey,
            issued_at_unix=placeholder.issued_at_unix,
            expires_at_unix=placeholder.expires_at_unix,
            signature=sign(placeholder.signing_message, verifier_secret),
        )

    def issue_funding_attestation(
        self,
        *,
        verifier_secret: int,
        ceremony: CeremonyCertificate,
        approved_ceremony_verifiers: Iterable[bytes],
        approved_mpc_verifiers: Iterable[bytes],
        bitcoin_core: BitcoinCoreSpvReader,
        minimum_confirmations: int,
        now_unix: int,
        attestation_ttl_seconds: int,
    ) -> SecurityAttestation:
        """Issue funding evidence only after a live canonical-chain check."""

        if public_key(verifier_secret) != bytes(self.verifier_pubkey):
            raise MpcQualificationError("funding evidence signer is not the MPC verifier")
        approved_ceremony = tuple(bytes(key) for key in approved_ceremony_verifiers)
        approved_mpc = tuple(bytes(key) for key in approved_mpc_verifiers)
        if not self.verify(
            ceremony=ceremony,
            approved_ceremony_verifiers=approved_ceremony,
            approved_mpc_verifiers=approved_mpc,
            now_unix=now_unix,
        ):
            raise MpcQualificationError(
                "MPC qualification failed funding verification"
            )
        ttl = int(attestation_ttl_seconds)
        if not 1 <= ttl <= 3_600:
            raise MpcQualificationError(
                "funding attestation lifetime must be between 1 and 3600 seconds"
            )
        try:
            observation = ceremony.observe_with_core(
                approved_independent_verifiers=approved_ceremony,
                bitcoin_core=bitcoin_core,
                minimum_confirmations=minimum_confirmations,
                observed_at_unix=now_unix,
            )
        except Exception as exc:
            raise MpcQualificationError(
                "canonical-chain evidence failed funding verification"
            ) from exc
        expires_at = min(self.expires_at_unix, int(now_unix) + ttl)
        if expires_at <= int(now_unix):
            raise MpcQualificationError("funding attestation would already be expired")
        return SecurityAttestation.create(
            role=ROLE_ACTIVE_MPC,
            subject_digest=self.statement.deployment_digest,
            evidence_digest=self.funding_evidence_digest(observation),
            signer_secret=verifier_secret,
            issued_at=int(now_unix),
            expires_at=expires_at,
        )

    def funding_evidence_digest(
        self, observation: CeremonyCoreObservation
    ) -> bytes:
        """Bind funding evidence to the exact live Core observations."""

        return sha256(
            _FUNDING_EVIDENCE_DOMAIN
            + self.evidence_digest
            + observation.digest
        ).digest()


def statement_from_ceremony(
    *,
    deployment_digest: bytes,
    deployment_context_digest: bytes,
    chain_genesis_hash: bytes,
    ceremony: CeremonyCertificate,
    reproducible_backend_build_digest: bytes,
    malicious_security_test_report_digest: bytes,
    transcript_replay_report_digest: bytes,
    secret_erasure_report_digest: bytes,
) -> MpcQualificationStatement:
    descriptor = ceremony.descriptor
    expected_context = _digest(
        deployment_context_digest, "deployment context digest"
    )
    expected_genesis = _digest(chain_genesis_hash, "chain genesis hash")
    if descriptor.context_digest != expected_context:
        raise MpcQualificationError(
            "ceremony context differs from the deployment context"
        )
    if descriptor.chain_genesis_hash != expected_genesis:
        raise MpcQualificationError(
            "ceremony chain differs from the deployment chain"
        )
    return MpcQualificationStatement(
        deployment_digest=_digest(deployment_digest, "deployment digest"),
        deployment_context_digest=expected_context,
        chain_genesis_hash=expected_genesis,
        descriptor_digest=descriptor.digest,
        ceremony_certificate_digest=ceremony_certificate_digest(ceremony),
        transcript_root=ceremony.transcript_root,
        artifact_digest=ceremony.artifact_digest,
        artifact_bytes=ceremony.artifact_bytes,
        backend_implementation_digest=descriptor.implementation_digest,
        protocol_security_reference_digest=descriptor.protocol_security_reference_digest,
        reproducible_backend_build_digest=_digest(
            reproducible_backend_build_digest, "reproducible backend build digest"
        ),
        malicious_security_test_report_digest=_digest(
            malicious_security_test_report_digest, "malicious security test report digest"
        ),
        transcript_replay_report_digest=_digest(
            transcript_replay_report_digest, "transcript replay report digest"
        ),
        secret_erasure_report_digest=_digest(
            secret_erasure_report_digest, "secret erasure report digest"
        ),
    )
