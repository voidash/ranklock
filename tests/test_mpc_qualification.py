from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.bip340 import public_key
from ranklock.bitcoin_spv import BitcoinSpvInclusionProof, commitment_script, header_satisfies_pow
from ranklock.bitcoin_tx import OutPoint, Transaction, TxIn, TxOut
from ranklock.deployment_policy import (
    PRODUCTION_ROLES,
    ROLE_ACTIVE_MPC,
    RoleAuthority,
    RuntimeSecurityFacts,
    SafetySubject,
    SecurityAttestation,
    SignedFundsSafetyPolicy,
    UnsignedFundsSafetyPolicy,
    evaluate_deployment,
)
from ranklock.mpc_qualification import (
    MpcQualificationCertificate,
    statement_from_ceremony,
)
from ranklock.setup_ceremony_evidence import (
    CeremonyCertificate,
    CeremonyParticipant,
    CommitmentPublicationAnchor,
    ExternalBeacon,
    MpcSessionDescriptor,
    ParticipantCommitment,
    commitment_set_digest,
)


def H(value: bytes) -> bytes:
    return sha256(value).digest()


def publication_proof(commitment: bytes) -> BitcoinSpvInclusionProof:
    transaction = Transaction(
        version=2,
        inputs=(TxIn(OutPoint(H(b"commitment funding"), 0)),),
        outputs=(TxOut(0, commitment_script(commitment)), TxOut(1_000, b"\x51")),
    )
    prefix = (
        (4).to_bytes(4, "little", signed=True)
        + bytes(32)
        + transaction.txid[::-1]
        + (1_800_000_000).to_bytes(4, "little")
        + (0x207FFFFF).to_bytes(4, "little")
    )
    for nonce in range(100_000):
        header = prefix + nonce.to_bytes(4, "little")
        if header_satisfies_pow(header):
            return BitcoinSpvInclusionProof(
                block_header=header,
                publication_transaction=transaction.serialize(),
                transaction_index=0,
                transaction_count=1,
                merkle_branch=(),
            )
    raise AssertionError("failed to mine test header")


PARTICIPANTS = {b"alice": 101, b"bob": 103, b"carol": 107}
CEREMONY_VERIFIER = 109
MPC_VERIFIER = 113
NOW = 1_800_000_000
DEPLOYMENT = H(b"deployment")


def fixture(
    *,
    deployment_digest: bytes = DEPLOYMENT,
    context_digest: bytes = H(b"context"),
    chain_genesis_hash: bytes = H(b"genesis"),
):
    participants = tuple(
        CeremonyParticipant(pid, public_key(secret))
        for pid, secret in sorted(PARTICIPANTS.items())
    )
    descriptor = MpcSessionDescriptor(
        session_id=H(b"session"),
        context_digest=context_digest,
        chain_genesis_hash=chain_genesis_hash,
        source_archive_digest=H(b"source"),
        implementation_digest=H(b"backend"),
        circuit_digest=H(b"circuit"),
        parameter_digest=H(b"parameters"),
        protocol_security_reference_digest=H(b"security proof"),
        commitment_cutoff_height=500,
        participants=participants,
        corruption_threshold=len(participants) - 1,
    )
    commitments = tuple(
        ParticipantCommitment.issue(
            participant_id=p.participant_id,
            descriptor_digest=descriptor.digest,
            private_view_commitment=H(b"view:" + p.participant_id),
            outbound_messages_root=H(b"out:" + p.participant_id),
            local_randomness_commitment=H(b"random:" + p.participant_id),
            participant_secret=PARTICIPANTS[p.participant_id],
        )
        for p in participants
    )
    set_digest = commitment_set_digest(
        descriptor=descriptor, commitments=commitments
    )
    anchor = CommitmentPublicationAnchor(
        chain_genesis_hash=descriptor.chain_genesis_hash,
        block_height=499,
        commitment_set_digest=set_digest,
        inclusion_proof=publication_proof(set_digest),
    )
    ceremony = CeremonyCertificate.assemble(
        descriptor=descriptor,
        commitments=commitments,
        commitment_anchor=anchor,
        beacon=ExternalBeacon(descriptor.chain_genesis_hash, 507, H(b"block")),
        backend_transcript_digest=H(b"transcript"),
        artifact_digest=H(b"artifact"),
        artifact_bytes=1_044_952,
        participant_secrets=PARTICIPANTS,
        independent_verifier_secret=CEREMONY_VERIFIER,
    )
    statement = statement_from_ceremony(
        deployment_digest=deployment_digest,
        deployment_context_digest=context_digest,
        chain_genesis_hash=chain_genesis_hash,
        ceremony=ceremony,
        reproducible_backend_build_digest=H(b"build report"),
        malicious_security_test_report_digest=H(b"malicious tests"),
        transcript_replay_report_digest=H(b"replay report"),
        secret_erasure_report_digest=H(b"erasure report"),
    )
    certificate = MpcQualificationCertificate.issue(
        statement=statement,
        verifier_secret=MPC_VERIFIER,
        issued_at_unix=NOW - 100,
        expires_at_unix=NOW + 10_000,
    )
    return ceremony, statement, certificate


class CeremonyCore:
    """Exact synthetic Core view for one signed ceremony."""

    def __init__(
        self,
        ceremony: CeremonyCertificate,
        *,
        genesis: bytes | None = None,
        confirmations: int = 6,
        move_tip: bool = False,
    ) -> None:
        self.ceremony = ceremony
        self.genesis = (
            ceremony.descriptor.chain_genesis_hash
            if genesis is None
            else bytes(genesis)
        )
        self.confirmations = int(confirmations)
        self.move_tip = bool(move_tip)
        self.tip_reads = 0

    def call(self, method: str, *params: object) -> object:
        anchor = self.ceremony.commitment_anchor
        proof = anchor.inclusion_proof
        beacon = self.ceremony.beacon
        if method == "getbestblockhash":
            self.tip_reads += 1
            if self.move_tip and self.tip_reads > 1:
                return H(b"replacement tip").hex()
            return H(b"stable tip").hex()
        if method == "getblockhash":
            height = int(params[0])
            if height == 0:
                return self.genesis.hex()
            if height == anchor.block_height:
                return anchor.block_hash.hex()
            if height == beacon.block_height:
                return beacon.block_hash.hex()
            raise AssertionError(f"unexpected block height: {height}")
        if method == "getblockheader":
            requested_hash = str(params[0])
            verbose = bool(params[1])
            if requested_hash == anchor.block_hash.hex():
                if not verbose:
                    return proof.block_header.hex()
                return {
                    "hash": anchor.block_hash.hex(),
                    "height": anchor.block_height,
                    "confirmations": self.confirmations,
                    "merkleroot": proof.merkle_root.hex(),
                }
            if requested_hash == beacon.block_hash.hex() and verbose:
                return {
                    "hash": beacon.block_hash.hex(),
                    "height": beacon.block_height,
                    "confirmations": self.confirmations,
                }
            raise AssertionError(f"unexpected block-header request: {params!r}")
        if method == "getrawtransaction":
            assert str(params[0]) == proof.publication_txid.hex()
            assert bool(params[1])
            assert str(params[2]) == anchor.block_hash.hex()
            return {
                "hex": proof.publication_transaction.hex(),
                "txid": proof.publication_txid.hex(),
                "blockhash": anchor.block_hash.hex(),
                "confirmations": self.confirmations,
            }
        raise AssertionError(f"unexpected RPC method: {method}")


def funding_attestation(
    ceremony: CeremonyCertificate,
    certificate: MpcQualificationCertificate,
    *,
    verifier_secret: int = MPC_VERIFIER,
    bitcoin_core: CeremonyCore | None = None,
):
    return certificate.issue_funding_attestation(
        verifier_secret=verifier_secret,
        ceremony=ceremony,
        approved_ceremony_verifiers={public_key(CEREMONY_VERIFIER)},
        approved_mpc_verifiers={public_key(MPC_VERIFIER)},
        bitcoin_core=CeremonyCore(ceremony) if bitcoin_core is None else bitcoin_core,
        minimum_confirmations=6,
        now_unix=NOW,
        attestation_ttl_seconds=300,
    )


def verify(ceremony, certificate) -> bool:
    return certificate.verify(
        ceremony=ceremony,
        approved_ceremony_verifiers={public_key(CEREMONY_VERIFIER)},
        approved_mpc_verifiers={public_key(MPC_VERIFIER)},
        now_unix=NOW,
    )


def test_independent_mpc_qualification_verifies_and_yields_bound_evidence() -> None:
    ceremony, _statement, certificate = fixture()
    assert verify(ceremony, certificate)
    expected_observation = ceremony.observe_with_core(
        approved_independent_verifiers={public_key(CEREMONY_VERIFIER)},
        bitcoin_core=CeremonyCore(ceremony),
        minimum_confirmations=6,
        observed_at_unix=NOW,
    )
    evidence = funding_attestation(ceremony, certificate)
    assert evidence.role == "active-mpc"
    assert evidence.subject_digest == DEPLOYMENT
    assert evidence.evidence_digest == certificate.funding_evidence_digest(
        expected_observation
    )
    assert evidence.evidence_digest != certificate.evidence_digest
    assert evidence.issued_at == NOW
    assert evidence.expires_at == NOW + 300


def test_ceremony_verifier_cannot_self_qualify_mpc() -> None:
    ceremony, statement, _certificate = fixture()
    self_signed = MpcQualificationCertificate.issue(
        statement=statement,
        verifier_secret=CEREMONY_VERIFIER,
        issued_at_unix=NOW - 100,
        expires_at_unix=NOW + 10_000,
    )
    assert not self_signed.verify(
        ceremony=ceremony,
        approved_ceremony_verifiers={public_key(CEREMONY_VERIFIER)},
        approved_mpc_verifiers={public_key(CEREMONY_VERIFIER)},
        now_unix=NOW,
    )


def test_weaker_corruption_threshold_cannot_be_promoted() -> None:
    ceremony, _statement, _certificate = fixture()
    weak_descriptor = replace(ceremony.descriptor, corruption_threshold=1)
    weak = replace(ceremony, descriptor=weak_descriptor)
    # It no longer matches the signed ceremony or target n-1 security.
    _ceremony, statement, _ = fixture()
    cert = MpcQualificationCertificate.issue(
        statement=statement,
        verifier_secret=MPC_VERIFIER,
        issued_at_unix=NOW - 100,
        expires_at_unix=NOW + 10_000,
    )
    assert not verify(weak, cert)


def test_report_or_artifact_substitution_breaks_qualification() -> None:
    ceremony, statement, certificate = fixture()
    altered_statement = replace(
        statement, malicious_security_test_report_digest=H(b"different report")
    )
    assert not verify(ceremony, replace(certificate, statement=altered_statement))
    assert not verify(
        replace(ceremony, artifact_digest=H(b"different artifact")), certificate
    )


def test_certificate_expires_and_evidence_needs_same_signer() -> None:
    ceremony, _statement, certificate = fixture()
    expired = replace(certificate, expires_at_unix=NOW)
    assert not verify(ceremony, expired)
    with pytest.raises(ValueError, match="not the MPC verifier"):
        funding_attestation(ceremony, certificate, verifier_secret=999)


def test_zero_placeholder_report_digest_is_rejected() -> None:
    ceremony, _statement, _certificate = fixture()
    with pytest.raises(ValueError, match="must be nonzero"):
        statement_from_ceremony(
            deployment_digest=DEPLOYMENT,
            deployment_context_digest=ceremony.descriptor.context_digest,
            chain_genesis_hash=ceremony.descriptor.chain_genesis_hash,
            ceremony=ceremony,
            reproducible_backend_build_digest=bytes(32),
            malicious_security_test_report_digest=H(b"malicious tests"),
            transcript_replay_report_digest=H(b"replay report"),
            secret_erasure_report_digest=H(b"erasure report"),
        )


def test_statement_and_funding_evidence_are_chain_and_context_bound() -> None:
    ceremony, _statement, certificate = fixture()
    with pytest.raises(ValueError, match="context differs"):
        statement_from_ceremony(
            deployment_digest=DEPLOYMENT,
            deployment_context_digest=H(b"another context"),
            chain_genesis_hash=ceremony.descriptor.chain_genesis_hash,
            ceremony=ceremony,
            reproducible_backend_build_digest=H(b"build report"),
            malicious_security_test_report_digest=H(b"malicious tests"),
            transcript_replay_report_digest=H(b"replay report"),
            secret_erasure_report_digest=H(b"erasure report"),
        )
    with pytest.raises(ValueError, match="chain differs"):
        statement_from_ceremony(
            deployment_digest=DEPLOYMENT,
            deployment_context_digest=ceremony.descriptor.context_digest,
            chain_genesis_hash=H(b"another chain"),
            ceremony=ceremony,
            reproducible_backend_build_digest=H(b"build report"),
            malicious_security_test_report_digest=H(b"malicious tests"),
            transcript_replay_report_digest=H(b"replay report"),
            secret_erasure_report_digest=H(b"erasure report"),
        )
    for core in (
        CeremonyCore(ceremony, genesis=H(b"another chain")),
        CeremonyCore(ceremony, confirmations=5),
        CeremonyCore(ceremony, move_tip=True),
    ):
        with pytest.raises(ValueError, match="canonical-chain evidence"):
            funding_attestation(ceremony, certificate, bitcoin_core=core)


def test_mpc_certificate_cannot_upgrade_the_legacy_subject_to_a_funding_gate() -> None:
    subject = SafetySubject(
        version="0.25.1",
        source_archive_sha256=H(b"source archive"),
        source_manifest_sha256=H(b"source manifest"),
        retained_object_sha256=H(b"retained object"),
        retained_manifest_digest=H(b"retained manifest"),
        generator_code_hash=H(b"generator"),
        bridge_commit=H(b"bridge commit"),
        context_digest=H(b"deployment context"),
    )
    genesis = H(b"regtest genesis")
    ceremony, _statement, certificate = fixture(
        deployment_digest=subject.digest,
        context_digest=subject.context_digest,
        chain_genesis_hash=genesis,
    )
    assert verify(ceremony, certificate)

    setup_secrets = tuple(PARTICIPANTS.values())
    governance_secrets = (211, 223, 227)
    rollback_witness_secrets = (229, 233)
    authority_secrets = {
        role: (MPC_VERIFIER if role == ROLE_ACTIVE_MPC else 307 + 2 * index)
        for index, role in enumerate(PRODUCTION_ROLES)
    }
    authorities = tuple(
        sorted(
            (
                RoleAuthority(role, 1, (public_key(authority_secrets[role]),))
                for role in PRODUCTION_ROLES
            ),
            key=lambda item: item.role,
        )
    )
    policy = SignedFundsSafetyPolicy.create(
        UnsignedFundsSafetyPolicy(
            subject_digest=subject.digest,
            network="regtest",
            chain_genesis_hash=genesis,
            maximum_value_sat=1_000_000,
            minimum_committee_members=len(setup_secrets),
            minimum_rollback_witnesses=len(rollback_witness_secrets),
            minimum_confirmations=6,
            rollback_witness_pubkeys=tuple(
                sorted(public_key(secret) for secret in rollback_witness_secrets)
            ),
            setup_participant_pubkeys=tuple(
                sorted(public_key(secret) for secret in setup_secrets)
            ),
            governance_pubkeys=tuple(
                sorted(public_key(secret) for secret in governance_secrets)
            ),
            governance_threshold=2,
            role_authorities=authorities,
        ),
        governance_secrets=governance_secrets[:2],
    )
    runtime = RuntimeSecurityFacts(
        network="regtest",
        chain_genesis_hash=genesis,
        value_at_risk_sat=100_000,
        committee_members=len(setup_secrets),
        committee_quorum=len(setup_secrets),
        rollback_witnesses=len(rollback_witness_secrets),
        minimum_confirmations=6,
        rollback_witness_pubkeys=policy.unsigned.rollback_witness_pubkeys,
        bitcoin_core_consensus_crosscheck=True,
        witness_selected_point_binding=True,
        durable_burn_before_release=True,
        rollback_protection_live=True,
        deterministic_fixture_secrets_absent=True,
        secret_file_permissions_locked=True,
    )
    mpc_attestation = funding_attestation(ceremony, certificate)
    other_attestations = tuple(
        SecurityAttestation.create(
            role=role,
            subject_digest=subject.digest,
            evidence_digest=H(b"evidence/" + role.encode()),
            issued_at=NOW - 100,
            expires_at=NOW + 10_000,
            signer_secret=authority_secrets[role],
        )
        for role in PRODUCTION_ROLES
        if role != ROLE_ACTIVE_MPC
    )
    decision = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=(mpc_attestation,) + other_attestations,
        runtime=runtime,
        now=NOW,
    )
    assert not decision.can_start
    assert not decision.may_authorize_funds
    assert any("legacy v0.25 safety subject" in failure for failure in decision.failures)

    wrong_subject = replace(mpc_attestation, subject_digest=H(b"other subject"))
    denied = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=(wrong_subject,) + other_attestations,
        runtime=runtime,
        now=NOW,
    )
    assert not denied.may_authorize_funds
    assert any(ROLE_ACTIVE_MPC in failure for failure in denied.failures)
