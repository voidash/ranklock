from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

from ranklock.bip340 import public_key
from ranklock.bitcoin_spv import BitcoinSpvInclusionProof, commitment_script, header_satisfies_pow
from ranklock.bitcoin_tx import OutPoint, Transaction, TxIn, TxOut
from ranklock.setup_ceremony_evidence import (
    CeremonyCertificate,
    CeremonyParticipant,
    CommitmentPublicationAnchor,
    ExternalBeacon,
    MpcSessionDescriptor,
    ParticipantCommitment,
    commitment_set_digest,
)

SECRETS = {b"alice": 101, b"bob": 103, b"carol": 107}
VERIFIER_SECRET = 109


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


def fixture():
    participants = tuple(
        CeremonyParticipant(participant_id=pid, signing_pubkey=public_key(secret))
        for pid, secret in sorted(SECRETS.items())
    )
    descriptor = MpcSessionDescriptor(
        session_id=H(b"session"),
        context_digest=H(b"context"),
        chain_genesis_hash=H(b"genesis"),
        source_archive_digest=H(b"source"),
        implementation_digest=H(b"mpc implementation"),
        circuit_digest=H(b"fused generator circuit"),
        parameter_digest=H(b"91 primes and two slots"),
        protocol_security_reference_digest=H(b"published protocol and proof"),
        commitment_cutoff_height=500,
        participants=participants,
        corruption_threshold=2,
    )
    commitments = tuple(
        ParticipantCommitment.issue(
            participant_id=participant.participant_id,
            descriptor_digest=descriptor.digest,
            private_view_commitment=H(b"view:" + participant.participant_id),
            outbound_messages_root=H(b"messages:" + participant.participant_id),
            local_randomness_commitment=H(b"randomness:" + participant.participant_id),
            participant_secret=SECRETS[participant.participant_id],
        )
        for participant in participants
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
    beacon = ExternalBeacon(
        chain_genesis_hash=descriptor.chain_genesis_hash,
        block_height=507,
        block_hash=H(b"block 507"),
    )
    certificate = CeremonyCertificate.assemble(
        descriptor=descriptor,
        commitments=commitments,
        commitment_anchor=anchor,
        beacon=beacon,
        backend_transcript_digest=H(b"backend transcript"),
        artifact_digest=H(b"retained object"),
        artifact_bytes=1_044_952,
        participant_secrets=SECRETS,
        independent_verifier_secret=VERIFIER_SECRET,
    )
    return descriptor, commitments, beacon, certificate


def test_complete_non_equivocating_certificate_verifies() -> None:
    _descriptor, _commitments, _beacon, certificate = fixture()
    assert certificate.verify(
        approved_independent_verifiers={public_key(VERIFIER_SECRET)}
    )


def test_beacon_must_be_after_commitment_cutoff_and_on_same_chain() -> None:
    descriptor, _commitments, beacon, certificate = fixture()
    stale = replace(certificate, beacon=replace(beacon, block_height=500))
    wrong_chain = replace(certificate, beacon=replace(beacon, chain_genesis_hash=H(b"other")))
    approved = {public_key(VERIFIER_SECRET)}
    assert not stale.verify(approved_independent_verifiers=approved)
    assert not wrong_chain.verify(approved_independent_verifiers=approved)
    assert descriptor.commitment_cutoff_height == 500


def test_missing_or_aborted_receipt_cannot_activate() -> None:
    _descriptor, _commitments, _beacon, certificate = fixture()
    approved = {public_key(VERIFIER_SECRET)}
    assert not replace(certificate, receipts=certificate.receipts[:-1]).verify(
        approved_independent_verifiers=approved
    )
    aborted = replace(certificate.receipts[0], completed=False)
    assert not replace(certificate, receipts=(aborted,) + certificate.receipts[1:]).verify(
        approved_independent_verifiers=approved
    )


def test_commitment_or_artifact_equivocation_is_detected() -> None:
    _descriptor, commitments, _beacon, certificate = fixture()
    approved = {public_key(VERIFIER_SECRET)}
    reused = replace(
        commitments[1],
        private_view_commitment=commitments[0].private_view_commitment,
    )
    # The altered row also lacks a valid signature, and either condition rejects.
    assert not replace(certificate, commitments=(commitments[0], reused, commitments[2])).verify(
        approved_independent_verifiers=approved
    )
    assert not replace(certificate, artifact_digest=H(b"substituted artifact")).verify(
        approved_independent_verifiers=approved
    )


def test_independent_verifier_must_be_approved_and_not_a_participant() -> None:
    descriptor, _commitments, _beacon, certificate = fixture()
    assert not certificate.verify(approved_independent_verifiers={public_key(777)})
    participant_key = descriptor.participants[0].signing_pubkey
    # Key substitution fails both independence and signature verification.
    substituted = replace(certificate, independent_verifier_pubkey=participant_key)
    assert not substituted.verify(approved_independent_verifiers={participant_key})


def test_commitment_publication_anchor_must_precede_cutoff_and_match_signed_set() -> None:
    descriptor, _commitments, _beacon, certificate = fixture()
    approved = {public_key(VERIFIER_SECRET)}
    late = replace(
        certificate,
        commitment_anchor=replace(
            certificate.commitment_anchor,
            block_height=descriptor.commitment_cutoff_height + 1,
        ),
    )
    substituted = replace(
        certificate,
        commitment_anchor=replace(
            certificate.commitment_anchor,
            commitment_set_digest=H(b"another commitment set"),
        ),
    )
    assert not late.verify(approved_independent_verifiers=approved)
    assert not substituted.verify(approved_independent_verifiers=approved)
