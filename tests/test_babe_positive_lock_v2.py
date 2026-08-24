from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.babe_positive_lock import (
    BabePositiveLockError,
    BabePositiveLockV2,
    assess_babe_positive_lock_v2,
    deterministic_fixture,
    honest_projective_output,
    setup_babe_positive_lock_v2,
    setup_positive_lock,
    statement_digest,
    statement_session,
    unlock_babe_positive_lock_v2,
)
from ranklock.bip340 import public_key, sign, verify
from ranklock.bn254_real import decompress_g1, decompress_g2, neg, pairing_product
from ranklock.bounded_mpc_embryo import encode_positive_lock


@pytest.fixture
def positive_fixture():
    vk, public_inputs, proof = deterministic_fixture(
        public_inputs=(17,),
        context=b"ranklock-babe-positive-lock-v2-test",
    )
    return vk, public_inputs, proof


def test_legacy_plaintext_hash_breaks_chosen_message_hiding(positive_fixture) -> None:
    vk, public_inputs, _proof = positive_fixture
    context = sha256(b"legacy-chosen-message-context").digest()
    message_zero = bytes(64)
    message_one = bytes([1]) + bytes(63)
    lock = setup_positive_lock(
        vk,
        public_inputs,
        message_one,
        scale=37,
        session_context=context,
    )
    digest = statement_digest(vk, public_inputs, session_context=context)

    candidate_hashes = tuple(
        sha256(
            b"ranklock/babe-positive-lock/payload/v1\x00" + digest + candidate
        ).digest()
        for candidate in (message_zero, message_one)
    )
    assert candidate_hashes[0] != candidate_hashes[1]
    assert lock.payload_hash == candidate_hashes[1]
    assert lock.payload_hash != candidate_hashes[0]


def test_v2_roundtrip_matches_the_exact_babe_session_equation(
    positive_fixture,
) -> None:
    vk, public_inputs, proof = positive_fixture
    context = sha256(b"v2-roundtrip-context").digest()
    payload = sha256(b"left").digest() + sha256(b"right").digest()
    scale = 41
    lock = setup_babe_positive_lock_v2(
        vk,
        public_inputs,
        payload,
        scale=scale,
        session_context=context,
    )
    r_a_g1 = honest_projective_output(proof, scale=scale)

    assert not hasattr(lock, "payload_hash")
    assert not hasattr(lock, "authentication_tag")
    assert lock.encoded_bytes == 202
    assert BabePositiveLockV2.parse(lock.encoded) == lock
    assert (
        unlock_babe_positive_lock_v2(
            vk,
            public_inputs,
            proof,
            lock,
            r_a_g1,
            session_context=context,
        )
        == payload
    )

    setup_session = statement_session(vk, public_inputs) ** scale
    decrypt_session = pairing_product(
        (
            (decompress_g1(r_a_g1), decompress_g2(proof.b_g2)),
            (neg(decompress_g1(proof.c_g1)), decompress_g2(lock.r_delta_g2)),
        )
    )
    assert decrypt_session == setup_session


def test_v2_rejects_invalid_proof_wrong_projective_output_and_context(
    positive_fixture,
) -> None:
    vk, public_inputs, proof = positive_fixture
    context = sha256(b"v2-negative-context").digest()
    scale = 43
    lock = setup_babe_positive_lock_v2(
        vk,
        public_inputs,
        bytes(range(64)),
        scale=scale,
        session_context=context,
    )
    r_a_g1 = honest_projective_output(proof, scale=scale)
    invalid_proof = replace(proof, c_g1=proof.a_g1)

    with pytest.raises(BabePositiveLockError, match="Groth16 proof is invalid"):
        unlock_babe_positive_lock_v2(
            vk,
            public_inputs,
            invalid_proof,
            lock,
            honest_projective_output(invalid_proof, scale=scale),
            session_context=context,
        )
    with pytest.raises(BabePositiveLockError, match="projective scalar output"):
        unlock_babe_positive_lock_v2(
            vk,
            public_inputs,
            proof,
            lock,
            honest_projective_output(proof, scale=scale + 1),
            session_context=context,
        )
    with pytest.raises(BabePositiveLockError, match="another statement"):
        unlock_babe_positive_lock_v2(
            vk,
            public_inputs,
            proof,
            lock,
            r_a_g1,
            session_context=sha256(b"other-context").digest(),
        )


def test_v2_ciphertext_authenticity_is_enforced_by_the_exact_ack_relation(
    positive_fixture,
) -> None:
    vk, public_inputs, proof = positive_fixture
    context = sha256(b"v2-ack-auth-context").digest()
    ack_sighash = sha256(b"exact-ack-sighash").digest()
    release_secret = 101
    signature = sign(
        ack_sighash,
        release_secret,
        sha256(b"ack-signature-aux").digest(),
    )
    scale = 47
    lock = setup_babe_positive_lock_v2(
        vk,
        public_inputs,
        signature,
        scale=scale,
        session_context=context,
    )
    tampered_payload = bytearray(lock.masked_payload)
    tampered_payload[0] ^= 1
    tampered_lock = replace(lock, masked_payload=bytes(tampered_payload))
    recovered = unlock_babe_positive_lock_v2(
        vk,
        public_inputs,
        proof,
        tampered_lock,
        honest_projective_output(proof, scale=scale),
        session_context=context,
    )

    assert recovered != signature
    assert not verify(ack_sighash, public_key(release_secret), recovered)


def test_v2_encoding_rejects_legacy_relabelling_and_noncanonical_bytes(
    positive_fixture,
) -> None:
    vk, public_inputs, _proof = positive_fixture
    context = sha256(b"v2-codec-context").digest()
    v1 = setup_positive_lock(
        vk,
        public_inputs,
        bytes(64),
        scale=53,
        session_context=context,
    )
    v2 = setup_babe_positive_lock_v2(
        vk,
        public_inputs,
        bytes(64),
        scale=53,
        session_context=context,
    )

    with pytest.raises(BabePositiveLockError, match="magic"):
        BabePositiveLockV2.parse(encode_positive_lock(v1))
    with pytest.raises(BabePositiveLockError, match="version"):
        BabePositiveLockV2.parse(v2.encoded[:4] + b"\x00\x03" + v2.encoded[6:])
    with pytest.raises(BabePositiveLockError, match="framing"):
        BabePositiveLockV2.parse(v2.encoded + b"\x00")
    with pytest.raises(BabePositiveLockError, match="truncated"):
        BabePositiveLockV2.parse(v2.encoded[:100])
    with pytest.raises(BabePositiveLockError, match="unknown.*schema"):
        replace(v2, schema="ranklock-babe-positive-lock-v3")


def test_v2_security_assessment_names_the_published_proof_without_overclaiming() -> (
    None
):
    assessment = assess_babe_positive_lock_v2()

    assert assessment.construction_reference == "BABE Construction 1, ePrint 2026/065"
    assert assessment.proof_models == (
        "generic-bilinear-group-model",
        "random-oracle-model",
    )
    assert assessment.reduction_dependencies == ("Groth16 knowledge soundness",)
    assert assessment.exact_ciphertext_shape_implemented is True
    assert assessment.plaintext_commitment_present is False
    assert assessment.local_equivalence_independently_reviewed is False
    assert assessment.complete_public_side_information_qualified is False
    assert assessment.deterministic_non_zk_relation_qualified is False
    assert assessment.bn254_production_profile_approved is False
    assert assessment.production_hiding_theorem_established is False
    assert assessment.funding_eligible is False
    with pytest.raises(ValueError, match="init=False"):
        replace(assessment, funding_eligible=True)
