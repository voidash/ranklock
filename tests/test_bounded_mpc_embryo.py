from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.babe_positive_lock import (
    deterministic_fixture,
    honest_projective_output,
    setup_positive_lock,
)
from ranklock.bip340 import public_key
from ranklock.bn254_real import G1, compress_g1, multiply
from ranklock.bounded_mpc_embryo import (
    MIB,
    ActiveMpcProfile,
    BoundedEmbryoError,
    BoundedSlotLedger,
    EmbryoPaperCost,
    SignedBoundedEmbryoManifest,
    UnsignedBoundedEmbryoManifest,
    active_mpc_generator_code_hash,
    assemble_signed_manifest,
    bounded_embryo_checkpoint,
    execute_certified_slot,
    recover_affine_state_from_two_queries,
    sign_manifest_fixture,
    slot_descriptor_from_artifact,
)


def _fixture(*, slot_count: int = 2):
    session_context = b"ranklock-v0.21-bounded-embryo-test"
    context_digest = sha256(b"context\x00" + session_context).digest()
    vk, inputs, proof = deterministic_fixture(context=session_context)
    scale = 37
    lock = setup_positive_lock(
        vk,
        inputs,
        b"A" * 32,
        scale=scale,
        session_context=session_context,
    )
    cost = EmbryoPaperCost()
    slots = tuple(
        slot_descriptor_from_artifact(
            slot_id,
            bytes((65 + slot_id,)) * cost.artifact_bytes,
            input_label_commitment=sha256(
                b"input-label-root" + slot_id.to_bytes(4, "big")
            ).digest(),
            independence_nonce=b"independent-random-tape" + slot_id.to_bytes(4, "big"),
        )
        for slot_id in range(slot_count)
    )
    secrets = (7, 11)
    pubkeys = tuple(sorted(public_key(secret) for secret in secrets))
    profile = ActiveMpcProfile(parties=len(secrets))
    unsigned = UnsignedBoundedEmbryoManifest(
        context_digest=context_digest,
        generator_code_hash=active_mpc_generator_code_hash(profile),
        transcript_digest=sha256(b"active-mpc-transcript").digest(),
        positive_lock=lock,
        slots=slots,
        contributor_pubkeys=pubkeys,
    )
    manifest = sign_manifest_fixture(unsigned, secrets)
    return {
        "session_context": session_context,
        "context_digest": context_digest,
        "vk": vk,
        "inputs": inputs,
        "proof": proof,
        "scale": scale,
        "secrets": secrets,
        "pubkeys": pubkeys,
        "profile": profile,
        "manifest": manifest,
    }


def test_appendix_c_cost_reconstructs_exact_slot_size_and_hashes():
    cost = EmbryoPaperCost()
    assert cost.chunk_conversion_bytes_per_coordinate == 14_848
    assert cost.chunk_conversion_hashes_per_coordinate == 188_352
    assert cost.residue_evaluation_bytes_per_coordinate == 126_720
    assert cost.residue_evaluation_hashes_per_coordinate == 1_147_358
    assert cost.it_label_bytes == 227_712
    assert cost.it_label_hashes == 3_174_552
    assert cost.curve_check_bytes == 371
    assert cost.artifact_bytes == 511_219
    assert cost.hash_calls == 5_845_972


def test_two_slot_manifest_is_exactly_sub_mib_and_three_slots_cannot_fit():
    fixture = _fixture()
    manifest = fixture["manifest"]
    assert manifest.encoded_bytes == 748
    assert manifest.retained_bytes == 1_023_186
    assert manifest.margin_to_one_mib == 25_390
    assert manifest.retained_bytes < MIB
    checkpoint = bounded_embryo_checkpoint(
        manifest_bytes_for_two_slots_two_contributors=manifest.encoded_bytes
    )
    assert checkpoint["q2_total_retained_bytes"] == manifest.retained_bytes
    assert checkpoint["q2_margin_to_one_mib"] == manifest.margin_to_one_mib
    assert checkpoint["q3_cannot_fit_one_mib_even_before_manifest"] is True


def test_manifest_round_trip_requires_exact_registered_committee():
    fixture = _fixture()
    manifest = fixture["manifest"]
    parsed = SignedBoundedEmbryoManifest.parse(manifest.encoded)
    assert parsed == manifest
    assert parsed.verify(
        required_pubkeys=fixture["pubkeys"],
        expected_context_digest=fixture["context_digest"],
        expected_generator_code_hash=active_mpc_generator_code_hash(fixture["profile"]),
    )
    assert not parsed.verify(required_pubkeys=(fixture["pubkeys"][0],))
    assert not parsed.verify(required_pubkeys=fixture["pubkeys"], expected_context_digest=bytes(32))


def test_manifest_tamper_and_missing_signature_are_rejected():
    fixture = _fixture()
    manifest = fixture["manifest"]
    tampered = bytearray(manifest.encoded)
    tampered[20] ^= 1
    parsed = SignedBoundedEmbryoManifest.parse(bytes(tampered))
    assert not parsed.verify(required_pubkeys=fixture["pubkeys"])

    with pytest.raises(BoundedEmbryoError):
        assemble_signed_manifest(
            manifest.unsigned,
            {fixture["pubkeys"][0]: manifest.contributor_signatures[0]},
        )


def test_slots_must_have_independent_roots_and_random_tapes():
    fixture = _fixture()
    unsigned = fixture["manifest"].unsigned
    duplicate = replace(
        unsigned.slots[1],
        independence_digest=unsigned.slots[0].independence_digest,
    )
    with pytest.raises(BoundedEmbryoError):
        replace(unsigned, slots=(unsigned.slots[0], duplicate))


def test_slot_is_burned_before_success_abort_timeout_or_retry():
    fixture = _fixture()
    ledger = BoundedSlotLedger(fixture["context_digest"], 2)
    ledger.begin(
        0,
        context_digest=fixture["context_digest"],
        input_digest=sha256(b"A").digest(),
        authorization_digest=sha256(b"authorization").digest(),
    )
    assert ledger.finalize(0, outcome="abort").outcome == "abort"
    assert ledger.remaining == 1
    with pytest.raises(BoundedEmbryoError):
        ledger.begin(
            0,
            context_digest=fixture["context_digest"],
            input_digest=sha256(b"A").digest(),
            authorization_digest=sha256(b"authorization").digest(),
        )


def test_two_affine_queries_recover_the_entire_reused_state():
    modulus = 101
    a, b = 17, 29
    v1, v2 = 3, 44
    t1 = (a + b * v1) % modulus
    t2 = (a + b * v2) % modulus
    assert recover_affine_state_from_two_queries(v1, t1, v2, t2, modulus=modulus) == (a, b)


def test_real_pairing_certificate_accepts_honest_output_and_burns_bad_slot():
    fixture = _fixture()
    manifest = fixture["manifest"]
    ledger = BoundedSlotLedger(fixture["context_digest"], 2)
    honest = honest_projective_output(fixture["proof"], scale=fixture["scale"])
    use = execute_certified_slot(
        manifest=manifest,
        required_pubkeys=fixture["pubkeys"],
        ledger=ledger,
        slot_id=0,
        input_digest=fixture["proof"].digest,
        authorization_digest=sha256(b"transaction-label-revelation-0").digest(),
        vk=fixture["vk"],
        proof=fixture["proof"],
        output_r_a_g1=honest,
    )
    assert use.outcome == "success"

    wrong = compress_g1(multiply(G1, 999, group="g1"))
    with pytest.raises(BoundedEmbryoError):
        execute_certified_slot(
            manifest=manifest,
            required_pubkeys=fixture["pubkeys"],
            ledger=ledger,
            slot_id=1,
            input_digest=fixture["proof"].digest,
            authorization_digest=sha256(b"transaction-label-revelation-1").digest(),
            vk=fixture["vk"],
            proof=fixture["proof"],
            output_r_a_g1=wrong,
        )
    assert ledger.use(1).outcome == "malformed"
    assert ledger.remaining == 0


def test_v019_unimportable_modules_are_now_exercised():
    from ranklock.authenticated_counterproof_semantics import (
        CounterproofContext,
        authenticate_bridge_proof,
    )
    from ranklock.predicate_locked_hashlock import ValidityFirstHashlockConnector

    context = CounterproofContext(
        program_id=b"program",
        verifier_key_digest=b"vk",
        deposit_id=b"deposit",
        game_index=1,
        operator_index=0,
        bridge_proof_txid=b"placeholder",
    )
    authenticated = authenticate_bridge_proof(
        b"bridge-proof-transaction",
        operator_secret=19,
        context_without_txid=context,
    )
    assert authenticated.verify()
    connector = ValidityFirstHashlockConnector(
        n_of_n_pubkey=public_key(23),
        preimage_hash=sha256(b"P" * 32).digest(),
        relative_delay=10,
        value_sat=100_000,
    )
    assert len(connector.output_key) == 32
