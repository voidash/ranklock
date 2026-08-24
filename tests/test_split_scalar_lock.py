from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.babe_positive_lock import (
    deterministic_fixture,
    honest_projective_output,
    statement_digest,
)
from ranklock.bip340 import public_key
from ranklock.bn254_real import CURVE_ORDER, compress_g1, multiply, decompress_g1
from ranklock.predicate_locked_hashlock import BoundTransaction, TxOutput
from ranklock.split_scalar_lock import (
    ScaleKnowledgeProof,
    SignedSplitScalarBundle,
    SplitScalarBundleSignature,
    SplitScalarHashlockConnector,
    SplitScalarLockError,
    UnsignedSplitScalarBundle,
    aggregate_projective_outputs,
    assemble_signed_split_scalar_bundle,
    presign_split_scalar_graph,
    setup_split_scalar_fixture,
    split_hashlock_ack_leaf_script,
    unlock_split_scalar_bundle,
)


def _fixture():
    vk, public_inputs, proof = deterministic_fixture(
        public_inputs=(17,), context=b"ranklock-v025-split-scalar-test-vk"
    )
    context = sha256(b"ranklock-v025-split-scalar/context").digest()
    participant_secrets = (101, 103)
    scalar_shares = (41, 73)
    preimages = (sha256(b"preimage-0").digest(), sha256(b"preimage-1").digest())
    bundle, chosen = setup_split_scalar_fixture(
        vk=vk,
        public_inputs=public_inputs,
        expected_context_digest=context,
        participant_secrets=participant_secrets,
        scalar_shares=scalar_shares,
        retained_object_digests=(sha256(b"artifact-0").digest(), sha256(b"artifact-1").digest()),
        retained_object_sizes=(1_044_952, 1_044_952),
        preimages=preimages,
    )
    outputs = tuple(honest_projective_output(proof, scale=share) for share in scalar_shares)
    return {
        "vk": vk,
        "public_inputs": public_inputs,
        "proof": proof,
        "context": context,
        "participant_secrets": participant_secrets,
        "scalar_shares": scalar_shares,
        "preimages": chosen,
        "bundle": bundle,
        "outputs": outputs,
    }


def test_bundle_roundtrip_unlock_and_aggregate_output():
    fixture = _fixture()
    bundle = fixture["bundle"]
    assert bundle.verify_for_statement(
        vk=fixture["vk"],
        public_inputs=fixture["public_inputs"],
        expected_context_digest=fixture["context"],
    )
    assert SignedSplitScalarBundle.parse(bundle.encoded) == bundle
    assert UnsignedSplitScalarBundle.parse(bundle.unsigned.encoded) == bundle.unsigned

    result = unlock_split_scalar_bundle(
        bundle,
        vk=fixture["vk"],
        public_inputs=fixture["public_inputs"],
        proof=fixture["proof"],
        participant_outputs_g1=fixture["outputs"],
        expected_context_digest=fixture["context"],
    )
    assert result.preimages == fixture["preimages"]
    expected_scale = sum(fixture["scalar_shares"]) % CURVE_ORDER
    expected = honest_projective_output(fixture["proof"], scale=expected_scale)
    assert result.aggregate_output_g1 == expected
    assert result.aggregate_output_g1 == aggregate_projective_outputs(fixture["outputs"])
    assert bundle.unsigned.total_retained_bytes == 2_089_904
    assert tuple(
        item.nonce_namespace_base for item in bundle.unsigned.contributions
    ) == (0, 2)


def test_missing_wrong_or_crosswired_participant_output_fails():
    fixture = _fixture()
    with pytest.raises(SplitScalarLockError, match="one projective output"):
        unlock_split_scalar_bundle(
            fixture["bundle"],
            vk=fixture["vk"],
            public_inputs=fixture["public_inputs"],
            proof=fixture["proof"],
            participant_outputs_g1=fixture["outputs"][:1],
            expected_context_digest=fixture["context"],
        )
    with pytest.raises(SplitScalarLockError, match="participant 0"):
        unlock_split_scalar_bundle(
            fixture["bundle"],
            vk=fixture["vk"],
            public_inputs=fixture["public_inputs"],
            proof=fixture["proof"],
            participant_outputs_g1=tuple(reversed(fixture["outputs"])),
            expected_context_digest=fixture["context"],
        )


def test_scale_proof_bundle_signatures_and_reordering_are_binding():
    fixture = _fixture()
    bundle = fixture["bundle"]
    first = bundle.unsigned.contributions[0]
    tampered_proof = replace(
        first.scale_proof,
        response=(first.scale_proof.response + 1) % CURVE_ORDER,
    )
    tampered_first = replace(first, scale_proof=tampered_proof)
    unsigned = replace(
        bundle.unsigned,
        contributions=(tampered_first, bundle.unsigned.contributions[1]),
    )
    tampered = replace(bundle, unsigned=unsigned)
    assert not tampered.verify_for_statement(
        vk=fixture["vk"],
        public_inputs=fixture["public_inputs"],
        expected_context_digest=fixture["context"],
    )

    bad_signature = bytearray(bundle.signatures[0]); bad_signature[-1] ^= 1
    assert not replace(bundle, signatures=(bytes(bad_signature), bundle.signatures[1])).verify_signatures()

    with pytest.raises(SplitScalarLockError, match="ordered"):
        UnsignedSplitScalarBundle(
            bundle.unsigned.context_digest,
            tuple(reversed(bundle.unsigned.contributions)),
        )

    overlapping_second = replace(
        bundle.unsigned.contributions[1], nonce_namespace_base=1
    )
    with pytest.raises(SplitScalarLockError, match="namespace ranges overlap"):
        UnsignedSplitScalarBundle(
            bundle.unsigned.context_digest,
            (bundle.unsigned.contributions[0], overlapping_second),
        )


def test_aggregate_zero_scalar_is_rejected():
    vk, public_inputs, _proof = deterministic_fixture()
    with pytest.raises(SplitScalarLockError, match="aggregate point is infinity"):
        setup_split_scalar_fixture(
            vk=vk,
            public_inputs=public_inputs,
            expected_context_digest=sha256(b"zero aggregate context").digest(),
            participant_secrets=(107, 109),
            scalar_shares=(19, CURVE_ORDER - 19),
            retained_object_digests=(sha256(b"z0").digest(), sha256(b"z1").digest()),
            retained_object_sizes=(1_044_952, 1_044_952),
            preimages=(sha256(b"k0").digest(), sha256(b"k1").digest()),
        )


def test_split_hashlock_script_and_presigned_graph_require_every_preimage():
    fixture = _fixture()
    n_of_n_secret = 131
    hashes = tuple(sha256(item).digest() for item in fixture["preimages"])
    connector = SplitScalarHashlockConnector(
        n_of_n_pubkey=public_key(n_of_n_secret),
        preimage_hashes=hashes,
        relative_delay=12,
        value_sat=100_000,
    )
    assert connector.ack_script == split_hashlock_ack_leaf_script(
        connector.n_of_n_pubkey, hashes
    )
    assert connector.verify_preimages(fixture["preimages"])
    assert not connector.verify_preimages(fixture["preimages"][:1])
    wrong = (fixture["preimages"][0], bytes(32))
    assert not connector.verify_preimages(wrong)

    prevout = sha256(b"connector txid").digest() + (0).to_bytes(4, "little")
    context = sha256(b"graph context").digest()
    ack = BoundTransaction(
        "ack",
        prevout,
        0xFFFFFFFF,
        (TxOutput(99_000, b"\x51"),),
        context,
    )
    nack = BoundTransaction(
        "nack",
        prevout,
        12,
        (TxOutput(98_500, b"\x51"),),
        context,
    )
    graph = presign_split_scalar_graph(
        connector, ack, nack, n_of_n_secret=n_of_n_secret
    )
    assert graph.verify_ack_witness(fixture["preimages"])
    assert not graph.verify_ack_witness(fixture["preimages"][:1])
    assert not graph.verify_timeout_nack(blocks_elapsed=11)
    assert graph.verify_timeout_nack(blocks_elapsed=12)


def test_noncanonical_bundle_and_wrong_statement_fail():
    fixture = _fixture()
    bundle = fixture["bundle"]
    with pytest.raises(SplitScalarLockError):
        SignedSplitScalarBundle.parse(bundle.encoded + b"\x00")
    legacy_unsigned = bytearray(bundle.unsigned.encoded)
    legacy_unsigned[8:10] = (2).to_bytes(2, "big")
    with pytest.raises(SplitScalarLockError, match="unsupported"):
        UnsignedSplitScalarBundle.parse(bytes(legacy_unsigned))
    assert not bundle.verify_for_statement(
        vk=fixture["vk"],
        public_inputs=(18,),
        expected_context_digest=fixture["context"],
    )


def test_bundle_context_is_the_only_positive_lock_session_authority():
    fixture = _fixture()
    bundle = fixture["bundle"]
    expected_statement = statement_digest(
        fixture["vk"],
        fixture["public_inputs"],
        session_context=fixture["context"],
    )
    assert all(
        contribution.positive_lock.statement_digest == expected_statement
        for contribution in bundle.unsigned.contributions
    )

    other_context = sha256(b"other authorization context").digest()
    rebound_unsigned = replace(bundle.unsigned, context_digest=other_context)
    rebound_bundle = SignedSplitScalarBundle.create(
        rebound_unsigned,
        participant_secrets=fixture["participant_secrets"],
    )
    assert not rebound_bundle.verify_for_statement(
        vk=fixture["vk"],
        public_inputs=fixture["public_inputs"],
        expected_context_digest=fixture["context"],
    )
    # The attacker may align the externally claimed context with the newly
    # signed bundle.  Verification must still fail because the positive locks
    # were created for the original context.
    assert not rebound_bundle.verify_for_statement(
        vk=fixture["vk"],
        public_inputs=fixture["public_inputs"],
        expected_context_digest=other_context,
    )
    assert not bundle.verify_for_statement(
        vk=fixture["vk"],
        public_inputs=fixture["public_inputs"],
        expected_context_digest=other_context,
    )

    with pytest.raises(SplitScalarLockError, match="statement qualification"):
        unlock_split_scalar_bundle(
            rebound_bundle,
            vk=fixture["vk"],
            public_inputs=fixture["public_inputs"],
            proof=fixture["proof"],
            participant_outputs_g1=fixture["outputs"],
            expected_context_digest=other_context,
        )


def test_unlock_canonicalizes_public_input_iterable_once():
    fixture = _fixture()
    result = unlock_split_scalar_bundle(
        fixture["bundle"],
        vk=fixture["vk"],
        public_inputs=(value for value in fixture["public_inputs"]),
        proof=fixture["proof"],
        participant_outputs_g1=fixture["outputs"],
        expected_context_digest=fixture["context"],
    )
    assert result.preimages == fixture["preimages"]


def test_bundle_signatures_can_be_produced_in_independent_processes():
    fixture = _fixture()
    unsigned = fixture["bundle"].unsigned
    messages = tuple(
        SplitScalarBundleSignature.create(
            unsigned,
            participant_index=index,
            participant_secret=secret,
        )
        for index, secret in enumerate(fixture["participant_secrets"])
    )
    assert all(SplitScalarBundleSignature.parse(item.encoded) == item for item in messages)
    assembled = assemble_signed_split_scalar_bundle(unsigned, tuple(reversed(messages)))
    assert assembled == fixture["bundle"]

    with pytest.raises(SplitScalarLockError, match="duplicate|incomplete|one bundle signature"):
        assemble_signed_split_scalar_bundle(unsigned, (messages[0], messages[0]))
    bad = replace(messages[1], unsigned_digest=sha256(b"other bundle").digest())
    with pytest.raises(SplitScalarLockError, match="failed verification"):
        assemble_signed_split_scalar_bundle(unsigned, (messages[0], bad))
