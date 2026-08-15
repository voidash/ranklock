from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock.bn254_real import G1, compress_g1, multiply
from ranklock.ciphertext_free_fault_key import (
    DerivedFaultKeyError,
    build_fault_key_committee,
    ciphertext_free_fault_key_frontier,
    recover_committee_fault_scalar,
    recover_fault_scalar,
    setup_derived_fault_key_share,
    verify_activation_witness,
)
from ranklock.real_secp import N, base_multiply, compress
from ranklock.split_basis_ppe_we import build_scalar_fixture


def _fixture():
    return build_scalar_fixture(
        witness_coefficients=((1, 1), (2, 3), (5, 8)),
        witness_scalars=(7, 11, 13),
        anchor_scalars=(17, 19),
        statement_g2_scalars=(23, 29),
        context=b"ranklock-v0.17-derived-fault-key",
    )


def test_accepting_pairing_session_derives_real_secp_fault_key_without_ciphertext() -> None:
    relation, witness = _fixture()
    share, setup_witness = setup_derived_fault_key_share(
        relation,
        epoch=b"e" * 32,
        signer_id=b"alice",
        scale=31,
        proof_nonce=37,
    )
    assert share.ciphertext_bytes == 0
    assert verify_activation_witness(share, setup_witness.scale)
    recovered = recover_fault_scalar(share, witness)
    assert recovered == setup_witness.fault_scalar
    assert compress(base_multiply(recovered)) == share.fault_public_key

    forged = list(witness)
    forged[0] = compress_g1(multiply(G1, 41, group="g1"))
    with pytest.raises(DerivedFaultKeyError, match="does not derive"):
        recover_fault_scalar(share, tuple(forged))


def test_epoch_and_signer_domain_separation_prevent_replay() -> None:
    relation, witness = _fixture()
    first, _ = setup_derived_fault_key_share(
        relation, epoch=b"a" * 32, signer_id=b"alice", scale=43, proof_nonce=47
    )
    second, _ = setup_derived_fault_key_share(
        relation, epoch=b"b" * 32, signer_id=b"alice", scale=43, proof_nonce=47
    )
    third, _ = setup_derived_fault_key_share(
        relation, epoch=b"a" * 32, signer_id=b"bob", scale=43, proof_nonce=47
    )
    assert len({first.fault_public_key, second.fault_public_key, third.fault_public_key}) == 3
    assert recover_fault_scalar(first, witness) != recover_fault_scalar(second, witness)


def test_activation_relation_rejects_wrong_scale_or_substituted_fault_key() -> None:
    relation, _witness = _fixture()
    share, setup_witness = setup_derived_fault_key_share(
        relation, epoch=b"z" * 32, signer_id=b"alice", scale=53, proof_nonce=59
    )
    assert verify_activation_witness(share, setup_witness.scale)
    assert not verify_activation_witness(share, setup_witness.scale + 1)
    substituted = replace(
        share,
        fault_public_key=compress(base_multiply(67)),
    )
    assert not verify_activation_witness(substituted, setup_witness.scale)


def test_multi_contributor_committee_recovers_bip340_normalized_aggregate() -> None:
    relation, witness = _fixture()
    shares = []
    for signer_id, scale, nonce in (
        (b"carol", 71, 73),
        (b"alice", 79, 83),
        (b"bob", 89, 97),
    ):
        share, _setup = setup_derived_fault_key_share(
            relation,
            epoch=b"c" * 32,
            signer_id=signer_id,
            scale=scale,
            proof_nonce=nonce,
        )
        shares.append(share)
    committee = build_fault_key_committee(tuple(reversed(shares)))
    assert tuple(share.signer_id for share in committee.shares) == (
        b"alice",
        b"bob",
        b"carol",
    )
    secret = recover_committee_fault_scalar(committee, witness)
    assert 0 < secret < N
    point = base_multiply(secret)
    assert point is not None
    assert point[0].to_bytes(32, "big") == committee.aggregate_xonly_public_key
    assert point[1] % 2 == 0

    report = ciphertext_free_fault_key_frontier(committee.shares[0], committee)
    assert report["committee_ciphertext_bytes"] == 0
    assert report["ciphertext_substitution_attack_eliminated"] is True
    assert report["activation_zero_knowledge_proof_constructed"] is False
