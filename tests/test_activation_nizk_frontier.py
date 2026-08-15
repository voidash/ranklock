from __future__ import annotations

from ranklock.activation_nizk_frontier import (
    ActivationPublicStatement,
    CeremonyContribution,
    activation_nizk_frontier,
    ceremony_decision,
    evaluate_visible_activation_relation,
)
from ranklock.ciphertext_free_fault_key import setup_derived_fault_key_share
from ranklock.split_basis_ppe_we import build_scalar_fixture


def _share(signer: bytes, scale: int, nonce: int):
    relation, _witness = build_scalar_fixture(
        witness_coefficients=((1, 1), (2, 3)),
        witness_scalars=(5, 7),
        anchor_scalars=(11, 13),
        statement_g2_scalars=(17,),
        context=b"ranklock-v0.17-activation-nizk",
    )
    return setup_derived_fault_key_share(
        relation,
        epoch=b"n" * 32,
        signer_id=signer,
        scale=scale,
        proof_nonce=nonce,
    )


def test_activation_relation_is_exact_and_executable() -> None:
    share, witness = _share(b"alice", 19, 23)
    assert evaluate_visible_activation_relation(share, witness.scale)
    assert not evaluate_visible_activation_relation(share, witness.scale + 1)
    report = activation_nizk_frontier(share)
    assert report["ciphertext_or_payload_consistency_needed"] is False
    assert report["ordinary_ZK_proof_system_can_instantiate_relation"] is True
    assert report["ordinary_ZK_proof_implemented_here"] is False


def test_ceremony_fails_closed_before_funding() -> None:
    alice, _ = _share(b"alice", 29, 31)
    bob, _ = _share(b"bob", 37, 41)
    contributions = tuple(
        CeremonyContribution(
            ActivationPublicStatement.from_share(share),
            b"proof-" + share.signer_id,
            b"test-proof-system",
        )
        for share in (alice, bob)
    )
    accepted = ceremony_decision(
        contributions,
        expected_signer_ids=(b"alice", b"bob"),
        proof_verdicts=(True, True),
    )
    assert accepted.funded
    assert len(accepted.accepted_receipts) == 2

    rejected = ceremony_decision(
        contributions,
        expected_signer_ids=(b"alice", b"bob"),
        proof_verdicts=(True, False),
    )
    assert not rejected.funded
    assert "failed" in rejected.reason
