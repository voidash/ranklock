from __future__ import annotations

from ranklock.bn254_real import FQ12
from ranklock.one_sided_static_session_gap import (
    IdentitySessionAudit,
    PublicAffineShiftBarrier,
    one_sided_static_session_checkpoint,
)


def test_identity_normalized_equation_has_no_direct_session_entropy() -> None:
    audit = IdentitySessionAudit(17, 23, 29, 31)
    assert audit.equation.accepts(audit.witness)
    assert audit.direct_residual == FQ12.one()
    assert audit.scaled_residual == FQ12.one()
    assert audit.session_digest == audit.public_identity_digest
    assert not audit.direct_lock_has_entropy


def test_identity_session_is_independent_of_accepting_witness() -> None:
    left = IdentitySessionAudit(17, 23, 29, 31)
    right = IdentitySessionAudit(17, 23, 29, 37)
    assert left.witness != right.witness
    assert left.session_digest == right.session_digest
    assert left.session_digest == left.public_identity_digest


def test_public_affine_nonidentity_target_leaks_through_scaled_anchors() -> None:
    audit = IdentitySessionAudit(17, 23, 29, 31)
    barrier = PublicAffineShiftBarrier.for_one_sided_equation(
        audit.equation,
        scale_r=audit.scale_r,
    )
    assert barrier.target != FQ12.one()
    assert barrier.public_reconstruction == barrier.target_to_scale
    assert barrier.leaks_scaled_target


def test_checkpoint_separates_size_pass_from_crypto_failure() -> None:
    checkpoint = one_sided_static_session_checkpoint()
    assert checkpoint["size_gate"]["decision"] == "PASS"
    assert checkpoint["size_gate"]["activation_plus_future_proof_bytes"] < 1 << 20
    assert checkpoint["cryptographic_gate"]["decision"] == "FAIL"
    assert not checkpoint["cryptographic_gate"]["constructed_static_witness_lift"]
    assert checkpoint["overall_decision"].startswith("CONDITIONAL_SIZE_PASS")
