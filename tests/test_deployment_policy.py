from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.bip340 import public_key
from ranklock.deployment_policy import (
    PRODUCTION_ROLES,
    DeploymentPolicyError,
    RoleAuthority,
    RuntimeSecurityFacts,
    SafetySubject,
    SecurityAttestation,
    SignedFundsSafetyPolicy,
    UnsignedFundsSafetyPolicy,
    evaluate_deployment,
)


NOW = 2_000_000_000


def _digest(tag: bytes) -> bytes:
    return sha256(tag).digest()


def _fixture():
    subject = SafetySubject(
        version="0.25.1",
        source_archive_sha256=_digest(b"source"),
        source_manifest_sha256=_digest(b"manifest"),
        retained_object_sha256=_digest(b"retained"),
        retained_manifest_digest=_digest(b"retained-manifest"),
        generator_code_hash=_digest(b"generator"),
        bridge_commit=_digest(b"bridge-commit"),
        context_digest=_digest(b"context"),
    )
    setup_secrets = (11, 13, 17)
    governance_secrets = (19, 23, 29)
    rollback_witness_secrets = (31, 37)
    authority_secrets = {role: 101 + 2 * i for i, role in enumerate(PRODUCTION_ROLES)}
    role_authorities = tuple(
        sorted(
            (
                RoleAuthority(role, 1, (public_key(authority_secrets[role]),))
                for role in PRODUCTION_ROLES
            ),
            key=lambda item: item.role,
        )
    )
    network = "regtest"
    genesis = _digest(b"regtest-genesis")
    unsigned = UnsignedFundsSafetyPolicy(
        subject_digest=subject.digest,
        network=network,
        chain_genesis_hash=genesis,
        maximum_value_sat=5_000_000,
        minimum_committee_members=3,
        minimum_rollback_witnesses=2,
        minimum_confirmations=6,
        rollback_witness_pubkeys=tuple(
            sorted(public_key(s) for s in rollback_witness_secrets)
        ),
        setup_participant_pubkeys=tuple(sorted(public_key(s) for s in setup_secrets)),
        governance_pubkeys=tuple(sorted(public_key(s) for s in governance_secrets)),
        governance_threshold=2,
        role_authorities=role_authorities,
    )
    policy = SignedFundsSafetyPolicy.create(
        unsigned,
        governance_secrets=governance_secrets[:2],
    )
    runtime = RuntimeSecurityFacts(
        network=network,
        chain_genesis_hash=genesis,
        value_at_risk_sat=1_000_000,
        committee_members=3,
        committee_quorum=3,
        rollback_witnesses=2,
        minimum_confirmations=6,
        rollback_witness_pubkeys=unsigned.rollback_witness_pubkeys,
        bitcoin_core_consensus_crosscheck=True,
        witness_selected_point_binding=True,
        durable_burn_before_release=True,
        rollback_protection_live=True,
        deterministic_fixture_secrets_absent=True,
        secret_file_permissions_locked=True,
    )
    attestations = tuple(
        SecurityAttestation.create(
            role=role,
            subject_digest=subject.digest,
            evidence_digest=_digest(b"evidence/" + role.encode()),
            issued_at=NOW - 100,
            expires_at=NOW + 1000,
            signer_secret=authority_secrets[role],
        )
        for role in PRODUCTION_ROLES
    )
    return subject, policy, runtime, attestations


def test_observe_is_non_authoritative_and_missing_evidence_fails_closed():
    subject, policy, runtime, attestations = _fixture()
    observe = evaluate_deployment(
        mode="observe",
        subject=subject,
        policy=None,
        attestations=(),
        runtime=runtime,
        now=NOW,
    )
    assert observe.can_start and not observe.may_authorize_funds

    denied = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations[:-1],
        runtime=runtime,
        now=NOW,
    )
    assert not denied.can_start
    assert not denied.may_authorize_funds
    assert any("threshold" in failure for failure in denied.failures)


def test_complete_distinct_attestations_enable_only_enforce_mode():
    subject, policy, runtime, attestations = _fixture()
    enforce = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=runtime,
        now=NOW,
    )
    assert enforce.can_start and enforce.may_authorize_funds
    assert not enforce.failures
    assert len(enforce.accepted_attestation_digests) == len(PRODUCTION_ROLES)

    canary = evaluate_deployment(
        mode="canary",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=runtime,
        now=NOW,
    )
    assert canary.can_start and not canary.may_authorize_funds


def test_expiry_tampering_value_cap_and_runtime_gates_deny():
    subject, policy, runtime, attestations = _fixture()
    expired = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=runtime,
        now=NOW + 2000,
    )
    assert not expired.may_authorize_funds

    too_large = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=replace(runtime, value_at_risk_sat=policy.unsigned.maximum_value_sat + 1),
        now=NOW,
    )
    assert any("value at risk" in failure for failure in too_large.failures)

    unbound = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=replace(runtime, witness_selected_point_binding=False),
        now=NOW,
    )
    assert any("witness-to-point" in failure for failure in unbound.failures)

    shallow = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=replace(runtime, minimum_confirmations=policy.unsigned.minimum_confirmations - 1),
        now=NOW,
    )
    assert any("confirmation depth" in failure for failure in shallow.failures)

    tampered = replace(attestations[0], evidence_digest=_digest(b"other"))
    denied = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=(tampered,) + attestations[1:],
        runtime=runtime,
        now=NOW,
    )
    assert not denied.may_authorize_funds


def test_split_scalar_setup_mode_replaces_active_mpc_role_but_adds_runtime_gates():
    from ranklock.deployment_policy import (
        COMMON_PRODUCTION_ROLES,
        ROLE_SPLIT_SCALAR_SETUP,
    )

    subject = SafetySubject(
        version="0.25.1-split",
        source_archive_sha256=_digest(b"split/source"),
        source_manifest_sha256=_digest(b"split/manifest"),
        retained_object_sha256=_digest(b"split/retained"),
        retained_manifest_digest=_digest(b"split/retained-manifest"),
        generator_code_hash=_digest(b"split/generator"),
        bridge_commit=_digest(b"split/bridge"),
        context_digest=_digest(b"split/context"),
    )
    setup_secrets = (311, 313)
    governance_secrets = (317, 331)
    rollback_witness_secrets = (337, 347)
    required_roles = (ROLE_SPLIT_SCALAR_SETUP,) + COMMON_PRODUCTION_ROLES
    authority_secrets = {role: 401 + 2 * i for i, role in enumerate(required_roles)}
    authorities = tuple(
        sorted(
            (
                RoleAuthority(role, 1, (public_key(authority_secrets[role]),))
                for role in required_roles
            ),
            key=lambda item: item.role,
        )
    )
    genesis = _digest(b"split/genesis")
    policy = SignedFundsSafetyPolicy.create(
        UnsignedFundsSafetyPolicy(
            subject_digest=subject.digest,
            network="regtest",
            chain_genesis_hash=genesis,
            maximum_value_sat=1_000_000,
            minimum_committee_members=2,
            minimum_rollback_witnesses=2,
        minimum_confirmations=6,
            rollback_witness_pubkeys=tuple(
                sorted(public_key(s) for s in rollback_witness_secrets)
            ),
            setup_participant_pubkeys=tuple(sorted(public_key(s) for s in setup_secrets)),
            governance_pubkeys=tuple(sorted(public_key(s) for s in governance_secrets)),
            governance_threshold=2,
            role_authorities=authorities,
            setup_security_mode="split-scalar-n-of-n",
        ),
        governance_secrets=governance_secrets,
    )
    runtime = RuntimeSecurityFacts(
        network="regtest",
        chain_genesis_hash=genesis,
        value_at_risk_sat=100_000,
        committee_members=2,
        committee_quorum=2,
        rollback_witnesses=2,
        minimum_confirmations=6,
        rollback_witness_pubkeys=policy.unsigned.rollback_witness_pubkeys,
        bitcoin_core_consensus_crosscheck=True,
        witness_selected_point_binding=True,
        durable_burn_before_release=True,
        rollback_protection_live=True,
        deterministic_fixture_secrets_absent=True,
        secret_file_permissions_locked=True,
        setup_security_mode="split-scalar-n-of-n",
        independent_scalar_artifacts=True,
        all_ack_preimages_required=True,
        split_scalar_bundle_verified=True,
    )
    attestations = tuple(
        SecurityAttestation.create(
            role=role,
            subject_digest=subject.digest,
            evidence_digest=_digest(b"split/evidence/" + role.encode()),
            issued_at=NOW - 1,
            expires_at=NOW + 1000,
            signer_secret=authority_secrets[role],
        )
        for role in required_roles
    )
    allowed = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=runtime,
        now=NOW,
    )
    assert allowed.may_authorize_funds and not allowed.failures

    denied = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=replace(runtime, all_ack_preimages_required=False),
        now=NOW,
    )
    assert not denied.may_authorize_funds
    assert any("every scalar-share preimage" in failure for failure in denied.failures)


def test_independent_audit_authorities_are_disjoint_from_each_other_and_operations():
    from ranklock.deployment_policy import (
        ROLE_CRYPTO_AUDIT,
        ROLE_IMPLEMENTATION_AUDIT,
        ROLE_OPERATIONS,
    )

    _subject, policy, _runtime, _attestations = _fixture()
    unsigned = policy.unsigned
    authorities = {authority.role: authority for authority in unsigned.role_authorities}

    shared_audit_key = authorities[ROLE_CRYPTO_AUDIT].authorized_pubkeys[0]
    overlapping_audits = tuple(
        sorted(
            (
                replace(
                    authority,
                    authorized_pubkeys=(shared_audit_key,),
                    minimum_signatures=1,
                )
                if authority.role == ROLE_IMPLEMENTATION_AUDIT
                else authority
                for authority in unsigned.role_authorities
            ),
            key=lambda item: item.role,
        )
    )
    with pytest.raises(DeploymentPolicyError, match="cryptography and implementation"):
        replace(unsigned, role_authorities=overlapping_audits)

    operations_key = authorities[ROLE_OPERATIONS].authorized_pubkeys[0]
    overlapping_operations = tuple(
        sorted(
            (
                replace(
                    authority,
                    authorized_pubkeys=(operations_key,),
                    minimum_signatures=1,
                )
                if authority.role == ROLE_CRYPTO_AUDIT
                else authority
                for authority in unsigned.role_authorities
            ),
            key=lambda item: item.role,
        )
    )
    with pytest.raises(DeploymentPolicyError, match="operational keys"):
        replace(unsigned, role_authorities=overlapping_operations)


def test_rollback_witness_identity_substitution_fails_even_at_same_count():
    subject, policy, runtime, attestations = _fixture()
    substituted = replace(
        runtime,
        rollback_witness_pubkeys=tuple(sorted((public_key(701), public_key(709)))),
    )
    denied = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=attestations,
        runtime=substituted,
        now=NOW,
    )
    assert not denied.may_authorize_funds
    assert any("identities differ" in failure for failure in denied.failures)


def test_attestation_equivocation_is_order_independent_and_fails_closed():
    subject, policy, runtime, attestations = _fixture()
    original = attestations[0]
    conflicting = SecurityAttestation.create(
        role=original.role,
        subject_digest=subject.digest,
        evidence_digest=_digest(b"conflicting evidence for same signer and role"),
        issued_at=NOW - 100,
        expires_at=NOW + 1000,
        signer_secret=101,
    )
    rows_a = (original, conflicting) + attestations[1:]
    rows_b = (conflicting, original) + attestations[1:]
    decision_a = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=rows_a,
        runtime=runtime,
        now=NOW,
    )
    decision_b = evaluate_deployment(
        mode="enforce",
        subject=subject,
        policy=policy,
        attestations=rows_b,
        runtime=runtime,
        now=NOW,
    )
    assert not decision_a.may_authorize_funds
    assert not decision_b.may_authorize_funds
    assert decision_a.failures == decision_b.failures
    assert any("equivocated" in failure for failure in decision_a.failures)


def test_rollback_witness_authorities_must_be_operationally_independent():
    _subject, policy, _runtime, _attestations = _fixture()
    unsigned = policy.unsigned
    overlapping = tuple(
        sorted((unsigned.setup_participant_pubkeys[0], public_key(719)))
    )
    with pytest.raises(DeploymentPolicyError, match="rollback witness identities must be independent"):
        replace(unsigned, rollback_witness_pubkeys=overlapping)
