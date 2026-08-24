from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock import proof_suite_registry
from ranklock.proof_suite_registry import (
    BLS381_DFB_CANDIDATE_ID,
    BLS461_DFB_CANDIDATE_ID,
    BN254_SPLIT_SUITE_ID,
    BN462_DFB_CANDIDATE_ID,
    BN462_DIRECT_CUSTODY_CANDIDATE_ID,
    SECURITY_FLOOR_REPORT_SCHEMA,
    ProofSuiteDecision,
    ProofSuiteQualificationError,
    evaluate_proof_suite,
    registered_proof_suites,
    require_funding_eligible_proof_suite,
    resolve_proof_suite,
)

ACTIVATION_TIME_UNIX = 1_800_000_000
ACTIVATION_CERTIFICATE_DIGEST = b"\xa5" * 32
REQUIRED_LIFETIME_DAYS = 365


def _evaluate(
    suite_id: bytes, *, required_security_bits: int = 128
) -> ProofSuiteDecision:
    return evaluate_proof_suite(
        suite_id,
        required_security_bits=required_security_bits,
        activation_certificate_digest=ACTIVATION_CERTIFICATE_DIGEST,
        activation_time_unix=ACTIVATION_TIME_UNIX,
        required_lifetime_days=REQUIRED_LIFETIME_DAYS,
    )


def test_compiled_registry_has_no_funding_eligible_suite() -> None:
    profiles = registered_proof_suites()
    assert tuple(profile.suite_id for profile in profiles) == (
        BN254_SPLIT_SUITE_ID,
        BLS381_DFB_CANDIDATE_ID,
        BLS461_DFB_CANDIDATE_ID,
        BN462_DFB_CANDIDATE_ID,
        BN462_DIRECT_CUSTODY_CANDIDATE_ID,
    )
    assert len({profile.suite_id for profile in profiles}) == len(profiles)
    assert all(profile.approved_security_floor_bits is None for profile in profiles)
    assert all(not _evaluate(profile.suite_id).funding_eligible for profile in profiles)


def test_bn254_is_disqualified_even_if_policy_lowers_its_floor() -> None:
    strict = _evaluate(BN254_SPLIT_SUITE_ID)
    assert not strict.funding_eligible
    assert any("below the required" in blocker for blocker in strict.blockers)

    lowered = _evaluate(BN254_SPLIT_SUITE_ID, required_security_bits=96)
    assert not lowered.funding_eligible
    assert any("disqualified" in blocker for blocker in lowered.blockers)
    assert any("variable-time" in blocker for blocker in lowered.blockers)


def test_bls381_name_is_a_candidate_not_an_implemented_suite() -> None:
    profile = resolve_proof_suite(BLS381_DFB_CANDIDATE_ID)
    assert profile.status == "research-candidate"
    decision = _evaluate(BLS381_DFB_CANDIDATE_ID)
    assert not decision.funding_eligible
    assert any("end-to-end BLS12-381" in blocker for blocker in decision.blockers)
    assert any(
        "security floor has not been approved" in blocker
        for blocker in decision.blockers
    )


def test_attack_ceiling_never_substitutes_for_an_approved_security_floor() -> None:
    profile = resolve_proof_suite(BLS381_DFB_CANDIDATE_ID)
    assert profile.attack_security_upper_bound_bits == 126
    assert profile.approved_security_floor_bits is None

    lowered = _evaluate(BLS381_DFB_CANDIDATE_ID, required_security_bits=96)
    assert not lowered.funding_eligible
    assert any(
        "security floor has not been approved" in blocker
        for blocker in lowered.blockers
    )


def test_approved_security_floor_requires_report_provenance_and_lifetime() -> None:
    profile = resolve_proof_suite(BLS381_DFB_CANDIDATE_ID)
    with pytest.raises(ProofSuiteQualificationError, match="report digest"):
        replace(profile, approved_security_floor_bits=120)

    approved = replace(
        profile,
        approved_security_floor_bits=120,
        security_floor_approval_digest=b"\x01" * 32,
        security_floor_report_schema=SECURITY_FLOOR_REPORT_SCHEMA,
        security_floor_approver_set_digest=b"\x02" * 32,
        security_floor_lifetime_days=365,
        security_floor_approved_at_unix=ACTIVATION_TIME_UNIX,
        security_floor_valid_through_unix=(
            ACTIVATION_TIME_UNIX + REQUIRED_LIFETIME_DAYS * 86_400
        ),
    )
    assert approved.approved_security_floor_bits == 120
    assert approved.security_floor_approval_digest == b"\x01" * 32

    with pytest.raises(ProofSuiteQualificationError, match="exceeds"):
        replace(
            approved,
            security_floor_valid_through_unix=(
                ACTIVATION_TIME_UNIX + (REQUIRED_LIFETIME_DAYS - 1) * 86_400
            ),
        )


def test_security_floor_must_cover_activation_and_full_deployment_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = resolve_proof_suite(BN462_DIRECT_CUSTODY_CANDIDATE_ID)
    approval_days = 400
    qualified = replace(
        profile,
        approved_security_floor_bits=128,
        security_floor_approval_digest=b"\x03" * 32,
        security_floor_report_schema=SECURITY_FLOOR_REPORT_SCHEMA,
        security_floor_approver_set_digest=b"\x04" * 32,
        security_floor_lifetime_days=365,
        security_floor_approved_at_unix=ACTIVATION_TIME_UNIX,
        security_floor_valid_through_unix=(
            ACTIVATION_TIME_UNIX + approval_days * 86_400
        ),
        end_to_end_proof_backend=True,
        canonical_subgroup_checked_encodings=True,
        native_constant_time_implementation=True,
        positive_lock_security_closed=True,
        release_primitive_security_closed=True,
        one_shot_state_security_closed=True,
        secret_erasure_security_closed=True,
        secret_result_transport_security_closed=True,
        independent_cryptography_audit=True,
        independent_implementation_audit=True,
        status="qualified",
        permanent_blockers=(),
    )
    qualified_by_id = {
        candidate.suite_id: candidate for candidate in registered_proof_suites()
    }
    qualified_by_id[qualified.suite_id] = qualified
    monkeypatch.setattr(
        proof_suite_registry,
        "_SUITES_BY_ID",
        qualified_by_id,
    )

    evidence_unverified = _evaluate(qualified.suite_id)
    assert not evidence_unverified.funding_eligible
    assert any(
        "activation-window verifier" in blocker
        for blocker in evidence_unverified.blockers
    )

    expired = evaluate_proof_suite(
        qualified.suite_id,
        required_security_bits=128,
        activation_certificate_digest=ACTIVATION_CERTIFICATE_DIGEST,
        activation_time_unix=qualified.security_floor_valid_through_unix,
        required_lifetime_days=1,
    )
    assert not expired.funding_eligible
    assert any("expired" in blocker for blocker in expired.blockers)

    too_long = evaluate_proof_suite(
        qualified.suite_id,
        required_security_bits=128,
        activation_certificate_digest=ACTIVATION_CERTIFICATE_DIGEST,
        activation_time_unix=ACTIVATION_TIME_UNIX,
        required_lifetime_days=366,
    )
    assert not too_long.funding_eligible
    assert any("exceeds" in blocker for blocker in too_long.blockers)


def test_direct_custody_qualification_facts_are_independently_closed() -> None:
    profile = resolve_proof_suite(BN462_DIRECT_CUSTODY_CANDIDATE_ID)
    assert not profile.positive_lock_security_closed
    assert not profile.release_primitive_security_closed
    assert not profile.one_shot_state_security_closed
    assert not profile.secret_erasure_security_closed
    assert not profile.secret_result_transport_security_closed

    with pytest.raises(ProofSuiteQualificationError, match="strict booleans"):
        replace(
            profile,
            end_to_end_proof_backend="yes",  # type: ignore[arg-type]
        )


def test_bls461_is_not_promoted_from_a_bit_length_guideline() -> None:
    profile = resolve_proof_suite(BLS461_DFB_CANDIDATE_ID)
    assert profile.approved_security_floor_bits is None
    decision = _evaluate(BLS461_DFB_CANDIDATE_ID)
    assert not decision.funding_eligible
    assert any(
        "security floor has not been approved" in blocker
        for blocker in decision.blockers
    )
    assert any("end-to-end BLS12-461" in blocker for blocker in decision.blockers)


def test_bn462_curve_candidate_has_no_approved_suite_floor_or_backend() -> None:
    profile = resolve_proof_suite(BN462_DFB_CANDIDATE_ID)
    assert profile.approved_security_floor_bits is None
    decision = _evaluate(BN462_DFB_CANDIDATE_ID)
    assert not decision.funding_eligible
    assert any(
        "security floor has not been approved" in blocker
        for blocker in decision.blockers
    )
    assert any("end-to-end BN462" in blocker for blocker in decision.blockers)


def test_direct_custody_is_a_distinct_nonfundable_release_profile() -> None:
    profile = resolve_proof_suite(BN462_DIRECT_CUSTODY_CANDIDATE_ID)
    assert profile.release_mechanism == "direct-scalar-custody"
    assert profile.status == "research-candidate"

    decision = _evaluate(BN462_DIRECT_CUSTODY_CANDIDATE_ID)
    assert not decision.funding_eligible
    assert any("direct-scalar custody" in blocker for blocker in decision.blockers)
    assert any("guarded one-shot" in blocker for blocker in decision.blockers)
    assert not any("DFB" in blocker for blocker in decision.blockers)


def test_unknown_or_coerced_suite_ids_and_security_floors_fail_closed() -> None:
    with pytest.raises(ProofSuiteQualificationError, match="allowlisted"):
        resolve_proof_suite(b"RL26-INVENTED")
    with pytest.raises(ProofSuiteQualificationError, match="immutable bytes"):
        resolve_proof_suite("RL25-BN254-SPLIT-N")  # type: ignore[arg-type]
    with pytest.raises(ProofSuiteQualificationError, match="security floor"):
        _evaluate(BN254_SPLIT_SUITE_ID, required_security_bits=True)
    with pytest.raises(ProofSuiteQualificationError, match="certificate digest"):
        evaluate_proof_suite(
            BN254_SPLIT_SUITE_ID,
            required_security_bits=128,
            activation_certificate_digest=b"too short",
            activation_time_unix=ACTIVATION_TIME_UNIX,
            required_lifetime_days=REQUIRED_LIFETIME_DAYS,
        )
    with pytest.raises(ProofSuiteQualificationError, match="activation time"):
        evaluate_proof_suite(
            BN254_SPLIT_SUITE_ID,
            required_security_bits=128,
            activation_certificate_digest=ACTIVATION_CERTIFICATE_DIGEST,
            activation_time_unix=True,
            required_lifetime_days=REQUIRED_LIFETIME_DAYS,
        )
    with pytest.raises(ProofSuiteQualificationError, match="deployment lifetime"):
        evaluate_proof_suite(
            BN254_SPLIT_SUITE_ID,
            required_security_bits=128,
            activation_certificate_digest=ACTIVATION_CERTIFICATE_DIGEST,
            activation_time_unix=ACTIVATION_TIME_UNIX,
            required_lifetime_days=0,
        )


def test_no_current_suite_can_pass_the_funding_requirement() -> None:
    for profile in registered_proof_suites():
        with pytest.raises(ProofSuiteQualificationError, match="not eligible"):
            require_funding_eligible_proof_suite(
                profile.suite_id,
                required_security_bits=128,
                activation_certificate_digest=ACTIVATION_CERTIFICATE_DIGEST,
                activation_time_unix=ACTIVATION_TIME_UNIX,
                required_lifetime_days=REQUIRED_LIFETIME_DAYS,
            )
