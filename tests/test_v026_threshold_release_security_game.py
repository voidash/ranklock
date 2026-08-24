from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock.v026.threshold_release_security_game import (
    StaticReleaseAssumption,
    StaticReleaseWorldKind,
    ThresholdReleaseSecurityGameError,
    evaluate_conditional_static_threshold_release,
)
from ranklock.v026.threshold_signature_release import ThresholdReleasePolicy


def test_reference_profile_establishes_only_fixed_coalition_arithmetic() -> None:
    evidence = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 2, 1),
        alternative_count=2,
    )

    assert len(evidence.worlds) == 12
    assert evidence.availability_slack == 0
    assert evidence.conditional_static_exposure_safety_established is True
    assert evidence.conditional_static_valid_proof_availability_established is True
    assert evidence.positive_lock_hiding_established is False
    assert evidence.participant_control_domain_independence_established is False
    assert evidence.mobile_pre_erasure_corruption_resistance_established is False
    assert evidence.production_release_theorem_established is False
    assert evidence.funding_eligible is False
    assert evidence.assumptions == tuple(StaticReleaseAssumption)

    for world in evidence.worlds:
        if world.kind is StaticReleaseWorldKind.VALID_PROOF_MAXIMUM_WITHHOLDING:
            assert world.corrupt_signatures_available == 0
            assert world.honest_signatures_available == 3 - world.corrupt_count
            assert world.ack_quorum_available is True
        else:
            assert world.corrupt_signatures_available == world.corrupt_count
            assert world.honest_signatures_available == 0
            assert world.ack_quorum_available is False


def test_every_small_admissible_policy_satisfies_the_exact_counting_game() -> None:
    checked = 0
    for participant_count in range(2, 11):
        for maximum_corruptions in range(participant_count):
            for threshold in range(1, participant_count + 1):
                if not (
                    maximum_corruptions
                    < threshold
                    <= participant_count - maximum_corruptions
                ):
                    continue
                policy = ThresholdReleasePolicy(
                    participant_count,
                    threshold,
                    maximum_corruptions,
                )
                evidence = evaluate_conditional_static_threshold_release(
                    policy,
                    alternative_count=3,
                )
                assert len(evidence.worlds) == 3 * (maximum_corruptions + 1) * 3
                assert evidence.conditional_static_exposure_safety_established
                assert evidence.conditional_static_valid_proof_availability_established
                assert evidence.availability_slack >= 0
                checked += 1
    assert checked == 124


def test_mobile_pre_erasure_corruption_breaks_a_simultaneous_one_bound() -> None:
    evidence = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 2, 1),
        alternative_count=2,
    )

    assert len(evidence.mobile_corruption_witnesses) == 2
    for alternative_index, witness in enumerate(evidence.mobile_corruption_witnesses):
        assert witness.alternative_index == alternative_index
        assert witness.participant_sequence == (0, 1)
        assert witness.maximum_simultaneous_corruptions == 1
        assert witness.accumulated_signature_count == 2
        assert witness.accumulated_signature_count >= witness.threshold

    zero_corruption = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 1, 0),
        alternative_count=1,
    )
    assert zero_corruption.mobile_corruption_witnesses == ()
    assert zero_corruption.production_release_theorem_established is False


def test_distinct_keys_do_not_prove_independent_control_domains() -> None:
    evidence = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 2, 1),
        alternative_count=2,
    )

    assert len(evidence.control_domain_witnesses) == 2
    for alternative_index, witness in enumerate(evidence.control_domain_witnesses):
        assert witness.alternative_index == alternative_index
        assert witness.aliased_participant_indices == (0, 1)
        assert witness.compromised_control_domain_count == 1
        assert witness.accumulated_signature_count == 2
        assert witness.accumulated_signature_count >= witness.threshold


def test_reference_profile_has_no_extra_honest_artifact_loss_tolerance() -> None:
    evidence = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 2, 1),
        alternative_count=2,
    )

    assert evidence.availability_slack == 0
    assert len(evidence.artifact_loss_witnesses) == 2
    for alternative_index, witness in enumerate(evidence.artifact_loss_witnesses):
        assert witness.alternative_index == alternative_index
        assert witness.corrupt_count == 1
        assert witness.unavailable_honest_count == 1
        assert witness.available_signature_count == 1
        assert witness.available_signature_count < witness.threshold

    slack_profile = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(5, 2, 1),
        alternative_count=1,
    )
    assert slack_profile.availability_slack == 2
    witness = slack_profile.artifact_loss_witnesses[0]
    assert witness.unavailable_honest_count == 3
    assert witness.available_signature_count == 1


def test_incomplete_or_relabelled_game_evidence_fails_closed() -> None:
    evidence = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 2, 1),
        alternative_count=2,
    )

    with pytest.raises(
        ThresholdReleaseSecurityGameError,
        match="worlds are incomplete or noncanonical",
    ):
        replace(evidence, worlds=evidence.worlds[:-1])

    with pytest.raises(
        ThresholdReleaseSecurityGameError,
        match="worlds are incomplete or noncanonical|quorum flag disagrees",
    ):
        replace(
            evidence,
            worlds=(
                replace(evidence.worlds[0], ack_quorum_available=True),
                *evidence.worlds[1:],
            ),
        )

    with pytest.raises(
        ThresholdReleaseSecurityGameError,
        match="assumptions are incomplete or noncanonical",
    ):
        replace(evidence, assumptions=evidence.assumptions[:-1])

    with pytest.raises(
        ThresholdReleaseSecurityGameError,
        match="mobile-corruption witnesses are incomplete or noncanonical",
    ):
        replace(evidence, mobile_corruption_witnesses=())

    with pytest.raises(
        ThresholdReleaseSecurityGameError,
        match="artifact-loss witnesses are incomplete or noncanonical",
    ):
        replace(evidence, artifact_loss_witnesses=())

    with pytest.raises(
        ThresholdReleaseSecurityGameError,
        match="control-domain witnesses are incomplete or noncanonical",
    ):
        replace(evidence, control_domain_witnesses=())

    with pytest.raises(ThresholdReleaseSecurityGameError, match="unknown schema"):
        replace(
            evidence, schema="ranklock-v026-conditional-static-threshold-evidence-v2"
        )

    with pytest.raises(ThresholdReleaseSecurityGameError, match="unknown schema"):
        replace(evidence.worlds[0], schema="ranklock-v026-static-release-world-v2")


@pytest.mark.parametrize("alternative_count", (0, 65, True))
def test_game_rejects_unimplementable_alternative_counts(
    alternative_count: int,
) -> None:
    with pytest.raises(ThresholdReleaseSecurityGameError, match="alternative count"):
        evaluate_conditional_static_threshold_release(
            ThresholdReleasePolicy(3, 2, 1),
            alternative_count=alternative_count,
        )


def test_evidence_digest_binds_policy_worlds_and_failure_witnesses() -> None:
    reference = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 2, 1),
        alternative_count=2,
    )
    replay = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 2, 1),
        alternative_count=2,
    )
    different_policy = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(5, 3, 2),
        alternative_count=2,
    )
    different_alternatives = evaluate_conditional_static_threshold_release(
        ThresholdReleasePolicy(3, 2, 1),
        alternative_count=1,
    )

    assert reference.encoded == replay.encoded
    assert reference.digest == replay.digest
    assert len(reference.encoded) == 502
    assert (
        reference.digest.hex()
        == "27286caeca8becaf78746a7b5be2d04d6fa450c2f1be8d9eae3032e98553ede9"
    )
    assert reference.digest != different_policy.digest
    assert reference.digest != different_alternatives.digest
