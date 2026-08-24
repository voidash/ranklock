from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path

import pytest

from ranklock.babe_positive_lock import (
    BabePositiveLockV2,
    PositiveGroth16Proof,
    PositiveGroth16VerifyingKey,
    deterministic_fixture,
    honest_projective_output,
)
from ranklock.v026.threshold_signature_release import (
    AckWitnessSelection,
    BabePublicSideInformationProfileV2,
    ExactAckSignature,
    ExactAckSignatureVector,
    ExactAckTemplate,
    ExactAckTemplateVector,
    FirstWriterWitnessSelectionModel,
    LockedAckSignatureSet,
    LockedParticipantAckSignatures,
    ParticipantAckSignatureRelease,
    PreliminaryContributionRoster,
    PreliminaryReleaseContribution,
    ThresholdRecoveryCapsule,
    ThresholdReleasePolicy,
    ThresholdSignatureReleaseError,
    WitnessSelectionConflictError,
    WitnessSelectionDisposition,
    assess_threshold_signature_release,
    exact_proof_statement_digest,
    recover_threshold_capsule,
)
from scripts.generate_v026_threshold_signature_release import (
    _local_sp1_groth16_attempt_evidence,
)

_OPAQUE_ALPHA_G1 = "d21f91b2993c7c99d8eb4ebdcbd2e31263b1f70652d691ca14480eab47ce2873"
_OPAQUE_BETA_G2 = (
    "8fd9b71a8ba2b318e8ce5f2751b9178b795a574d9c96bf21c10bb09b5261ff16"
    "2f96096460af078f7cb14d3f1cad285a4fa14b97ef187884a0c73ce582102f8e"
)
_OPAQUE_GAMMA_G2 = (
    "8a60b98b5744bef73b563b8b4a32d79f30651b0ac9fd05356b91ebd88e92ef76"
    "095d122bad1127e20694d493e597fd82cace61ef9c6f8f374e3e584948ddf1fb"
)
_OPAQUE_DELTA_G2 = (
    "ccd27f43fa573249b69377fcd2213cfc008f6c9001550b89c449236a7ba84f670"
    "0cdb089c8a0ebd9196b900b44a9918b7843254992f34c6e98809aebbf0bcffe"
)
_OPAQUE_IC_G1 = (
    "ead4b346fc3ba82b36826a47cadcc7220ed54b7c24ec062bc23c6ea37be79bec",
    "dd3249413e4ca9f36e36b8ae3b1e0c69c948d231fcf54a24aab9579daf09b4d3",
    "e89f86405dc86d8263f1a2303db959132cb75c141055551a9c429407499103de",
    "96c531b4d5ca03bbe63b25485e53e00ad20eb656e702bb5ca8c3072465d00000",
)
_OPAQUE_PROOFS = (
    (
        "82806490d235cd626a2015dd1d837974c6bd89460836d673c61c8a474e84e872",
        (
            "c1b6d5051098295540795c19a7aa044609af0b5d5dd4fd191d9623323fa2cb48"
            "037bae3768afabb4fcd3f901b26b416a9bd7034ed505911fc23b0ec2842f9bc7"
        ),
        "aeb8045de1f54d0186c928910affe2e623aa84a088dcfa54a2c466c19c45e966",
    ),
    (
        "c37f96a32b51f499627a4a414cc3cd0cd6e6f4d43f7459736564a5281640e346",
        (
            "e997da8132debd338b0cfa08f6249195401793ee5a02d7e8791ef6d672784410"
            "2d2a54bc4766acf9088371bd6b6bc2732a496075e08d367bc79a8d886b64e672"
        ),
        "9b8a58086f2bb39c0038b06b5caba227bb38da8caae95547753ef40b188183d0",
    ),
)


def _digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _opaque_vk_and_proofs() -> tuple[
    PositiveGroth16VerifyingKey, tuple[PositiveGroth16Proof, ...]
]:
    vk = PositiveGroth16VerifyingKey(
        alpha_g1=bytes.fromhex(_OPAQUE_ALPHA_G1),
        beta_g2=bytes.fromhex(_OPAQUE_BETA_G2),
        gamma_g2=bytes.fromhex(_OPAQUE_GAMMA_G2),
        delta_g2=bytes.fromhex(_OPAQUE_DELTA_G2),
        ic_g1=tuple(bytes.fromhex(item) for item in _OPAQUE_IC_G1),
        context=b"ranklock-v026-threshold-opaque-public-vector-v1",
    )
    proofs = tuple(
        PositiveGroth16Proof(*(bytes.fromhex(item) for item in encoded))
        for encoded in _OPAQUE_PROOFS
    )
    return vk, proofs


@dataclass(frozen=True, slots=True)
class _Fixture:
    vk: PositiveGroth16VerifyingKey
    public_inputs: tuple[tuple[int, ...], ...]
    proofs: tuple[PositiveGroth16Proof, ...]
    policy: ThresholdReleasePolicy
    side_information_profile: BabePublicSideInformationProfileV2
    identity_secrets: tuple[int, ...]
    release_secrets: tuple[tuple[int, ...], ...]
    scales: tuple[tuple[int, ...], ...]
    roster: PreliminaryContributionRoster
    templates: ExactAckTemplateVector
    signature_vectors: tuple[ExactAckSignatureVector, ...]
    locked_set: LockedAckSignatureSet


@pytest.fixture(scope="module")
def release_fixture() -> _Fixture:
    vk, proofs = _opaque_vk_and_proofs()
    public_inputs = ((17,), (17,))
    policy = ThresholdReleasePolicy(3, 2, 1)
    side_information_profile = BabePublicSideInformationProfileV2(
        _digest("relation-circuit"),
        _digest("complete-crs"),
        _digest("proving-key"),
        _digest("projectivizer"),
        _digest("ceremony-transcript"),
    )
    setup_intent_digest = _digest("setup-intent")
    identity_secrets = (101, 102, 103)
    release_secrets = ((201, 211), (202, 212), (203, 213))
    scales = ((31, 43), (37, 47), (41, 53))
    contributions = tuple(
        PreliminaryReleaseContribution.create(
            setup_intent_digest=setup_intent_digest,
            participant_index=participant_index,
            participant_identity_secret=identity_secrets[participant_index],
            release_secrets=release_secrets[participant_index],
            retained_artifact_digests=tuple(
                _digest(f"retained-{participant_index}-{alternative_index}")
                for alternative_index in range(2)
            ),
            scales=scales[participant_index],
            vk=vk,
            scale_proof_nonces=(71 + 2 * participant_index, 72 + 2 * participant_index),
            signature_aux_rand=_digest(f"contribution-aux-{participant_index}"),
        )
        for participant_index in range(policy.participant_count)
    )
    roster = PreliminaryContributionRoster(policy, contributions)
    templates = ExactAckTemplateVector(
        setup_intent_digest,
        _digest("exact-graph-template"),
        side_information_profile,
        tuple(
            ExactAckTemplate(
                alternative_index,
                _digest(f"counterproof-template-{alternative_index}"),
                exact_proof_statement_digest(
                    vk,
                    public_inputs[alternative_index],
                    counterproof_template_digest=_digest(
                        f"counterproof-template-{alternative_index}"
                    ),
                    side_information_profile=side_information_profile,
                ),
                _digest(f"ack-template-{alternative_index}"),
                _digest(f"ack-sighash-{alternative_index}"),
            )
            for alternative_index in range(2)
        ),
    )
    signature_vectors = tuple(
        ExactAckSignatureVector.create(
            templates,
            release_secrets=release_secrets[participant_index],
            auxiliary_randomness=tuple(
                _digest(f"ack-aux-{participant_index}-{alternative_index}")
                for alternative_index in range(2)
            ),
        )
        for participant_index in range(policy.participant_count)
    )
    rows = tuple(
        LockedParticipantAckSignatures.create(
            roster=roster,
            templates=templates,
            participant_index=participant_index,
            participant_identity_secret=identity_secrets[participant_index],
            release_secrets=release_secrets[participant_index],
            scales=scales[participant_index],
            vk=vk,
            public_inputs_by_alternative=public_inputs,
            auxiliary_randomness=tuple(
                _digest(f"ack-aux-{participant_index}-{alternative_index}")
                for alternative_index in range(2)
            ),
            row_signature_aux_rand=_digest(f"row-aux-{participant_index}"),
        )
        for participant_index in range(policy.participant_count)
    )
    locked_set = LockedAckSignatureSet(roster, templates, rows)
    locked_set.validate(vk, public_inputs)
    return _Fixture(
        vk,
        public_inputs,
        proofs,
        policy,
        side_information_profile,
        identity_secrets,
        release_secrets,
        scales,
        roster,
        templates,
        signature_vectors,
        locked_set,
    )


def _unlock_all(
    fixture: _Fixture,
    alternative_index: int,
) -> tuple[ParticipantAckSignatureRelease, ...]:
    return tuple(
        fixture.locked_set.unlock_participant(
            participant_index,
            alternative_index,
            vk=fixture.vk,
            public_inputs_by_alternative=fixture.public_inputs,
            proof=fixture.proofs[alternative_index],
            r_a_g1=honest_projective_output(
                fixture.proofs[alternative_index],
                scale=fixture.scales[participant_index][alternative_index],
            ),
        )
        for participant_index in range(fixture.policy.participant_count)
    )


@pytest.fixture(scope="module")
def releases_by_alternative(
    release_fixture: _Fixture,
) -> tuple[tuple[ParticipantAckSignatureRelease, ...], ...]:
    return (_unlock_all(release_fixture, 0), _unlock_all(release_fixture, 1))


@pytest.mark.parametrize(
    ("participant_count", "threshold", "max_corrupt"),
    (
        (1, 1, 0),
        (65, 33, 32),
        (3, 1, 1),
        (3, 3, 1),
        (3, 2, 2),
        (3, 2, -1),
        (True, 1, 0),
    ),
)
def test_policy_enforces_exact_n_t_f_constraints(
    participant_count: int,
    threshold: int,
    max_corrupt: int,
) -> None:
    with pytest.raises(ThresholdSignatureReleaseError):
        ThresholdReleasePolicy(participant_count, threshold, max_corrupt)


def test_policy_and_assessment_schema_relabelling_is_rejected() -> None:
    policy = ThresholdReleasePolicy(3, 2, 1)
    with pytest.raises(ThresholdSignatureReleaseError, match="policy schema"):
        replace(policy, schema="ranklock-v026-threshold-release-policy-v3")

    assessment = assess_threshold_signature_release(policy)
    with pytest.raises(ThresholdSignatureReleaseError, match="assessment schema"):
        replace(
            assessment,
            schema="ranklock-v026-threshold-signature-release-assessment-v5",
        )


def test_typed_dag_uses_real_exact_bip340_signatures(
    release_fixture: _Fixture,
    releases_by_alternative: tuple[tuple[ParticipantAckSignatureRelease, ...], ...],
) -> None:
    capsule = recover_threshold_capsule(
        release_fixture.locked_set,
        0,
        (
            releases_by_alternative[0][2],
            releases_by_alternative[0][0],
            releases_by_alternative[0][1],
        ),
    )

    assert isinstance(
        release_fixture.roster.contributions[0], PreliminaryReleaseContribution
    )
    assert isinstance(release_fixture.templates, ExactAckTemplateVector)
    assert isinstance(release_fixture.locked_set, LockedAckSignatureSet)
    assert isinstance(capsule, ThresholdRecoveryCapsule)
    assert capsule.alternative_index == 0
    assert capsule.selected_participant_indices == (0, 1)
    assert len(capsule.signatures) == release_fixture.policy.threshold
    assert all(
        item.exact_signature.verify_exact(
            release_fixture.templates.templates[0],
            item.release_pubkey,
        )
        for item in capsule.signatures
    )


def test_every_participant_alternative_has_an_independent_lock_and_anchor(
    release_fixture: _Fixture,
) -> None:
    locks = tuple(
        lock
        for row in release_fixture.locked_set.rows
        for lock in row.alternative_locks
    )
    alternatives = tuple(
        alternative
        for contribution in release_fixture.roster.contributions
        for alternative in contribution.alternatives
    )

    assert len(locks) == 6
    assert len({lock.positive_lock.r_delta_g2 for lock in locks}) == 6
    assert len({item.retained_artifact_digest for item in alternatives}) == 6
    assert len({item.release_pubkey for item in alternatives}) == 6
    assert not (
        {item.release_pubkey for item in alternatives}
        & {
            contribution.participant_identity_pubkey
            for contribution in release_fixture.roster.contributions
        }
    )
    assert all(len(lock.positive_lock.masked_payload) == 64 for lock in locks)
    assert all(isinstance(lock.positive_lock, BabePositiveLockV2) for lock in locks)
    assert all(not hasattr(lock.positive_lock, "payload_hash") for lock in locks)
    assert all(
        BabePositiveLockV2.parse(lock.positive_lock.encoded) == lock.positive_lock
        for lock in locks
    )


def test_any_one_missing_recovers_each_alternative_in_two_of_three_profile(
    release_fixture: _Fixture,
    releases_by_alternative: tuple[tuple[ParticipantAckSignatureRelease, ...], ...],
) -> None:
    for alternative_index, releases in enumerate(releases_by_alternative):
        for missing_index in range(release_fixture.policy.participant_count):
            available = tuple(
                release
                for release in releases
                if release.participant_index != missing_index
            )
            capsule = recover_threshold_capsule(
                release_fixture.locked_set,
                alternative_index,
                available,
            )
            assert missing_index not in capsule.selected_participant_indices
            assert len(capsule.selected_participant_indices) == 2


def test_equal_base_inputs_cannot_reuse_cross_template_proof_or_signature_after_reorg(
    release_fixture: _Fixture,
    releases_by_alternative: tuple[tuple[ParticipantAckSignatureRelease, ...], ...],
) -> None:
    assert release_fixture.public_inputs[0] == release_fixture.public_inputs[1]
    assert (
        release_fixture.templates.templates[0].counterproof_template_digest
        != release_fixture.templates.templates[1].counterproof_template_digest
    )
    alt0_releases = releases_by_alternative[0][:2]
    alt0_capsule = recover_threshold_capsule(
        release_fixture.locked_set, 0, alt0_releases
    )
    assert alt0_capsule.alternative_index == 0

    with pytest.raises(ThresholdSignatureReleaseError, match="another ACK alternative"):
        recover_threshold_capsule(release_fixture.locked_set, 1, alt0_releases)

    with pytest.raises(ThresholdSignatureReleaseError, match="proof did not release"):
        release_fixture.locked_set.unlock_participant(
            0,
            1,
            vk=release_fixture.vk,
            public_inputs_by_alternative=release_fixture.public_inputs,
            proof=release_fixture.proofs[0],
            r_a_g1=honest_projective_output(
                release_fixture.proofs[0],
                scale=release_fixture.scales[0][1],
            ),
        )

    assert not alt0_releases[0].exact_signature.verify_exact(
        release_fixture.templates.templates[1],
        release_fixture.roster.contributions[0].alternatives[1].release_pubkey,
    )


def test_invalid_proof_and_wrong_projective_scale_do_not_unlock(
    release_fixture: _Fixture,
) -> None:
    invalid_proof = replace(
        release_fixture.proofs[0],
        c_g1=release_fixture.proofs[0].a_g1,
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="proof did not release"):
        release_fixture.locked_set.unlock_participant(
            0,
            0,
            vk=release_fixture.vk,
            public_inputs_by_alternative=release_fixture.public_inputs,
            proof=invalid_proof,
            r_a_g1=honest_projective_output(
                invalid_proof,
                scale=release_fixture.scales[0][0],
            ),
        )
    with pytest.raises(ThresholdSignatureReleaseError, match="proof did not release"):
        release_fixture.locked_set.unlock_participant(
            0,
            0,
            vk=release_fixture.vk,
            public_inputs_by_alternative=release_fixture.public_inputs,
            proof=release_fixture.proofs[0],
            r_a_g1=honest_projective_output(
                release_fixture.proofs[0],
                scale=release_fixture.scales[0][0] + 1,
            ),
        )


def test_duplicate_wrong_index_and_unknown_index_releases_are_rejected(
    release_fixture: _Fixture,
    releases_by_alternative: tuple[tuple[ParticipantAckSignatureRelease, ...], ...],
) -> None:
    releases = releases_by_alternative[0]
    with pytest.raises(ThresholdSignatureReleaseError, match="duplicate"):
        recover_threshold_capsule(
            release_fixture.locked_set, 0, (releases[0], releases[0])
        )

    with pytest.raises(ThresholdSignatureReleaseError, match="non-exact or invalid"):
        recover_threshold_capsule(
            release_fixture.locked_set,
            0,
            (replace(releases[0], participant_index=1), releases[2]),
        )

    with pytest.raises(ThresholdSignatureReleaseError, match="outside the roster"):
        recover_threshold_capsule(
            release_fixture.locked_set,
            0,
            (replace(releases[0], participant_index=9),),
        )


def test_wrong_alt_sighash_malformed_and_unknown_signer_are_rejected(
    release_fixture: _Fixture,
    releases_by_alternative: tuple[tuple[ParticipantAckSignatureRelease, ...], ...],
) -> None:
    release = releases_by_alternative[0][0]
    exact = release.exact_signature
    wrong_alt = replace(exact, alternative_index=1)
    with pytest.raises(ThresholdSignatureReleaseError, match="non-exact or invalid"):
        recover_threshold_capsule(
            release_fixture.locked_set,
            0,
            (
                replace(release, exact_signature=wrong_alt),
                releases_by_alternative[0][1],
            ),
        )

    wrong_sighash = replace(
        exact, ack_sighash=release_fixture.templates.templates[1].ack_sighash
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="non-exact or invalid"):
        recover_threshold_capsule(
            release_fixture.locked_set,
            0,
            (
                replace(release, exact_signature=wrong_sighash),
                releases_by_alternative[0][1],
            ),
        )

    with pytest.raises(ThresholdSignatureReleaseError, match="raw ACK signature"):
        ExactAckSignature.from_locked_payload(
            release_fixture.templates.templates[0],
            exact.signature[:-1],
        )

    unknown_signature = ExactAckSignature.create(
        release_fixture.templates.templates[0],
        release_secret=999,
        auxiliary_randomness=_digest("unknown-signer-aux"),
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="non-exact or invalid"):
        recover_threshold_capsule(
            release_fixture.locked_set,
            0,
            (
                replace(release, exact_signature=unknown_signature),
                releases_by_alternative[0][1],
            ),
        )


def test_corrupt_signature_and_foreign_set_are_rejected(
    release_fixture: _Fixture,
    releases_by_alternative: tuple[tuple[ParticipantAckSignatureRelease, ...], ...],
) -> None:
    release = releases_by_alternative[0][0]
    signature = release.exact_signature.signature
    corrupt = replace(
        release.exact_signature,
        signature=signature[:-1] + bytes((signature[-1] ^ 1,)),
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="non-exact or invalid"):
        recover_threshold_capsule(
            release_fixture.locked_set,
            0,
            (replace(release, exact_signature=corrupt), releases_by_alternative[0][1]),
        )
    with pytest.raises(ThresholdSignatureReleaseError, match="another locked set"):
        recover_threshold_capsule(
            release_fixture.locked_set,
            0,
            (
                replace(release, locked_set_digest=_digest("foreign-set")),
                releases_by_alternative[0][1],
            ),
        )


def test_subject_keys_artifacts_and_scales_cannot_alias(
    release_fixture: _Fixture,
) -> None:
    first = release_fixture.roster.contributions[0]
    second = release_fixture.roster.contributions[1]
    duplicate_alternative = replace(
        second.alternatives[1],
        release_pubkey=first.alternatives[0].release_pubkey,
    )
    duplicate_key = replace(
        second,
        alternatives=(second.alternatives[0], duplicate_alternative),
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="globally distinct"):
        PreliminaryContributionRoster(
            release_fixture.policy,
            (
                release_fixture.roster.contributions[0],
                duplicate_key,
                release_fixture.roster.contributions[2],
            ),
        )

    with pytest.raises(ThresholdSignatureReleaseError, match="must be distinct"):
        replace(
            first,
            alternatives=(
                first.alternatives[0],
                replace(
                    first.alternatives[1],
                    release_pubkey=first.alternatives[0].release_pubkey,
                ),
            ),
        )

    identity_alias_alternative = replace(
        second.alternatives[1],
        release_pubkey=release_fixture.roster.contributions[
            2
        ].participant_identity_pubkey,
    )
    identity_alias = replace(
        second,
        alternatives=(second.alternatives[0], identity_alias_alternative),
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="must not alias"):
        PreliminaryContributionRoster(
            release_fixture.policy,
            (first, identity_alias, release_fixture.roster.contributions[2]),
        )

    duplicate_anchor = replace(
        release_fixture.roster.contributions[1].alternatives[1],
        r_delta_g2=release_fixture.roster.contributions[0].alternatives[0].r_delta_g2,
    )
    contribution = replace(
        release_fixture.roster.contributions[1],
        alternatives=(
            release_fixture.roster.contributions[1].alternatives[0],
            duplicate_anchor,
        ),
    )
    with pytest.raises(
        ThresholdSignatureReleaseError, match="distinct artifact and scale anchor"
    ):
        PreliminaryContributionRoster(
            release_fixture.policy,
            (
                release_fixture.roster.contributions[0],
                contribution,
                release_fixture.roster.contributions[2],
            ),
        )


def test_exact_context_template_roster_and_proof_statement_binding(
    release_fixture: _Fixture,
) -> None:
    foreign_templates = replace(
        release_fixture.templates,
        graph_template_digest=_digest("foreign-graph"),
    )
    rebound = LockedAckSignatureSet(
        release_fixture.roster,
        foreign_templates,
        release_fixture.locked_set.rows,
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="another template vector"):
        rebound.validate(release_fixture.vk, release_fixture.public_inputs)

    wrong_inputs = ((23,), release_fixture.public_inputs[1])
    with pytest.raises(ThresholdSignatureReleaseError, match="another proof statement"):
        release_fixture.locked_set.validate(release_fixture.vk, wrong_inputs)

    tampered_contribution = replace(
        release_fixture.roster.contributions[0],
        participant_signature=bytes(64),
    )
    tampered_roster = PreliminaryContributionRoster(
        release_fixture.policy,
        (tampered_contribution, *release_fixture.roster.contributions[1:]),
    )
    assert not tampered_roster.verify(release_fixture.vk)


def test_complete_fixed_public_side_information_is_digest_bound(
    release_fixture: _Fixture,
) -> None:
    profile = release_fixture.side_information_profile
    for attribute in (
        "relation_circuit_digest",
        "complete_crs_digest",
        "proving_key_digest",
        "projectivizer_digest",
        "ceremony_transcript_digest",
    ):
        mutated_profile = replace(
            profile,
            **{attribute: _digest(f"mutated-{attribute}")},
        )
        assert mutated_profile.digest != profile.digest
        foreign_templates = replace(
            release_fixture.templates,
            side_information_profile=mutated_profile,
        )
        rebound = LockedAckSignatureSet(
            release_fixture.roster,
            foreign_templates,
            release_fixture.locked_set.rows,
        )
        with pytest.raises(
            ThresholdSignatureReleaseError,
            match="another proof statement",
        ):
            rebound.validate(release_fixture.vk, release_fixture.public_inputs)

    with pytest.raises(ThresholdSignatureReleaseError, match="must be distinct"):
        replace(
            profile,
            proving_key_digest=profile.relation_circuit_digest,
        )
    with pytest.raises(ThresholdSignatureReleaseError, match="unknown.*schema"):
        replace(profile, schema="ranklock-v026-babe-public-side-information-v3")
    with pytest.raises(ThresholdSignatureReleaseError, match="template-vector schema"):
        replace(
            release_fixture.templates,
            schema="ranklock-v026-exact-ack-template-vector-v4",
        )


def test_known_toxic_fixture_is_rejected_and_qualified_crs_remains_a_blocker(
    release_fixture: _Fixture,
) -> None:
    toxic_vk, toxic_inputs, _ = deterministic_fixture(
        context=b"known-toxic-threshold-negative"
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="known-toxic"):
        exact_proof_statement_digest(
            toxic_vk,
            toxic_inputs,
            counterproof_template_digest=_digest("toxic-counterproof"),
            side_information_profile=release_fixture.side_information_profile,
        )

    assessment = assess_threshold_signature_release(release_fixture.policy)
    assert any(
        "qualified CRS" in item and "toxic-waste" in item
        for item in assessment.unverified_blockers
    )


def test_first_writer_adopts_witness_selection_without_poisonable_parent_identity(
    release_fixture: _Fixture,
    releases_by_alternative: tuple[tuple[ParticipantAckSignatureRelease, ...], ...],
) -> None:
    releases = releases_by_alternative[0]
    capsule_01 = recover_threshold_capsule(release_fixture.locked_set, 0, releases[:2])
    capsule_12 = recover_threshold_capsule(release_fixture.locked_set, 0, releases[1:])
    assert capsule_01.digest != capsule_12.digest

    model = FirstWriterWitnessSelectionModel(release_fixture.locked_set)
    disposition, adopted = model.adopt(capsule_01)
    assert disposition is WitnessSelectionDisposition.ADOPTED
    assert isinstance(adopted, AckWitnessSelection)
    assert adopted.participant_bitmap == b"\x03"
    assert not hasattr(adopted, "ack_txid")
    assert not hasattr(adopted, "ack_wtxid")
    assert not hasattr(adopted, "descendant_parent_txid")

    replay_disposition, replay = model.adopt(capsule_01)
    assert replay_disposition is WitnessSelectionDisposition.EXACT_REPLAY
    assert replay is adopted
    assert model.adopted(0) is adopted

    with pytest.raises(WitnessSelectionConflictError, match="already adopted"):
        model.adopt(capsule_12)

    with pytest.raises(TypeError):
        model.adopt(capsule_01, ack_txid=_digest("poisoned-parent"))


def test_alt0_capsule_cannot_be_published_as_alt1(
    release_fixture: _Fixture,
    releases_by_alternative: tuple[tuple[ParticipantAckSignatureRelease, ...], ...],
) -> None:
    capsule = recover_threshold_capsule(
        release_fixture.locked_set,
        0,
        releases_by_alternative[0][:2],
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="mixes ACK alternatives"):
        replace(capsule, alternative_index=1)


def test_two_corrupt_early_releases_show_weakened_theorem(
    release_fixture: _Fixture,
) -> None:
    early_releases = tuple(
        ParticipantAckSignatureRelease(
            participant_index,
            0,
            release_fixture.locked_set.digest,
            release_fixture.signature_vectors[participant_index].signatures[0],
        )
        for participant_index in (0, 1)
    )
    with pytest.raises(ThresholdSignatureReleaseError, match="fewer than threshold"):
        recover_threshold_capsule(
            release_fixture.locked_set,
            0,
            early_releases[: release_fixture.policy.max_corrupt],
        )
    capsule = recover_threshold_capsule(release_fixture.locked_set, 0, early_releases)
    assessment = assess_threshold_signature_release(release_fixture.policy)

    assert capsule.selected_participant_indices == (0, 1)
    assert len(early_releases) > release_fixture.policy.max_corrupt
    assert assessment.funding_eligible is False
    assert any(
        "cumulative pre-erasure corruption bound" in item
        for item in assessment.unverified_blockers
    )


def test_research_assessment_is_fail_closed_and_names_blockers(
    release_fixture: _Fixture,
) -> None:
    assessment = assess_threshold_signature_release(release_fixture.policy)

    assert (
        assessment.schema == "ranklock-v026-threshold-signature-release-assessment-v4"
    )
    assert assessment.funding_eligible is False
    assert (
        assessment.lock_granularity
        == "one-independent-positive-lock-per-participant-alternative"
    )
    assert any(
        "setup abort handling" in item for item in assessment.unverified_blockers
    )
    assert any("scale randomness" in item for item in assessment.unverified_blockers)
    assert any("key erasure" in item for item in assessment.unverified_blockers)
    assert any(
        "independent control domains" in item for item in assessment.unverified_blockers
    )
    assert any(
        "GGM-plus-ROM extractable-WE proof" in item
        for item in assessment.unverified_blockers
    )
    assert any("selected-commitment" in item for item in assessment.unverified_blockers)
    assert any("mobile bound" in item for item in assessment.unverified_blockers)
    assert any(
        "samples fresh prover randomness r and s" in item
        for item in assessment.unverified_blockers
    )
    assert any(
        "accepts five public inputs" in item and "requires seven" in item
        for item in assessment.unverified_blockers
    )
    assert any(
        "operator key and game index" in item and "selected commitment" in item
        for item in assessment.unverified_blockers
    )
    assert any("variable-time" in item for item in assessment.unverified_blockers)
    assert any(
        "BN254 concrete security" in item for item in assessment.unverified_blockers
    )
    assert any(
        "exact Rust serialization" in item for item in assessment.unverified_blockers
    )
    assert len(assessment.unverified_blockers) == 16
    with pytest.raises(ThresholdSignatureReleaseError, match="funding-ineligible"):
        replace(assessment, funding_eligible=True)


def test_threshold_evidence_is_byte_exact_and_source_bound() -> None:
    root = Path(__file__).parents[1]
    generator = root / "scripts/generate_v026_threshold_signature_release.py"
    result_path = root / "results/v026_threshold_signature_release.json"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(
        (str(root / "src"), str(root), environment.get("PYTHONPATH", ""))
    )
    command = (sys.executable, str(generator))
    first = subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
    ).stdout
    second = subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
    ).stdout
    committed = result_path.read_bytes()

    assert first == second == committed
    subprocess.run(
        (*command, "--check"),
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
    )
    result = json.loads(committed)
    assert result["schema"] == "ranklock-v026-threshold-signature-release-result-v11"
    positive_lock_profile = result["positive_lock_security_profile"]
    assert positive_lock_profile["exact_ciphertext_shape_implemented"] is True
    assert positive_lock_profile["fixed_public_side_information_profile_bound"] is True
    assert positive_lock_profile["fixed_public_side_information_profile_fields"] == [
        "relation_circuit_digest",
        "complete_crs_digest",
        "proving_key_digest",
        "projectivizer_digest",
        "ceremony_transcript_digest",
    ]
    assert positive_lock_profile["plaintext_commitment_present"] is False
    assert positive_lock_profile["proof_models"] == [
        "generic-bilinear-group-model",
        "random-oracle-model",
    ]
    assert positive_lock_profile["local_equivalence_independently_reviewed"] is False
    assert positive_lock_profile["complete_public_side_information_qualified"] is False
    assert positive_lock_profile["deterministic_non_zk_relation_qualified"] is False
    assert positive_lock_profile["bn254_production_profile_approved"] is False
    assert positive_lock_profile["production_hiding_theorem_established"] is False
    assert positive_lock_profile["funding_eligible"] is False
    static_game = result["conditional_static_game"]
    assert (
        result["claim_boundary"]["babe_construction_one_ciphertext_profile_implemented"]
        is True
    )
    assert (
        result["claim_boundary"][
            "plaintext_payload_commitment_present_in_threshold_locks"
        ]
        is False
    )
    assert static_game["conditional_static_exposure_safety_established"] is True
    assert (
        static_game["conditional_static_valid_proof_availability_established"] is True
    )
    assert static_game["availability_slack"] == 0
    assert static_game["world_count"] == 12
    assert len(static_game["mobile_corruption_witnesses"]) == 2
    assert len(static_game["control_domain_witnesses"]) == 2
    assert len(static_game["artifact_loss_witnesses"]) == 2
    assert static_game["positive_lock_hiding_established"] is False
    assert static_game["participant_control_domain_independence_established"] is False
    assert static_game["production_release_theorem_established"] is False
    assert static_game["funding_eligible"] is False
    assert (
        result["claim_boundary"]["threshold_availability_theorem_established"] is False
    )
    assert result["claim_boundary"]["production_theorem_established"] is False
    assert (
        result["claim_boundary"]["deployed_sp1_direct_babe_compatibility_established"]
        is False
    )
    assert (
        result["claim_boundary"]["deployed_sp1_randomized_groth16_matches_babe_r_prime"]
        is False
    )
    assert (
        result["claim_boundary"]["deterministic_wrapper_architecture_gate_executed"]
        is True
    )
    assert result["claim_boundary"]["metadata_only_wrapper_rejected"] is True
    assert (
        result["claim_boundary"]["manifest_mapped_wrapper_identity_theorem_established"]
        is False
    )
    assert result["claim_boundary"]["subject_bound_counterproof_guest_selected"] is True
    assert (
        result["claim_boundary"]["subject_bound_counterproof_guest_implemented"] is True
    )
    assert (
        result["claim_boundary"]["subject_bound_counterproof_guest_source_implemented"]
        is True
    )
    assert (
        result["claim_boundary"]["subject_bound_counterproof_relation_native_verified"]
        is True
    )
    assert result["claim_boundary"]["subject_bound_counterproof_sp1_elf_built"] is True
    assert (
        result["claim_boundary"]["subject_bound_counterproof_sp1_execution_verified"]
        is True
    )
    assert (
        result["claim_boundary"][
            "subject_bound_counterproof_sp1_resource_profile_qualified"
        ]
        is True
    )
    assert (
        result["claim_boundary"][
            "subject_bound_sp1_standalone_receipt_verifier_implemented"
        ]
        is True
    )
    assert (
        result["claim_boundary"][
            "subject_bound_reorg_aware_canonical_chain_confirmation_implemented"
        ]
        is True
    )
    assert (
        result["claim_boundary"][
            "subject_bound_confirmed_ack_witness_cas_composition_implemented"
        ]
        is True
    )
    assert (
        result["claim_boundary"][
            "subject_bound_confirmed_ack_witness_cas_positive_receipt_executed"
        ]
        is False
    )
    assert (
        result["claim_boundary"][
            "subject_bound_confirmed_ack_witness_cas_is_enforced_runtime_path"
        ]
        is False
    )
    assert (
        result["claim_boundary"][
            "subject_bound_runtime_consumes_confirmation_capability"
        ]
        is False
    )
    assert (
        result["claim_boundary"][
            "subject_bound_verified_receipt_transaction_binding_implemented"
        ]
        is True
    )
    assert (
        result["claim_boundary"]["subject_bound_sp1_local_groth16_proof_generated"]
        is False
    )
    assert (
        result["claim_boundary"]["subject_bound_sp1_local_groth16_proof_verified"]
        is False
    )
    assert (
        result["claim_boundary"]["bridge_proof_txid_in_subject_public_output"] is True
    )
    assert (
        result["claim_boundary"]["onchain_bridge_proof_txid_runtime_match_implemented"]
        is False
    )
    assert (
        result["claim_boundary"]["deterministic_non_zk_final_groth16_implemented"]
        is False
    )
    assert result["claim_boundary"]["safe_for_funds"] is False
    sp1_compatibility = result["sp1_babe_compatibility"]
    assert sp1_compatibility["production_public_input_count"] == 5
    assert sp1_compatibility["ranklock_extended_public_input_count"] == 7
    assert sp1_compatibility["production_vk_accepts_ranklock_extended_layout"] is False
    assert sp1_compatibility["sp1_gnark_prover_samples_random_r_and_s"] is True
    assert sp1_compatibility["babe_deterministic_r_prime_instantiated"] is False
    assert (
        sp1_compatibility["selected_commitment_in_counterproof_public_values"] is False
    )
    assert sp1_compatibility["direct_integration_compatible"] is False
    assert sp1_compatibility["funding_eligible"] is False
    assert sp1_compatibility["universal_vk_sha256"] == (
        "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696"
    )
    wrapper_gate = result["deterministic_wrapper_gate"]
    assert wrapper_gate["metadata_only_route_sound"] is False
    assert wrapper_gate["manifest_mapped_route_requires_identity_theorem"] is True
    assert (
        wrapper_gate["operator_game_authoritative_subject_identity_established"] is True
    )
    assert wrapper_gate["selected_architecture"] == (
        "subject-bound-counterproof-guest-plus-deterministic-final-groth16"
    )
    assert wrapper_gate["subject_bound_counterproof_guest_implemented"] is True
    assert wrapper_gate["subject_bound_counterproof_guest_source_implemented"] is True
    assert wrapper_gate["subject_bound_counterproof_relation_native_verified"] is True
    assert wrapper_gate["subject_bound_counterproof_sp1_execution_verified"] is True
    assert (
        wrapper_gate["subject_bound_sp1_standalone_receipt_verifier_implemented"]
        is True
    )
    assert (
        wrapper_gate["subject_bound_verified_receipt_transaction_binding_implemented"]
        is True
    )
    assert (
        wrapper_gate["subject_bound_confirmed_ack_witness_cas_composition_implemented"]
        is True
    )
    assert (
        wrapper_gate[
            "subject_bound_confirmed_ack_witness_cas_pure_regression_test_count"
        ]
        == 2
    )
    assert (
        wrapper_gate[
            "subject_bound_confirmed_ack_witness_cas_positive_receipt_executed"
        ]
        is False
    )
    assert (
        wrapper_gate["subject_bound_confirmed_ack_witness_cas_is_enforced_runtime_path"]
        is False
    )
    assert wrapper_gate["subject_bound_sp1_local_groth16_proof_generated"] is False
    assert wrapper_gate["subject_bound_sp1_local_groth16_proof_verified"] is False
    assert wrapper_gate["deterministic_non_zk_final_groth16_implemented"] is False
    assert wrapper_gate["complete_wrapper_r1cs_present"] is False
    assert wrapper_gate["complete_wrapper_proving_key_present"] is False
    assert wrapper_gate["wrapper_projectivizer_present"] is False
    assert wrapper_gate["production_wrapper_compatible"] is False
    assert wrapper_gate["funding_eligible"] is False
    assert wrapper_gate["decision"] == (
        "SUBJECT_BOUND_SP1_LOCAL_PROVING_CAPACITY_BLOCKED_FINAL_GROTH16_REQUIRED"
    )
    assert wrapper_gate["schema"] == (
        "ranklock-v026-deterministic-wrapper-gate-assessment-v6"
    )
    assert len(wrapper_gate["blockers"]) == 9
    assert wrapper_gate["zkaleido_commit"] == (
        "c2683cf676490decc045d9a91d6c8b5740138f1c"
    )
    subject_gate = result["subject_bound_counterproof_gate"]
    assert subject_gate["relation_source_implemented"] is True
    assert subject_gate["distinct_guest_source_implemented"] is True
    assert subject_gate["signed_manifest_commitment_verified"] is True
    assert subject_gate["threshold_resolution_bytes_cross_checked"] is True
    assert subject_gate["canonical_ack_txid_and_sighash_recomputed"] is True
    assert subject_gate["bridge_proof_txid_in_public_output"] is True
    assert subject_gate["native_real_signature_test_passed"] is True
    assert subject_gate["native_subject_test_count"] == 9
    assert subject_gate["legacy_relation_regression_test_count"] == 33
    assert subject_gate["sp1_elf_built"] is True
    assert subject_gate["sp1_program_vkey_derived"] is True
    assert subject_gate["sp1_predicate_emitted"] is True
    assert subject_gate["sp1_guest_execution_verified"] is True
    assert subject_gate["sp1_resource_profile_qualified"] is True
    assert subject_gate["deterministic_rebuild_verified"] is True
    assert subject_gate["source_dependency_tracking_verified"] is True
    assert subject_gate["standalone_sp1_groth16_receipt_verifier_implemented"] is True
    assert (
        subject_gate["verified_receipt_transaction_binding_capability_implemented"]
        is True
    )
    assert subject_gate["receipt_verifier_regression_test_count"] == 4
    assert (
        subject_gate["reorg_aware_canonical_chain_confirmation_capability_implemented"]
        is True
    )
    assert subject_gate["canonical_chain_confirmation_core_regression_test_count"] == 2
    assert subject_gate["confirmed_ack_witness_cas_composition_implemented"] is True
    assert subject_gate["confirmed_ack_witness_cas_pure_regression_test_count"] == 2
    assert subject_gate["confirmed_ack_witness_cas_positive_receipt_executed"] is False
    assert subject_gate["confirmed_ack_witness_cas_is_enforced_runtime_path"] is False
    assert subject_gate["runtime_consumes_canonical_confirmation_capability"] is False
    assert subject_gate["legacy_elf_identity_rebuilt_and_compared"] is True
    assert subject_gate["legacy_elf_matches_published"] is False
    assert subject_gate["local_sp1_groth16_proof_generated"] is False
    assert subject_gate["local_sp1_groth16_proof_verified"] is False
    assert subject_gate["production_sp1_proof_generated"] is False
    assert subject_gate["production_sp1_proof_verified"] is False
    assert subject_gate["onchain_bridge_proof_txid_runtime_match_implemented"] is False
    assert subject_gate["setup_manifest_authority_qualified"] is False
    assert subject_gate["deterministic_final_groth16_implemented"] is False
    assert subject_gate["production_theorem_established"] is False
    assert subject_gate["funding_eligible"] is False
    assert subject_gate["schema"] == "ranklock-v026-subject-bound-counterproof-gate-v6"
    assert len(subject_gate["blockers"]) == 7
    assert subject_gate["local_sp1_groth16_attempt"] == {
        "artifact_sha256": (
            "97b496b5a02450d7494894001f3a6e188001898220b4840d43f1d8b88dd77a13"
        ),
        "artifact_size_bytes": 1_043,
        "backend": "SP1_PROVER=cpu",
        "free_disk_gib_after_swap_reclaim": 48,
        "free_disk_gib_at_start": 56,
        "free_disk_gib_safety_cutoff": 15,
        "insecure_rng_warning_count": 2,
        "log_sha256": (
            "294ecc0f72afd006c6a557d1caffabcb72c657f6bb8090c2b06af22f728ff85d"
        ),
        "log_size_bytes": 423,
        "max_observed_process_footprint_gib_lower_bound": 40,
        "max_observed_system_swap_used_mib_lower_bound": 41_239,
        "observed_cpu_seconds_lower_bound": 37_366,
        "observed_wall_seconds_lower_bound": 2_859,
        "proof_receipt_created": False,
        "proof_verified": False,
        "result": "safety-terminated-at-free-disk-cutoff-without-receipt",
        "schema": "ranklock-v026-local-sp1-groth16-attempt-evidence-v1",
        "sp1_circuit_version": "v6.2.4",
        "subject_elf_sha256": (
            "1db3e54249b8e9d2609097ac144f982d80e2fa01ce2913a6a6d1a93b27339f5e"
        ),
    }
    assert subject_gate["sp1_execution_profiles"] == [
        {
            "alternative_count": 2,
            "cycles": 23_633_673,
            "gas": 23_496_238,
            "participant_count": 3,
            "release_cell_count": 6,
        },
        {
            "alternative_count": 2,
            "cycles": 74_348_051,
            "gas": 76_946_196,
            "participant_count": 32,
            "release_cell_count": 64,
        },
        {
            "alternative_count": 4,
            "cycles": 82_346_560,
            "gas": 84_443_876,
            "participant_count": 16,
            "release_cell_count": 64,
        },
    ]
    assert subject_gate["artifacts"][4] == {
        "name": "counterproof-subject-v1.elf",
        "sha256": "1db3e54249b8e9d2609097ac144f982d80e2fa01ce2913a6a6d1a93b27339f5e",
        "size_bytes": 2_276_936,
    }
    assert subject_gate["published_legacy_counterproof_elf_sha256"] == (
        "9ae1d4ef5816b598cf9b02be659d3bae6535151834f1fd77a5f4b572a60be8b7"
    )
    assert result["reproduction"]["source_sha256"] == {
        "babe_positive_lock": sha256(
            (root / "src/ranklock/babe_positive_lock.py").read_bytes()
        ).hexdigest(),
        "babe_positive_lock_v2_tests": sha256(
            (root / "tests/test_babe_positive_lock_v2.py").read_bytes()
        ).hexdigest(),
        "generator": sha256(generator.read_bytes()).hexdigest(),
        "deterministic_wrapper_gate": sha256(
            (root / "src/ranklock/v026/deterministic_wrapper_gate.py").read_bytes()
        ).hexdigest(),
        "deterministic_wrapper_gate_tests": sha256(
            (root / "tests/test_v026_deterministic_wrapper_gate.py").read_bytes()
        ).hexdigest(),
        "model": sha256(
            (root / "src/ranklock/v026/threshold_signature_release.py").read_bytes()
        ).hexdigest(),
        "security_game": sha256(
            (root / "src/ranklock/v026/threshold_release_security_game.py").read_bytes()
        ).hexdigest(),
        "security_game_tests": sha256(
            (root / "tests/test_v026_threshold_release_security_game.py").read_bytes()
        ).hexdigest(),
        "sp1_babe_compatibility": sha256(
            (root / "src/ranklock/v026/sp1_babe_compatibility.py").read_bytes()
        ).hexdigest(),
        "sp1_babe_compatibility_tests": sha256(
            (root / "tests/test_v026_sp1_babe_compatibility.py").read_bytes()
        ).hexdigest(),
        "subject_bound_counterproof_gate": sha256(
            (root / "src/ranklock/v026/subject_bound_counterproof_gate.py").read_bytes()
        ).hexdigest(),
        "subject_bound_counterproof_gate_tests": sha256(
            (root / "tests/test_v026_subject_bound_counterproof_gate.py").read_bytes()
        ).hexdigest(),
        "subject_bound_counterproof_patch": sha256(
            (
                root / "integration/alpen-validity-first-f94c-v025/pending/"
                "v026-subject-bound-counterproof-guest.diff"
            ).read_bytes()
        ).hexdigest(),
        "threshold_v3_prerequisite_patch": sha256(
            (
                root / "integration/alpen-validity-first-f94c-v025/pending/"
                "v026-threshold-v3-research.diff"
            ).read_bytes()
        ).hexdigest(),
        "tests": sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def test_local_sp1_attempt_loader_rejects_summary_and_raw_log_tampering(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    source = root / "results/v026-subject-bound-sp1"
    target = tmp_path / "results/v026-subject-bound-sp1"
    target.mkdir(parents=True)
    attempt_name = "local-groth16-cpu-attempt-v1.json"
    log_name = "bridge_counterproof_subject_v1_SP1_v6.2.4.local-groth16.log"
    attempt_bytes = (source / attempt_name).read_bytes()
    log_bytes = (source / log_name).read_bytes()
    (target / attempt_name).write_bytes(attempt_bytes)
    (target / log_name).write_bytes(log_bytes)

    evidence = _local_sp1_groth16_attempt_evidence(tmp_path)
    assert evidence.proof_receipt_created is False
    assert evidence.proof_verified is False

    (target / log_name).write_bytes(log_bytes + b"tamper")
    with pytest.raises(RuntimeError, match="log hash"):
        _local_sp1_groth16_attempt_evidence(tmp_path)

    (target / log_name).write_bytes(log_bytes)
    attempt = json.loads(attempt_bytes)
    attempt["proof_verified"] = True
    (target / attempt_name).write_text(json.dumps(attempt), encoding="ascii")
    with pytest.raises(RuntimeError, match="must not claim"):
        _local_sp1_groth16_attempt_evidence(tmp_path)

    attempt["proof_verified"] = False
    attempt["unexpected"] = "field"
    (target / attempt_name).write_text(json.dumps(attempt), encoding="ascii")
    with pytest.raises(RuntimeError, match="field roster"):
        _local_sp1_groth16_attempt_evidence(tmp_path)
