from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.v026.subject_bound_counterproof_gate import (
    LocalSp1Groth16AttemptEvidenceV1,
    Sp1ArtifactFileEvidenceV1,
    Sp1ExecutionProfileV1,
    SubjectBoundCounterproofGateError,
    SubjectBoundSp1ArtifactEvidenceV1,
    assess_subject_bound_counterproof_gate,
)

_ARTIFACT_NAMES = (
    "bridge-proof-vkey.bin",
    "bridge-proof.elf",
    "bridge-proof.predicate",
    "counterproof-subject-v1-vkey.bin",
    "counterproof-subject-v1.elf",
    "counterproof-subject-v1.predicate",
    "counterproof-vkey.bin",
    "counterproof.elf",
    "counterproof.predicate",
)


def _digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _evidence() -> SubjectBoundSp1ArtifactEvidenceV1:
    artifacts = tuple(
        Sp1ArtifactFileEvidenceV1(name, _digest(name), index + 1)
        for index, name in enumerate(_ARTIFACT_NAMES)
    )
    subject_hash = next(
        artifact.sha256
        for artifact in artifacts
        if artifact.name == "counterproof-subject-v1.elf"
    )
    return SubjectBoundSp1ArtifactEvidenceV1(
        artifacts=artifacts,
        execution_profiles=(
            Sp1ExecutionProfileV1(2, 3, 23_633_673, 23_496_238),
            Sp1ExecutionProfileV1(2, 32, 74_348_051, 76_946_196),
            Sp1ExecutionProfileV1(4, 16, 82_346_560, 84_443_876),
        ),
        subject_elf_rebuild_sha256=(subject_hash,) * 3,
        published_legacy_counterproof_elf_sha256=_digest("published legacy"),
        asm_params_sha256=_digest("ASM params"),
        asm_verifying_key_sha256=_digest("ASM VK"),
        moho_verifying_key_sha256=_digest("Moho VK"),
        cargo_prove_version="sp1 6.2.0 (3772ff9)",
        succinct_rustc_version="rustc 1.93.0-dev (LLVM 21.1.8)",
        sp1_commit="3772ff9",
    )


def _attempt(subject_elf_sha256: bytes) -> LocalSp1Groth16AttemptEvidenceV1:
    return LocalSp1Groth16AttemptEvidenceV1(
        artifact_sha256=_digest("attempt artifact"),
        artifact_size_bytes=1_043,
        log_sha256=_digest("attempt log"),
        log_size_bytes=423,
        subject_elf_sha256=subject_elf_sha256,
        sp1_circuit_version="v6.2.4",
        backend="SP1_PROVER=cpu",
        observed_wall_seconds_lower_bound=2_859,
        observed_cpu_seconds_lower_bound=37_366,
        max_observed_process_footprint_gib_lower_bound=40,
        max_observed_system_swap_used_mib_lower_bound=41_239,
        free_disk_gib_at_start=56,
        free_disk_gib_safety_cutoff=15,
        free_disk_gib_after_swap_reclaim=48,
        insecure_rng_warning_count=2,
        result="safety-terminated-at-free-disk-cutoff-without-receipt",
    )


def _assessment():
    evidence = _evidence()
    return assess_subject_bound_counterproof_gate(
        _digest("subject patch"),
        _digest("threshold patch"),
        evidence,
        _attempt(evidence.artifact("counterproof-subject-v1.elf").sha256),
    )


def test_sp1_gate_records_built_executed_but_fail_closed_boundary() -> None:
    assessment = _assessment()

    assert assessment.relation_source_implemented is True
    assert assessment.distinct_guest_source_implemented is True
    assert assessment.signed_manifest_commitment_verified is True
    assert assessment.threshold_resolution_bytes_cross_checked is True
    assert assessment.canonical_ack_txid_and_sighash_recomputed is True
    assert assessment.bridge_proof_txid_in_public_output is True
    assert assessment.native_real_signature_test_passed is True
    assert assessment.native_subject_test_count == 9
    assert assessment.legacy_relation_regression_test_count == 33
    assert assessment.sp1_elf_built is True
    assert assessment.sp1_program_vkey_derived is True
    assert assessment.sp1_predicate_emitted is True
    assert assessment.sp1_guest_execution_verified is True
    assert assessment.sp1_resource_profile_qualified is True
    assert assessment.deterministic_rebuild_verified is True
    assert assessment.source_dependency_tracking_verified is True
    assert assessment.standalone_sp1_groth16_receipt_verifier_implemented is True
    assert (
        assessment.verified_receipt_transaction_binding_capability_implemented is True
    )
    assert assessment.receipt_verifier_regression_test_count == 4
    assert (
        assessment.reorg_aware_canonical_chain_confirmation_capability_implemented
        is True
    )
    assert assessment.canonical_chain_confirmation_core_regression_test_count == 2
    assert assessment.confirmed_ack_witness_cas_composition_implemented is True
    assert assessment.confirmed_ack_witness_cas_pure_regression_test_count == 2
    assert assessment.confirmed_ack_witness_cas_positive_receipt_executed is False
    assert assessment.confirmed_ack_witness_cas_is_enforced_runtime_path is False
    assert assessment.runtime_consumes_canonical_confirmation_capability is False
    assert assessment.legacy_elf_identity_rebuilt_and_compared is True
    assert assessment.legacy_elf_matches_published is False
    assert assessment.local_sp1_groth16_proof_generated is False
    assert assessment.local_sp1_groth16_proof_verified is False
    assert assessment.production_sp1_proof_generated is False
    assert assessment.production_sp1_proof_verified is False
    assert assessment.onchain_bridge_proof_txid_runtime_match_implemented is False
    assert assessment.setup_manifest_authority_qualified is False
    assert assessment.deterministic_final_groth16_implemented is False
    assert assessment.production_theorem_established is False
    assert assessment.funding_eligible is False
    assert len(assessment.blockers) == 7
    assert assessment.schema == "ranklock-v026-subject-bound-counterproof-gate-v6"


def test_gate_identity_and_authority_flags_are_not_caller_settable() -> None:
    assessment = _assessment()

    with pytest.raises(ValueError):
        replace(assessment, sp1_elf_built=False)
    with pytest.raises(ValueError):
        replace(assessment, local_sp1_groth16_proof_verified=True)
    with pytest.raises(ValueError):
        replace(assessment, production_sp1_proof_verified=True)
    with pytest.raises(ValueError):
        replace(
            assessment,
            runtime_consumes_canonical_confirmation_capability=True,
        )
    with pytest.raises(ValueError):
        replace(assessment, confirmed_ack_witness_cas_positive_receipt_executed=True)
    with pytest.raises(ValueError):
        replace(assessment, confirmed_ack_witness_cas_is_enforced_runtime_path=True)
    with pytest.raises(ValueError):
        replace(assessment, funding_eligible=True)


@pytest.mark.parametrize("digest", (b"", bytes(31), bytes(32)))
def test_gate_rejects_invalid_patch_digests(digest: bytes) -> None:
    evidence = _evidence()
    with pytest.raises(SubjectBoundCounterproofGateError):
        assess_subject_bound_counterproof_gate(
            digest,
            _digest("threshold patch"),
            evidence,
            _attempt(evidence.artifact("counterproof-subject-v1.elf").sha256),
        )


@pytest.mark.parametrize(
    ("alternatives", "participants"),
    ((5, 2), (4, 17), (2, 65)),
)
def test_execution_profile_rejects_unadmitted_matrix_shapes(
    alternatives: int,
    participants: int,
) -> None:
    with pytest.raises(SubjectBoundCounterproofGateError):
        Sp1ExecutionProfileV1(alternatives, participants, 1, 1)


def test_evidence_rejects_cycle_limit_and_rebuild_drift() -> None:
    evidence = _evidence()
    profiles = evidence.execution_profiles[:-1] + (
        replace(evidence.execution_profiles[-1], cycles=100_000_000),
    )
    with pytest.raises(SubjectBoundCounterproofGateError, match="cycle limit"):
        replace(evidence, execution_profiles=profiles)

    with pytest.raises(SubjectBoundCounterproofGateError, match="rebuild hashes"):
        replace(
            evidence,
            subject_elf_rebuild_sha256=(
                evidence.subject_elf_rebuild_sha256[0],
                evidence.subject_elf_rebuild_sha256[1],
                _digest("different rebuild"),
            ),
        )


def test_evidence_rejects_incomplete_artifact_roster_and_false_legacy_match() -> None:
    evidence = _evidence()
    with pytest.raises(SubjectBoundCounterproofGateError, match="artifact roster"):
        replace(evidence, artifacts=evidence.artifacts[:-1])

    rebuilt_legacy = evidence.artifact("counterproof.elf").sha256
    with pytest.raises(SubjectBoundCounterproofGateError, match="published artifact"):
        replace(
            evidence,
            published_legacy_counterproof_elf_sha256=rebuilt_legacy,
        )


def test_gate_rejects_attempt_for_a_different_subject_elf() -> None:
    evidence = _evidence()
    with pytest.raises(SubjectBoundCounterproofGateError, match="durable subject ELF"):
        assess_subject_bound_counterproof_gate(
            _digest("subject patch"),
            _digest("threshold patch"),
            evidence,
            _attempt(_digest("different subject ELF")),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (
            lambda attempt: replace(
                attempt,
                observed_cpu_seconds_lower_bound=(
                    attempt.observed_wall_seconds_lower_bound
                ),
            ),
            "more CPU than wall time",
        ),
        (
            lambda attempt: replace(attempt, free_disk_gib_after_swap_reclaim=15),
            "disk measurements",
        ),
        (
            lambda attempt: replace(attempt, backend="SP1_PROVER=network"),
            "CPU backend",
        ),
        (
            lambda attempt: replace(attempt, result="completed"),
            "no-receipt outcome",
        ),
    ),
)
def test_local_attempt_rejects_inconsistent_or_upgraded_evidence(
    mutation,
    message: str,
) -> None:
    evidence = _evidence()
    attempt = _attempt(evidence.artifact("counterproof-subject-v1.elf").sha256)
    with pytest.raises(SubjectBoundCounterproofGateError, match=message):
        mutation(attempt)

    with pytest.raises(ValueError):
        replace(attempt, proof_receipt_created=True)
    with pytest.raises(ValueError):
        replace(attempt, proof_verified=True)
