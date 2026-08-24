"""Emit deterministic evidence for the v0.26 threshold-signature profile."""

from __future__ import annotations

import argparse
import json
import sys
from hashlib import sha256
from pathlib import Path

from ranklock.babe_positive_lock import assess_babe_positive_lock_v2
from ranklock.v026.deterministic_wrapper_gate import (
    assess_deterministic_wrapper_gate,
)
from ranklock.v026.sp1_babe_compatibility import (
    BABE_PAPER_SHA256,
    BABE_PAPER_URL,
    assess_sp1_babe_compatibility,
)
from ranklock.v026.subject_bound_counterproof_gate import (
    LocalSp1Groth16AttemptEvidenceV1,
    Sp1ArtifactFileEvidenceV1,
    Sp1ExecutionProfileV1,
    SubjectBoundSp1ArtifactEvidenceV1,
    assess_subject_bound_counterproof_gate,
)
from ranklock.v026.threshold_release_security_game import (
    evaluate_conditional_static_threshold_release,
)
from ranklock.v026.threshold_signature_release import (
    ThresholdReleasePolicy,
    assess_threshold_signature_release,
)

_ALTERNATIVE_COUNT = 2
_MAX_PARTICIPANTS = 64
_RAW_ACK_SIGNATURE_BYTES = 64
_RESULT_PATH = Path("results/v026_threshold_signature_release.json")
_SCHEMA = "ranklock-v026-threshold-signature-release-result-v11"
_SP1_ARTIFACT_DIRECTORY = Path("results/v026-subject-bound-sp1")
_LOCAL_SP1_ATTEMPT_FILE = "local-groth16-cpu-attempt-v1.json"
_LOCAL_SP1_LOG_FILE = "bridge_counterproof_subject_v1_SP1_v6.2.4.local-groth16.log"
_LOCAL_SP1_COMMAND = (
    "cargo test -p strata-bridge-counterproof "
    "subject_bound_sp1_guest_generates_and_verifies_groth16_proof "
    "--features sp1-execution-tests -- --ignored --nocapture"
)
_LOCAL_SP1_ATTEMPT_KEYS = frozenset(
    {
        "backend",
        "command",
        "free_disk_gib_after_swap_reclaim",
        "free_disk_gib_at_start",
        "free_disk_gib_safety_cutoff",
        "insecure_rng_warning_count",
        "log_file",
        "log_sha256",
        "max_observed_process_footprint_gib_lower_bound",
        "max_observed_system_swap_used_mib_lower_bound",
        "observed_cpu_seconds_lower_bound",
        "observed_wall_seconds_lower_bound",
        "proof_receipt_created",
        "proof_verified",
        "result",
        "schema",
        "sp1_circuit_version",
        "subject_elf_sha256",
    }
)
_SP1_ARTIFACT_NAMES = (
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
_SUBJECT_ELF_SHA256 = bytes.fromhex(
    "1db3e54249b8e9d2609097ac144f982d80e2fa01ce2913a6a6d1a93b27339f5e"
)
_ASM_PARAMS_SHA256 = bytes.fromhex(
    "364806caaf3500e195288216bbba73c8e0d5e6ede7092ff9c5f7e219f6070f53"
)
_ASM_VERIFYING_KEY_SHA256 = bytes.fromhex(
    "d3303f17e741960aa648534ad1ada2d20db396815c7baa1012d881082982e31a"
)
_MOHO_VERIFYING_KEY_SHA256 = bytes.fromhex(
    "90afb979f5c95bbca73e18fa625471910fdc5129c9c2f5a90b98429abab3c69a"
)


def _sha256_file(path: Path) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise RuntimeError(f"failed to hash required evidence input {path}") from exc


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def _subject_sp1_evidence(
    repo_root: Path,
    published_legacy_counterproof_elf_sha256: bytes,
) -> SubjectBoundSp1ArtifactEvidenceV1:
    artifact_directory = repo_root / _SP1_ARTIFACT_DIRECTORY
    artifacts: list[Sp1ArtifactFileEvidenceV1] = []
    for name in _SP1_ARTIFACT_NAMES:
        path = artifact_directory / name
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise RuntimeError(f"failed to read required SP1 artifact {path}") from exc
        artifacts.append(
            Sp1ArtifactFileEvidenceV1(name, sha256(payload).digest(), len(payload))
        )
    return SubjectBoundSp1ArtifactEvidenceV1(
        artifacts=tuple(artifacts),
        execution_profiles=(
            Sp1ExecutionProfileV1(2, 3, 23_633_673, 23_496_238),
            Sp1ExecutionProfileV1(2, 32, 74_348_051, 76_946_196),
            Sp1ExecutionProfileV1(4, 16, 82_346_560, 84_443_876),
        ),
        subject_elf_rebuild_sha256=(_SUBJECT_ELF_SHA256,) * 3,
        published_legacy_counterproof_elf_sha256=(
            published_legacy_counterproof_elf_sha256
        ),
        asm_params_sha256=_ASM_PARAMS_SHA256,
        asm_verifying_key_sha256=_ASM_VERIFYING_KEY_SHA256,
        moho_verifying_key_sha256=_MOHO_VERIFYING_KEY_SHA256,
        cargo_prove_version="sp1 6.2.0 (3772ff9)",
        succinct_rustc_version="rustc 1.93.0-dev (LLVM 21.1.8)",
        sp1_commit="3772ff9",
    )


def _local_sp1_groth16_attempt_evidence(
    repo_root: Path,
) -> LocalSp1Groth16AttemptEvidenceV1:
    artifact_directory = repo_root / _SP1_ARTIFACT_DIRECTORY
    attempt_path = artifact_directory / _LOCAL_SP1_ATTEMPT_FILE
    try:
        attempt_bytes = attempt_path.read_bytes()
        raw = json.loads(attempt_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            f"failed to read strict local SP1 attempt evidence {attempt_path}"
        ) from exc
    if type(raw) is not dict or set(raw) != _LOCAL_SP1_ATTEMPT_KEYS:
        raise RuntimeError("local SP1 attempt evidence has a noncanonical field roster")
    if raw["schema"] != "ranklock-v026-local-sp1-groth16-attempt-evidence-v1":
        raise RuntimeError("local SP1 attempt evidence has an unknown schema")
    if raw["command"] != _LOCAL_SP1_COMMAND:
        raise RuntimeError("local SP1 attempt evidence has the wrong command")
    if raw["log_file"] != _LOCAL_SP1_LOG_FILE:
        raise RuntimeError("local SP1 attempt evidence has the wrong log identity")
    if raw["proof_receipt_created"] is not False or raw["proof_verified"] is not False:
        raise RuntimeError("local SP1 attempt must not claim a proof or verification")
    if raw["subject_elf_sha256"] != _SUBJECT_ELF_SHA256.hex():
        raise RuntimeError("local SP1 attempt is not bound to the durable subject ELF")
    log_path = artifact_directory / _LOCAL_SP1_LOG_FILE
    try:
        log_bytes = log_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"failed to read local SP1 attempt log {log_path}") from exc
    log_sha256 = sha256(log_bytes).hexdigest()
    if raw["log_sha256"] != log_sha256:
        raise RuntimeError("local SP1 attempt log hash does not match the raw log")
    warning = b"stderr: WARNING: Using insecure random number generator."
    if log_bytes.count(warning) != raw["insecure_rng_warning_count"]:
        raise RuntimeError("local SP1 attempt warning count does not match the raw log")
    return LocalSp1Groth16AttemptEvidenceV1(
        artifact_sha256=sha256(attempt_bytes).digest(),
        artifact_size_bytes=len(attempt_bytes),
        log_sha256=bytes.fromhex(log_sha256),
        log_size_bytes=len(log_bytes),
        subject_elf_sha256=bytes.fromhex(raw["subject_elf_sha256"]),
        sp1_circuit_version=raw["sp1_circuit_version"],
        backend=raw["backend"],
        observed_wall_seconds_lower_bound=raw["observed_wall_seconds_lower_bound"],
        observed_cpu_seconds_lower_bound=raw["observed_cpu_seconds_lower_bound"],
        max_observed_process_footprint_gib_lower_bound=(
            raw["max_observed_process_footprint_gib_lower_bound"]
        ),
        max_observed_system_swap_used_mib_lower_bound=(
            raw["max_observed_system_swap_used_mib_lower_bound"]
        ),
        free_disk_gib_at_start=raw["free_disk_gib_at_start"],
        free_disk_gib_safety_cutoff=raw["free_disk_gib_safety_cutoff"],
        free_disk_gib_after_swap_reclaim=raw["free_disk_gib_after_swap_reclaim"],
        insecure_rng_warning_count=raw["insecure_rng_warning_count"],
        result=raw["result"],
    )


def build_result(repo_root: Path) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    policy = ThresholdReleasePolicy(
        participant_count=3,
        threshold=2,
        max_corrupt=1,
    )
    assessment = assess_threshold_signature_release(policy)
    babe_assessment = assess_babe_positive_lock_v2()
    sp1_babe_assessment = assess_sp1_babe_compatibility(
        root.parent
        / "artifacts/upstream/sp1-bridge-guests-prod-v0.3.0-rc.2-29570989611"
    )
    static_evidence = evaluate_conditional_static_threshold_release(
        policy,
        alternative_count=_ALTERNATIVE_COUNT,
    )
    blocker_count = len(assessment.unverified_blockers)
    if blocker_count != 16:
        raise RuntimeError(
            f"threshold assessment must retain exactly 16 blockers, got {blocker_count}"
        )
    participant_alternative_count = policy.participant_count * _ALTERNATIVE_COUNT
    source_paths = {
        "babe_positive_lock": root / "src/ranklock/babe_positive_lock.py",
        "babe_positive_lock_v2_tests": (root / "tests/test_babe_positive_lock_v2.py"),
        "generator": Path(__file__).resolve(strict=True),
        "deterministic_wrapper_gate": (
            root / "src/ranklock/v026/deterministic_wrapper_gate.py"
        ),
        "deterministic_wrapper_gate_tests": (
            root / "tests/test_v026_deterministic_wrapper_gate.py"
        ),
        "model": root / "src/ranklock/v026/threshold_signature_release.py",
        "security_game": (
            root / "src/ranklock/v026/threshold_release_security_game.py"
        ),
        "tests": root / "tests/test_v026_threshold_signature_release.py",
        "security_game_tests": (
            root / "tests/test_v026_threshold_release_security_game.py"
        ),
        "sp1_babe_compatibility": (
            root / "src/ranklock/v026/sp1_babe_compatibility.py"
        ),
        "sp1_babe_compatibility_tests": (
            root / "tests/test_v026_sp1_babe_compatibility.py"
        ),
        "subject_bound_counterproof_gate": (
            root / "src/ranklock/v026/subject_bound_counterproof_gate.py"
        ),
        "subject_bound_counterproof_gate_tests": (
            root / "tests/test_v026_subject_bound_counterproof_gate.py"
        ),
        "subject_bound_counterproof_patch": (
            root / "integration/alpen-validity-first-f94c-v025/pending/"
            "v026-subject-bound-counterproof-guest.diff"
        ),
        "threshold_v3_prerequisite_patch": (
            root / "integration/alpen-validity-first-f94c-v025/pending/"
            "v026-threshold-v3-research.diff"
        ),
    }
    source_hashes = {label: _sha256_file(path) for label, path in source_paths.items()}
    subject_sp1_evidence = _subject_sp1_evidence(
        root,
        sp1_babe_assessment.artifacts.counterproof_elf_sha256,
    )
    local_sp1_attempt = _local_sp1_groth16_attempt_evidence(root)
    subject_bound_gate = assess_subject_bound_counterproof_gate(
        bytes.fromhex(source_hashes["subject_bound_counterproof_patch"]),
        bytes.fromhex(source_hashes["threshold_v3_prerequisite_patch"]),
        subject_sp1_evidence,
        local_sp1_attempt,
    )
    wrapper_gate = assess_deterministic_wrapper_gate(
        sp1_babe_assessment,
        subject_bound_gate,
    )
    return {
        "assessment": {
            "funding_eligible": assessment.funding_eligible,
            "lock_granularity": assessment.lock_granularity,
            "schema": assessment.schema,
            "unverified_blocker_count": blocker_count,
            "unverified_blockers": list(assessment.unverified_blockers),
        },
        "claim_boundary": {
            "babe_construction_one_ciphertext_profile_implemented": True,
            "bitcoin_integration_verified": False,
            "circuit_layout_and_semantic_projection_qualified": False,
            "conditional_static_exposure_safety_established": (
                static_evidence.conditional_static_exposure_safety_established
            ),
            "conditional_static_valid_proof_availability_established": (
                static_evidence.conditional_static_valid_proof_availability_established
            ),
            "cryptographic_fixture_execution_embedded": False,
            "durable_witness_selection_and_rust_cas_verified": False,
            "deployed_sp1_direct_babe_compatibility_established": False,
            "deployed_sp1_randomized_groth16_matches_babe_r_prime": False,
            "deterministic_non_zk_final_groth16_implemented": False,
            "deterministic_wrapper_architecture_gate_executed": True,
            "evidence_class": "EXACT static profile and claim-boundary evidence only",
            "full_lock_bytes_reported": False,
            "funding_eligible": False,
            "known_toxic_fixture_exclusion_regression": {
                "execution_embedded": False,
                "test": "test_known_toxic_fixture_is_rejected_and_qualified_crs_remains_a_blocker",
            },
            "mobile_pre_erasure_corruption_resistance_established": False,
            "manifest_mapped_wrapper_identity_theorem_established": False,
            "metadata_only_wrapper_rejected": True,
            "opaque_crs_qualified": False,
            "participant_control_domain_independence_established": False,
            "plaintext_payload_commitment_present_in_threshold_locks": False,
            "positive_lock_hiding_over_complete_crs_established": False,
            "production_ceremony_qualified": False,
            "production_theorem_established": False,
            "protected_value_theorem_established": False,
            "retained_artifact_custody_and_erasure_attested": False,
            "safe_for_funds": False,
            "subject_bound_counterproof_guest_implemented": (
                subject_bound_gate.sp1_elf_built
            ),
            "subject_bound_counterproof_guest_source_implemented": (
                subject_bound_gate.distinct_guest_source_implemented
            ),
            "subject_bound_counterproof_relation_native_verified": (
                subject_bound_gate.native_real_signature_test_passed
            ),
            "subject_bound_counterproof_sp1_elf_built": subject_bound_gate.sp1_elf_built,
            "subject_bound_counterproof_sp1_execution_verified": (
                subject_bound_gate.sp1_guest_execution_verified
            ),
            "subject_bound_counterproof_sp1_resource_profile_qualified": (
                subject_bound_gate.sp1_resource_profile_qualified
            ),
            "subject_bound_sp1_standalone_receipt_verifier_implemented": (
                subject_bound_gate.standalone_sp1_groth16_receipt_verifier_implemented
            ),
            "subject_bound_verified_receipt_transaction_binding_implemented": (
                subject_bound_gate.verified_receipt_transaction_binding_capability_implemented
            ),
            "subject_bound_reorg_aware_canonical_chain_confirmation_implemented": (
                subject_bound_gate.reorg_aware_canonical_chain_confirmation_capability_implemented
            ),
            "subject_bound_confirmed_ack_witness_cas_composition_implemented": (
                subject_bound_gate.confirmed_ack_witness_cas_composition_implemented
            ),
            "subject_bound_confirmed_ack_witness_cas_positive_receipt_executed": (
                subject_bound_gate.confirmed_ack_witness_cas_positive_receipt_executed
            ),
            "subject_bound_confirmed_ack_witness_cas_is_enforced_runtime_path": (
                subject_bound_gate.confirmed_ack_witness_cas_is_enforced_runtime_path
            ),
            "subject_bound_runtime_consumes_confirmation_capability": (
                subject_bound_gate.runtime_consumes_canonical_confirmation_capability
            ),
            "subject_bound_sp1_local_groth16_proof_generated": (
                subject_bound_gate.local_sp1_groth16_proof_generated
            ),
            "subject_bound_sp1_local_groth16_proof_verified": (
                subject_bound_gate.local_sp1_groth16_proof_verified
            ),
            "bridge_proof_txid_in_subject_public_output": (
                subject_bound_gate.bridge_proof_txid_in_public_output
            ),
            "onchain_bridge_proof_txid_runtime_match_implemented": (
                subject_bound_gate.onchain_bridge_proof_txid_runtime_match_implemented
            ),
            "subject_bound_counterproof_guest_selected": True,
            "threshold_availability_theorem_established": False,
            "variable_time_research_code": True,
        },
        "deterministic_wrapper_gate": {
            "artifact_binding_digest": wrapper_gate.artifacts.binding_digest.hex(),
            "blockers": list(wrapper_gate.blockers),
            "complete_wrapper_proving_key_present": (
                wrapper_gate.complete_wrapper_proving_key_present
            ),
            "complete_wrapper_r1cs_present": wrapper_gate.complete_wrapper_r1cs_present,
            "decision": wrapper_gate.decision,
            "deterministic_non_zk_final_groth16_implemented": (
                wrapper_gate.deterministic_non_zk_final_groth16_implemented
            ),
            "example_pins_verifier_as_circuit_constant": (
                wrapper_gate.example_pins_verifier_as_circuit_constant
            ),
            "funding_eligible": wrapper_gate.funding_eligible,
            "manifest_mapped_route_requires_identity_theorem": (
                wrapper_gate.manifest_mapped_route_requires_identity_theorem
            ),
            "metadata_only_route_sound": wrapper_gate.metadata_only_route_sound,
            "operator_game_authoritative_subject_identity_established": (
                wrapper_gate.operator_game_authoritative_subject_identity_established
            ),
            "production_wrapper_compatible": wrapper_gate.production_wrapper_compatible,
            "schema": wrapper_gate.schema,
            "selected_architecture": wrapper_gate.selected_architecture,
            "sp1_in_sp1_mechanics_example_present": (
                wrapper_gate.sp1_in_sp1_mechanics_example_present
            ),
            "subject_bound_counterproof_guest_implemented": (
                wrapper_gate.subject_bound_counterproof_guest_implemented
            ),
            "subject_bound_counterproof_guest_source_implemented": (
                wrapper_gate.subject_bound_counterproof_guest_source_implemented
            ),
            "subject_bound_counterproof_relation_native_verified": (
                wrapper_gate.subject_bound_counterproof_relation_native_verified
            ),
            "subject_bound_counterproof_sp1_execution_verified": (
                wrapper_gate.subject_bound_counterproof_sp1_execution_verified
            ),
            "subject_bound_sp1_standalone_receipt_verifier_implemented": (
                wrapper_gate.subject_bound_sp1_standalone_receipt_verifier_implemented
            ),
            "subject_bound_verified_receipt_transaction_binding_implemented": (
                wrapper_gate.subject_bound_verified_receipt_transaction_binding_implemented
            ),
            "subject_bound_reorg_aware_canonical_chain_confirmation_implemented": (
                wrapper_gate.subject_bound_reorg_aware_canonical_chain_confirmation_implemented
            ),
            "subject_bound_canonical_chain_confirmation_core_regression_test_count": (
                wrapper_gate.subject_bound_canonical_chain_confirmation_core_regression_test_count
            ),
            "subject_bound_confirmed_ack_witness_cas_composition_implemented": (
                wrapper_gate.subject_bound_confirmed_ack_witness_cas_composition_implemented
            ),
            "subject_bound_confirmed_ack_witness_cas_pure_regression_test_count": (
                wrapper_gate.subject_bound_confirmed_ack_witness_cas_pure_regression_test_count
            ),
            "subject_bound_confirmed_ack_witness_cas_positive_receipt_executed": (
                wrapper_gate.subject_bound_confirmed_ack_witness_cas_positive_receipt_executed
            ),
            "subject_bound_confirmed_ack_witness_cas_is_enforced_runtime_path": (
                wrapper_gate.subject_bound_confirmed_ack_witness_cas_is_enforced_runtime_path
            ),
            "subject_bound_runtime_consumes_confirmation_capability": (
                wrapper_gate.subject_bound_runtime_consumes_confirmation_capability
            ),
            "subject_bound_sp1_local_groth16_proof_generated": (
                wrapper_gate.subject_bound_sp1_local_groth16_proof_generated
            ),
            "subject_bound_sp1_local_groth16_proof_verified": (
                wrapper_gate.subject_bound_sp1_local_groth16_proof_verified
            ),
            "wrapper_projectivizer_present": wrapper_gate.wrapper_projectivizer_present,
            "zkaleido_commit": wrapper_gate.zkaleido_commit,
            "zkaleido_example_source_sha256": (
                wrapper_gate.zkaleido_example_source_sha256
            ),
            "zkaleido_example_source_url": wrapper_gate.zkaleido_example_source_url,
            "zkaleido_verifier_source_sha256": (
                wrapper_gate.zkaleido_verifier_source_sha256
            ),
            "zkaleido_verifier_source_url": wrapper_gate.zkaleido_verifier_source_url,
        },
        "subject_bound_counterproof_gate": {
            "artifacts": [
                {
                    "name": artifact.name,
                    "sha256": artifact.sha256.hex(),
                    "size_bytes": artifact.size_bytes,
                }
                for artifact in subject_bound_gate.sp1_evidence.artifacts
            ],
            "asm_params_sha256": (
                subject_bound_gate.sp1_evidence.asm_params_sha256.hex()
            ),
            "asm_verifying_key_sha256": (
                subject_bound_gate.sp1_evidence.asm_verifying_key_sha256.hex()
            ),
            "blockers": list(subject_bound_gate.blockers),
            "bridge_proof_txid_in_public_output": (
                subject_bound_gate.bridge_proof_txid_in_public_output
            ),
            "canonical_ack_txid_and_sighash_recomputed": (
                subject_bound_gate.canonical_ack_txid_and_sighash_recomputed
            ),
            "deterministic_final_groth16_implemented": (
                subject_bound_gate.deterministic_final_groth16_implemented
            ),
            "deterministic_rebuild_verified": (
                subject_bound_gate.deterministic_rebuild_verified
            ),
            "distinct_guest_source_implemented": (
                subject_bound_gate.distinct_guest_source_implemented
            ),
            "funding_eligible": subject_bound_gate.funding_eligible,
            "legacy_elf_identity_rebuilt_and_compared": (
                subject_bound_gate.legacy_elf_identity_rebuilt_and_compared
            ),
            "legacy_elf_matches_published": (
                subject_bound_gate.legacy_elf_matches_published
            ),
            "legacy_relation_regression_test_count": (
                subject_bound_gate.legacy_relation_regression_test_count
            ),
            "local_sp1_groth16_attempt": {
                "artifact_sha256": (
                    subject_bound_gate.local_groth16_attempt.artifact_sha256.hex()
                ),
                "artifact_size_bytes": (
                    subject_bound_gate.local_groth16_attempt.artifact_size_bytes
                ),
                "backend": subject_bound_gate.local_groth16_attempt.backend,
                "free_disk_gib_after_swap_reclaim": (
                    subject_bound_gate.local_groth16_attempt.free_disk_gib_after_swap_reclaim
                ),
                "free_disk_gib_at_start": (
                    subject_bound_gate.local_groth16_attempt.free_disk_gib_at_start
                ),
                "free_disk_gib_safety_cutoff": (
                    subject_bound_gate.local_groth16_attempt.free_disk_gib_safety_cutoff
                ),
                "insecure_rng_warning_count": (
                    subject_bound_gate.local_groth16_attempt.insecure_rng_warning_count
                ),
                "log_sha256": (
                    subject_bound_gate.local_groth16_attempt.log_sha256.hex()
                ),
                "log_size_bytes": (
                    subject_bound_gate.local_groth16_attempt.log_size_bytes
                ),
                "max_observed_process_footprint_gib_lower_bound": (
                    subject_bound_gate.local_groth16_attempt.max_observed_process_footprint_gib_lower_bound
                ),
                "max_observed_system_swap_used_mib_lower_bound": (
                    subject_bound_gate.local_groth16_attempt.max_observed_system_swap_used_mib_lower_bound
                ),
                "observed_cpu_seconds_lower_bound": (
                    subject_bound_gate.local_groth16_attempt.observed_cpu_seconds_lower_bound
                ),
                "observed_wall_seconds_lower_bound": (
                    subject_bound_gate.local_groth16_attempt.observed_wall_seconds_lower_bound
                ),
                "proof_receipt_created": (
                    subject_bound_gate.local_groth16_attempt.proof_receipt_created
                ),
                "proof_verified": (
                    subject_bound_gate.local_groth16_attempt.proof_verified
                ),
                "result": subject_bound_gate.local_groth16_attempt.result,
                "schema": subject_bound_gate.local_groth16_attempt.schema,
                "sp1_circuit_version": (
                    subject_bound_gate.local_groth16_attempt.sp1_circuit_version
                ),
                "subject_elf_sha256": (
                    subject_bound_gate.local_groth16_attempt.subject_elf_sha256.hex()
                ),
            },
            "local_sp1_groth16_proof_generated": (
                subject_bound_gate.local_sp1_groth16_proof_generated
            ),
            "local_sp1_groth16_proof_verified": (
                subject_bound_gate.local_sp1_groth16_proof_verified
            ),
            "native_real_signature_test_passed": (
                subject_bound_gate.native_real_signature_test_passed
            ),
            "native_subject_test_count": subject_bound_gate.native_subject_test_count,
            "moho_verifying_key_sha256": (
                subject_bound_gate.sp1_evidence.moho_verifying_key_sha256.hex()
            ),
            "onchain_bridge_proof_txid_runtime_match_implemented": (
                subject_bound_gate.onchain_bridge_proof_txid_runtime_match_implemented
            ),
            "production_theorem_established": (
                subject_bound_gate.production_theorem_established
            ),
            "production_sp1_proof_generated": (
                subject_bound_gate.production_sp1_proof_generated
            ),
            "production_sp1_proof_verified": (
                subject_bound_gate.production_sp1_proof_verified
            ),
            "published_legacy_counterproof_elf_sha256": (
                subject_bound_gate.sp1_evidence.published_legacy_counterproof_elf_sha256.hex()
            ),
            "receipt_verifier_regression_test_count": (
                subject_bound_gate.receipt_verifier_regression_test_count
            ),
            "reorg_aware_canonical_chain_confirmation_capability_implemented": (
                subject_bound_gate.reorg_aware_canonical_chain_confirmation_capability_implemented
            ),
            "canonical_chain_confirmation_core_regression_test_count": (
                subject_bound_gate.canonical_chain_confirmation_core_regression_test_count
            ),
            "confirmed_ack_witness_cas_composition_implemented": (
                subject_bound_gate.confirmed_ack_witness_cas_composition_implemented
            ),
            "confirmed_ack_witness_cas_pure_regression_test_count": (
                subject_bound_gate.confirmed_ack_witness_cas_pure_regression_test_count
            ),
            "confirmed_ack_witness_cas_positive_receipt_executed": (
                subject_bound_gate.confirmed_ack_witness_cas_positive_receipt_executed
            ),
            "confirmed_ack_witness_cas_is_enforced_runtime_path": (
                subject_bound_gate.confirmed_ack_witness_cas_is_enforced_runtime_path
            ),
            "runtime_consumes_canonical_confirmation_capability": (
                subject_bound_gate.runtime_consumes_canonical_confirmation_capability
            ),
            "relation_source_implemented": subject_bound_gate.relation_source_implemented,
            "schema": subject_bound_gate.schema,
            "setup_manifest_authority_qualified": (
                subject_bound_gate.setup_manifest_authority_qualified
            ),
            "signed_manifest_commitment_verified": (
                subject_bound_gate.signed_manifest_commitment_verified
            ),
            "source_patch_sha256": subject_bound_gate.source_patch_sha256.hex(),
            "sp1_elf_built": subject_bound_gate.sp1_elf_built,
            "sp1_execution_profiles": [
                {
                    "alternative_count": profile.alternative_count,
                    "cycles": profile.cycles,
                    "gas": profile.gas,
                    "participant_count": profile.participant_count,
                    "release_cell_count": (
                        profile.alternative_count * profile.participant_count
                    ),
                }
                for profile in subject_bound_gate.sp1_evidence.execution_profiles
            ],
            "sp1_guest_execution_verified": (
                subject_bound_gate.sp1_guest_execution_verified
            ),
            "sp1_predicate_emitted": subject_bound_gate.sp1_predicate_emitted,
            "sp1_program_vkey_derived": subject_bound_gate.sp1_program_vkey_derived,
            "sp1_resource_profile_qualified": (
                subject_bound_gate.sp1_resource_profile_qualified
            ),
            "sp1_toolchain": {
                "cargo_prove_version": (
                    subject_bound_gate.sp1_evidence.cargo_prove_version
                ),
                "reserved_cycle_limit": (
                    subject_bound_gate.sp1_evidence.reserved_cycle_limit
                ),
                "sp1_commit": subject_bound_gate.sp1_evidence.sp1_commit,
                "succinct_rustc_version": (
                    subject_bound_gate.sp1_evidence.succinct_rustc_version
                ),
            },
            "strata_commit": subject_bound_gate.strata_commit,
            "subject_elf_rebuild_sha256": [
                digest.hex()
                for digest in subject_bound_gate.sp1_evidence.subject_elf_rebuild_sha256
            ],
            "source_dependency_tracking_verified": (
                subject_bound_gate.source_dependency_tracking_verified
            ),
            "standalone_sp1_groth16_receipt_verifier_implemented": (
                subject_bound_gate.standalone_sp1_groth16_receipt_verifier_implemented
            ),
            "verified_receipt_transaction_binding_capability_implemented": (
                subject_bound_gate.verified_receipt_transaction_binding_capability_implemented
            ),
            "threshold_patch_sha256": (subject_bound_gate.threshold_patch_sha256.hex()),
            "threshold_resolution_bytes_cross_checked": (
                subject_bound_gate.threshold_resolution_bytes_cross_checked
            ),
        },
        "conditional_static_game": {
            "artifact_loss_witnesses": [
                {
                    "alternative_index": witness.alternative_index,
                    "available_signature_count": witness.available_signature_count,
                    "corrupt_count": witness.corrupt_count,
                    "schema": witness.schema,
                    "threshold": witness.threshold,
                    "unavailable_honest_count": witness.unavailable_honest_count,
                }
                for witness in static_evidence.artifact_loss_witnesses
            ],
            "availability_slack": static_evidence.availability_slack,
            "conditional_static_exposure_safety_established": (
                static_evidence.conditional_static_exposure_safety_established
            ),
            "conditional_static_valid_proof_availability_established": (
                static_evidence.conditional_static_valid_proof_availability_established
            ),
            "control_domain_witnesses": [
                {
                    "accumulated_signature_count": (
                        witness.accumulated_signature_count
                    ),
                    "aliased_participant_indices": list(
                        witness.aliased_participant_indices
                    ),
                    "alternative_index": witness.alternative_index,
                    "compromised_control_domain_count": (
                        witness.compromised_control_domain_count
                    ),
                    "schema": witness.schema,
                    "threshold": witness.threshold,
                }
                for witness in static_evidence.control_domain_witnesses
            ],
            "digest": static_evidence.digest.hex(),
            "funding_eligible": static_evidence.funding_eligible,
            "mobile_corruption_witnesses": [
                {
                    "accumulated_signature_count": (
                        witness.accumulated_signature_count
                    ),
                    "alternative_index": witness.alternative_index,
                    "maximum_simultaneous_corruptions": (
                        witness.maximum_simultaneous_corruptions
                    ),
                    "participant_sequence": list(witness.participant_sequence),
                    "schema": witness.schema,
                    "threshold": witness.threshold,
                }
                for witness in static_evidence.mobile_corruption_witnesses
            ],
            "positive_lock_hiding_established": (
                static_evidence.positive_lock_hiding_established
            ),
            "participant_control_domain_independence_established": (
                static_evidence.participant_control_domain_independence_established
            ),
            "production_release_theorem_established": (
                static_evidence.production_release_theorem_established
            ),
            "required_unverified_assumptions": [
                assumption.value for assumption in static_evidence.assumptions
            ],
            "schema": static_evidence.schema,
            "world_count": len(static_evidence.worlds),
            "worlds": [
                {
                    "ack_quorum_available": world.ack_quorum_available,
                    "alternative_index": world.alternative_index,
                    "available_signature_count": world.available_signature_count,
                    "corrupt_count": world.corrupt_count,
                    "corrupt_signatures_available": (
                        world.corrupt_signatures_available
                    ),
                    "honest_signatures_available": world.honest_signatures_available,
                    "kind": world.kind.value,
                    "schema": world.schema,
                    "threshold": world.threshold,
                }
                for world in static_evidence.worlds
            ],
        },
        "positive_lock_security_profile": {
            "complete_public_side_information_qualified": (
                babe_assessment.complete_public_side_information_qualified
            ),
            "deterministic_non_zk_relation_qualified": (
                babe_assessment.deterministic_non_zk_relation_qualified
            ),
            "construction_reference": babe_assessment.construction_reference,
            "exact_ciphertext_shape_implemented": (
                babe_assessment.exact_ciphertext_shape_implemented
            ),
            "fixed_public_side_information_profile_bound": True,
            "fixed_public_side_information_profile_fields": [
                "relation_circuit_digest",
                "complete_crs_digest",
                "proving_key_digest",
                "projectivizer_digest",
                "ceremony_transcript_digest",
            ],
            "funding_eligible": babe_assessment.funding_eligible,
            "local_equivalence_independently_reviewed": (
                babe_assessment.local_equivalence_independently_reviewed
            ),
            "bn254_production_profile_approved": (
                babe_assessment.bn254_production_profile_approved
            ),
            "plaintext_commitment_present": (
                babe_assessment.plaintext_commitment_present
            ),
            "production_hiding_theorem_established": (
                babe_assessment.production_hiding_theorem_established
            ),
            "proof_models": list(babe_assessment.proof_models),
            "reduction_dependencies": list(babe_assessment.reduction_dependencies),
            "schema": babe_assessment.schema,
            "security_definition": babe_assessment.security_definition,
        },
        "sp1_babe_compatibility": {
            "artifact_binding_digest": (
                sp1_babe_assessment.artifacts.binding_digest.hex()
            ),
            "artifact_bundle": {
                "counterproof_elf_sha256": (
                    sp1_babe_assessment.artifacts.counterproof_elf_sha256.hex()
                ),
                "counterproof_predicate_sha256": (
                    sp1_babe_assessment.artifacts.counterproof_predicate_sha256.hex()
                ),
                "counterproof_program_vkey": (
                    sp1_babe_assessment.artifacts.counterproof_program_vkey.hex()
                ),
                "environment": sp1_babe_assessment.artifacts.environment,
                "file_names": list(sp1_babe_assessment.artifacts.imported_file_names),
                "manifest_schema": (sp1_babe_assessment.artifacts.manifest_schema),
                "manifest_sha256": (
                    sp1_babe_assessment.artifacts.manifest_sha256.hex()
                ),
                "predicate_universal_vk_hash_prefix": (
                    sp1_babe_assessment.artifacts.predicate_universal_vk_hash_prefix.hex()
                ),
                "strata_bridge_ref": (sp1_babe_assessment.artifacts.strata_bridge_ref),
                "strata_bridge_sha": (sp1_babe_assessment.artifacts.strata_bridge_sha),
            },
            "babe_deterministic_r_prime_instantiated": (
                sp1_babe_assessment.babe_deterministic_r_prime_instantiated
            ),
            "babe_paper_sha256": BABE_PAPER_SHA256,
            "babe_paper_url": BABE_PAPER_URL,
            "complete_proving_key_present_in_import": (
                sp1_babe_assessment.complete_proving_key_present_in_import
            ),
            "complete_r1cs_present_in_import": (
                sp1_babe_assessment.complete_r1cs_present_in_import
            ),
            "counterproof_public_value_fields": [
                "operator_xonly_pubkey",
                "game_index_u32_le",
            ],
            "counterproof_types_source_sha256": (
                sp1_babe_assessment.counterproof_types_source_sha256
            ),
            "counterproof_types_source_url": (
                sp1_babe_assessment.counterproof_types_source_url
            ),
            "direct_integration_compatible": (
                sp1_babe_assessment.direct_integration_compatible
            ),
            "funding_eligible": sp1_babe_assessment.funding_eligible,
            "gnark_commit": sp1_babe_assessment.gnark_commit,
            "gnark_prove_source_sha256": (
                sp1_babe_assessment.gnark_prove_source_sha256
            ),
            "gnark_prove_source_url": (sp1_babe_assessment.gnark_prove_source_url),
            "production_public_input_count": (
                sp1_babe_assessment.production_public_input_count
            ),
            "production_vk_accepts_ranklock_extended_layout": (
                sp1_babe_assessment.production_vk_accepts_ranklock_extended_layout
            ),
            "projectivizer_present_in_import": (
                sp1_babe_assessment.projectivizer_present_in_import
            ),
            "ranklock_extended_public_input_count": (
                sp1_babe_assessment.ranklock_extended_public_input_count
            ),
            "schema": sp1_babe_assessment.schema,
            "selected_commitment_in_counterproof_public_values": (
                sp1_babe_assessment.selected_commitment_in_counterproof_public_values
            ),
            "sp1_gnark_prover_samples_random_r_and_s": (
                sp1_babe_assessment.sp1_gnark_prover_samples_random_r_and_s
            ),
            "sp1_version": sp1_babe_assessment.sp1_version,
            "universal_vk_sha256": (sp1_babe_assessment.universal_vk_sha256.hex()),
        },
        "profile": {
            "alternative_count": _ALTERNATIVE_COUNT,
            "required_distinct_participant_alternative_positive_locks": (
                participant_alternative_count
            ),
            "required_distinct_participant_alternative_release_keys": (
                participant_alternative_count
            ),
            "max_corrupt": policy.max_corrupt,
            "maximum_participant_count": _MAX_PARTICIPANTS,
            "participant_alternative_count": participant_alternative_count,
            "participant_count": policy.participant_count,
            "policy_digest": policy.digest.hex(),
            "policy_schema": policy.schema,
            "raw_ack_signature_payload_bytes": _RAW_ACK_SIGNATURE_BYTES,
            "threshold": policy.threshold,
            "threshold_inequalities": {
                "f_less_than_t": policy.max_corrupt < policy.threshold,
                "t_at_most_n_minus_f": (
                    policy.threshold <= policy.participant_count - policy.max_corrupt
                ),
            },
        },
        "reproduction": {
            "check_command": (
                "PYTHONPATH=src:. uv run python "
                "scripts/generate_v026_threshold_signature_release.py --check"
            ),
            "command": (
                "PYTHONPATH=src:. uv run python "
                "scripts/generate_v026_threshold_signature_release.py"
            ),
            "focused_test_command": (
                "PYTHONPATH=src:. uv run --with pytest pytest -q "
                "tests/test_babe_positive_lock_v2.py "
                "tests/test_v026_sp1_babe_compatibility.py "
                "tests/test_v026_subject_bound_counterproof_gate.py "
                "tests/test_v026_deterministic_wrapper_gate.py "
                "tests/test_v026_threshold_signature_release.py "
                "tests/test_v026_threshold_release_security_game.py"
            ),
            "source_sha256": source_hashes,
        },
        "schema": _SCHEMA,
    }


def build_result_bytes(repo_root: Path) -> bytes:
    return _canonical_json_bytes(build_result(repo_root))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="emit deterministic v0.26 threshold-signature evidence"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help=f"compare generated bytes with {_RESULT_PATH}",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help=f"atomically replace {_RESULT_PATH} with generated bytes",
    )
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    generated = build_result_bytes(repo_root)
    result_path = repo_root / _RESULT_PATH
    if args.check:
        try:
            committed = result_path.read_bytes()
        except OSError as exc:
            raise RuntimeError(
                f"failed to read committed threshold evidence {result_path}"
            ) from exc
        if committed != generated:
            raise RuntimeError("committed threshold evidence is stale")
        return 0
    if args.write:
        temporary_path = result_path.with_suffix(result_path.suffix + ".tmp")
        try:
            temporary_path.write_bytes(generated)
            temporary_path.replace(result_path)
        except OSError as exc:
            raise RuntimeError(
                f"failed to replace threshold evidence {result_path}"
            ) from exc
        return 0
    sys.stdout.buffer.write(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
