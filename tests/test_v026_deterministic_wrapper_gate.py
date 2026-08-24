from __future__ import annotations

from dataclasses import replace
from functools import cache
from hashlib import sha256
from pathlib import Path

import pytest

from ranklock.bip340 import public_key
from ranklock.v026.deterministic_wrapper_gate import (
    DeterministicWrapperGateError,
    DeterministicWrapperStatementV1,
    WrapperAckSubjectV1,
    WrapperBindingManifestV1,
    WrapperBindingRowV1,
    WrapperSemanticWitnessV1,
    assess_deterministic_wrapper_gate,
    metadata_relabelling_witness,
    selected_commitment,
)
from ranklock.v026.sp1_babe_compatibility import (
    Sp1BabeCompatibilityAssessmentV1,
    Sp1Groth16StatementV1,
    assess_sp1_babe_compatibility,
)
from ranklock.v026.subject_bound_counterproof_gate import (
    LocalSp1Groth16AttemptEvidenceV1,
    Sp1ArtifactFileEvidenceV1,
    Sp1ExecutionProfileV1,
    SubjectBoundSp1ArtifactEvidenceV1,
    assess_subject_bound_counterproof_gate,
)

_ARTIFACT_BUNDLE = (
    Path(__file__).resolve().parents[2]
    / "artifacts/upstream/sp1-bridge-guests-prod-v0.3.0-rc.2-29570989611"
)
_COUNTERPROOF_PROGRAM_VKEY = bytes.fromhex(
    "00fc65c2f437f49e8cb93e196c917724ca679eaee622295320ecc25b07e4d189"
)
_SUBJECT_ARTIFACT_DIRECTORY = (
    Path(__file__).resolve().parents[1] / "results/v026-subject-bound-sp1"
)
_SUBJECT_ARTIFACT_NAMES = (
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


def _field_digest(label: str) -> bytes:
    result = bytearray(_digest(label))
    result[0] &= 0x1F
    return bytes(result)


@cache
def _subject_gate():
    artifacts = tuple(
        Sp1ArtifactFileEvidenceV1(
            name,
            sha256((_SUBJECT_ARTIFACT_DIRECTORY / name).read_bytes()).digest(),
            (_SUBJECT_ARTIFACT_DIRECTORY / name).stat().st_size,
        )
        for name in _SUBJECT_ARTIFACT_NAMES
    )
    subject_hash = next(
        artifact.sha256
        for artifact in artifacts
        if artifact.name == "counterproof-subject-v1.elf"
    )
    evidence = SubjectBoundSp1ArtifactEvidenceV1(
        artifacts=artifacts,
        execution_profiles=(
            Sp1ExecutionProfileV1(2, 3, 23_633_673, 23_496_238),
            Sp1ExecutionProfileV1(2, 32, 74_348_051, 76_946_196),
            Sp1ExecutionProfileV1(4, 16, 82_346_560, 84_443_876),
        ),
        subject_elf_rebuild_sha256=(subject_hash,) * 3,
        published_legacy_counterproof_elf_sha256=bytes.fromhex(
            "9ae1d4ef5816b598cf9b02be659d3bae6535151834f1fd77a5f4b572a60be8b7"
        ),
        asm_params_sha256=bytes.fromhex(
            "364806caaf3500e195288216bbba73c8e0d5e6ede7092ff9c5f7e219f6070f53"
        ),
        asm_verifying_key_sha256=bytes.fromhex(
            "d3303f17e741960aa648534ad1ada2d20db396815c7baa1012d881082982e31a"
        ),
        moho_verifying_key_sha256=bytes.fromhex(
            "90afb979f5c95bbca73e18fa625471910fdc5129c9c2f5a90b98429abab3c69a"
        ),
        cargo_prove_version="sp1 6.2.0 (3772ff9)",
        succinct_rustc_version="rustc 1.93.0-dev (LLVM 21.1.8)",
        sp1_commit="3772ff9",
    )
    attempt = LocalSp1Groth16AttemptEvidenceV1(
        artifact_sha256=_digest("attempt artifact"),
        artifact_size_bytes=1_043,
        log_sha256=_digest("attempt log"),
        log_size_bytes=423,
        subject_elf_sha256=subject_hash,
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
    return assess_subject_bound_counterproof_gate(
        sha256(b"subject patch").digest(),
        sha256(b"threshold patch").digest(),
        evidence,
        attempt,
    )


@cache
def _compatibility() -> Sp1BabeCompatibilityAssessmentV1:
    return assess_sp1_babe_compatibility(_ARTIFACT_BUNDLE)


def _subject(
    funded_setup_digest: bytes,
    alternative_index: int,
    *,
    key_offset: int = 0,
) -> WrapperAckSubjectV1:
    return WrapperAckSubjectV1(
        selected_commitment(funded_setup_digest, alternative_index),
        public_key(10 + key_offset),
        3,
        2,
        tuple(public_key(20 + key_offset + index) for index in range(3)),
        _digest(f"R-outpoint-{key_offset}") + alternative_index.to_bytes(4, "little"),
        120_000 + alternative_index,
        bytes.fromhex("5120") + public_key(30 + key_offset),
        _digest(f"ACK-txid-{key_offset}-{alternative_index}"),
        _digest(f"ACK-sighash-{key_offset}-{alternative_index}"),
    )


def _manifest(
    funded_setup_digest: bytes,
    *,
    operator_secret: int = 40,
    game_index: int = 7,
    key_offset: int = 0,
) -> WrapperBindingManifestV1:
    subject = _subject(funded_setup_digest, 0, key_offset=key_offset)
    row = WrapperBindingRowV1(0, public_key(operator_secret), game_index, subject)
    return WrapperBindingManifestV1(
        _compatibility().artifacts.binding_digest,
        _COUNTERPROOF_PROGRAM_VKEY,
        funded_setup_digest,
        (row,),
    )


def _inner_statement(manifest: WrapperBindingManifestV1) -> Sp1Groth16StatementV1:
    row = manifest.rows[0]
    return Sp1Groth16StatementV1.for_counterproof_output(
        program_vkey_hash=manifest.counterproof_program_vkey,
        operator_xonly_pubkey=row.operator_xonly_pubkey,
        game_index=row.game_index,
        vk_root=_field_digest("vk-root"),
        proof_nonce=_field_digest("proof-nonce"),
    )


def test_wrapper_subject_and_manifest_are_canonical_and_p1_bound() -> None:
    funded = _digest("funded-setup")
    manifest = _manifest(funded)
    statement = DeterministicWrapperStatementV1.from_manifest(manifest, 0)
    witness = WrapperSemanticWitnessV1(
        _compatibility().artifacts,
        manifest,
        0,
        _inner_statement(manifest),
    )

    witness.validate_projection(statement)
    assert manifest.rows[0].ack_subject.selected_commitment == selected_commitment(
        funded, 0
    )
    assert manifest.rows[0].counterproof_public_values == (
        public_key(40) + (7).to_bytes(4, "little")
    )
    assert len(manifest.rows[0].ack_subject.encoded) == 314
    assert len(statement.public_values) == 72
    assert len(statement.digest) == 32
    assert all(0 <= limb < 2**128 for limb in statement.public_input_limbs)


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (
            lambda subject: replace(subject, selected_commitment=_digest("wrong")),
            "not derived",
        ),
        (
            lambda subject: replace(
                subject,
                resolution_outpoint_consensus=bytes(32) + bytes.fromhex("ffffffff"),
            ),
            "must not be null",
        ),
        (
            lambda subject: replace(subject, resolution_value_sat=0),
            "MoneyRange",
        ),
        (
            lambda subject: replace(subject, resolution_script_pubkey=bytes(34)),
            "not P2TR",
        ),
        (
            lambda subject: replace(
                subject,
                release_pubkeys=(subject.release_pubkeys[0],) * 3,
            ),
            "must be distinct",
        ),
    ),
)
def test_wrapper_subject_mutations_fail_closed(mutation, message: str) -> None:
    funded = _digest("funded-setup")
    baseline = _subject(funded, 0)
    with pytest.raises(DeterministicWrapperGateError, match=message):
        changed = mutation(baseline)
        if changed.selected_commitment != baseline.selected_commitment:
            row = WrapperBindingRowV1(0, public_key(40), 7, changed)
            WrapperBindingManifestV1(
                _compatibility().artifacts.binding_digest,
                _COUNTERPROOF_PROGRAM_VKEY,
                funded,
                (row,),
            )


def test_manifest_rejects_duplicate_authority_and_subject_classes() -> None:
    funded = _digest("funded-setup")
    first = WrapperBindingRowV1(0, public_key(40), 7, _subject(funded, 0))
    second_subject = _subject(funded, 1, key_offset=100)
    duplicate_authority = WrapperBindingRowV1(1, public_key(40), 7, second_subject)

    with pytest.raises(DeterministicWrapperGateError, match="operator/game"):
        WrapperBindingManifestV1(
            _compatibility().artifacts.binding_digest,
            _COUNTERPROOF_PROGRAM_VKEY,
            funded,
            (first, duplicate_authority),
        )

    with pytest.raises(DeterministicWrapperGateError, match="contiguous"):
        WrapperBindingManifestV1(
            _compatibility().artifacts.binding_digest,
            _COUNTERPROOF_PROGRAM_VKEY,
            funded,
            (replace(first, alternative_index=1),),
        )


def test_metadata_only_wrapper_has_an_exact_cross_setup_relabelling_witness() -> None:
    source_manifest = _manifest(_digest("funded-setup-A"))
    target_manifest = _manifest(_digest("funded-setup-B"), key_offset=100)
    inner = _inner_statement(source_manifest)
    artifacts = _compatibility().artifacts
    source = WrapperSemanticWitnessV1(artifacts, source_manifest, 0, inner)
    target = WrapperSemanticWitnessV1(artifacts, target_manifest, 0, inner)

    witness = metadata_relabelling_witness(source, target)

    assert source.inner_sp1_statement == target.inner_sp1_statement
    assert (
        source_manifest.rows[0].counterproof_public_values
        == target_manifest.rows[0].counterproof_public_values
    )
    assert (
        source_manifest.rows[0].ack_subject.selected_commitment
        != target_manifest.rows[0].ack_subject.selected_commitment
    )
    assert (
        witness.source_wrapper_statement.ack_subject_digest
        != witness.target_wrapper_statement.ack_subject_digest
    )


def test_semantic_projection_rejects_manifest_subject_operator_and_game_drift() -> None:
    manifest = _manifest(_digest("funded-setup"))
    statement = DeterministicWrapperStatementV1.from_manifest(manifest, 0)
    inner = _inner_statement(manifest)
    artifacts = _compatibility().artifacts
    witness = WrapperSemanticWitnessV1(artifacts, manifest, 0, inner)
    witness.validate_projection(statement)

    with pytest.raises(DeterministicWrapperGateError, match="another manifest"):
        witness.validate_projection(
            replace(statement, ack_subject_digest=_digest("other-subject"))
        )

    row = manifest.rows[0]
    wrong_operator = Sp1Groth16StatementV1.for_counterproof_output(
        program_vkey_hash=manifest.counterproof_program_vkey,
        operator_xonly_pubkey=public_key(41),
        game_index=row.game_index,
        vk_root=inner.vk_root,
        proof_nonce=inner.proof_nonce,
    )
    with pytest.raises(DeterministicWrapperGateError, match="operator/game"):
        WrapperSemanticWitnessV1(
            artifacts, manifest, 0, wrong_operator
        ).validate_projection(statement)

    wrong_game = Sp1Groth16StatementV1.for_counterproof_output(
        program_vkey_hash=manifest.counterproof_program_vkey,
        operator_xonly_pubkey=row.operator_xonly_pubkey,
        game_index=row.game_index + 1,
        vk_root=inner.vk_root,
        proof_nonce=inner.proof_nonce,
    )
    with pytest.raises(DeterministicWrapperGateError, match="operator/game"):
        WrapperSemanticWitnessV1(
            artifacts, manifest, 0, wrong_game
        ).validate_projection(statement)


def test_semantic_projection_rejects_unpinned_artifact_binding() -> None:
    manifest = _manifest(_digest("funded-setup"))
    forged = replace(manifest, artifact_binding_digest=_digest("other-artifacts"))
    statement = DeterministicWrapperStatementV1.from_manifest(forged, 0)

    with pytest.raises(DeterministicWrapperGateError, match="pinned.*artifacts"):
        WrapperSemanticWitnessV1(
            _compatibility().artifacts,
            forged,
            0,
            _inner_statement(forged),
        ).validate_projection(statement)


def test_manifest_mapping_is_conditional_not_a_production_wrapper() -> None:
    compatibility = _compatibility()
    assessment = assess_deterministic_wrapper_gate(compatibility, _subject_gate())

    assert assessment.metadata_only_route_sound is False
    assert assessment.sp1_in_sp1_mechanics_example_present is True
    assert assessment.example_pins_verifier_as_circuit_constant is False
    assert assessment.manifest_mapped_route_requires_identity_theorem is True
    assert assessment.operator_game_authoritative_subject_identity_established is True
    assert assessment.selected_architecture == (
        "subject-bound-counterproof-guest-plus-deterministic-final-groth16"
    )
    assert assessment.subject_bound_counterproof_guest_implemented is True
    assert assessment.subject_bound_counterproof_guest_source_implemented is True
    assert assessment.subject_bound_counterproof_relation_native_verified is True
    assert assessment.subject_bound_counterproof_sp1_execution_verified is True
    assert assessment.subject_bound_sp1_standalone_receipt_verifier_implemented is True
    assert (
        assessment.subject_bound_verified_receipt_transaction_binding_implemented
        is True
    )
    assert (
        assessment.subject_bound_reorg_aware_canonical_chain_confirmation_implemented
        is True
    )
    assert (
        assessment.subject_bound_canonical_chain_confirmation_core_regression_test_count
        == 2
    )
    assert (
        assessment.subject_bound_confirmed_ack_witness_cas_composition_implemented
        is True
    )
    assert (
        assessment.subject_bound_confirmed_ack_witness_cas_pure_regression_test_count
        == 2
    )
    assert (
        assessment.subject_bound_confirmed_ack_witness_cas_positive_receipt_executed
        is False
    )
    assert (
        assessment.subject_bound_confirmed_ack_witness_cas_is_enforced_runtime_path
        is False
    )
    assert assessment.subject_bound_runtime_consumes_confirmation_capability is False
    assert assessment.subject_bound_sp1_local_groth16_proof_generated is False
    assert assessment.subject_bound_sp1_local_groth16_proof_verified is False
    assert assessment.deterministic_non_zk_final_groth16_implemented is False
    assert assessment.complete_wrapper_r1cs_present is False
    assert assessment.complete_wrapper_proving_key_present is False
    assert assessment.wrapper_projectivizer_present is False
    assert assessment.production_wrapper_compatible is False
    assert assessment.funding_eligible is False
    assert assessment.decision == (
        "SUBJECT_BOUND_SP1_LOCAL_PROVING_CAPACITY_BLOCKED_FINAL_GROTH16_REQUIRED"
    )
    assert assessment.schema == "ranklock-v026-deterministic-wrapper-gate-assessment-v6"
    assert len(assessment.blockers) == 9
    assert assessment.zkaleido_commit == ("c2683cf676490decc045d9a91d6c8b5740138f1c")

    with pytest.raises(ValueError, match="init=False"):
        replace(assessment, metadata_only_route_sound=True)
    with pytest.raises(ValueError, match="init=False"):
        replace(assessment, funding_eligible=True)
