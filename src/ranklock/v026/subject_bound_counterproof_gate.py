"""Fail-closed evidence boundary for the subject-bound counterproof guest.

The SP1 artifact and guest-execution gates are executable. A real local CPU
Groth16 attempt also established that this workstation cannot complete the
proof inside its safe disk/memory envelope. That capacity result remains
strictly separate from proof generation, runtime admission, the final
deterministic Groth16 wrapper, and any funding decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_STRATA_COMMIT = "f94c06d08ff29eee746f3e20bd63078d2949b304"
_EXPECTED_ARTIFACT_NAMES = (
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
_EXPECTED_EXECUTION_PROFILES = ((2, 3), (2, 32), (4, 16))
_SP1_RESERVED_CYCLE_LIMIT = 100_000_000


class SubjectBoundCounterproofGateError(ValueError):
    """Invalid immutable evidence input for the subject-bound guest gate."""


def _digest(value: bytes, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise SubjectBoundCounterproofGateError(f"{name} must be 32 immutable bytes")
    if value == bytes(32):
        raise SubjectBoundCounterproofGateError(f"{name} must not be zero")
    return value


@dataclass(frozen=True, slots=True)
class Sp1ArtifactFileEvidenceV1:
    """Content identity and exact size of one rebuilt SP1 output."""

    name: str
    sha256: bytes
    size_bytes: int

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name:
            raise SubjectBoundCounterproofGateError(
                "SP1 artifact name must be a nonempty string"
            )
        _digest(self.sha256, f"{self.name} SHA-256")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise SubjectBoundCounterproofGateError(
                f"{self.name} size must be a positive integer"
            )


@dataclass(frozen=True, slots=True)
class Sp1ExecutionProfileV1:
    """Measured execution cost for one admitted release-matrix shape."""

    alternative_count: int
    participant_count: int
    cycles: int
    gas: int

    def __post_init__(self) -> None:
        alternatives = self.alternative_count
        participants = self.participant_count
        if type(alternatives) is not int or not 2 <= alternatives <= 4:
            raise SubjectBoundCounterproofGateError(
                "SP1 execution alternatives must be in 2..4"
            )
        if type(participants) is not int or not 2 <= participants <= 64:
            raise SubjectBoundCounterproofGateError(
                "SP1 execution participants must be in 2..64"
            )
        if alternatives * participants > 64:
            raise SubjectBoundCounterproofGateError(
                "SP1 execution release matrix exceeds 64 cells"
            )
        if type(self.cycles) is not int or self.cycles <= 0:
            raise SubjectBoundCounterproofGateError(
                "SP1 execution cycles must be a positive integer"
            )
        if type(self.gas) is not int or self.gas <= 0:
            raise SubjectBoundCounterproofGateError(
                "SP1 execution gas must be a positive integer"
            )


@dataclass(frozen=True, slots=True)
class LocalSp1Groth16AttemptEvidenceV1:
    """Content-bound evidence from one safety-terminated local proving run."""

    artifact_sha256: bytes
    artifact_size_bytes: int
    log_sha256: bytes
    log_size_bytes: int
    subject_elf_sha256: bytes
    sp1_circuit_version: str
    backend: str
    observed_wall_seconds_lower_bound: int
    observed_cpu_seconds_lower_bound: int
    max_observed_process_footprint_gib_lower_bound: int
    max_observed_system_swap_used_mib_lower_bound: int
    free_disk_gib_at_start: int
    free_disk_gib_safety_cutoff: int
    free_disk_gib_after_swap_reclaim: int
    insecure_rng_warning_count: int
    result: str
    proof_receipt_created: bool = field(default=False, init=False)
    proof_verified: bool = field(default=False, init=False)
    schema: str = "ranklock-v026-local-sp1-groth16-attempt-evidence-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-local-sp1-groth16-attempt-evidence-v1":
            raise SubjectBoundCounterproofGateError(
                "unknown local SP1 Groth16 attempt-evidence schema"
            )
        for name, digest in (
            ("local proving-attempt artifact SHA-256", self.artifact_sha256),
            ("local proving-attempt log SHA-256", self.log_sha256),
            ("local proving-attempt subject ELF SHA-256", self.subject_elf_sha256),
        ):
            _digest(digest, name)
        for name, value in (
            ("attempt artifact size", self.artifact_size_bytes),
            ("attempt log size", self.log_size_bytes),
            ("observed wall seconds", self.observed_wall_seconds_lower_bound),
            ("observed CPU seconds", self.observed_cpu_seconds_lower_bound),
            (
                "observed process footprint GiB",
                self.max_observed_process_footprint_gib_lower_bound,
            ),
            (
                "observed system swap MiB",
                self.max_observed_system_swap_used_mib_lower_bound,
            ),
            ("free disk at start", self.free_disk_gib_at_start),
            ("free-disk safety cutoff", self.free_disk_gib_safety_cutoff),
            ("free disk after reclaim", self.free_disk_gib_after_swap_reclaim),
            ("insecure-RNG warning count", self.insecure_rng_warning_count),
        ):
            if type(value) is not int or value <= 0:
                raise SubjectBoundCounterproofGateError(
                    f"{name} must be a positive integer"
                )
        if self.observed_cpu_seconds_lower_bound <= (
            self.observed_wall_seconds_lower_bound
        ):
            raise SubjectBoundCounterproofGateError(
                "multi-core proving evidence must report more CPU than wall time"
            )
        if not (
            self.free_disk_gib_safety_cutoff
            < self.free_disk_gib_after_swap_reclaim
            <= self.free_disk_gib_at_start
        ):
            raise SubjectBoundCounterproofGateError(
                "local proving disk measurements are inconsistent"
            )
        if self.sp1_circuit_version != "v6.2.4":
            raise SubjectBoundCounterproofGateError(
                "local proving evidence must use SP1 circuit v6.2.4"
            )
        if self.backend != "SP1_PROVER=cpu":
            raise SubjectBoundCounterproofGateError(
                "local proving evidence must identify the CPU backend"
            )
        if self.result != "safety-terminated-at-free-disk-cutoff-without-receipt":
            raise SubjectBoundCounterproofGateError(
                "local proving result must remain the exact no-receipt outcome"
            )


@dataclass(frozen=True, slots=True)
class SubjectBoundSp1ArtifactEvidenceV1:
    """Rebuilt artifact identities and locally executed SP1 frontier."""

    artifacts: tuple[Sp1ArtifactFileEvidenceV1, ...]
    execution_profiles: tuple[Sp1ExecutionProfileV1, ...]
    subject_elf_rebuild_sha256: tuple[bytes, ...]
    published_legacy_counterproof_elf_sha256: bytes
    asm_params_sha256: bytes
    asm_verifying_key_sha256: bytes
    moho_verifying_key_sha256: bytes
    cargo_prove_version: str
    succinct_rustc_version: str
    sp1_commit: str
    reserved_cycle_limit: int = _SP1_RESERVED_CYCLE_LIMIT
    schema: str = "ranklock-v026-subject-bound-sp1-artifact-evidence-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-subject-bound-sp1-artifact-evidence-v1":
            raise SubjectBoundCounterproofGateError(
                "unknown subject-bound SP1 evidence schema"
            )
        if (
            type(self.artifacts) is not tuple
            or tuple(artifact.name for artifact in self.artifacts)
            != _EXPECTED_ARTIFACT_NAMES
        ):
            raise SubjectBoundCounterproofGateError(
                "SP1 artifact roster must be exact, ordered, and complete"
            )
        if not all(
            isinstance(artifact, Sp1ArtifactFileEvidenceV1)
            for artifact in self.artifacts
        ):
            raise SubjectBoundCounterproofGateError(
                "SP1 artifact roster contains an invalid entry"
            )
        if (
            tuple(
                (profile.alternative_count, profile.participant_count)
                for profile in self.execution_profiles
            )
            != _EXPECTED_EXECUTION_PROFILES
        ):
            raise SubjectBoundCounterproofGateError(
                "SP1 execution profile roster must contain the minimum and final frontier"
            )
        if not all(
            isinstance(profile, Sp1ExecutionProfileV1)
            for profile in self.execution_profiles
        ):
            raise SubjectBoundCounterproofGateError(
                "SP1 execution profile roster contains an invalid entry"
            )
        if (
            type(self.reserved_cycle_limit) is not int
            or self.reserved_cycle_limit != _SP1_RESERVED_CYCLE_LIMIT
        ):
            raise SubjectBoundCounterproofGateError(
                "SP1 evidence must use the pinned 100,000,000-cycle reserved limit"
            )
        if max(profile.cycles for profile in self.execution_profiles) >= (
            self.reserved_cycle_limit
        ):
            raise SubjectBoundCounterproofGateError(
                "SP1 execution profile reaches or exceeds the reserved cycle limit"
            )
        subject_hash = self.artifact("counterproof-subject-v1.elf").sha256
        if (
            type(self.subject_elf_rebuild_sha256) is not tuple
            or len(self.subject_elf_rebuild_sha256) < 3
        ):
            raise SubjectBoundCounterproofGateError(
                "SP1 subject ELF needs at least three recorded deterministic rebuilds"
            )
        for index, digest in enumerate(self.subject_elf_rebuild_sha256):
            _digest(digest, f"subject ELF rebuild {index} SHA-256")
            if digest != subject_hash:
                raise SubjectBoundCounterproofGateError(
                    "SP1 subject ELF rebuild hashes do not match the durable artifact"
                )
        for name, digest in (
            (
                "published legacy counterproof ELF SHA-256",
                self.published_legacy_counterproof_elf_sha256,
            ),
            ("ASM parameter SHA-256", self.asm_params_sha256),
            ("ASM verifying-key SHA-256", self.asm_verifying_key_sha256),
            ("Moho verifying-key SHA-256", self.moho_verifying_key_sha256),
        ):
            _digest(digest, name)
        if (
            self.artifact("counterproof.elf").sha256
            == self.published_legacy_counterproof_elf_sha256
        ):
            raise SubjectBoundCounterproofGateError(
                "rebuilt legacy ELF must not be misreported as the published artifact"
            )
        for name, value in (
            ("cargo-prove version", self.cargo_prove_version),
            ("succinct rustc version", self.succinct_rustc_version),
            ("SP1 commit", self.sp1_commit),
        ):
            if type(value) is not str or not value:
                raise SubjectBoundCounterproofGateError(
                    f"{name} must be a nonempty string"
                )

    def artifact(self, name: str) -> Sp1ArtifactFileEvidenceV1:
        """Return one member of the exact artifact roster."""

        for artifact in self.artifacts:
            if artifact.name == name:
                return artifact
        raise SubjectBoundCounterproofGateError(
            f"SP1 artifact roster does not contain {name}"
        )


@dataclass(frozen=True, slots=True)
class SubjectBoundCounterproofGateV6:
    """Boundary after execution, receipt, confirmation, and capacity evidence."""

    source_patch_sha256: bytes
    threshold_patch_sha256: bytes
    sp1_evidence: SubjectBoundSp1ArtifactEvidenceV1
    local_groth16_attempt: LocalSp1Groth16AttemptEvidenceV1
    strata_commit: str = _STRATA_COMMIT
    relation_source_implemented: bool = field(default=True, init=False)
    distinct_guest_source_implemented: bool = field(default=True, init=False)
    signed_manifest_commitment_verified: bool = field(default=True, init=False)
    threshold_resolution_bytes_cross_checked: bool = field(default=True, init=False)
    canonical_ack_txid_and_sighash_recomputed: bool = field(default=True, init=False)
    bridge_proof_txid_in_public_output: bool = field(default=True, init=False)
    native_real_signature_test_passed: bool = field(default=True, init=False)
    native_subject_test_count: int = field(default=9, init=False)
    legacy_relation_regression_test_count: int = field(default=33, init=False)
    sp1_elf_built: bool = field(default=True, init=False)
    sp1_program_vkey_derived: bool = field(default=True, init=False)
    sp1_predicate_emitted: bool = field(default=True, init=False)
    sp1_guest_execution_verified: bool = field(default=True, init=False)
    sp1_resource_profile_qualified: bool = field(default=True, init=False)
    deterministic_rebuild_verified: bool = field(default=True, init=False)
    source_dependency_tracking_verified: bool = field(default=True, init=False)
    standalone_sp1_groth16_receipt_verifier_implemented: bool = field(
        default=True, init=False
    )
    verified_receipt_transaction_binding_capability_implemented: bool = field(
        default=True, init=False
    )
    receipt_verifier_regression_test_count: int = field(default=4, init=False)
    reorg_aware_canonical_chain_confirmation_capability_implemented: bool = field(
        default=True, init=False
    )
    canonical_chain_confirmation_core_regression_test_count: int = field(
        default=2, init=False
    )
    confirmed_ack_witness_cas_composition_implemented: bool = field(
        default=True, init=False
    )
    confirmed_ack_witness_cas_pure_regression_test_count: int = field(
        default=2, init=False
    )
    confirmed_ack_witness_cas_positive_receipt_executed: bool = field(
        default=False, init=False
    )
    confirmed_ack_witness_cas_is_enforced_runtime_path: bool = field(
        default=False, init=False
    )
    runtime_consumes_canonical_confirmation_capability: bool = field(
        default=False, init=False
    )
    legacy_elf_identity_rebuilt_and_compared: bool = field(default=True, init=False)
    legacy_elf_matches_published: bool = field(default=False, init=False)
    local_sp1_groth16_proof_generated: bool = field(default=False, init=False)
    local_sp1_groth16_proof_verified: bool = field(default=False, init=False)
    production_sp1_proof_generated: bool = field(default=False, init=False)
    production_sp1_proof_verified: bool = field(default=False, init=False)
    onchain_bridge_proof_txid_runtime_match_implemented: bool = field(
        default=False, init=False
    )
    setup_manifest_authority_qualified: bool = field(default=False, init=False)
    deterministic_final_groth16_implemented: bool = field(default=False, init=False)
    production_theorem_established: bool = field(default=False, init=False)
    funding_eligible: bool = field(default=False, init=False)
    blockers: tuple[str, ...] = field(
        default=(
            "the executor can bind a confirmed receipt subject to one verified ACK witness, recheck Bitcoin before and after immutable witness CAS, and reject conflicts, but no valid receipt executes that composed path, no duty requires it, and the lower-level witness store remains independently callable",
            "the setup ceremony does not yet authorize, persist, and distribute the exact signed subject manifest",
            "a real local SP1 6.2.4 CPU Groth16 attempt emitted two insecure-RNG warnings, exceeded a 40 GiB observed process footprint and 41,239 MiB system swap, and was safety-terminated after at least 2,859 wall seconds without creating a receipt",
            "the production receipt verifier and negative regressions are implemented but no valid receipt exists for a positive algebraic-verification run; a qualified production prover or authorized network-prover capacity, latency, and quota profile is absent",
            "the deterministic final non-zero-knowledge Groth16/BABE circuit, proving key, qualified CRS, and projectivizer are absent",
            "threshold release and funding runtimes do not consume the new proof identity",
            "the rebuilt current-source legacy ELF differs from the published deployed artifact, so activation requires a new versioned subject predicate and must not overwrite legacy identity",
        ),
        init=False,
    )
    schema: str = field(
        default="ranklock-v026-subject-bound-counterproof-gate-v6", init=False
    )

    def __post_init__(self) -> None:
        _digest(self.source_patch_sha256, "subject-bound source patch SHA-256")
        _digest(self.threshold_patch_sha256, "threshold-v3 patch SHA-256")
        if not isinstance(self.sp1_evidence, SubjectBoundSp1ArtifactEvidenceV1):
            raise SubjectBoundCounterproofGateError(
                "subject-bound gate has invalid SP1 artifact evidence"
            )
        if not isinstance(self.local_groth16_attempt, LocalSp1Groth16AttemptEvidenceV1):
            raise SubjectBoundCounterproofGateError(
                "subject-bound gate has invalid local Groth16 attempt evidence"
            )
        if (
            self.local_groth16_attempt.subject_elf_sha256
            != self.sp1_evidence.artifact("counterproof-subject-v1.elf").sha256
        ):
            raise SubjectBoundCounterproofGateError(
                "local proving attempt does not bind the durable subject ELF"
            )
        if self.strata_commit != _STRATA_COMMIT:
            raise SubjectBoundCounterproofGateError(
                "subject-bound relation is pinned to the exact audited Strata commit"
            )
        if not self.blockers:
            raise SubjectBoundCounterproofGateError(
                "subject-bound relation assessment must remain fail-closed"
            )


def assess_subject_bound_counterproof_gate(
    source_patch_sha256: bytes,
    threshold_patch_sha256: bytes,
    sp1_evidence: SubjectBoundSp1ArtifactEvidenceV1,
    local_groth16_attempt: LocalSp1Groth16AttemptEvidenceV1,
) -> SubjectBoundCounterproofGateV6:
    """Return the immutable artifact, execution, and capacity boundary."""

    return SubjectBoundCounterproofGateV6(
        source_patch_sha256,
        threshold_patch_sha256,
        sp1_evidence,
        local_groth16_attempt,
    )
