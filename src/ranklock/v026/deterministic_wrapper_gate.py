"""Fail-closed architecture gate for a deterministic SP1-to-BABE wrapper.

The deployed counterproof proof exposes only ``(operator_pubkey, game_index)``.
Consequently, a wrapper that verifies that proof and independently accepts an ACK
subject hash does not bind the proof to the ACK subject.  This module makes the
missing relation executable.  It specifies a canonical manifest which maps the
exact SP1 output to one funded selected commitment and ACK subject, and it emits a
concrete relabelling witness for wrappers which omit that constraint.

This is a relation and architecture specification, not a proof-system backend.  It
does not verify an SP1 proof inside a circuit, generate deterministic non-ZK
Groth16 proofs, or construct the BABE projective artifact.  Those absences are
immutable funding blockers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from ..bip340 import BIP340Error, lift_x
from ..bn254_real import CURVE_ORDER
from .sp1_babe_compatibility import (
    ImportedCounterproofArtifactEvidenceV1,
    Sp1BabeCompatibilityAssessmentV1,
    Sp1Groth16StatementV1,
)
from .subject_bound_counterproof_gate import SubjectBoundCounterproofGateV6

_HASH_BYTES = 32
_XONLY_BYTES = 32
_OUTPOINT_BYTES = 36
_P2TR_SCRIPT_BYTES = 34
_MAX_PARTICIPANTS = 64
_MAX_MONEY_SAT = 2_100_000_000_000_000

_ACK_SUBJECT_MAGIC = b"RL26WAS1"
_MANIFEST_MAGIC = b"RL26WBM1"
_WRAPPER_PUBLIC_VALUES_MAGIC = b"RL26WST1"
_ACK_SUBJECT_DOMAIN = b"ranklock/v026/wrapper-ack-subject/v1\x00"
_MANIFEST_DOMAIN = b"ranklock/v026/wrapper-binding-manifest/v1\x00"
_WRAPPER_STATEMENT_DOMAIN = b"ranklock/v026/deterministic-wrapper-statement/v1\x00"
_INNER_STATEMENT_DOMAIN = b"ranklock/v026/wrapper-inner-sp1-statement/v1\x00"
_SELECTED_COMMITMENT_TAG = b"RankLock/v026/threshold-v3/selected-alternative/v1"

ZKALEIDO_COMMIT = "c2683cf676490decc045d9a91d6c8b5740138f1c"
ZKALEIDO_SP1_IN_SP1_EXAMPLE_SHA256 = (
    "763877301a8da187c37678612fcdcd96c893d52390809434113a97cd298e33bc"
)
ZKALEIDO_SP1_IN_SP1_EXAMPLE_URL = (
    "https://raw.githubusercontent.com/alpenlabs/zkaleido/"
    f"{ZKALEIDO_COMMIT}/examples/groth16-verify-sp1/src/lib.rs"
)
ZKALEIDO_SP1_VERIFIER_SOURCE_SHA256 = (
    "81b154b594edebc57c45e4367eee33e0646b94e72809a8f0a457798c927096bb"
)
ZKALEIDO_SP1_VERIFIER_SOURCE_URL = (
    "https://raw.githubusercontent.com/alpenlabs/zkaleido/"
    f"{ZKALEIDO_COMMIT}/adapters/sp1/groth16-verifier/src/verifier.rs"
)


class DeterministicWrapperGateError(ValueError):
    """Invalid wrapper statement, manifest, or semantic projection."""


def _fixed(value: bytes, width: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != width:
        raise DeterministicWrapperGateError(f"{name} must be {width} immutable bytes")
    return value


def _digest(value: bytes, name: str) -> bytes:
    value = _fixed(value, _HASH_BYTES, name)
    if value == bytes(_HASH_BYTES):
        raise DeterministicWrapperGateError(f"{name} must not be zero")
    return value


def _field(value: bytes, name: str) -> bytes:
    value = _fixed(value, _HASH_BYTES, name)
    if int.from_bytes(value, "big") >= CURVE_ORDER:
        raise DeterministicWrapperGateError(f"{name} is not a canonical BN254 scalar")
    return value


def _xonly(value: bytes, name: str) -> bytes:
    value = _fixed(value, _XONLY_BYTES, name)
    try:
        lift_x(int.from_bytes(value, "big"))
    except BIP340Error as exc:
        raise DeterministicWrapperGateError(
            f"{name} is not a valid x-only key"
        ) from exc
    return value


def _strict_u(value: int, width: int, name: str) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << (width * 8):
        raise DeterministicWrapperGateError(f"{name} does not fit u{width * 8}")
    return value.to_bytes(width, "big")


def _hash(domain: bytes, *parts: bytes) -> bytes:
    result = sha256(domain)
    for part in parts:
        part = bytes(part)
        result.update(len(part).to_bytes(8, "big"))
        result.update(part)
    return result.digest()


def _tagged_hash(tag: bytes, message: bytes) -> bytes:
    tag_hash = sha256(tag).digest()
    return sha256(tag_hash + tag_hash + message).digest()


def selected_commitment(funded_setup_digest: bytes, alternative_index: int) -> bytes:
    """Reproduce the frozen Rust P1-selected commitment formula exactly."""

    funded_setup_digest = _digest(funded_setup_digest, "funded-setup digest")
    index = _strict_u(alternative_index, 4, "alternative index")
    return _tagged_hash(_SELECTED_COMMITMENT_TAG, funded_setup_digest + index)


@dataclass(frozen=True, slots=True)
class WrapperAckSubjectV1:
    """Canonical logical projection of the Rust threshold-ACK subject."""

    selected_commitment: bytes
    graph_pubkey: bytes
    participant_count: int
    threshold: int
    release_pubkeys: tuple[bytes, ...]
    resolution_outpoint_consensus: bytes
    resolution_value_sat: int
    resolution_script_pubkey: bytes
    ack_txid: bytes
    ack_sighash: bytes
    schema: str = "ranklock-v026-wrapper-ack-subject-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-wrapper-ack-subject-v1":
            raise DeterministicWrapperGateError("unknown wrapper ACK-subject schema")
        _digest(self.selected_commitment, "selected commitment")
        _xonly(self.graph_pubkey, "graph public key")
        count = self.participant_count
        threshold = self.threshold
        if type(count) is not int or not 2 <= count <= _MAX_PARTICIPANTS:
            raise DeterministicWrapperGateError("participant count must be in 2..64")
        if type(threshold) is not int or not 1 <= threshold <= count:
            raise DeterministicWrapperGateError(
                "threshold must be in 1..participant count"
            )
        if (
            type(self.release_pubkeys) is not tuple
            or len(self.release_pubkeys) != count
        ):
            raise DeterministicWrapperGateError(
                "release-key roster must be a participant-count tuple"
            )
        keys = tuple(
            _xonly(value, f"release public key {index}")
            for index, value in enumerate(self.release_pubkeys)
        )
        if len(set(keys)) != len(keys):
            raise DeterministicWrapperGateError("release public keys must be distinct")
        outpoint = _fixed(
            self.resolution_outpoint_consensus,
            _OUTPOINT_BYTES,
            "resolution outpoint",
        )
        if outpoint == bytes(32) + bytes.fromhex("ffffffff"):
            raise DeterministicWrapperGateError("resolution outpoint must not be null")
        value = self.resolution_value_sat
        if type(value) is not int or not 0 < value <= _MAX_MONEY_SAT:
            raise DeterministicWrapperGateError(
                "resolution value is outside MoneyRange"
            )
        script = _fixed(
            self.resolution_script_pubkey,
            _P2TR_SCRIPT_BYTES,
            "resolution scriptPubKey",
        )
        if script[:2] != bytes.fromhex("5120"):
            raise DeterministicWrapperGateError("resolution scriptPubKey is not P2TR")
        _xonly(script[2:], "resolution output key")
        _digest(self.ack_txid, "ACK txid")
        _digest(self.ack_sighash, "ACK sighash")

    @property
    def encoded(self) -> bytes:
        return (
            _ACK_SUBJECT_MAGIC
            + self.selected_commitment
            + self.graph_pubkey
            + _strict_u(self.participant_count, 2, "participant count")
            + _strict_u(self.threshold, 2, "threshold")
            + b"".join(self.release_pubkeys)
            + self.resolution_outpoint_consensus
            + _strict_u(self.resolution_value_sat, 8, "resolution value")
            + self.resolution_script_pubkey
            + self.ack_txid
            + self.ack_sighash
        )

    @property
    def digest(self) -> bytes:
        return _hash(_ACK_SUBJECT_DOMAIN, self.encoded)


@dataclass(frozen=True, slots=True)
class WrapperBindingRowV1:
    """One setup-authoritative operator/game to ACK-subject mapping."""

    alternative_index: int
    operator_xonly_pubkey: bytes
    game_index: int
    ack_subject: WrapperAckSubjectV1
    schema: str = "ranklock-v026-wrapper-binding-row-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-wrapper-binding-row-v1":
            raise DeterministicWrapperGateError("unknown wrapper binding-row schema")
        _strict_u(self.alternative_index, 4, "alternative index")
        _xonly(self.operator_xonly_pubkey, "counterproof operator public key")
        if type(self.game_index) is not int or not 0 < self.game_index <= 0xFFFF_FFFF:
            raise DeterministicWrapperGateError("game index must be a nonzero u32")
        if not isinstance(self.ack_subject, WrapperAckSubjectV1):
            raise DeterministicWrapperGateError(
                "binding row has the wrong ACK-subject type"
            )

    @property
    def counterproof_public_values(self) -> bytes:
        return self.operator_xonly_pubkey + self.game_index.to_bytes(4, "little")

    @property
    def encoded(self) -> bytes:
        return (
            _strict_u(self.alternative_index, 4, "alternative index")
            + self.operator_xonly_pubkey
            + self.game_index.to_bytes(4, "little")
            + self.ack_subject.encoded
        )


@dataclass(frozen=True, slots=True)
class WrapperBindingManifestV1:
    """Complete setup mapping which a sound wrapper relation must authenticate."""

    artifact_binding_digest: bytes
    counterproof_program_vkey: bytes
    funded_setup_digest: bytes
    rows: tuple[WrapperBindingRowV1, ...]
    schema: str = "ranklock-v026-wrapper-binding-manifest-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-wrapper-binding-manifest-v1":
            raise DeterministicWrapperGateError(
                "unknown wrapper binding-manifest schema"
            )
        _digest(self.artifact_binding_digest, "artifact-binding digest")
        _field(self.counterproof_program_vkey, "counterproof program vkey")
        funded = _digest(self.funded_setup_digest, "funded-setup digest")
        if type(self.rows) is not tuple or not self.rows:
            raise DeterministicWrapperGateError(
                "binding manifest rows must be nonempty"
            )
        if len(self.rows) > _MAX_PARTICIPANTS:
            raise DeterministicWrapperGateError(
                "binding manifest has too many alternatives"
            )
        if not all(isinstance(row, WrapperBindingRowV1) for row in self.rows):
            raise DeterministicWrapperGateError(
                "binding manifest contains an invalid row"
            )
        if tuple(row.alternative_index for row in self.rows) != tuple(
            range(len(self.rows))
        ):
            raise DeterministicWrapperGateError(
                "binding manifest alternatives must be contiguous and ordered"
            )
        for row in self.rows:
            expected = selected_commitment(funded, row.alternative_index)
            if row.ack_subject.selected_commitment != expected:
                raise DeterministicWrapperGateError(
                    "ACK subject selected commitment is not derived from funded setup"
                )
        uniqueness_classes = (
            (
                tuple((row.operator_xonly_pubkey, row.game_index) for row in self.rows),
                "operator/game mappings",
            ),
            (
                tuple(row.ack_subject.selected_commitment for row in self.rows),
                "selected commitments",
            ),
            (tuple(row.ack_subject.digest for row in self.rows), "ACK subjects"),
            (tuple(row.ack_subject.ack_txid for row in self.rows), "ACK txids"),
            (tuple(row.ack_subject.ack_sighash for row in self.rows), "ACK sighashes"),
        )
        for values, label in uniqueness_classes:
            if len(set(values)) != len(values):
                raise DeterministicWrapperGateError(
                    f"binding manifest {label} must be unique"
                )

    @property
    def encoded(self) -> bytes:
        return (
            _MANIFEST_MAGIC
            + self.artifact_binding_digest
            + self.counterproof_program_vkey
            + self.funded_setup_digest
            + _strict_u(len(self.rows), 2, "alternative count")
            + b"".join(row.encoded for row in self.rows)
        )

    @property
    def digest(self) -> bytes:
        return _hash(_MANIFEST_DOMAIN, self.encoded)

    def row(self, alternative_index: int) -> WrapperBindingRowV1:
        if type(alternative_index) is not int or not 0 <= alternative_index < len(
            self.rows
        ):
            raise DeterministicWrapperGateError(
                "alternative is outside binding manifest"
            )
        return self.rows[alternative_index]


@dataclass(frozen=True, slots=True)
class DeterministicWrapperStatementV1:
    """Two-limb future statement consumed by a deterministic outer Groth16 proof."""

    manifest_digest: bytes
    ack_subject_digest: bytes
    schema: str = "ranklock-v026-deterministic-wrapper-statement-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-deterministic-wrapper-statement-v1":
            raise DeterministicWrapperGateError(
                "unknown deterministic-wrapper statement schema"
            )
        _digest(self.manifest_digest, "wrapper manifest digest")
        _digest(self.ack_subject_digest, "wrapper ACK-subject digest")

    @property
    def public_values(self) -> bytes:
        return (
            _WRAPPER_PUBLIC_VALUES_MAGIC
            + self.manifest_digest
            + self.ack_subject_digest
        )

    @property
    def digest(self) -> bytes:
        return _hash(_WRAPPER_STATEMENT_DOMAIN, self.public_values)

    @property
    def public_input_limbs(self) -> tuple[int, int]:
        digest = self.digest
        return int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")

    @classmethod
    def from_manifest(
        cls,
        manifest: WrapperBindingManifestV1,
        alternative_index: int,
    ) -> DeterministicWrapperStatementV1:
        if not isinstance(manifest, WrapperBindingManifestV1):
            raise DeterministicWrapperGateError("wrapper manifest has the wrong type")
        row = manifest.row(alternative_index)
        return cls(manifest.digest, row.ack_subject.digest)


def _inner_statement_digest(statement: Sp1Groth16StatementV1) -> bytes:
    return _hash(
        _INNER_STATEMENT_DOMAIN,
        b"".join(value.to_bytes(32, "big") for value in statement.public_inputs),
    )


@dataclass(frozen=True, slots=True)
class WrapperSemanticWitnessV1:
    """Reference witness for the non-cryptographic semantic projection gate."""

    pinned_artifacts: ImportedCounterproofArtifactEvidenceV1
    manifest: WrapperBindingManifestV1
    alternative_index: int
    inner_sp1_statement: Sp1Groth16StatementV1
    schema: str = "ranklock-v026-wrapper-semantic-witness-v1"

    def validate_projection(self, statement: DeterministicWrapperStatementV1) -> None:
        """Validate binding constraints, deliberately excluding proof verification."""

        if self.schema != "ranklock-v026-wrapper-semantic-witness-v1":
            raise DeterministicWrapperGateError(
                "unknown wrapper semantic-witness schema"
            )
        if not isinstance(
            self.pinned_artifacts,
            ImportedCounterproofArtifactEvidenceV1,
        ):
            raise DeterministicWrapperGateError(
                "semantic witness has the wrong pinned-artifact type"
            )
        if not isinstance(self.manifest, WrapperBindingManifestV1):
            raise DeterministicWrapperGateError(
                "semantic witness has the wrong manifest type"
            )
        if (
            self.manifest.artifact_binding_digest
            != self.pinned_artifacts.binding_digest
            or self.manifest.counterproof_program_vkey
            != self.pinned_artifacts.counterproof_program_vkey
        ):
            raise DeterministicWrapperGateError(
                "wrapper manifest does not match pinned counterproof artifacts"
            )
        if not isinstance(self.inner_sp1_statement, Sp1Groth16StatementV1):
            raise DeterministicWrapperGateError(
                "semantic witness has the wrong SP1 statement type"
            )
        expected_wrapper = DeterministicWrapperStatementV1.from_manifest(
            self.manifest,
            self.alternative_index,
        )
        if statement != expected_wrapper:
            raise DeterministicWrapperGateError(
                "wrapper statement binds another manifest or ACK subject"
            )
        row = self.manifest.row(self.alternative_index)
        expected_inner = Sp1Groth16StatementV1.for_counterproof_output(
            program_vkey_hash=self.manifest.counterproof_program_vkey,
            operator_xonly_pubkey=row.operator_xonly_pubkey,
            game_index=row.game_index,
            vk_root=self.inner_sp1_statement.vk_root,
            proof_nonce=self.inner_sp1_statement.proof_nonce,
        )
        if self.inner_sp1_statement != expected_inner:
            raise DeterministicWrapperGateError(
                "inner SP1 statement does not commit the manifest operator/game mapping"
            )


@dataclass(frozen=True, slots=True)
class MetadataRelabellingWitnessV1:
    """Same deployed SP1 statement paired with two distinct ACK subjects."""

    inner_statement_digest: bytes
    source_wrapper_statement: DeterministicWrapperStatementV1
    target_wrapper_statement: DeterministicWrapperStatementV1
    schema: str = "ranklock-v026-metadata-relabelling-witness-v1"

    def __post_init__(self) -> None:
        _digest(self.inner_statement_digest, "inner statement digest")
        if self.source_wrapper_statement == self.target_wrapper_statement:
            raise DeterministicWrapperGateError(
                "relabelling witness requires distinct wrapper statements"
            )


def metadata_relabelling_witness(
    source: WrapperSemanticWitnessV1,
    target: WrapperSemanticWitnessV1,
) -> MetadataRelabellingWitnessV1:
    """Show why independently hashing wrapper metadata adds no proof binding."""

    source_statement = DeterministicWrapperStatementV1.from_manifest(
        source.manifest,
        source.alternative_index,
    )
    target_statement = DeterministicWrapperStatementV1.from_manifest(
        target.manifest,
        target.alternative_index,
    )
    source.validate_projection(source_statement)
    target.validate_projection(target_statement)
    source_inner = _inner_statement_digest(source.inner_sp1_statement)
    target_inner = _inner_statement_digest(target.inner_sp1_statement)
    if source_inner != target_inner:
        raise DeterministicWrapperGateError(
            "relabelling witness requires the exact same deployed SP1 statement"
        )
    if source_statement.ack_subject_digest == target_statement.ack_subject_digest:
        raise DeterministicWrapperGateError(
            "relabelling witness requires distinct ACK subjects"
        )
    return MetadataRelabellingWitnessV1(
        source_inner,
        source_statement,
        target_statement,
    )


@dataclass(frozen=True, slots=True)
class DeterministicWrapperGateAssessmentV6:
    """Decision boundary after execution and a local proving-capacity failure."""

    artifacts: ImportedCounterproofArtifactEvidenceV1
    subject_bound_gate: SubjectBoundCounterproofGateV6
    metadata_only_route_sound: bool = field(default=False, init=False)
    sp1_in_sp1_mechanics_example_present: bool = field(default=True, init=False)
    example_pins_verifier_as_circuit_constant: bool = field(default=False, init=False)
    manifest_mapped_route_requires_identity_theorem: bool = field(
        default=True, init=False
    )
    operator_game_authoritative_subject_identity_established: bool = field(
        default=True,
        init=False,
    )
    selected_architecture: str = field(
        default="subject-bound-counterproof-guest-plus-deterministic-final-groth16",
        init=False,
    )
    subject_bound_counterproof_guest_implemented: bool = field(default=True, init=False)
    subject_bound_counterproof_guest_source_implemented: bool = field(
        default=True, init=False
    )
    subject_bound_counterproof_relation_native_verified: bool = field(
        default=True, init=False
    )
    subject_bound_counterproof_sp1_execution_verified: bool = field(
        default=True, init=False
    )
    subject_bound_sp1_standalone_receipt_verifier_implemented: bool = field(
        default=True, init=False
    )
    subject_bound_verified_receipt_transaction_binding_implemented: bool = field(
        default=True, init=False
    )
    subject_bound_reorg_aware_canonical_chain_confirmation_implemented: bool = field(
        default=True, init=False
    )
    subject_bound_canonical_chain_confirmation_core_regression_test_count: int = field(
        default=2, init=False
    )
    subject_bound_confirmed_ack_witness_cas_composition_implemented: bool = field(
        default=True, init=False
    )
    subject_bound_confirmed_ack_witness_cas_pure_regression_test_count: int = field(
        default=2, init=False
    )
    subject_bound_confirmed_ack_witness_cas_positive_receipt_executed: bool = field(
        default=False, init=False
    )
    subject_bound_confirmed_ack_witness_cas_is_enforced_runtime_path: bool = field(
        default=False, init=False
    )
    subject_bound_runtime_consumes_confirmation_capability: bool = field(
        default=False, init=False
    )
    subject_bound_sp1_local_groth16_proof_generated: bool = field(
        default=False, init=False
    )
    subject_bound_sp1_local_groth16_proof_verified: bool = field(
        default=False, init=False
    )
    deterministic_non_zk_final_groth16_implemented: bool = field(
        default=False, init=False
    )
    complete_wrapper_r1cs_present: bool = field(default=False, init=False)
    complete_wrapper_proving_key_present: bool = field(default=False, init=False)
    wrapper_projectivizer_present: bool = field(default=False, init=False)
    production_wrapper_compatible: bool = field(default=False, init=False)
    funding_eligible: bool = field(default=False, init=False)
    decision: str = field(
        default=(
            "SUBJECT_BOUND_SP1_LOCAL_PROVING_CAPACITY_BLOCKED_FINAL_GROTH16_REQUIRED"
        ),
        init=False,
    )
    blockers: tuple[str, ...] = field(
        default=(
            "the executor composes subject binding, pre/post Bitcoin reconfirmation, and immutable ACK-witness CAS, but no valid receipt executes the composed path, no duty requires it, and the lower-level witness store remains independently callable",
            "the setup ceremony does not authorize the exact signed manifest consumed by the subject-bound guest",
            "a real local SP1 6.2.4 CPU Groth16 attempt was safety-terminated after exhausting the workstation's safe disk/memory envelope without creating a receipt",
            "the production receipt verifier has negative coverage but no valid receipt for a positive algebraic run; qualified production or authorized network-prover capacity, latency, and quota bounds are absent",
            "the wrapper must pin the exact inner verifier, program vkey, VK root, and success policy as circuit constants",
            "the SP1-in-SP1 mechanics example accepts its verifier as witness input and is not a sound production wrapper",
            "a deterministic non-zero-knowledge final Groth16 prover is not implemented",
            "the complete wrapper R1CS, proving key, qualified CRS, and projectivizer are absent",
            "BABE equivalence and complete public-side-information security have no independent review",
        ),
        init=False,
    )
    zkaleido_commit: str = field(default=ZKALEIDO_COMMIT, init=False)
    zkaleido_example_source_sha256: str = field(
        default=ZKALEIDO_SP1_IN_SP1_EXAMPLE_SHA256,
        init=False,
    )
    zkaleido_example_source_url: str = field(
        default=ZKALEIDO_SP1_IN_SP1_EXAMPLE_URL,
        init=False,
    )
    zkaleido_verifier_source_sha256: str = field(
        default=ZKALEIDO_SP1_VERIFIER_SOURCE_SHA256,
        init=False,
    )
    zkaleido_verifier_source_url: str = field(
        default=ZKALEIDO_SP1_VERIFIER_SOURCE_URL,
        init=False,
    )
    schema: str = field(
        default="ranklock-v026-deterministic-wrapper-gate-assessment-v6",
        init=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.artifacts, ImportedCounterproofArtifactEvidenceV1):
            raise DeterministicWrapperGateError(
                "wrapper assessment has invalid artifact evidence"
            )
        if not isinstance(self.subject_bound_gate, SubjectBoundCounterproofGateV6):
            raise DeterministicWrapperGateError(
                "wrapper assessment has invalid subject-bound guest evidence"
            )
        if (
            not self.subject_bound_gate.sp1_guest_execution_verified
            or not self.subject_bound_gate.sp1_resource_profile_qualified
            or self.subject_bound_gate.funding_eligible
        ):
            raise DeterministicWrapperGateError(
                "wrapper assessment requires executed, resource-qualified, funding-blocked subject evidence"
            )
        if not self.blockers:
            raise DeterministicWrapperGateError(
                "wrapper assessment must remain fail-closed"
            )


def assess_deterministic_wrapper_gate(
    compatibility: Sp1BabeCompatibilityAssessmentV1,
    subject_bound_gate: SubjectBoundCounterproofGateV6,
) -> DeterministicWrapperGateAssessmentV6:
    """Select the first semantically credible post-adapter architecture."""

    if not isinstance(compatibility, Sp1BabeCompatibilityAssessmentV1):
        raise DeterministicWrapperGateError(
            "SP1/BABE compatibility assessment has the wrong type"
        )
    if compatibility.direct_integration_compatible or compatibility.funding_eligible:
        raise DeterministicWrapperGateError(
            "deterministic wrapper gate requires a failed direct-integration assessment"
        )
    if not isinstance(subject_bound_gate, SubjectBoundCounterproofGateV6):
        raise DeterministicWrapperGateError(
            "subject-bound gate assessment has the wrong type"
        )
    return DeterministicWrapperGateAssessmentV6(
        compatibility.artifacts,
        subject_bound_gate,
    )
