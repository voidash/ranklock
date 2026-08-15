from __future__ import annotations

"""Proof-carrying Embryo activation frontier.

This module makes the missing malicious-setup relation exact.  A deterministic Embryo
artifact is committed by a Merkle root.  The activation relation proves knowledge of a
seed, hidden scalar and ACK preimage such that:

* the committed bytes are the canonical generator output;
* ``r_delta`` and the positive-Groth16 lock use the same nonzero scalar ``r``;
* the lock hides exactly the preimage committed by the Bitcoin hashlock;
* the artifact, program, statement and transaction graph share one context.

The relation is executable.  A real succinct NIZK/STARK for it is deliberately left as an
external interface; serializing arbitrary bytes in ``proof_bytes`` is not treated as a proof.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Iterable

from .babe_positive_lock import (
    PositiveGroth16VerifyingKey,
    PositiveLock,
    setup_positive_lock,
)
from .bn254_real import CURVE_ORDER, compress_g2, decompress_g2, eq_points, multiply


class ProofCarryingEmbryoError(RuntimeError):
    pass


GENERATOR_SPEC = b"ranklock/embryo-deterministic-generator/spec/v1"
GENERATOR_CODE_HASH = sha256(GENERATOR_SPEC).digest()
DEFAULT_ARTIFACT_BYTES = 500 * 1024
DEFAULT_CHUNK_BYTES = 4096


def _lp(value: bytes) -> bytes:
    value = bytes(value)
    return len(value).to_bytes(8, "big") + value


def deterministic_artifact_bytes(
    seed: bytes,
    context_digest: bytes,
    *,
    length: int = DEFAULT_ARTIFACT_BYTES,
) -> bytes:
    seed, context_digest = bytes(seed), bytes(context_digest)
    if len(seed) < 16 or len(context_digest) != 32:
        raise ProofCarryingEmbryoError("generator seed/context length mismatch")
    if not 0 < length <= 16 * 1024 * 1024:
        raise ProofCarryingEmbryoError("artifact length outside research bound")
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            sha256(
                b"ranklock/embryo-artifact-stream/v1\x00"
                + _lp(seed)
                + context_digest
                + counter.to_bytes(8, "big")
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def merkle_root(data: bytes, *, chunk_bytes: int = DEFAULT_CHUNK_BYTES) -> bytes:
    data = bytes(data)
    if chunk_bytes <= 0 or not data:
        raise ProofCarryingEmbryoError("invalid Merkle input")
    leaves = [
        sha256(
            b"ranklock/embryo-artifact-leaf/v1\x00"
            + index.to_bytes(8, "big")
            + len(chunk).to_bytes(4, "big")
            + chunk
        ).digest()
        for index, start in enumerate(range(0, len(data), chunk_bytes))
        for chunk in (data[start : start + chunk_bytes],)
    ]
    while len(leaves) > 1:
        if len(leaves) & 1:
            leaves.append(leaves[-1])
        leaves = [
            sha256(b"ranklock/embryo-artifact-node/v1\x00" + leaves[i] + leaves[i + 1]).digest()
            for i in range(0, len(leaves), 2)
        ]
    return leaves[0]


@dataclass(frozen=True, slots=True)
class ActivationStatement:
    generator_code_hash: bytes
    context_digest: bytes
    artifact_root: bytes
    artifact_length: int
    r_delta_g2: bytes
    positive_lock: PositiveLock
    preimage_hash: bytes
    connector_digest: bytes
    schema: str = "ranklock-proof-carrying-embryo-statement-v1"

    def __post_init__(self) -> None:
        for name in (
            "generator_code_hash",
            "context_digest",
            "artifact_root",
            "preimage_hash",
            "connector_digest",
        ):
            if len(getattr(self, name)) != 32:
                raise ProofCarryingEmbryoError(f"{name} must be 32 bytes")
        if not 0 < self.artifact_length <= 16 * 1024 * 1024:
            raise ProofCarryingEmbryoError("artifact length outside research bound")
        decompress_g2(self.r_delta_g2)
        if self.r_delta_g2 != self.positive_lock.r_delta_g2:
            raise ProofCarryingEmbryoError("statement has split-brain r_delta values")

    @property
    def digest(self) -> bytes:
        h = sha256(b"ranklock/proof-carrying-embryo-statement/v1\x00")
        h.update(self.generator_code_hash)
        h.update(self.context_digest)
        h.update(self.artifact_root)
        h.update(self.artifact_length.to_bytes(8, "big"))
        h.update(self.r_delta_g2)
        h.update(self.positive_lock.vk_digest)
        h.update(self.positive_lock.statement_digest)
        h.update(self.positive_lock.r_delta_g2)
        h.update(len(self.positive_lock.masked_payload).to_bytes(4, "big"))
        h.update(self.positive_lock.masked_payload)
        h.update(self.positive_lock.payload_hash)
        h.update(self.preimage_hash)
        h.update(self.connector_digest)
        return h.digest()


@dataclass(frozen=True, slots=True)
class ActivationWitness:
    generator_seed: bytes
    scale: int
    preimage: bytes
    schema: str = "ranklock-proof-carrying-embryo-witness-v1"

    def __post_init__(self) -> None:
        if len(self.generator_seed) < 16:
            raise ProofCarryingEmbryoError("generator seed is too short")
        if self.scale % CURVE_ORDER == 0:
            raise ProofCarryingEmbryoError("activation scale is zero")
        if len(self.preimage) != 32:
            raise ProofCarryingEmbryoError("ACK preimage must be 32 bytes")


@dataclass(frozen=True, slots=True)
class ActivationRelationResult:
    accepts: bool
    checks: tuple[tuple[str, bool], ...]
    schema: str = "ranklock-proof-carrying-embryo-relation-result-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "accepts": self.accepts,
            "checks": {name: value for name, value in self.checks},
        }


def build_activation_statement(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    *,
    witness: ActivationWitness,
    session_context: bytes,
    connector_digest: bytes,
    artifact_length: int = DEFAULT_ARTIFACT_BYTES,
) -> tuple[ActivationStatement, bytes]:
    context_digest = sha256(
        b"ranklock/proof-carrying-embryo-context/v1\x00"
        + vk.digest
        + _lp(bytes(session_context))
        + bytes(connector_digest)
    ).digest()
    artifact = deterministic_artifact_bytes(
        witness.generator_seed,
        context_digest,
        length=artifact_length,
    )
    lock = setup_positive_lock(
        vk,
        public_inputs,
        witness.preimage,
        scale=witness.scale,
        session_context=session_context,
    )
    statement = ActivationStatement(
        generator_code_hash=GENERATOR_CODE_HASH,
        context_digest=context_digest,
        artifact_root=merkle_root(artifact),
        artifact_length=len(artifact),
        r_delta_g2=lock.r_delta_g2,
        positive_lock=lock,
        preimage_hash=sha256(witness.preimage).digest(),
        connector_digest=bytes(connector_digest),
    )
    return statement, artifact


def verify_activation_relation(
    statement: ActivationStatement,
    witness: ActivationWitness,
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    *,
    session_context: bytes,
) -> ActivationRelationResult:
    regenerated = deterministic_artifact_bytes(
        witness.generator_seed,
        statement.context_digest,
        length=statement.artifact_length,
    )
    expected_lock = setup_positive_lock(
        vk,
        public_inputs,
        witness.preimage,
        scale=witness.scale,
        session_context=session_context,
    )
    scale = witness.scale % CURVE_ORDER
    expected_r_delta = compress_g2(
        multiply(decompress_g2(vk.delta_g2), scale, group="g2")
    )
    checks = (
        ("generator_code_hash", statement.generator_code_hash == GENERATOR_CODE_HASH),
        ("artifact_root", statement.artifact_root == merkle_root(regenerated)),
        ("vk_digest", statement.positive_lock.vk_digest == vk.digest),
        ("r_delta", statement.r_delta_g2 == expected_r_delta),
        ("positive_lock", statement.positive_lock == expected_lock),
        ("preimage_hash", statement.preimage_hash == sha256(witness.preimage).digest()),
    )
    return ActivationRelationResult(all(value for _name, value in checks), checks)


ProofVerifier = Callable[[bytes, bytes], bool]


@dataclass(frozen=True, slots=True)
class ProofCarryingEmbryo:
    statement: ActivationStatement
    artifact: bytes
    proof_system_id: bytes
    proof_bytes: bytes
    schema: str = "ranklock-proof-carrying-embryo-v1"

    def __post_init__(self) -> None:
        if not self.proof_system_id or not self.proof_bytes:
            raise ProofCarryingEmbryoError("proof system id/proof is empty")
        if len(self.artifact) != self.statement.artifact_length:
            raise ProofCarryingEmbryoError("artifact length does not match statement")
        if merkle_root(self.artifact) != self.statement.artifact_root:
            raise ProofCarryingEmbryoError("artifact root mismatch")

    def verify(self, verifier: ProofVerifier) -> bool:
        return bool(verifier(self.statement.digest, self.proof_bytes))


@dataclass(frozen=True, slots=True)
class ProofCarryingEmbryoCost:
    artifact_bytes: int = DEFAULT_ARTIFACT_BYTES
    projective_transport_bytes: int = 100_352
    proof_bytes: int = 128 * 1024
    manifest_connector_bytes: int = 8 * 1024
    ceiling_bytes: int = 1 << 20
    embryo_hash_calls: int = 5_800_000
    cut_and_choose_copies: int = 181
    schema: str = "ranklock-proof-carrying-embryo-cost-v1"

    @property
    def total_bytes(self) -> int:
        return (
            self.artifact_bytes
            + self.projective_transport_bytes
            + self.proof_bytes
            + self.manifest_connector_bytes
        )

    @property
    def margin_bytes(self) -> int:
        return self.ceiling_bytes - self.total_bytes

    @property
    def cut_and_choose_hash_calls(self) -> int:
        return self.embryo_hash_calls * self.cut_and_choose_copies

    @property
    def maximum_proving_overhead_factor_to_beat_cut_and_choose(self) -> int:
        return self.cut_and_choose_copies - 1

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "artifact_bytes": self.artifact_bytes,
            "projective_transport_bytes": self.projective_transport_bytes,
            "proof_bytes_allowance": self.proof_bytes,
            "manifest_connector_bytes": self.manifest_connector_bytes,
            "total_bytes": self.total_bytes,
            "margin_bytes": self.margin_bytes,
            "cut_and_choose_hash_calls": self.cut_and_choose_hash_calls,
            "proof_generation_overhead_must_be_below": (
                self.maximum_proving_overhead_factor_to_beat_cut_and_choose
            ),
            "warning": "proof size and proving overhead are unmeasured allowances",
        }


def proof_carrying_embryo_checkpoint() -> dict[str, object]:
    cost = ProofCarryingEmbryoCost()
    return {
        "schema": "ranklock-proof-carrying-embryo-checkpoint-v1",
        "activation_relation_executable": True,
        "strict_artifact_root_binding": True,
        "real_succinct_activation_proof_instantiated": False,
        "planning_cost": cost.document(),
        "under_one_mib_with_128k_proof_allowance": cost.margin_bytes >= 0,
        "decision": "CONCRETE_FALLBACK_RELATION_REAL_PROOF_BACKEND_MISSING",
        "breakthrough_target_met": False,
    }
