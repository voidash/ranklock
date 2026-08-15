from __future__ import annotations

"""Strict binary envelope for proof-carrying Embryo artifacts."""

from dataclasses import dataclass

from .babe_positive_lock import PositiveLock
from .proof_carrying_embryo import (
    ActivationStatement,
    ProofCarryingEmbryo,
    ProofCarryingEmbryoError,
    merkle_root,
)

MAGIC = b"RLPC19\x00\x00"
VERSION = 1
MAX_ARTIFACT = 16 * 1024 * 1024
MAX_PROOF = 4 * 1024 * 1024


class ArtifactFormatError(ValueError):
    pass


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _take(raw: bytes, offset: int, length: int) -> tuple[bytes, int]:
    end = offset + length
    if end > len(raw):
        raise ArtifactFormatError("truncated proof-carrying artifact")
    return raw[offset:end], end


@dataclass(frozen=True, slots=True)
class EncodedProofCarryingArtifact:
    value: ProofCarryingEmbryo

    def encode(self) -> bytes:
        value = self.value
        lock = value.statement.positive_lock
        if len(value.proof_system_id) >= 2**16:
            raise ArtifactFormatError("proof system id is too long")
        if len(lock.masked_payload) >= 2**32:
            raise ArtifactFormatError("masked payload is too long")
        if len(value.artifact) > MAX_ARTIFACT or len(value.proof_bytes) > MAX_PROOF:
            raise ArtifactFormatError("artifact/proof exceeds format bound")
        out = bytearray(MAGIC)
        out.extend(_u16(VERSION))
        statement = value.statement
        for fixed in (
            statement.generator_code_hash,
            statement.context_digest,
            statement.artifact_root,
            statement.r_delta_g2,
            statement.preimage_hash,
            statement.connector_digest,
            lock.vk_digest,
            lock.statement_digest,
            lock.r_delta_g2,
            lock.payload_hash,
        ):
            out.extend(fixed)
        out.extend(_u32(len(lock.masked_payload)))
        out.extend(lock.masked_payload)
        out.extend(_u16(len(value.proof_system_id)))
        out.extend(value.proof_system_id)
        out.extend(_u64(len(value.artifact)))
        out.extend(value.artifact)
        out.extend(_u32(len(value.proof_bytes)))
        out.extend(value.proof_bytes)
        return bytes(out)

    @classmethod
    def parse(cls, raw: bytes) -> "EncodedProofCarryingArtifact":
        raw = bytes(raw)
        offset = 0
        magic, offset = _take(raw, offset, len(MAGIC))
        if magic != MAGIC:
            raise ArtifactFormatError("wrong proof-carrying artifact magic")
        version_raw, offset = _take(raw, offset, 2)
        if int.from_bytes(version_raw, "big") != VERSION:
            raise ArtifactFormatError("unsupported proof-carrying artifact version")
        fixed: list[bytes] = []
        fixed_lengths = (32, 32, 32, 64, 32, 32, 32, 32, 64, 32)
        for length in fixed_lengths:
            value, offset = _take(raw, offset, length)
            fixed.append(value)
        payload_len_raw, offset = _take(raw, offset, 4)
        payload_len = int.from_bytes(payload_len_raw, "big")
        payload, offset = _take(raw, offset, payload_len)
        ps_len_raw, offset = _take(raw, offset, 2)
        ps_len = int.from_bytes(ps_len_raw, "big")
        proof_system_id, offset = _take(raw, offset, ps_len)
        artifact_len_raw, offset = _take(raw, offset, 8)
        artifact_len = int.from_bytes(artifact_len_raw, "big")
        if artifact_len > MAX_ARTIFACT:
            raise ArtifactFormatError("artifact exceeds format bound")
        artifact, offset = _take(raw, offset, artifact_len)
        proof_len_raw, offset = _take(raw, offset, 4)
        proof_len = int.from_bytes(proof_len_raw, "big")
        if proof_len > MAX_PROOF:
            raise ArtifactFormatError("proof exceeds format bound")
        proof, offset = _take(raw, offset, proof_len)
        if offset != len(raw):
            raise ArtifactFormatError("trailing bytes after proof-carrying artifact")
        (
            generator_code_hash,
            context_digest,
            artifact_root,
            statement_r_delta,
            preimage_hash,
            connector_digest,
            vk_digest,
            lock_statement_digest,
            lock_r_delta,
            payload_hash,
        ) = fixed
        lock = PositiveLock(
            vk_digest,
            lock_statement_digest,
            lock_r_delta,
            payload,
            payload_hash,
        )
        statement = ActivationStatement(
            generator_code_hash,
            context_digest,
            artifact_root,
            artifact_len,
            statement_r_delta,
            lock,
            preimage_hash,
            connector_digest,
        )
        if merkle_root(artifact) != artifact_root:
            raise ArtifactFormatError("serialized artifact root mismatch")
        try:
            value = ProofCarryingEmbryo(
                statement,
                artifact,
                proof_system_id,
                proof,
            )
        except ProofCarryingEmbryoError as exc:
            raise ArtifactFormatError(str(exc)) from exc
        return cls(value)
