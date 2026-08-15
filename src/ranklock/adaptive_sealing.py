from __future__ import annotations

"""Whole-slot adaptive sealing for one-shot RankLock artifacts.

The transform is the concrete random-oracle-style wrapper used by the v0.24
qualification harness.  It preserves the exact plaintext slot length and keeps
all parsing of the DFB/Embryo object behind an authenticated seed release.

This is research code.  SHAKE256 is used as a practical programmable-random-
oracle heuristic; this module is not a standard-model adaptive garbling proof.
"""

from hashlib import sha256, shake_256

from .bounded_mpc_embryo import (
    BoundedEmbryoError,
    SignedBoundedEmbryoManifest,
    UnsignedBoundedEmbryoManifest,
)
from .embryo_mask_fusion import FusedRetainedObject, MaskFusionError


PROGRAM_SEED_BYTES = 32
_PROGRAM_SEED_COMMIT_DOMAIN = b"ranklock/rom-prv-to-prv1/program-seed-commitment/v1\x00"
_PROGRAM_PAD_DOMAIN = b"ranklock/rom-prv-to-prv1/program-pad/v1\x00"


class AdaptiveSealingError(ValueError):
    pass


def _require_seed(program_seed: bytes) -> bytes:
    seed = bytes(program_seed)
    if len(seed) != PROGRAM_SEED_BYTES:
        raise AdaptiveSealingError("program seed must be exactly 32 bytes")
    return seed


def program_seed_commitment(program_seed: bytes) -> bytes:
    """Commit a whole-slot opening seed without context-dependent ambiguity."""

    return sha256(_PROGRAM_SEED_COMMIT_DOMAIN + _require_seed(program_seed)).digest()


def _program_pad(
    *, context_digest: bytes, slot_id: int, program_seed: bytes, length: int
) -> bytes:
    context = bytes(context_digest)
    if len(context) != 32:
        raise AdaptiveSealingError("context digest must be 32 bytes")
    if not 0 <= int(slot_id) < 2**32:
        raise AdaptiveSealingError("slot id must fit u32")
    if not 0 <= int(length) < 2**64:
        raise AdaptiveSealingError("slot length must fit u64")
    seed = _require_seed(program_seed)
    transcript = (
        _PROGRAM_PAD_DOMAIN
        + context
        + int(slot_id).to_bytes(4, "big")
        + seed
        + int(length).to_bytes(8, "big")
    )
    return shake_256(transcript).digest(length)


def seal_fused_slot(
    plaintext: bytes,
    *,
    context_digest: bytes,
    slot_id: int,
    program_seed: bytes,
) -> bytes:
    """XOR-seal a complete canonical fused slot at exactly equal length."""

    source = bytes(plaintext)
    pad = _program_pad(
        context_digest=context_digest,
        slot_id=slot_id,
        program_seed=program_seed,
        length=len(source),
    )
    return bytes(left ^ right for left, right in zip(source, pad, strict=True))


def open_fused_slot(
    ciphertext: bytes,
    *,
    context_digest: bytes,
    slot_id: int,
    program_seed: bytes,
) -> bytes:
    """Open a whole-slot ciphertext.  XOR sealing is its own inverse."""

    return seal_fused_slot(
        ciphertext,
        context_digest=context_digest,
        slot_id=slot_id,
        program_seed=program_seed,
    )


def parse_sealed_retained_object(raw: bytes) -> FusedRetainedObject:
    """Parse the signed manifest and opaque equal-length slot ciphertexts.

    Unlike ``parse_fused_retained_object``, this parser deliberately does not
    parse a slot as DFB material before its seed is authorized.  Manifest
    framing, lengths, roots, signatures and canonical trailing-byte rules are
    still enforced by the existing retained-object classes.
    """

    encoded = bytes(raw)
    try:
        unsigned, body_end = UnsignedBoundedEmbryoManifest.parse_body(encoded)
        manifest_end = body_end + unsigned.contributor_count * 64 + 32
        if manifest_end > len(encoded):
            raise AdaptiveSealingError("truncated sealed retained-object manifest")
        manifest = SignedBoundedEmbryoManifest.parse(encoded[:manifest_end])
        cursor = manifest_end
        slots: list[bytes] = []
        for descriptor in manifest.unsigned.slots:
            end = cursor + descriptor.artifact_length
            if end > len(encoded):
                raise AdaptiveSealingError("truncated sealed retained-object slot")
            slots.append(encoded[cursor:end])
            cursor = end
        if cursor != len(encoded):
            raise AdaptiveSealingError("sealed retained object has trailing bytes")
        result = FusedRetainedObject(manifest=manifest, slots=tuple(slots))
        if result.encoded != encoded:
            raise AdaptiveSealingError("non-canonical sealed retained-object encoding")
        return result
    except (BoundedEmbryoError, MaskFusionError) as exc:
        raise AdaptiveSealingError(str(exc)) from exc
