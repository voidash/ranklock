from __future__ import annotations

"""Context-bound, exactly-one-label-per-bit RankLock authorization.

The release signature authenticates the authorization header *and a digest of
all 512 online openings*.  The openings are still checked against the activated
label root only *after* the one-shot slot has been burned.  This ordering has
two distinct effects:

* an outsider cannot mutate an honestly authorized opening vector to consume a
  slot, because the pre-burn signature check fails; and
* a valid authorizer cannot turn a deliberately malformed, signed opening
  vector, parsing failure or exceptional point into a retry oracle, because a
  cryptographically authorized attempt is burned before semantic validation.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Iterable, Sequence

import numpy as np

from .adaptive_sealing import open_fused_slot, program_seed_commitment
from .bip340 import public_key, sign, verify
from .bn254_real import affine, compress_g1, decompress_g1
from .bounded_mpc_embryo import (
    BoundedEmbryoError,
    BoundedSlotLedger,
    SignedBoundedEmbryoManifest,
    SlotUse,
)
from .dfb_real import CoordinateInputEncoding, DfbProfile
from .embryo_mask_fusion import FusedSlotReplay, parse_fused_slot, replay_fused_slot


LABEL_BYTES = 16
HASH_BYTES = 32
SIGNATURE_BYTES = 64
POINT_BYTES = 32
RELEASE_HEADER_BYTES = 196
OPENING_BYTES = LABEL_BYTES + HASH_BYTES

_CONTEXT_DOMAIN = b"ranklock/evaluation-context/v1\x00"
_LABEL_HASH_DOMAIN = b"ranklock/input-label-leaf/v1\x00"
_PAIR_HASH_DOMAIN = b"ranklock/input-label-pair/v1\x00"
_ROOT_DOMAIN = b"ranklock/input-label-root/v1\x00"
_OPENINGS_DIGEST_DOMAIN = b"ranklock/authorized-label-openings/v1\x00"
_RELEASE_SIGN_DOMAIN = b"ranklock/authorized-label-release-sign/v2\x00"
_INPUT_DIGEST_DOMAIN = b"ranklock/authorized-input/v1\x00"
_AUTH_DIGEST_DOMAIN = b"ranklock/authorized-release/v1\x00"
_ARTIFACT_ROOT_DOMAIN = b"ranklock/bounded-embryo-artifact-root/v1\x00"


class LabelAuthorizationError(ValueError):
    pass


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = sha256(domain)
    for part in parts:
        h.update(bytes(part))
    return h.digest()


def _u(value: int, width: int, name: str) -> bytes:
    value = int(value)
    if not 0 <= value < 1 << (8 * width):
        raise LabelAuthorizationError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "big")


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    chain_genesis_hash: bytes
    program_id: bytes
    verifier_key_digest: bytes
    deposit_outpoint: bytes
    game_index: int
    operator_index: int
    counterproof_txid: bytes
    epoch: int
    deadline_height: int
    schema: str = "ranklock-evaluation-context-v1"

    def __post_init__(self) -> None:
        for name in (
            "chain_genesis_hash",
            "program_id",
            "verifier_key_digest",
            "counterproof_txid",
        ):
            if len(bytes(getattr(self, name))) != 32:
                raise LabelAuthorizationError(f"{name} must be 32 bytes")
        if len(bytes(self.deposit_outpoint)) != 36:
            raise LabelAuthorizationError("deposit outpoint must be 36 bytes")
        _u(self.game_index, 8, "game index")
        _u(self.operator_index, 4, "operator index")
        _u(self.epoch, 8, "epoch")
        _u(self.deadline_height, 8, "deadline height")

    @property
    def canonical_bytes(self) -> bytes:
        return (
            bytes(self.chain_genesis_hash)
            + bytes(self.program_id)
            + bytes(self.verifier_key_digest)
            + bytes(self.deposit_outpoint)
            + _u(self.game_index, 8, "game index")
            + _u(self.operator_index, 4, "operator index")
            + bytes(self.counterproof_txid)
            + _u(self.epoch, 8, "epoch")
            + _u(self.deadline_height, 8, "deadline height")
        )

    @property
    def digest(self) -> bytes:
        return _sha(_CONTEXT_DOMAIN, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class LabelOpening:
    label: bytes
    sibling_hash: bytes

    def __post_init__(self) -> None:
        if len(bytes(self.label)) != LABEL_BYTES:
            raise LabelAuthorizationError("selected label must be 16 bytes")
        if len(bytes(self.sibling_hash)) != HASH_BYTES:
            raise LabelAuthorizationError("sibling label hash must be 32 bytes")

    @property
    def encoded(self) -> bytes:
        return bytes(self.label) + bytes(self.sibling_hash)


@dataclass(frozen=True, slots=True)
class LabelCommitmentTree:
    context_digest: bytes
    slot_id: int
    input_bits: int
    program_seed: bytes
    label_pairs: tuple[tuple[bytes, bytes], ...]
    root: bytes
    schema: str = "ranklock-complete-label-pair-tree-v1"

    def __post_init__(self) -> None:
        if len(bytes(self.context_digest)) != 32:
            raise LabelAuthorizationError("tree context digest must be 32 bytes")
        if not 0 <= self.slot_id < 2**32:
            raise LabelAuthorizationError("tree slot id must fit u32")
        if self.input_bits <= 1:
            raise LabelAuthorizationError("tree input width must exceed one")
        if len(bytes(self.program_seed)) != 32:
            raise LabelAuthorizationError("tree program seed must be 32 bytes")
        if len(self.label_pairs) != 2 * self.input_bits:
            raise LabelAuthorizationError("tree must contain x/y label pairs")
        if any(len(left) != 16 or len(right) != 16 for left, right in self.label_pairs):
            raise LabelAuthorizationError("tree labels must be 16 bytes")
        if len(bytes(self.root)) != 32:
            raise LabelAuthorizationError("tree root must be 32 bytes")

    @classmethod
    def from_input_encodings(
        cls,
        input_encodings: Sequence[CoordinateInputEncoding],
        *,
        context_digest: bytes,
        slot_id: int,
        input_bits: int,
        program_seed: bytes,
    ) -> "LabelCommitmentTree":
        if len(input_encodings) != 2:
            raise LabelAuthorizationError("exactly x/y input encodings are required")
        pairs: list[tuple[bytes, bytes]] = []
        for coordinate in input_encodings:
            labels = np.asarray(coordinate.labels, dtype="<u8")
            masks = np.asarray(coordinate.masks, dtype="<u8")
            if labels.shape != (input_bits, 2) or masks.shape != labels.shape:
                raise LabelAuthorizationError("input encoding has the wrong shape")
            if not np.array_equal(labels, masks):
                raise LabelAuthorizationError(
                    "label tree must be built from an unbound zero-input template"
                )
            if coordinate.delta is None:
                raise LabelAuthorizationError("trusted setup input delta is absent")
            delta = int(coordinate.delta)
            if not 0 < delta < 2**128:
                raise LabelAuthorizationError("trusted setup input delta is non-canonical")
            delta_words = np.frombuffer(delta.to_bytes(16, "little"), dtype="<u8")
            for bit in range(input_bits):
                left = labels[bit].tobytes(order="C")
                # The paired label is derived by the per-coordinate Free-XOR
                # delta and is available only in trusted setup state.
                right_words = np.bitwise_xor(labels[bit], delta_words)
                right = np.asarray(right_words, dtype="<u8").tobytes(order="C")
                # ``labels`` contains the encoding selected by setup's zero
                # template.  For template generation this is M; canonicalize
                # the pair by treating it as the zero label and M xor Delta as
                # the one label.
                pairs.append((left, right))
        root = _root_from_pairs(
            context_digest=bytes(context_digest),
            slot_id=slot_id,
            input_bits=input_bits,
            program_seed=bytes(program_seed),
            pairs=tuple(pairs),
        )
        return cls(
            context_digest=bytes(context_digest),
            slot_id=int(slot_id),
            input_bits=int(input_bits),
            program_seed=bytes(program_seed),
            label_pairs=tuple(pairs),
            root=root,
        )


def _label_hash(
    *, context_digest: bytes, slot_id: int, coordinate: int, bit: int, label: bytes
) -> bytes:
    return _sha(
        _LABEL_HASH_DOMAIN,
        context_digest,
        _u(slot_id, 4, "slot id"),
        bytes([coordinate]),
        _u(bit, 2, "bit index"),
        label,
    )


def _pair_hash(
    *,
    context_digest: bytes,
    slot_id: int,
    coordinate: int,
    bit: int,
    zero_hash: bytes,
    one_hash: bytes,
) -> bytes:
    return _sha(
        _PAIR_HASH_DOMAIN,
        context_digest,
        _u(slot_id, 4, "slot id"),
        bytes([coordinate]),
        _u(bit, 2, "bit index"),
        zero_hash,
        one_hash,
    )


def root_from_label_hash_pairs(
    *,
    context_digest: bytes,
    slot_id: int,
    input_bits: int,
    program_seed_commitment_value: bytes,
    label_hash_pairs: Sequence[tuple[bytes, bytes]],
) -> bytes:
    """Reconstruct the public label root from zero/one label hashes.

    This is the public verification interface used by the v0.25 committee
    release protocol.  Publishing 128-bit-label hashes does not reveal the
    labels under the stated preimage-resistance assumption, and avoids asking
    any one committee member to know the aggregate unselected label.
    """

    context = bytes(context_digest)
    commitment = bytes(program_seed_commitment_value)
    if len(context) != 32 or len(commitment) != 32:
        raise LabelAuthorizationError("root context/seed commitment must be 32 bytes")
    if len(label_hash_pairs) != 2 * input_bits:
        raise LabelAuthorizationError("wrong number of label-hash pairs")
    pair_hashes: list[bytes] = []
    for flat_index, (zero_hash, one_hash) in enumerate(label_hash_pairs):
        coordinate, bit = divmod(flat_index, input_bits)
        zero_hash, one_hash = bytes(zero_hash), bytes(one_hash)
        if len(zero_hash) != HASH_BYTES or len(one_hash) != HASH_BYTES:
            raise LabelAuthorizationError("label hashes must be 32 bytes")
        pair_hashes.append(
            _pair_hash(
                context_digest=context,
                slot_id=slot_id,
                coordinate=coordinate,
                bit=bit,
                zero_hash=zero_hash,
                one_hash=one_hash,
            )
        )
    return _sha(
        _ROOT_DOMAIN,
        context,
        _u(slot_id, 4, "slot id"),
        _u(input_bits, 2, "input bits"),
        commitment,
        *pair_hashes,
    )


def _root_from_pair_hashes(
    *,
    context_digest: bytes,
    slot_id: int,
    input_bits: int,
    program_seed: bytes,
    pair_hashes: Sequence[bytes],
) -> bytes:
    if len(pair_hashes) != 2 * input_bits:
        raise LabelAuthorizationError("wrong number of pair commitments")
    return _sha(
        _ROOT_DOMAIN,
        context_digest,
        _u(slot_id, 4, "slot id"),
        _u(input_bits, 2, "input bits"),
        program_seed_commitment(program_seed),
        *pair_hashes,
    )


def _root_from_pairs(
    *,
    context_digest: bytes,
    slot_id: int,
    input_bits: int,
    program_seed: bytes,
    pairs: Sequence[tuple[bytes, bytes]],
) -> bytes:
    pair_hashes: list[bytes] = []
    for flat_index, (zero_label, one_label) in enumerate(pairs):
        coordinate, bit = divmod(flat_index, input_bits)
        zero_hash = _label_hash(
            context_digest=context_digest,
            slot_id=slot_id,
            coordinate=coordinate,
            bit=bit,
            label=zero_label,
        )
        one_hash = _label_hash(
            context_digest=context_digest,
            slot_id=slot_id,
            coordinate=coordinate,
            bit=bit,
            label=one_label,
        )
        pair_hashes.append(
            _pair_hash(
                context_digest=context_digest,
                slot_id=slot_id,
                coordinate=coordinate,
                bit=bit,
                zero_hash=zero_hash,
                one_hash=one_hash,
            )
        )
    return _root_from_pair_hashes(
        context_digest=context_digest,
        slot_id=slot_id,
        input_bits=input_bits,
        program_seed=program_seed,
        pair_hashes=pair_hashes,
    )


@dataclass(frozen=True, slots=True)
class AuthorizedLabelRelease:
    context_digest: bytes
    slot_id: int
    point_encoding: bytes
    input_label_root: bytes
    program_seed: bytes
    authorization_txid: bytes
    authorizer_pubkey: bytes
    openings: tuple[LabelOpening, ...]
    authorizer_signature: bytes
    schema: str = "ranklock-authorized-label-release-v2"

    def __post_init__(self) -> None:
        for name in ("context_digest", "input_label_root", "program_seed", "authorization_txid", "authorizer_pubkey"):
            if len(bytes(getattr(self, name))) != 32:
                raise LabelAuthorizationError(f"{name} must be 32 bytes")
        if not 0 <= self.slot_id < 2**32:
            raise LabelAuthorizationError("release slot id must fit u32")
        if len(bytes(self.point_encoding)) != POINT_BYTES:
            raise LabelAuthorizationError("release point must be 32 bytes")
        if not self.openings or len(self.openings) % 2:
            raise LabelAuthorizationError("release must contain equal x/y openings")
        if len(bytes(self.authorizer_signature)) != SIGNATURE_BYTES:
            raise LabelAuthorizationError("authorizer signature must be 64 bytes")

    @property
    def input_bits(self) -> int:
        return len(self.openings) // 2

    @property
    def header_bytes(self) -> bytes:
        return (
            bytes(self.context_digest)
            + _u(self.slot_id, 4, "slot id")
            + bytes(self.point_encoding)
            + bytes(self.input_label_root)
            + bytes(self.program_seed)
            + bytes(self.authorization_txid)
            + bytes(self.authorizer_pubkey)
        )

    @property
    def openings_digest(self) -> bytes:
        return _sha(
            _OPENINGS_DIGEST_DOMAIN,
            _u(self.input_bits, 2, "input bits"),
            *(opening.encoded for opening in self.openings),
        )

    @property
    def signing_message(self) -> bytes:
        return _sha(
            _RELEASE_SIGN_DOMAIN,
            self.header_bytes,
            _u(self.input_bits, 2, "input bits"),
            self.openings_digest,
        )

    @property
    def compact_bytes(self) -> bytes:
        return (
            self.header_bytes
            + b"".join(opening.encoded for opening in self.openings)
            + bytes(self.authorizer_signature)
        )

    @property
    def compact_size(self) -> int:
        return len(self.compact_bytes)

    def verify_signature(self, expected_authorizer_pubkey: bytes) -> bool:
        expected = bytes(expected_authorizer_pubkey)
        return (
            len(expected) == 32
            and bytes(self.authorizer_pubkey) == expected
            and verify(self.signing_message, expected, bytes(self.authorizer_signature))
        )

    @classmethod
    def parse_compact(
        cls, raw: bytes, *, input_bits: int = 256
    ) -> "AuthorizedLabelRelease":
        encoded = bytes(raw)
        expected = RELEASE_HEADER_BYTES + 2 * input_bits * OPENING_BYTES + SIGNATURE_BYTES
        if len(encoded) != expected:
            raise LabelAuthorizationError(
                f"authorized release must be exactly {expected} bytes"
            )
        context = encoded[0:32]
        slot_id = int.from_bytes(encoded[32:36], "big")
        point = encoded[36:68]
        root = encoded[68:100]
        seed = encoded[100:132]
        txid = encoded[132:164]
        pubkey = encoded[164:196]
        cursor = RELEASE_HEADER_BYTES
        openings: list[LabelOpening] = []
        for _ in range(2 * input_bits):
            openings.append(
                LabelOpening(
                    label=encoded[cursor : cursor + LABEL_BYTES],
                    sibling_hash=encoded[
                        cursor + LABEL_BYTES : cursor + OPENING_BYTES
                    ],
                )
            )
            cursor += OPENING_BYTES
        release = cls(
            context_digest=context,
            slot_id=slot_id,
            point_encoding=point,
            input_label_root=root,
            program_seed=seed,
            authorization_txid=txid,
            authorizer_pubkey=pubkey,
            openings=tuple(openings),
            authorizer_signature=encoded[cursor : cursor + SIGNATURE_BYTES],
        )
        if release.compact_bytes != encoded:
            raise LabelAuthorizationError("non-canonical authorized release")
        return release

    def reconstruct_root(self) -> bytes:
        try:
            point = decompress_g1(bytes(self.point_encoding))
            if compress_g1(point) != bytes(self.point_encoding):
                raise LabelAuthorizationError("non-canonical point encoding")
            coordinates = affine(point)
            if coordinates is None:
                raise LabelAuthorizationError("point at infinity is unauthorized")
            x, y = coordinates
            values = (int(x.n), int(y.n))
        except (ValueError, AttributeError) as exc:
            raise LabelAuthorizationError("invalid canonical BN254 point") from exc

        pair_hashes: list[bytes] = []
        for flat_index, opening in enumerate(self.openings):
            coordinate, bit = divmod(flat_index, self.input_bits)
            selected_bit = (values[coordinate] >> bit) & 1
            selected_hash = _label_hash(
                context_digest=bytes(self.context_digest),
                slot_id=self.slot_id,
                coordinate=coordinate,
                bit=bit,
                label=bytes(opening.label),
            )
            if selected_bit == 0:
                zero_hash, one_hash = selected_hash, bytes(opening.sibling_hash)
            else:
                zero_hash, one_hash = bytes(opening.sibling_hash), selected_hash
            pair_hashes.append(
                _pair_hash(
                    context_digest=bytes(self.context_digest),
                    slot_id=self.slot_id,
                    coordinate=coordinate,
                    bit=bit,
                    zero_hash=zero_hash,
                    one_hash=one_hash,
                )
            )
        return _root_from_pair_hashes(
            context_digest=bytes(self.context_digest),
            slot_id=self.slot_id,
            input_bits=self.input_bits,
            program_seed=bytes(self.program_seed),
            pair_hashes=pair_hashes,
        )


@dataclass(frozen=True, slots=True)
class AuthorizedFusedSlotExecution:
    replay: FusedSlotReplay
    slot_use: SlotUse


def _point_values(point: object) -> tuple[int, int]:
    coordinates = affine(point)  # type: ignore[arg-type]
    if coordinates is None:
        raise LabelAuthorizationError("point at infinity is unauthorized")
    x, y = coordinates
    return int(x.n), int(y.n)


def issue_label_release(
    tree: LabelCommitmentTree,
    *,
    point: object,
    authorization_txid: bytes,
    authorizer_secret: int,
) -> AuthorizedLabelRelease:
    point_encoding = compress_g1(point)  # type: ignore[arg-type]
    canonical = decompress_g1(point_encoding)
    if compress_g1(canonical) != point_encoding:
        raise LabelAuthorizationError("point did not round-trip canonically")
    values = _point_values(canonical)
    openings: list[LabelOpening] = []
    for flat_index, pair in enumerate(tree.label_pairs):
        coordinate, bit = divmod(flat_index, tree.input_bits)
        selected_bit = (values[coordinate] >> bit) & 1
        selected = pair[selected_bit]
        sibling = pair[1 - selected_bit]
        openings.append(
            LabelOpening(
                label=selected,
                sibling_hash=_label_hash(
                    context_digest=tree.context_digest,
                    slot_id=tree.slot_id,
                    coordinate=coordinate,
                    bit=bit,
                    label=sibling,
                ),
            )
        )
    placeholder = AuthorizedLabelRelease(
        context_digest=tree.context_digest,
        slot_id=tree.slot_id,
        point_encoding=point_encoding,
        input_label_root=tree.root,
        program_seed=tree.program_seed,
        authorization_txid=bytes(authorization_txid),
        authorizer_pubkey=public_key(authorizer_secret),
        openings=tuple(openings),
        authorizer_signature=bytes(SIGNATURE_BYTES),
    )
    return AuthorizedLabelRelease(
        context_digest=placeholder.context_digest,
        slot_id=placeholder.slot_id,
        point_encoding=placeholder.point_encoding,
        input_label_root=placeholder.input_label_root,
        program_seed=placeholder.program_seed,
        authorization_txid=placeholder.authorization_txid,
        authorizer_pubkey=placeholder.authorizer_pubkey,
        openings=placeholder.openings,
        authorizer_signature=sign(placeholder.signing_message, authorizer_secret),
    )


def execute_authorized_fused_slot(
    *,
    manifest: SignedBoundedEmbryoManifest,
    required_manifest_pubkeys: Iterable[bytes],
    context: EvaluationContext,
    expected_authorizer_pubkey: bytes,
    ledger: BoundedSlotLedger,
    slot_artifact: bytes,
    profile: DfbProfile,
    release: AuthorizedLabelRelease,
    nonce_namespace_base: int = 0,
) -> AuthorizedFusedSlotExecution:
    """Authenticate, burn, open, parse and replay one fused slot."""

    # Outsider-authentication and activated-descriptor failures happen before
    # burn so arbitrary network traffic cannot consume a funded slot.
    if not manifest.verify(
        required_pubkeys=required_manifest_pubkeys,
        expected_context_digest=context.digest,
    ):
        raise LabelAuthorizationError("activation manifest failed verification")
    if release.context_digest != context.digest:
        raise LabelAuthorizationError("release is bound to another context")
    if not 0 <= release.slot_id < manifest.unsigned.slot_count:
        raise LabelAuthorizationError("release slot is outside the manifest")
    descriptor = manifest.unsigned.slots[release.slot_id]
    if descriptor.slot_id != release.slot_id:
        raise LabelAuthorizationError("non-canonical manifest slot mapping")
    if descriptor.input_label_root != release.input_label_root:
        raise LabelAuthorizationError("release label root does not match activated slot")
    artifact = bytes(slot_artifact)
    artifact_root = _sha(
        _ARTIFACT_ROOT_DOMAIN,
        _u(release.slot_id, 4, "slot id"),
        artifact,
    )
    if len(artifact) != descriptor.artifact_length or artifact_root != descriptor.artifact_root:
        raise LabelAuthorizationError("slot artifact does not match activated descriptor")
    if not release.verify_signature(expected_authorizer_pubkey):
        raise LabelAuthorizationError("release authorizer signature failed")

    # A cryptographically authorized attempt is consumed before point, opening,
    # seed, program or evaluator parsing.
    ledger.begin(
        release.slot_id,
        context_digest=context.digest,
        input_digest=_sha(_INPUT_DIGEST_DOMAIN, release.point_encoding),
        authorization_digest=_sha(
            _AUTH_DIGEST_DOMAIN, release.signing_message, release.authorization_txid
        ),
    )
    try:
        if release.reconstruct_root() != release.input_label_root:
            raise LabelAuthorizationError("label openings or program seed do not match root")
        point = decompress_g1(release.point_encoding)
        if compress_g1(point) != release.point_encoding:
            raise LabelAuthorizationError("point encoding is non-canonical")
        plaintext = open_fused_slot(
            artifact,
            context_digest=context.digest,
            slot_id=release.slot_id,
            program_seed=release.program_seed,
        )
        namespace = int(nonce_namespace_base) + int(release.slot_id)
        slot_profile = profile.with_nonce_namespace(namespace)
        program, mask_state = parse_fused_slot(plaintext, profile=slot_profile)
        labels = b"".join(opening.label for opening in release.openings)
        split = profile.input_bits * LABEL_BYTES
        if len(labels) != 2 * split:
            raise LabelAuthorizationError("authorized label vector has wrong length")
        replay = replay_fused_slot(
            program=program,
            mask_state=mask_state,
            input_point=point,
            x_input_labels=labels[:split],
            y_input_labels=labels[split:],
        )
        slot_use = ledger.finalize(release.slot_id, outcome="success")
        return AuthorizedFusedSlotExecution(replay=replay, slot_use=slot_use)
    except Exception as exc:
        # ``begin`` already consumed the slot.  Preserve that fact even when a
        # parser or evaluator raises a different research-code exception.
        try:
            ledger.finalize(release.slot_id, outcome="malformed")
        except BoundedEmbryoError:
            pass
        if isinstance(exc, LabelAuthorizationError):
            raise
        raise LabelAuthorizationError(f"authorized slot evaluation failed: {exc}") from exc
