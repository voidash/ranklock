from __future__ import annotations

"""N-of-N, crash-durable authorization for RankLock one-shot slots.

Why an online committee is necessary in this checkpoint
--------------------------------------------------------

A static release published on one Bitcoin branch remains public after a reorg.
If a conflicting branch can publish the opposite labels, the one-shot input
encoding is lost.  A local evaluator database cannot prevent independent nodes
from serving the two forks.

v0.25 therefore introduces a conservative *safety mode*: every 32-byte program
seed and every 16-byte input label is XOR-shared across all setup participants.
Every participant must release the selected share.  Each participant burns its
slot durably before release and rejects a different point/witness forever.
Consequently, one honest participant is sufficient for safety against a
corrupt n-1 coalition; the coalition's missing XOR share is a one-time pad.
The price is liveness: any participant may refuse or disappear.

The ``dealer_split_fixture`` helper is deterministic test plumbing.  It is not
an active-MPC setup because the dealer sees all aggregate labels and seeds.
Production generation must create the same share commitments inside a reviewed
actively secure MPC and provision each participant over an authenticated secret
channel.
"""

from dataclasses import dataclass
from hashlib import sha256, shake_256
import secrets
from typing import Callable, Iterable, Sequence

from .adaptive_sealing import open_fused_slot, program_seed_commitment
from .authorized_labels import (
    HASH_BYTES,
    LABEL_BYTES,
    LabelAuthorizationError,
    LabelCommitmentTree,
    LabelOpening,
    _ARTIFACT_ROOT_DOMAIN,
    _label_hash,
    _sha,
    _u,
    root_from_label_hash_pairs,
)
from .bip340 import N as SECP256K1_ORDER, public_key, sign, verify
from .bitcoin_authorization import BitcoinAuthorizationBinding
from .bn254_real import affine, compress_g1, decompress_g1
from .bounded_mpc_embryo import SignedBoundedEmbryoManifest
from .dfb_real import DfbProfile
from .durable_slot_ledger import DurableSlotLedger, SlotTerminalError
from .rollback_witness import rollback_witness_set_digest
from .embryo_mask_fusion import FusedSlotReplay, parse_fused_slot, replay_fused_slot


_MAGIC_GUIDE = b"RLGD2501"
_MAGIC_ACTIVATION = b"RLAC2512"
_MAGIC_REQUEST = b"RLRQ2501"
_MAGIC_RESPONSE = b"RLRS2501"
_MAGIC_SECRETS = b"RLSS2501"
_SIGNATURE_BYTES = 64
_POINT_BYTES = 32
_SHARE_BYTES = LABEL_BYTES
_SHARE_OPENING_BYTES = _SHARE_BYTES + 2 * HASH_BYTES

_GUIDE_DIGEST_DOMAIN = b"ranklock/committee-label-guide/v1\x00"
_ACTIVATION_DIGEST_DOMAIN = b"ranklock/committee-activation/v3\x00"
_ACTIVATION_SIGN_DOMAIN = b"ranklock/committee-activation-sign/v3\x00"
_REQUEST_SIGN_DOMAIN = b"ranklock/committee-request-sign/v1\x00"
_REQUEST_DIGEST_DOMAIN = b"ranklock/committee-request/v1\x00"
_RESPONSE_OPENINGS_DOMAIN = b"ranklock/committee-response-openings/v1\x00"
_RESPONSE_SIGN_DOMAIN = b"ranklock/committee-response-sign/v1\x00"
_SHARE_LABEL_DOMAIN = b"ranklock/committee-share-label/v1\x00"
_SHARE_PAIR_DOMAIN = b"ranklock/committee-share-pair/v1\x00"
_SHARE_ROOT_DOMAIN = b"ranklock/committee-share-root/v1\x00"
_SHARE_SEED_COMMIT_DOMAIN = b"ranklock/committee-seed-share/v1\x00"
_INPUT_DIGEST_DOMAIN = b"ranklock/committee-input/v1\x00"


class CommitteeAuthorizationError(ValueError):
    pass


def _xor(values: Sequence[bytes], *, width: int) -> bytes:
    if not values:
        raise CommitteeAuthorizationError("cannot XOR an empty share vector")
    output = bytearray(width)
    for value in values:
        encoded = bytes(value)
        if len(encoded) != width:
            raise CommitteeAuthorizationError("share width mismatch")
        for index, byte in enumerate(encoded):
            output[index] ^= byte
    return bytes(output)


def _point_values(point_encoding: bytes) -> tuple[object, tuple[int, int]]:
    try:
        point = decompress_g1(bytes(point_encoding))
        if compress_g1(point) != bytes(point_encoding):
            raise CommitteeAuthorizationError("point encoding is non-canonical")
        coordinates = affine(point)
        if coordinates is None:
            raise CommitteeAuthorizationError("point at infinity is unauthorized")
        x, y = coordinates
        return point, (int(x.n), int(y.n))
    except (ValueError, AttributeError, LabelAuthorizationError) as exc:
        if isinstance(exc, CommitteeAuthorizationError):
            raise
        raise CommitteeAuthorizationError("invalid canonical BN254 point") from exc


def _share_label_hash(
    *,
    context_digest: bytes,
    slot_id: int,
    participant_index: int,
    coordinate: int,
    bit: int,
    share: bytes,
) -> bytes:
    return _sha(
        _SHARE_LABEL_DOMAIN,
        context_digest,
        _u(slot_id, 4, "slot id"),
        _u(participant_index, 4, "participant index"),
        bytes((coordinate,)),
        _u(bit, 2, "bit index"),
        share,
    )


def _share_pair_hash(
    *,
    context_digest: bytes,
    slot_id: int,
    participant_index: int,
    coordinate: int,
    bit: int,
    zero_hash: bytes,
    one_hash: bytes,
) -> bytes:
    return _sha(
        _SHARE_PAIR_DOMAIN,
        context_digest,
        _u(slot_id, 4, "slot id"),
        _u(participant_index, 4, "participant index"),
        bytes((coordinate,)),
        _u(bit, 2, "bit index"),
        zero_hash,
        one_hash,
    )


def _seed_share_commitment(
    *, context_digest: bytes, slot_id: int, participant_index: int, seed_share: bytes
) -> bytes:
    if len(bytes(seed_share)) != 32:
        raise CommitteeAuthorizationError("program-seed share must be 32 bytes")
    return _sha(
        _SHARE_SEED_COMMIT_DOMAIN,
        context_digest,
        _u(slot_id, 4, "slot id"),
        _u(participant_index, 4, "participant index"),
        seed_share,
    )


def _share_root_from_pair_hashes(
    *,
    context_digest: bytes,
    slot_id: int,
    participant_index: int,
    input_bits: int,
    seed_share: bytes,
    pair_hashes: Sequence[bytes],
) -> bytes:
    if len(pair_hashes) != 2 * input_bits:
        raise CommitteeAuthorizationError("wrong number of participant pair hashes")
    return _sha(
        _SHARE_ROOT_DOMAIN,
        context_digest,
        _u(slot_id, 4, "slot id"),
        _u(participant_index, 4, "participant index"),
        _u(input_bits, 2, "input bits"),
        _seed_share_commitment(
            context_digest=context_digest,
            slot_id=slot_id,
            participant_index=participant_index,
            seed_share=seed_share,
        ),
        *pair_hashes,
    )


def _share_root_from_pairs(
    *,
    context_digest: bytes,
    slot_id: int,
    participant_index: int,
    input_bits: int,
    seed_share: bytes,
    pairs: Sequence[tuple[bytes, bytes]],
) -> bytes:
    pair_hashes: list[bytes] = []
    if len(pairs) != 2 * input_bits:
        raise CommitteeAuthorizationError("wrong number of participant share pairs")
    for flat_index, (zero, one) in enumerate(pairs):
        coordinate, bit = divmod(flat_index, input_bits)
        zero, one = bytes(zero), bytes(one)
        if len(zero) != _SHARE_BYTES or len(one) != _SHARE_BYTES:
            raise CommitteeAuthorizationError("label shares must be 16 bytes")
        pair_hashes.append(
            _share_pair_hash(
                context_digest=context_digest,
                slot_id=slot_id,
                participant_index=participant_index,
                coordinate=coordinate,
                bit=bit,
                zero_hash=_share_label_hash(
                    context_digest=context_digest,
                    slot_id=slot_id,
                    participant_index=participant_index,
                    coordinate=coordinate,
                    bit=bit,
                    share=zero,
                ),
                one_hash=_share_label_hash(
                    context_digest=context_digest,
                    slot_id=slot_id,
                    participant_index=participant_index,
                    coordinate=coordinate,
                    bit=bit,
                    share=one,
                ),
            )
        )
    return _share_root_from_pair_hashes(
        context_digest=context_digest,
        slot_id=slot_id,
        participant_index=participant_index,
        input_bits=input_bits,
        seed_share=seed_share,
        pair_hashes=pair_hashes,
    )


@dataclass(frozen=True, slots=True)
class CommitteeLabelGuide:
    context_digest: bytes
    slot_id: int
    input_bits: int
    program_seed_commitment_value: bytes
    label_hash_pairs: tuple[tuple[bytes, bytes], ...]
    schema: str = "ranklock-committee-label-guide-v1"

    def __post_init__(self) -> None:
        if len(bytes(self.context_digest)) != 32:
            raise CommitteeAuthorizationError("guide context digest must be 32 bytes")
        if not 0 <= int(self.slot_id) < 2**32:
            raise CommitteeAuthorizationError("guide slot id must fit u32")
        if not 1 < int(self.input_bits) < 2**16:
            raise CommitteeAuthorizationError("guide input width is invalid")
        if len(bytes(self.program_seed_commitment_value)) != 32:
            raise CommitteeAuthorizationError("guide seed commitment must be 32 bytes")
        if len(self.label_hash_pairs) != 2 * self.input_bits:
            raise CommitteeAuthorizationError("guide has the wrong number of label pairs")
        if any(len(zero) != 32 or len(one) != 32 for zero, one in self.label_hash_pairs):
            raise CommitteeAuthorizationError("guide label hashes must be 32 bytes")

    @classmethod
    def from_tree(cls, tree: LabelCommitmentTree) -> "CommitteeLabelGuide":
        pairs: list[tuple[bytes, bytes]] = []
        for flat_index, (zero, one) in enumerate(tree.label_pairs):
            coordinate, bit = divmod(flat_index, tree.input_bits)
            pairs.append(
                (
                    _label_hash(
                        context_digest=tree.context_digest,
                        slot_id=tree.slot_id,
                        coordinate=coordinate,
                        bit=bit,
                        label=zero,
                    ),
                    _label_hash(
                        context_digest=tree.context_digest,
                        slot_id=tree.slot_id,
                        coordinate=coordinate,
                        bit=bit,
                        label=one,
                    ),
                )
            )
        guide = cls(
            context_digest=tree.context_digest,
            slot_id=tree.slot_id,
            input_bits=tree.input_bits,
            program_seed_commitment_value=program_seed_commitment(tree.program_seed),
            label_hash_pairs=tuple(pairs),
        )
        if guide.aggregate_root != tree.root:
            raise CommitteeAuthorizationError("public guide does not reconstruct tree root")
        return guide

    @property
    def aggregate_root(self) -> bytes:
        return root_from_label_hash_pairs(
            context_digest=self.context_digest,
            slot_id=self.slot_id,
            input_bits=self.input_bits,
            program_seed_commitment_value=self.program_seed_commitment_value,
            label_hash_pairs=self.label_hash_pairs,
        )

    @property
    def compact_bytes(self) -> bytes:
        return (
            _MAGIC_GUIDE
            + bytes(self.context_digest)
            + _u(self.slot_id, 4, "slot id")
            + _u(self.input_bits, 2, "input bits")
            + bytes(self.program_seed_commitment_value)
            + b"".join(zero + one for zero, one in self.label_hash_pairs)
        )

    @property
    def digest(self) -> bytes:
        return _sha(_GUIDE_DIGEST_DOMAIN, self.compact_bytes)

    @classmethod
    def parse_compact(cls, raw: bytes) -> "CommitteeLabelGuide":
        encoded = bytes(raw)
        minimum = len(_MAGIC_GUIDE) + 32 + 4 + 2 + 32
        if len(encoded) < minimum or encoded[:8] != _MAGIC_GUIDE:
            raise CommitteeAuthorizationError("invalid committee guide framing")
        context = encoded[8:40]
        slot_id = int.from_bytes(encoded[40:44], "big")
        input_bits = int.from_bytes(encoded[44:46], "big")
        expected = minimum + 2 * input_bits * 64
        if len(encoded) != expected:
            raise CommitteeAuthorizationError("committee guide length mismatch")
        commitment = encoded[46:78]
        cursor = 78
        pairs: list[tuple[bytes, bytes]] = []
        for _ in range(2 * input_bits):
            pairs.append((encoded[cursor : cursor + 32], encoded[cursor + 32 : cursor + 64]))
            cursor += 64
        result = cls(context, slot_id, input_bits, commitment, tuple(pairs))
        if result.compact_bytes != encoded:
            raise CommitteeAuthorizationError("non-canonical committee guide")
        return result


@dataclass(frozen=True, slots=True)
class CommitteeParticipantDescriptor:
    participant_index: int
    participant_pubkey: bytes
    share_root: bytes
    schema: str = "ranklock-committee-participant-descriptor-v1"

    def __post_init__(self) -> None:
        if not 0 <= int(self.participant_index) < 2**32:
            raise CommitteeAuthorizationError("participant index must fit u32")
        if len(bytes(self.participant_pubkey)) != 32 or len(bytes(self.share_root)) != 32:
            raise CommitteeAuthorizationError("participant key/root must be 32 bytes")

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.participant_index, 4, "participant index")
            + bytes(self.participant_pubkey)
            + bytes(self.share_root)
        )


@dataclass(frozen=True, slots=True)
class UnsignedCommitteeActivation:
    context_digest: bytes
    chain_genesis_hash: bytes
    counterproof_txid: bytes
    slot_id: int
    input_bits: int
    minimum_confirmations: int
    aggregate_label_root: bytes
    program_seed_commitment_value: bytes
    artifact_root: bytes
    guide_digest: bytes
    request_authorizer_pubkey: bytes
    rollback_witness_set_digest: bytes
    participants: tuple[CommitteeParticipantDescriptor, ...]
    schema: str = "ranklock-unsigned-committee-activation-v3"

    def __post_init__(self) -> None:
        for name in (
            "context_digest",
            "chain_genesis_hash",
            "counterproof_txid",
            "aggregate_label_root",
            "program_seed_commitment_value",
            "artifact_root",
            "guide_digest",
            "request_authorizer_pubkey",
            "rollback_witness_set_digest",
        ):
            if len(bytes(getattr(self, name))) != 32:
                raise CommitteeAuthorizationError(f"{name} must be 32 bytes")
        if not 0 <= int(self.slot_id) < 2**32:
            raise CommitteeAuthorizationError("activation slot id must fit u32")
        if not 1 < int(self.input_bits) < 2**16:
            raise CommitteeAuthorizationError("activation input width is invalid")
        if not 1 <= int(self.minimum_confirmations) < 2**16:
            raise CommitteeAuthorizationError("activation confirmation depth is invalid")
        if len(self.participants) < 2:
            raise CommitteeAuthorizationError("safety committee requires at least two participants")
        indexes = tuple(item.participant_index for item in self.participants)
        pubkeys = tuple(item.participant_pubkey for item in self.participants)
        roots = tuple(item.share_root for item in self.participants)
        if indexes != tuple(range(len(self.participants))):
            raise CommitteeAuthorizationError("participant indexes must be canonical and contiguous")
        if len(set(pubkeys)) != len(pubkeys) or len(set(roots)) != len(roots):
            raise CommitteeAuthorizationError("participant keys and roots must be unique")

    @property
    def encoded(self) -> bytes:
        return (
            _MAGIC_ACTIVATION
            + bytes(self.context_digest)
            + bytes(self.chain_genesis_hash)
            + bytes(self.counterproof_txid)
            + _u(self.slot_id, 4, "slot id")
            + _u(self.input_bits, 2, "input bits")
            + _u(self.minimum_confirmations, 2, "minimum confirmations")
            + bytes(self.aggregate_label_root)
            + bytes(self.program_seed_commitment_value)
            + bytes(self.artifact_root)
            + bytes(self.guide_digest)
            + bytes(self.request_authorizer_pubkey)
            + bytes(self.rollback_witness_set_digest)
            + _u(len(self.participants), 2, "participant count")
            + b"".join(item.encoded for item in self.participants)
        )

    @property
    def digest(self) -> bytes:
        return _sha(_ACTIVATION_DIGEST_DOMAIN, self.encoded)

    @property
    def signing_message(self) -> bytes:
        return _sha(_ACTIVATION_SIGN_DOMAIN, self.digest)


@dataclass(frozen=True, slots=True)
class SignedCommitteeActivation:
    unsigned: UnsignedCommitteeActivation
    participant_signatures: tuple[bytes, ...]
    schema: str = "ranklock-signed-committee-activation-v1"

    def __post_init__(self) -> None:
        if len(self.participant_signatures) != len(self.unsigned.participants):
            raise CommitteeAuthorizationError("activation requires every participant signature")
        if any(len(bytes(signature)) != _SIGNATURE_BYTES for signature in self.participant_signatures):
            raise CommitteeAuthorizationError("activation signatures must be 64 bytes")

    @property
    def encoded(self) -> bytes:
        return self.unsigned.encoded + b"".join(self.participant_signatures)

    @property
    def digest(self) -> bytes:
        return self.unsigned.digest

    def verify(self) -> bool:
        return all(
            verify(
                self.unsigned.signing_message,
                descriptor.participant_pubkey,
                signature,
            )
            for descriptor, signature in zip(
                self.unsigned.participants, self.participant_signatures, strict=True
            )
        )

    @classmethod
    def parse_compact(cls, raw: bytes) -> "SignedCommitteeActivation":
        encoded = bytes(raw)
        fixed = 8 + 32 * 9 + 4 + 2 + 2 + 2
        if len(encoded) < fixed or encoded[:8] != _MAGIC_ACTIVATION:
            raise CommitteeAuthorizationError("invalid committee activation framing")
        cursor = 8
        context = encoded[cursor : cursor + 32]; cursor += 32
        chain = encoded[cursor : cursor + 32]; cursor += 32
        txid = encoded[cursor : cursor + 32]; cursor += 32
        slot_id = int.from_bytes(encoded[cursor : cursor + 4], "big"); cursor += 4
        input_bits = int.from_bytes(encoded[cursor : cursor + 2], "big"); cursor += 2
        minimum_confirmations = int.from_bytes(encoded[cursor : cursor + 2], "big"); cursor += 2
        aggregate_root = encoded[cursor : cursor + 32]; cursor += 32
        seed_commitment = encoded[cursor : cursor + 32]; cursor += 32
        artifact_root = encoded[cursor : cursor + 32]; cursor += 32
        guide_digest = encoded[cursor : cursor + 32]; cursor += 32
        authorizer = encoded[cursor : cursor + 32]; cursor += 32
        rollback_set_digest = encoded[cursor : cursor + 32]; cursor += 32
        count = int.from_bytes(encoded[cursor : cursor + 2], "big"); cursor += 2
        if count < 2:
            raise CommitteeAuthorizationError("activation participant count is invalid")
        expected = cursor + count * 68 + count * 64
        if len(encoded) != expected:
            raise CommitteeAuthorizationError("committee activation length mismatch")
        descriptors: list[CommitteeParticipantDescriptor] = []
        for _ in range(count):
            index = int.from_bytes(encoded[cursor : cursor + 4], "big"); cursor += 4
            pubkey = encoded[cursor : cursor + 32]; cursor += 32
            root = encoded[cursor : cursor + 32]; cursor += 32
            descriptors.append(CommitteeParticipantDescriptor(index, pubkey, root))
        signatures = tuple(
            encoded[cursor + 64 * index : cursor + 64 * (index + 1)]
            for index in range(count)
        )
        unsigned = UnsignedCommitteeActivation(
            context,
            chain,
            txid,
            slot_id,
            input_bits,
            minimum_confirmations,
            aggregate_root,
            seed_commitment,
            artifact_root,
            guide_digest,
            authorizer,
            rollback_set_digest,
            tuple(descriptors),
        )
        result = cls(unsigned, signatures)
        if result.encoded != encoded:
            raise CommitteeAuthorizationError("non-canonical committee activation")
        return result


@dataclass(frozen=True, slots=True)
class ParticipantSlotSecrets:
    context_digest: bytes
    slot_id: int
    input_bits: int
    participant_index: int
    participant_secret: int
    program_seed_share: bytes
    label_share_pairs: tuple[tuple[bytes, bytes], ...]
    share_root: bytes
    schema: str = "ranklock-participant-slot-secrets-v1"

    def __post_init__(self) -> None:
        if len(bytes(self.context_digest)) != 32 or len(bytes(self.program_seed_share)) != 32:
            raise CommitteeAuthorizationError("participant context/seed share is malformed")
        if len(bytes(self.share_root)) != 32:
            raise CommitteeAuthorizationError("participant share root must be 32 bytes")
        if len(self.label_share_pairs) != 2 * self.input_bits:
            raise CommitteeAuthorizationError("participant label-share count mismatch")
        if _share_root_from_pairs(
            context_digest=self.context_digest,
            slot_id=self.slot_id,
            participant_index=self.participant_index,
            input_bits=self.input_bits,
            seed_share=self.program_seed_share,
            pairs=self.label_share_pairs,
        ) != bytes(self.share_root):
            raise CommitteeAuthorizationError("participant secrets do not match share root")

    @property
    def participant_pubkey(self) -> bytes:
        return public_key(self.participant_secret)

    @property
    def compact_secret_bytes(self) -> bytes:
        if not 1 <= int(self.participant_secret) < SECP256K1_ORDER:
            raise CommitteeAuthorizationError("participant signing secret is non-canonical")
        return (
            _MAGIC_SECRETS
            + bytes(self.context_digest)
            + _u(self.slot_id, 4, "slot id")
            + _u(self.input_bits, 2, "input bits")
            + _u(self.participant_index, 4, "participant index")
            + int(self.participant_secret).to_bytes(32, "big")
            + bytes(self.program_seed_share)
            + bytes(self.share_root)
            + b"".join(zero + one for zero, one in self.label_share_pairs)
        )

    @classmethod
    def parse_secret_bytes(cls, raw: bytes) -> "ParticipantSlotSecrets":
        encoded = bytes(raw)
        fixed = 8 + 32 + 4 + 2 + 4 + 32 + 32 + 32
        if len(encoded) < fixed or encoded[:8] != _MAGIC_SECRETS:
            raise CommitteeAuthorizationError("invalid participant-secret framing")
        cursor = 8
        context = encoded[cursor : cursor + 32]; cursor += 32
        slot_id = int.from_bytes(encoded[cursor : cursor + 4], "big"); cursor += 4
        input_bits = int.from_bytes(encoded[cursor : cursor + 2], "big"); cursor += 2
        index = int.from_bytes(encoded[cursor : cursor + 4], "big"); cursor += 4
        secret = int.from_bytes(encoded[cursor : cursor + 32], "big"); cursor += 32
        seed_share = encoded[cursor : cursor + 32]; cursor += 32
        root = encoded[cursor : cursor + 32]; cursor += 32
        expected = fixed + 2 * input_bits * 2 * _SHARE_BYTES
        if len(encoded) != expected:
            raise CommitteeAuthorizationError("participant-secret length mismatch")
        pairs: list[tuple[bytes, bytes]] = []
        for _ in range(2 * input_bits):
            pairs.append((
                encoded[cursor : cursor + _SHARE_BYTES],
                encoded[cursor + _SHARE_BYTES : cursor + 2 * _SHARE_BYTES],
            ))
            cursor += 2 * _SHARE_BYTES
        result = cls(
            context, slot_id, input_bits, index, secret, seed_share, tuple(pairs), root
        )
        if result.compact_secret_bytes != encoded:
            raise CommitteeAuthorizationError("non-canonical participant-secret encoding")
        return result


class _DeterministicEntropy:
    def __init__(self, seed: bytes) -> None:
        self.seed = bytes(seed)
        if len(self.seed) < 16:
            raise CommitteeAuthorizationError("fixture entropy seed must be at least 16 bytes")
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        transcript = (
            b"ranklock/dealer-fixture-entropy/v1\x00"
            + self.seed
            + self.counter.to_bytes(8, "big")
        )
        self.counter += 1
        return shake_256(transcript).digest(length)


def _split_value(value: bytes, count: int, random_bytes: Callable[[int], bytes]) -> tuple[bytes, ...]:
    value = bytes(value)
    shares = [bytes(random_bytes(len(value))) for _ in range(count - 1)]
    shares.append(_xor((value, *shares), width=len(value)))
    return tuple(shares)


def dealer_split_fixture(
    tree: LabelCommitmentTree,
    *,
    chain_genesis_hash: bytes,
    counterproof_txid: bytes,
    artifact_root: bytes,
    participant_secrets: Sequence[int],
    request_authorizer_pubkey: bytes,
    rollback_witness_pubkeys: Sequence[bytes],
    minimum_confirmations: int = 6,
    deterministic_seed: bytes | None = None,
    allow_public_secrets: bool = False,
) -> tuple[SignedCommitteeActivation, CommitteeLabelGuide, tuple[ParticipantSlotSecrets, ...]]:
    """Split one trusted tree for tests; **not** a production setup ceremony."""

    count = len(participant_secrets)
    if count < 2:
        raise CommitteeAuthorizationError("dealer fixture requires at least two participants")
    # A deterministic seed makes every share a public value. That is correct
    # for conformance fixtures -- handoff rule 1 says never fund one -- but it
    # must never happen because a caller wanted reproducibility and did not
    # realise the shares stop being secret. Require saying so out loud.
    if deterministic_seed is not None and not allow_public_secrets:
        raise CommitteeAuthorizationError(
            "deterministic_seed makes every participant share public; pass "
            "allow_public_secrets=True to confirm this is a conformance "
            "fixture that will never hold value"
        )
    random_bytes: Callable[[int], bytes]
    random_bytes = secrets.token_bytes if deterministic_seed is None else _DeterministicEntropy(deterministic_seed)
    seed_shares = _split_value(tree.program_seed, count, random_bytes)
    per_participant_pairs: list[list[tuple[bytes, bytes]]] = [[] for _ in range(count)]
    for zero, one in tree.label_pairs:
        zero_shares = _split_value(zero, count, random_bytes)
        one_shares = _split_value(one, count, random_bytes)
        for index in range(count):
            per_participant_pairs[index].append((zero_shares[index], one_shares[index]))

    participant_states: list[ParticipantSlotSecrets] = []
    descriptors: list[CommitteeParticipantDescriptor] = []
    for index, secret in enumerate(participant_secrets):
        pairs = tuple(per_participant_pairs[index])
        root = _share_root_from_pairs(
            context_digest=tree.context_digest,
            slot_id=tree.slot_id,
            participant_index=index,
            input_bits=tree.input_bits,
            seed_share=seed_shares[index],
            pairs=pairs,
        )
        state = ParticipantSlotSecrets(
            context_digest=tree.context_digest,
            slot_id=tree.slot_id,
            input_bits=tree.input_bits,
            participant_index=index,
            participant_secret=int(secret),
            program_seed_share=seed_shares[index],
            label_share_pairs=pairs,
            share_root=root,
        )
        participant_states.append(state)
        descriptors.append(
            CommitteeParticipantDescriptor(index, state.participant_pubkey, root)
        )

    guide = CommitteeLabelGuide.from_tree(tree)
    unsigned = UnsignedCommitteeActivation(
        context_digest=tree.context_digest,
        chain_genesis_hash=bytes(chain_genesis_hash),
        counterproof_txid=bytes(counterproof_txid),
        slot_id=tree.slot_id,
        input_bits=tree.input_bits,
        minimum_confirmations=int(minimum_confirmations),
        aggregate_label_root=tree.root,
        program_seed_commitment_value=program_seed_commitment(tree.program_seed),
        artifact_root=bytes(artifact_root),
        guide_digest=guide.digest,
        request_authorizer_pubkey=bytes(request_authorizer_pubkey),
        rollback_witness_set_digest=rollback_witness_set_digest(rollback_witness_pubkeys),
        participants=tuple(descriptors),
    )
    activation = SignedCommitteeActivation(
        unsigned=unsigned,
        participant_signatures=tuple(
            sign(unsigned.signing_message, int(secret)) for secret in participant_secrets
        ),
    )
    if not activation.verify():  # pragma: no cover - internal defense
        raise CommitteeAuthorizationError("fixture activation signatures failed")
    return activation, guide, tuple(participant_states)


@dataclass(frozen=True, slots=True)
class CommitteeAuthorizationRequest:
    context_digest: bytes
    activation_digest: bytes
    slot_id: int
    point_encoding: bytes
    bitcoin_binding: BitcoinAuthorizationBinding
    request_authorizer_pubkey: bytes
    request_signature: bytes
    schema: str = "ranklock-committee-authorization-request-v1"

    def __post_init__(self) -> None:
        for name in ("context_digest", "activation_digest", "request_authorizer_pubkey"):
            if len(bytes(getattr(self, name))) != 32:
                raise CommitteeAuthorizationError(f"{name} must be 32 bytes")
        if len(bytes(self.point_encoding)) != _POINT_BYTES:
            raise CommitteeAuthorizationError("request point must be 32 bytes")
        if len(bytes(self.request_signature)) != _SIGNATURE_BYTES:
            raise CommitteeAuthorizationError("request signature must be 64 bytes")

    @property
    def unsigned_bytes(self) -> bytes:
        return (
            _MAGIC_REQUEST
            + bytes(self.context_digest)
            + bytes(self.activation_digest)
            + _u(self.slot_id, 4, "slot id")
            + bytes(self.point_encoding)
            + self.bitcoin_binding.canonical_bytes
            + bytes(self.request_authorizer_pubkey)
        )

    @property
    def signing_message(self) -> bytes:
        return _sha(_REQUEST_SIGN_DOMAIN, self.unsigned_bytes)

    @property
    def digest(self) -> bytes:
        return _sha(_REQUEST_DIGEST_DOMAIN, self.signing_message, self.request_signature)

    @property
    def compact_bytes(self) -> bytes:
        return self.unsigned_bytes + bytes(self.request_signature)

    def verify(self, activation: SignedCommitteeActivation) -> bool:
        unsigned = activation.unsigned
        return bool(
            activation.verify()
            and self.context_digest == unsigned.context_digest
            and self.activation_digest == activation.digest
            and self.slot_id == unsigned.slot_id
            and self.request_authorizer_pubkey == unsigned.request_authorizer_pubkey
            and self.bitcoin_binding.chain_genesis_hash == unsigned.chain_genesis_hash
            and self.bitcoin_binding.counterproof_txid == unsigned.counterproof_txid
            and verify(
                self.signing_message,
                self.request_authorizer_pubkey,
                self.request_signature,
            )
        )

    @classmethod
    def parse_compact(cls, raw: bytes) -> "CommitteeAuthorizationRequest":
        encoded = bytes(raw)
        binding_bytes = 32 + 36 + 4 + 32 + 32 + 32
        expected = 8 + 32 + 32 + 4 + 32 + binding_bytes + 32 + 64
        if len(encoded) != expected or encoded[:8] != _MAGIC_REQUEST:
            raise CommitteeAuthorizationError("invalid committee request framing")
        cursor = 8
        context = encoded[cursor : cursor + 32]; cursor += 32
        activation = encoded[cursor : cursor + 32]; cursor += 32
        slot_id = int.from_bytes(encoded[cursor : cursor + 4], "big"); cursor += 4
        point = encoded[cursor : cursor + 32]; cursor += 32
        chain = encoded[cursor : cursor + 32]; cursor += 32
        outpoint = encoded[cursor : cursor + 36]; cursor += 36
        input_index = int.from_bytes(encoded[cursor : cursor + 4], "big"); cursor += 4
        txid = encoded[cursor : cursor + 32]; cursor += 32
        wtxid = encoded[cursor : cursor + 32]; cursor += 32
        witness = encoded[cursor : cursor + 32]; cursor += 32
        authorizer = encoded[cursor : cursor + 32]; cursor += 32
        signature = encoded[cursor : cursor + 64]
        result = cls(
            context,
            activation,
            slot_id,
            point,
            BitcoinAuthorizationBinding(chain, outpoint, input_index, txid, wtxid, witness),
            authorizer,
            signature,
        )
        if result.compact_bytes != encoded:
            raise CommitteeAuthorizationError("non-canonical committee request")
        return result


def issue_committee_request(
    activation: SignedCommitteeActivation,
    *,
    point: object,
    bitcoin_binding: BitcoinAuthorizationBinding,
    request_authorizer_secret: int,
) -> CommitteeAuthorizationRequest:
    if not activation.verify():
        raise CommitteeAuthorizationError("committee activation failed verification")
    unsigned = activation.unsigned
    if bitcoin_binding.chain_genesis_hash != unsigned.chain_genesis_hash:
        raise CommitteeAuthorizationError("Bitcoin binding is for another chain")
    if bitcoin_binding.counterproof_txid != unsigned.counterproof_txid:
        raise CommitteeAuthorizationError("Bitcoin binding is for another counterproof")
    if public_key(request_authorizer_secret) != unsigned.request_authorizer_pubkey:
        raise CommitteeAuthorizationError("request authorizer secret does not match activation")
    point_encoding = compress_g1(point)  # type: ignore[arg-type]
    placeholder = CommitteeAuthorizationRequest(
        unsigned.context_digest,
        activation.digest,
        unsigned.slot_id,
        point_encoding,
        bitcoin_binding,
        unsigned.request_authorizer_pubkey,
        bytes(_SIGNATURE_BYTES),
    )
    return CommitteeAuthorizationRequest(
        placeholder.context_digest,
        placeholder.activation_digest,
        placeholder.slot_id,
        placeholder.point_encoding,
        placeholder.bitcoin_binding,
        placeholder.request_authorizer_pubkey,
        sign(placeholder.signing_message, request_authorizer_secret),
    )


@dataclass(frozen=True, slots=True)
class ShareOpening:
    selected_share: bytes
    sibling_share_hash: bytes
    aggregate_sibling_hash: bytes

    def __post_init__(self) -> None:
        if len(bytes(self.selected_share)) != _SHARE_BYTES:
            raise CommitteeAuthorizationError("selected label share must be 16 bytes")
        if len(bytes(self.sibling_share_hash)) != HASH_BYTES:
            raise CommitteeAuthorizationError("sibling share hash must be 32 bytes")
        if len(bytes(self.aggregate_sibling_hash)) != HASH_BYTES:
            raise CommitteeAuthorizationError("aggregate sibling label hash must be 32 bytes")

    @property
    def encoded(self) -> bytes:
        return (
            bytes(self.selected_share)
            + bytes(self.sibling_share_hash)
            + bytes(self.aggregate_sibling_hash)
        )


@dataclass(frozen=True, slots=True)
class ParticipantShareResponse:
    activation_digest: bytes
    request_digest: bytes
    participant_index: int
    participant_pubkey: bytes
    program_seed_share: bytes
    share_root: bytes
    input_bits: int
    openings: tuple[ShareOpening, ...]
    participant_signature: bytes
    schema: str = "ranklock-participant-share-response-v1"

    def __post_init__(self) -> None:
        for name in ("activation_digest", "request_digest", "participant_pubkey", "program_seed_share", "share_root"):
            if len(bytes(getattr(self, name))) != 32:
                raise CommitteeAuthorizationError(f"{name} must be 32 bytes")
        if len(self.openings) != 2 * self.input_bits:
            raise CommitteeAuthorizationError("participant response opening count mismatch")
        if len(bytes(self.participant_signature)) != _SIGNATURE_BYTES:
            raise CommitteeAuthorizationError("participant signature must be 64 bytes")

    @property
    def header_bytes(self) -> bytes:
        return (
            _MAGIC_RESPONSE
            + bytes(self.activation_digest)
            + bytes(self.request_digest)
            + _u(self.participant_index, 4, "participant index")
            + bytes(self.participant_pubkey)
            + bytes(self.program_seed_share)
            + bytes(self.share_root)
            + _u(self.input_bits, 2, "input bits")
        )

    @property
    def openings_digest(self) -> bytes:
        return _sha(
            _RESPONSE_OPENINGS_DOMAIN,
            _u(self.input_bits, 2, "input bits"),
            *(opening.encoded for opening in self.openings),
        )

    @property
    def signing_message(self) -> bytes:
        return _sha(_RESPONSE_SIGN_DOMAIN, self.header_bytes, self.openings_digest)

    @property
    def compact_bytes(self) -> bytes:
        return (
            self.header_bytes
            + b"".join(opening.encoded for opening in self.openings)
            + bytes(self.participant_signature)
        )

    def verify_signature(self) -> bool:
        return verify(
            self.signing_message,
            self.participant_pubkey,
            self.participant_signature,
        )

    def reconstruct_share_root_for_request(
        self, request: CommitteeAuthorizationRequest
    ) -> bytes:
        _point, values = _point_values(request.point_encoding)
        pair_hashes: list[bytes] = []
        for flat_index, opening in enumerate(self.openings):
            coordinate, bit = divmod(flat_index, self.input_bits)
            selected_bit = (values[coordinate] >> bit) & 1
            selected_hash = _share_label_hash(
                context_digest=request.context_digest,
                slot_id=request.slot_id,
                participant_index=self.participant_index,
                coordinate=coordinate,
                bit=bit,
                share=opening.selected_share,
            )
            if selected_bit == 0:
                zero_hash, one_hash = selected_hash, opening.sibling_share_hash
            else:
                zero_hash, one_hash = opening.sibling_share_hash, selected_hash
            pair_hashes.append(
                _share_pair_hash(
                    context_digest=request.context_digest,
                    slot_id=request.slot_id,
                    participant_index=self.participant_index,
                    coordinate=coordinate,
                    bit=bit,
                    zero_hash=zero_hash,
                    one_hash=one_hash,
                )
            )
        return _share_root_from_pair_hashes(
            context_digest=request.context_digest,
            slot_id=request.slot_id,
            participant_index=self.participant_index,
            input_bits=self.input_bits,
            seed_share=self.program_seed_share,
            pair_hashes=pair_hashes,
        )

    @classmethod
    def parse_compact(cls, raw: bytes) -> "ParticipantShareResponse":
        encoded = bytes(raw)
        fixed = 8 + 32 + 32 + 4 + 32 + 32 + 32 + 2
        if len(encoded) < fixed + 64 or encoded[:8] != _MAGIC_RESPONSE:
            raise CommitteeAuthorizationError("invalid participant response framing")
        cursor = 8
        activation = encoded[cursor : cursor + 32]; cursor += 32
        request = encoded[cursor : cursor + 32]; cursor += 32
        index = int.from_bytes(encoded[cursor : cursor + 4], "big"); cursor += 4
        pubkey = encoded[cursor : cursor + 32]; cursor += 32
        seed_share = encoded[cursor : cursor + 32]; cursor += 32
        root = encoded[cursor : cursor + 32]; cursor += 32
        input_bits = int.from_bytes(encoded[cursor : cursor + 2], "big"); cursor += 2
        expected = fixed + 2 * input_bits * _SHARE_OPENING_BYTES + 64
        if len(encoded) != expected:
            raise CommitteeAuthorizationError("participant response length mismatch")
        openings: list[ShareOpening] = []
        for _ in range(2 * input_bits):
            openings.append(
                ShareOpening(
                    encoded[cursor : cursor + _SHARE_BYTES],
                    encoded[cursor + _SHARE_BYTES : cursor + _SHARE_BYTES + HASH_BYTES],
                    encoded[cursor + _SHARE_BYTES + HASH_BYTES : cursor + _SHARE_OPENING_BYTES],
                )
            )
            cursor += _SHARE_OPENING_BYTES
        result = cls(
            activation,
            request,
            index,
            pubkey,
            seed_share,
            root,
            input_bits,
            tuple(openings),
            encoded[cursor : cursor + 64],
        )
        if result.compact_bytes != encoded:
            raise CommitteeAuthorizationError("non-canonical participant response")
        return result


def _descriptor_for(
    activation: SignedCommitteeActivation, participant_index: int
) -> CommitteeParticipantDescriptor:
    if not 0 <= participant_index < len(activation.unsigned.participants):
        raise CommitteeAuthorizationError("participant is outside activation")
    descriptor = activation.unsigned.participants[participant_index]
    if descriptor.participant_index != participant_index:
        raise CommitteeAuthorizationError("non-canonical participant mapping")
    return descriptor


def prepare_participant_response(
    *,
    activation: SignedCommitteeActivation,
    request: CommitteeAuthorizationRequest,
    observed_raw_transaction: bytes,
    participant: ParticipantSlotSecrets,
    guide: CommitteeLabelGuide,
    ledger: DurableSlotLedger,
) -> ParticipantShareResponse:
    """Verify and durably burn, then construct one response in memory.

    This lower-level primitive deliberately leaves the slot in ``burned``
    state.  A production sidecar must still anchor that burn at its independent
    rollback witnesses and re-check Bitcoin Core's active-chain view before it
    makes the returned bytes externally visible.  Only after those checks may
    it finalize the slot as ``success``.

    Exact replays of an already-successful request are deterministic and are
    permitted so a process can repair a missing output file after a crash.
    """

    if not activation.verify():
        raise CommitteeAuthorizationError("committee activation failed verification")
    if not request.verify(activation):
        raise CommitteeAuthorizationError("committee request signature/binding failed")
    unsigned = activation.unsigned
    if (
        guide.context_digest != unsigned.context_digest
        or guide.slot_id != unsigned.slot_id
        or guide.input_bits != unsigned.input_bits
        or guide.digest != unsigned.guide_digest
        or guide.aggregate_root != unsigned.aggregate_label_root
        or guide.program_seed_commitment_value != unsigned.program_seed_commitment_value
    ):
        raise CommitteeAuthorizationError("participant label guide does not match activation")
    if not request.bitcoin_binding.verify_raw_transaction(observed_raw_transaction):
        raise CommitteeAuthorizationError("observed transaction does not match signed witness binding")
    descriptor = _descriptor_for(activation, participant.participant_index)
    if (
        participant.context_digest != activation.unsigned.context_digest
        or participant.slot_id != activation.unsigned.slot_id
        or participant.input_bits != activation.unsigned.input_bits
        or participant.participant_pubkey != descriptor.participant_pubkey
        or participant.share_root != descriptor.share_root
    ):
        raise CommitteeAuthorizationError("participant secret state does not match activation")
    if ledger.context_digest != activation.unsigned.context_digest:
        raise CommitteeAuthorizationError("participant ledger is for another context")

    use = ledger.begin(
        request.slot_id,
        context_digest=request.context_digest,
        input_digest=_sha(_INPUT_DIGEST_DOMAIN, request.point_encoding),
        authorization_digest=request.digest,
        chain_binding_digest=request.bitcoin_binding.digest,
    )
    if use.terminal and use.state != "success":
        raise CommitteeAuthorizationError(
            f"exact request previously terminated as {use.state}"
        )
    try:
        _point, values = _point_values(request.point_encoding)
        openings: list[ShareOpening] = []
        for flat_index, pair in enumerate(participant.label_share_pairs):
            coordinate, bit = divmod(flat_index, participant.input_bits)
            selected_bit = (values[coordinate] >> bit) & 1
            selected = pair[selected_bit]
            sibling = pair[1 - selected_bit]
            aggregate_zero_hash, aggregate_one_hash = guide.label_hash_pairs[flat_index]
            openings.append(
                ShareOpening(
                    selected,
                    _share_label_hash(
                        context_digest=request.context_digest,
                        slot_id=request.slot_id,
                        participant_index=participant.participant_index,
                        coordinate=coordinate,
                        bit=bit,
                        share=sibling,
                    ),
                    aggregate_one_hash if selected_bit == 0 else aggregate_zero_hash,
                )
            )
        placeholder = ParticipantShareResponse(
            activation.digest,
            request.digest,
            participant.participant_index,
            participant.participant_pubkey,
            participant.program_seed_share,
            participant.share_root,
            participant.input_bits,
            tuple(openings),
            bytes(_SIGNATURE_BYTES),
        )
        response = ParticipantShareResponse(
            placeholder.activation_digest,
            placeholder.request_digest,
            placeholder.participant_index,
            placeholder.participant_pubkey,
            placeholder.program_seed_share,
            placeholder.share_root,
            placeholder.input_bits,
            placeholder.openings,
            sign(placeholder.signing_message, participant.participant_secret),
        )
        if not response.verify_signature() or response.reconstruct_share_root_for_request(request) != participant.share_root:
            raise CommitteeAuthorizationError("internally generated participant response failed")
        return response
    except Exception as exc:
        try:
            ledger.finalize(request.slot_id, outcome="malformed")
        except SlotTerminalError:
            pass
        if isinstance(exc, CommitteeAuthorizationError):
            raise
        raise CommitteeAuthorizationError(f"participant release failed: {exc}") from exc


def issue_participant_response(
    *,
    activation: SignedCommitteeActivation,
    request: CommitteeAuthorizationRequest,
    observed_raw_transaction: bytes,
    participant: ParticipantSlotSecrets,
    guide: CommitteeLabelGuide,
    ledger: DurableSlotLedger,
) -> ParticipantShareResponse:
    """Compatibility wrapper for non-networked harnesses.

    It preserves the historical API by finalizing ``success`` immediately
    after deterministic response construction.  Funded deployments must use
    :func:`prepare_participant_response` through ``ParticipantReleaseSidecar``
    so the durable burn is independently witnessed and Bitcoin is re-checked
    before response publication.
    """

    response = prepare_participant_response(
        activation=activation,
        request=request,
        observed_raw_transaction=observed_raw_transaction,
        participant=participant,
        guide=guide,
        ledger=ledger,
    )
    ledger.finalize(request.slot_id, outcome="success")
    return response


@dataclass(frozen=True, slots=True)
class ReconstructedCommitteeRelease:
    request: CommitteeAuthorizationRequest
    program_seed: bytes
    openings: tuple[LabelOpening, ...]
    participant_pubkeys: tuple[bytes, ...]
    schema: str = "ranklock-reconstructed-committee-release-v1"

    @property
    def labels(self) -> bytes:
        return b"".join(opening.label for opening in self.openings)


def reconstruct_committee_release(
    *,
    activation: SignedCommitteeActivation,
    request: CommitteeAuthorizationRequest,
    responses: Sequence[ParticipantShareResponse],
    guide: CommitteeLabelGuide | None = None,
) -> ReconstructedCommitteeRelease:
    if not activation.verify() or not request.verify(activation):
        raise CommitteeAuthorizationError("activation/request verification failed")
    unsigned = activation.unsigned
    if guide is not None and (
        guide.context_digest != unsigned.context_digest
        or guide.slot_id != unsigned.slot_id
        or guide.input_bits != unsigned.input_bits
        or guide.digest != unsigned.guide_digest
        or guide.aggregate_root != unsigned.aggregate_label_root
        or guide.program_seed_commitment_value != unsigned.program_seed_commitment_value
    ):
        raise CommitteeAuthorizationError("label guide does not match activation")
    if len(responses) != len(unsigned.participants):
        raise CommitteeAuthorizationError("all n-of-n participant responses are required")
    by_index: dict[int, ParticipantShareResponse] = {}
    for response in responses:
        if response.participant_index in by_index:
            raise CommitteeAuthorizationError("duplicate participant response")
        by_index[response.participant_index] = response
    if set(by_index) != set(range(len(unsigned.participants))):
        raise CommitteeAuthorizationError("participant response set is incomplete")

    ordered: list[ParticipantShareResponse] = []
    for descriptor in unsigned.participants:
        response = by_index[descriptor.participant_index]
        if (
            response.activation_digest != activation.digest
            or response.request_digest != request.digest
            or response.participant_pubkey != descriptor.participant_pubkey
            or response.share_root != descriptor.share_root
            or response.input_bits != unsigned.input_bits
            or not response.verify_signature()
            or response.reconstruct_share_root_for_request(request) != descriptor.share_root
        ):
            raise CommitteeAuthorizationError("participant response failed verification")
        ordered.append(response)

    seed = _xor(tuple(response.program_seed_share for response in ordered), width=32)
    if program_seed_commitment(seed) != unsigned.program_seed_commitment_value:
        raise CommitteeAuthorizationError("reconstructed program seed does not match activation")

    _point, values = _point_values(request.point_encoding)
    openings: list[LabelOpening] = []
    for flat_index in range(2 * unsigned.input_bits):
        coordinate, bit = divmod(flat_index, unsigned.input_bits)
        selected_bit = (values[coordinate] >> bit) & 1
        label = _xor(
            tuple(response.openings[flat_index].selected_share for response in ordered),
            width=LABEL_BYTES,
        )
        aggregate_siblings = {
            bytes(response.openings[flat_index].aggregate_sibling_hash)
            for response in ordered
        }
        if len(aggregate_siblings) != 1:
            raise CommitteeAuthorizationError("participants disagree on aggregate sibling hash")
        aggregate_sibling = aggregate_siblings.pop()
        actual_selected_hash = _label_hash(
            context_digest=request.context_digest,
            slot_id=request.slot_id,
            coordinate=coordinate,
            bit=bit,
            label=label,
        )
        if guide is not None:
            zero_hash, one_hash = guide.label_hash_pairs[flat_index]
            expected_selected_hash = zero_hash if selected_bit == 0 else one_hash
            expected_sibling_hash = one_hash if selected_bit == 0 else zero_hash
            if (
                actual_selected_hash != expected_selected_hash
                or aggregate_sibling != expected_sibling_hash
            ):
                raise CommitteeAuthorizationError("participant shares reconstruct the wrong label")
        openings.append(LabelOpening(label, aggregate_sibling))
    label_hash_pairs: list[tuple[bytes, bytes]] = []
    for flat_index, opening in enumerate(openings):
        coordinate, bit = divmod(flat_index, unsigned.input_bits)
        selected_bit = (values[coordinate] >> bit) & 1
        selected_hash = _label_hash(
            context_digest=request.context_digest,
            slot_id=request.slot_id,
            coordinate=coordinate,
            bit=bit,
            label=opening.label,
        )
        if selected_bit == 0:
            label_hash_pairs.append((selected_hash, opening.sibling_hash))
        else:
            label_hash_pairs.append((opening.sibling_hash, selected_hash))
    if root_from_label_hash_pairs(
        context_digest=request.context_digest,
        slot_id=request.slot_id,
        input_bits=unsigned.input_bits,
        program_seed_commitment_value=unsigned.program_seed_commitment_value,
        label_hash_pairs=label_hash_pairs,
    ) != unsigned.aggregate_label_root:
        raise CommitteeAuthorizationError("aggregate labels/siblings do not reconstruct activated root")

    return ReconstructedCommitteeRelease(
        request=request,
        program_seed=seed,
        openings=tuple(openings),
        participant_pubkeys=tuple(item.participant_pubkey for item in unsigned.participants),
    )


@dataclass(frozen=True, slots=True)
class CommitteeFusedSlotExecution:
    replay: FusedSlotReplay
    reconstructed_release: ReconstructedCommitteeRelease
    schema: str = "ranklock-committee-fused-slot-execution-v1"


def execute_committee_authorized_fused_slot(
    *,
    manifest: SignedBoundedEmbryoManifest,
    required_manifest_pubkeys: Iterable[bytes],
    activation: SignedCommitteeActivation,
    request: CommitteeAuthorizationRequest,
    responses: Sequence[ParticipantShareResponse],
    guide: CommitteeLabelGuide | None = None,
    slot_artifact: bytes,
    profile: DfbProfile,
    nonce_namespace_base: int = 0,
) -> CommitteeFusedSlotExecution:
    unsigned = activation.unsigned
    if not manifest.verify(
        required_pubkeys=required_manifest_pubkeys,
        expected_context_digest=unsigned.context_digest,
    ):
        raise CommitteeAuthorizationError("RankLock manifest failed verification")
    if not 0 <= unsigned.slot_id < manifest.unsigned.slot_count:
        raise CommitteeAuthorizationError("committee slot is outside RankLock manifest")
    descriptor = manifest.unsigned.slots[unsigned.slot_id]
    artifact = bytes(slot_artifact)
    artifact_root = _sha(
        _ARTIFACT_ROOT_DOMAIN,
        _u(unsigned.slot_id, 4, "slot id"),
        artifact,
    )
    if (
        descriptor.slot_id != unsigned.slot_id
        or descriptor.input_label_root != unsigned.aggregate_label_root
        or descriptor.artifact_root != unsigned.artifact_root
        or descriptor.artifact_root != artifact_root
        or descriptor.artifact_length != len(artifact)
    ):
        raise CommitteeAuthorizationError("committee activation does not match retained slot")

    reconstructed = reconstruct_committee_release(
        activation=activation,
        guide=guide,
        request=request,
        responses=responses,
    )
    point, _values = _point_values(request.point_encoding)
    plaintext = open_fused_slot(
        artifact,
        context_digest=unsigned.context_digest,
        slot_id=unsigned.slot_id,
        program_seed=reconstructed.program_seed,
    )
    namespace = int(nonce_namespace_base) + int(unsigned.slot_id)
    slot_profile = profile.with_nonce_namespace(namespace)
    program, mask_state = parse_fused_slot(plaintext, profile=slot_profile)
    labels = reconstructed.labels
    split = profile.input_bits * LABEL_BYTES
    if len(labels) != 2 * split:
        raise CommitteeAuthorizationError("committee label vector has the wrong length")
    replay = replay_fused_slot(
        program=program,
        mask_state=mask_state,
        input_point=point,
        x_input_labels=labels[:split],
        y_input_labels=labels[split:],
    )
    return CommitteeFusedSlotExecution(replay, reconstructed)
