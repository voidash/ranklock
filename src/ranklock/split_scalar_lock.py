from __future__ import annotations

"""Dealer-free split-scalar safety mode for RankLock.

The exact fused DFB/Embryo generator has not been compiled into an actively secure
MPC.  This module provides a conservative alternative that preserves *safety* with
one honest setup participant without asking any party to reveal its scalar share.

Each participant ``j`` independently generates a complete two-slot RankLock object
for a non-zero scalar ``r_j`` and a positive lock hiding an independent 32-byte ACK
preimage ``k_j``.  The final ACK leaf requires *all* preimages.  For a future proof
point ``A`` the evaluator obtains one certified output ``[r_j]A`` per participant,
unlocks every ``k_j``, and may aggregate the public outputs to
``[sum_j r_j]A``.  A corrupt ``n-1`` coalition can abort or publish its own
preimages, but it cannot satisfy the honest participant's hashlock or derive its
labels.

This is intentionally an N-of-N safety construction: it trades liveness and roughly
linear retained size for a much smaller malicious-setup assumption.  It does not
make the Python cryptography constant-time and it does not replace Bitcoin Core or
bridge integration tests.
"""

from dataclasses import dataclass
from hashlib import sha256
import secrets
from typing import Iterable, Sequence

from .babe_positive_lock import (
    BabePositiveLockError,
    PositiveGroth16Proof,
    PositiveGroth16VerifyingKey,
    PositiveLock,
    setup_positive_lock,
    statement_digest,
    unlock_positive_lock,
)
from .bip340 import (
    lift_x,
    public_key,
    sign,
    tapbranch_hash,
    tapleaf_hash,
    taproot_output_key,
    verify,
)
from .bn254_real import (
    CURVE_ORDER,
    FQ12,
    Point,
    add,
    compress_g1,
    compress_g2,
    decompress_g1,
    decompress_g2,
    is_inf,
    multiply,
    neg,
    pairing_product,
)
from .bounded_mpc_embryo import decode_positive_lock, encode_positive_lock
from .predicate_locked_hashlock import (
    NUMS_INTERNAL_KEY,
    BoundTransaction,
    timeout_nack_leaf_script,
)


_MAGIC_UNSIGNED = b"RLSSU250"
_MAGIC_SIGNED = b"RLSSS250"
_MAGIC_BUNDLE_SIGNATURE = b"RLSG2501"
# Version 3 makes the bundle context digest the sole positive-lock statement
# context.  Version-2 bundles accepted an independently supplied lock session
# and are semantically ambiguous, so they must not parse under this API.
_VERSION = 3
_SIG_BYTES = 64
_G1_BYTES = 32
_G2_BYTES = 64
_HASH_BYTES = 32
_PREIMAGE_BYTES = 32

_OP_EQUAL = 0x87
_OP_EQUALVERIFY = 0x88
_OP_SHA256 = 0xA8
_OP_CHECKSIGVERIFY = 0xAD

_CONTRIBUTION_DOMAIN = b"ranklock/split-scalar/contribution/v1\x00"
_UNSIGNED_DOMAIN = b"ranklock/split-scalar/unsigned-bundle/v3\x00"
_SIGN_DOMAIN = b"ranklock/split-scalar/bundle-sign/v3\x00"
_SCALE_CHALLENGE_DOMAIN = b"ranklock/split-scalar/scale-challenge/v1\x00"
_SCALE_NONCE_DOMAIN = b"ranklock/split-scalar/scale-nonce/v1\x00"
_CONNECTOR_DOMAIN = b"ranklock/split-scalar/hashlock-connector/v1\x00"


class SplitScalarLockError(ValueError):
    pass


def _u(value: int, width: int, name: str) -> bytes:
    value = int(value)
    if not 0 <= value < 1 << (8 * width):
        raise SplitScalarLockError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "big")


def _d(raw: bytes, width: int, name: str) -> bytes:
    raw = bytes(raw)
    if len(raw) != width:
        raise SplitScalarLockError(f"{name} must be {width} bytes")
    return raw


def _push(data: bytes) -> bytes:
    data = bytes(data)
    if not 0 < len(data) <= 75:
        raise SplitScalarLockError("split-hashlock script supports direct pushes of 1..75 bytes")
    return bytes((len(data),)) + data


def _hash_to_scalar(domain: bytes, *parts: bytes, nonzero: bool = False) -> int:
    """Hash to Fr with exact rejection sampling from 256-bit candidates."""

    limit = (1 << 256) - ((1 << 256) % CURVE_ORDER)
    for counter in range(1 << 32):
        candidate = int.from_bytes(
            sha256(
                bytes(domain)
                + b"".join(len(part).to_bytes(8, "big") + bytes(part) for part in parts)
                + counter.to_bytes(4, "big")
            ).digest(),
            "big",
        )
        if candidate >= limit:
            continue
        value = candidate % CURVE_ORDER
        if nonzero and value == 0:
            continue
        return value
    raise SplitScalarLockError("hash-to-scalar counter exhausted")


def _sum_points(points: Sequence[Point], *, group: str) -> Point:
    if not points:
        raise SplitScalarLockError("cannot aggregate an empty point vector")
    result = points[0]
    for point in points[1:]:
        result = add(result, point, group=group)
    if is_inf(result):
        raise SplitScalarLockError("aggregate point is infinity")
    return result


@dataclass(frozen=True, slots=True)
class ScaleKnowledgeProof:
    """Schnorr proof of knowledge for ``r_delta = [r] delta`` in BN254 G2."""

    commitment_g2: bytes
    response: int
    schema: str = "ranklock-split-scalar-scale-pok-v1"

    def __post_init__(self) -> None:
        _d(self.commitment_g2, _G2_BYTES, "scale-proof commitment")
        decompress_g2(self.commitment_g2)
        if not 0 <= int(self.response) < CURVE_ORDER:
            raise SplitScalarLockError("scale-proof response is non-canonical")

    @property
    def encoded(self) -> bytes:
        return bytes(self.commitment_g2) + int(self.response).to_bytes(32, "big")

    @classmethod
    def parse(cls, raw: bytes) -> "ScaleKnowledgeProof":
        raw = bytes(raw)
        if len(raw) != 96:
            raise SplitScalarLockError("scale proof must be 96 bytes")
        response = int.from_bytes(raw[64:], "big")
        if response >= CURVE_ORDER:
            raise SplitScalarLockError("scale-proof response is non-canonical")
        result = cls(raw[:64], response)
        if result.encoded != raw:
            raise SplitScalarLockError("non-canonical scale proof")
        return result

    @classmethod
    def create(
        cls,
        *,
        scale: int,
        delta_g2: bytes,
        r_delta_g2: bytes,
        transcript: bytes,
        nonce: int | None = None,
    ) -> "ScaleKnowledgeProof":
        scale = int(scale) % CURVE_ORDER
        if scale == 0:
            raise SplitScalarLockError("scale share must be nonzero")
        base = decompress_g2(_d(delta_g2, _G2_BYTES, "delta G2"))
        target = decompress_g2(_d(r_delta_g2, _G2_BYTES, "scaled delta G2"))
        if compress_g2(multiply(base, scale, group="g2")) != compress_g2(target):
            raise SplitScalarLockError("scale witness does not match positive-lock r_delta")
        if nonce is None:
            nonce = _hash_to_scalar(
                _SCALE_NONCE_DOMAIN,
                scale.to_bytes(32, "big"),
                delta_g2,
                r_delta_g2,
                transcript,
                nonzero=True,
            )
        nonce = int(nonce) % CURVE_ORDER
        if nonce == 0:
            raise SplitScalarLockError("scale-proof nonce must be nonzero")
        commitment = compress_g2(multiply(base, nonce, group="g2"))
        challenge = _hash_to_scalar(
            _SCALE_CHALLENGE_DOMAIN,
            delta_g2,
            r_delta_g2,
            commitment,
            transcript,
        )
        return cls(commitment, (nonce + challenge * scale) % CURVE_ORDER)

    def verify(self, *, delta_g2: bytes, r_delta_g2: bytes, transcript: bytes) -> bool:
        try:
            base = decompress_g2(_d(delta_g2, _G2_BYTES, "delta G2"))
            target = decompress_g2(_d(r_delta_g2, _G2_BYTES, "scaled delta G2"))
            commitment = decompress_g2(self.commitment_g2)
            challenge = _hash_to_scalar(
                _SCALE_CHALLENGE_DOMAIN,
                delta_g2,
                r_delta_g2,
                self.commitment_g2,
                transcript,
            )
            left = multiply(base, int(self.response), group="g2")
            right = add(commitment, multiply(target, challenge, group="g2"), group="g2")
            if is_inf(left) or is_inf(right):
                return is_inf(left) and is_inf(right)
            return compress_g2(left) == compress_g2(right)
        except (ValueError, SplitScalarLockError, ZeroDivisionError, OverflowError):
            return False


@dataclass(frozen=True, slots=True)
class SplitScalarContribution:
    participant_index: int
    participant_pubkey: bytes
    retained_object_digest: bytes
    retained_object_bytes: int
    slot_count: int
    nonce_namespace_base: int
    positive_lock: PositiveLock
    preimage_hash: bytes
    scale_proof: ScaleKnowledgeProof
    schema: str = "ranklock-split-scalar-contribution-v1"

    def __post_init__(self) -> None:
        if not 0 <= int(self.participant_index) < 2**16:
            raise SplitScalarLockError("participant index must fit u16")
        _d(self.participant_pubkey, 32, "participant public key")
        try:
            lift_x(int.from_bytes(self.participant_pubkey, "big"))
        except ValueError as exc:
            raise SplitScalarLockError("participant public key is invalid") from exc
        _d(self.retained_object_digest, 32, "retained-object digest")
        if not 0 < int(self.retained_object_bytes) < 2**63:
            raise SplitScalarLockError("retained-object size is invalid")
        if int(self.slot_count) != 2:
            raise SplitScalarLockError("split-scalar safety mode requires exactly two slots")
        if not 0 <= int(self.nonce_namespace_base) < (1 << 14):
            raise SplitScalarLockError("nonce namespace base must fit the DFB namespace")
        if int(self.nonce_namespace_base) + int(self.slot_count) > (1 << 14):
            raise SplitScalarLockError("nonce namespace range exceeds the DFB namespace")
        _d(self.preimage_hash, 32, "raw ACK preimage hash")
        if len(self.positive_lock.masked_payload) != _PREIMAGE_BYTES:
            raise SplitScalarLockError("positive lock must hide exactly one 32-byte ACK preimage")

    @property
    def scale_transcript(self) -> bytes:
        return sha256(
            _CONTRIBUTION_DOMAIN
            + _u(self.participant_index, 2, "participant index")
            + self.participant_pubkey
            + self.retained_object_digest
            + _u(self.retained_object_bytes, 8, "retained-object size")
            + _u(self.slot_count, 2, "slot count")
            + _u(self.nonce_namespace_base, 2, "nonce namespace base")
            + self.positive_lock.vk_digest
            + self.positive_lock.statement_digest
            + self.preimage_hash
        ).digest()

    @property
    def encoded(self) -> bytes:
        encoded_lock = encode_positive_lock(self.positive_lock)
        return (
            _u(self.participant_index, 2, "participant index")
            + self.participant_pubkey
            + self.retained_object_digest
            + _u(self.retained_object_bytes, 8, "retained-object size")
            + _u(self.slot_count, 2, "slot count")
            + _u(self.nonce_namespace_base, 2, "nonce namespace base")
            + _u(len(encoded_lock), 4, "positive-lock length")
            + encoded_lock
            + self.preimage_hash
            + self.scale_proof.encoded
        )

    @property
    def digest(self) -> bytes:
        return sha256(_CONTRIBUTION_DOMAIN + self.encoded).digest()

    def verify_scale_proof(self, vk: PositiveGroth16VerifyingKey) -> bool:
        return self.scale_proof.verify(
            delta_g2=vk.delta_g2,
            r_delta_g2=self.positive_lock.r_delta_g2,
            transcript=self.scale_transcript,
        )

    @classmethod
    def create(
        cls,
        *,
        participant_index: int,
        participant_secret: int,
        retained_object_digest: bytes,
        retained_object_bytes: int,
        positive_lock: PositiveLock,
        preimage_hash: bytes,
        scale: int,
        vk: PositiveGroth16VerifyingKey,
        slot_count: int = 2,
        nonce_namespace_base: int | None = None,
        proof_nonce: int | None = None,
    ) -> "SplitScalarContribution":
        if nonce_namespace_base is None:
            nonce_namespace_base = int(participant_index) * int(slot_count)
        placeholder = cls(
            participant_index=int(participant_index),
            participant_pubkey=public_key(participant_secret),
            retained_object_digest=bytes(retained_object_digest),
            retained_object_bytes=int(retained_object_bytes),
            slot_count=int(slot_count),
            nonce_namespace_base=int(nonce_namespace_base),
            positive_lock=positive_lock,
            preimage_hash=bytes(preimage_hash),
            scale_proof=ScaleKnowledgeProof(
                compress_g2(multiply(decompress_g2(vk.delta_g2), 1, group="g2")), 0
            ),
        )
        proof = ScaleKnowledgeProof.create(
            scale=scale,
            delta_g2=vk.delta_g2,
            r_delta_g2=positive_lock.r_delta_g2,
            transcript=placeholder.scale_transcript,
            nonce=proof_nonce,
        )
        return cls(
            participant_index=placeholder.participant_index,
            participant_pubkey=placeholder.participant_pubkey,
            retained_object_digest=placeholder.retained_object_digest,
            retained_object_bytes=placeholder.retained_object_bytes,
            slot_count=placeholder.slot_count,
            nonce_namespace_base=placeholder.nonce_namespace_base,
            positive_lock=placeholder.positive_lock,
            preimage_hash=placeholder.preimage_hash,
            scale_proof=proof,
        )

    @classmethod
    def parse_from(cls, raw: bytes, offset: int = 0) -> tuple["SplitScalarContribution", int]:
        raw = bytes(raw)
        fixed_before_lock = 2 + 32 + 32 + 8 + 2 + 2 + 4
        if offset < 0 or offset + fixed_before_lock > len(raw):
            raise SplitScalarLockError("truncated split-scalar contribution")
        cursor = offset
        participant_index = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        participant_pubkey = raw[cursor : cursor + 32]; cursor += 32
        retained_digest = raw[cursor : cursor + 32]; cursor += 32
        retained_bytes = int.from_bytes(raw[cursor : cursor + 8], "big"); cursor += 8
        slot_count = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        nonce_namespace_base = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        lock_length = int.from_bytes(raw[cursor : cursor + 4], "big"); cursor += 4
        if lock_length == 0 or cursor + lock_length + 32 + 96 > len(raw):
            raise SplitScalarLockError("invalid split-scalar positive-lock length")
        lock, lock_end = decode_positive_lock(raw[cursor : cursor + lock_length], offset=0)
        if lock_end != lock_length:
            raise SplitScalarLockError("positive-lock length is non-canonical")
        cursor += lock_length
        preimage_hash = raw[cursor : cursor + 32]; cursor += 32
        proof = ScaleKnowledgeProof.parse(raw[cursor : cursor + 96]); cursor += 96
        result = cls(
            participant_index=participant_index,
            participant_pubkey=participant_pubkey,
            retained_object_digest=retained_digest,
            retained_object_bytes=retained_bytes,
            slot_count=slot_count,
            nonce_namespace_base=nonce_namespace_base,
            positive_lock=lock,
            preimage_hash=preimage_hash,
            scale_proof=proof,
        )
        if result.encoded != raw[offset:cursor]:
            raise SplitScalarLockError("non-canonical split-scalar contribution")
        return result, cursor


@dataclass(frozen=True, slots=True)
class UnsignedSplitScalarBundle:
    context_digest: bytes
    contributions: tuple[SplitScalarContribution, ...]
    schema: str = "ranklock-unsigned-split-scalar-bundle-v3"

    def __post_init__(self) -> None:
        _d(self.context_digest, 32, "split-scalar context digest")
        if not 2 <= len(self.contributions) < 2**16:
            raise SplitScalarLockError("split-scalar safety mode requires at least two participants")
        expected = tuple(range(len(self.contributions)))
        actual = tuple(item.participant_index for item in self.contributions)
        if actual != expected:
            raise SplitScalarLockError("contributions must be ordered at contiguous participant indices")
        pubkeys = tuple(item.participant_pubkey for item in self.contributions)
        if len(set(pubkeys)) != len(pubkeys):
            raise SplitScalarLockError("participant public keys are duplicated")
        retained = tuple(item.retained_object_digest for item in self.contributions)
        if len(set(retained)) != len(retained):
            raise SplitScalarLockError("participant retained objects are duplicated")
        preimage_hashes = tuple(item.preimage_hash for item in self.contributions)
        if len(set(preimage_hashes)) != len(preimage_hashes):
            raise SplitScalarLockError("participant ACK preimage hashes are duplicated")
        vk_digests = {item.positive_lock.vk_digest for item in self.contributions}
        statements = {item.positive_lock.statement_digest for item in self.contributions}
        if len(vk_digests) != 1 or len(statements) != 1:
            raise SplitScalarLockError("participant positive locks target different statements")
        namespace_owners: dict[int, int] = {}
        for item in self.contributions:
            for namespace in range(
                item.nonce_namespace_base,
                item.nonce_namespace_base + item.slot_count,
            ):
                previous = namespace_owners.setdefault(namespace, item.participant_index)
                if previous != item.participant_index:
                    raise SplitScalarLockError(
                        "participant DFB nonce namespace ranges overlap"
                    )

    @property
    def encoded(self) -> bytes:
        body = bytearray(
            _MAGIC_UNSIGNED
            + _u(_VERSION, 2, "version")
            + self.context_digest
            + _u(len(self.contributions), 2, "participant count")
        )
        for contribution in self.contributions:
            encoded = contribution.encoded
            body.extend(_u(len(encoded), 4, "contribution length"))
            body.extend(encoded)
        return bytes(body)

    @property
    def digest(self) -> bytes:
        return sha256(_UNSIGNED_DOMAIN + self.encoded).digest()

    @property
    def participant_pubkeys(self) -> tuple[bytes, ...]:
        return tuple(item.participant_pubkey for item in self.contributions)

    @property
    def total_retained_bytes(self) -> int:
        return sum(item.retained_object_bytes for item in self.contributions)

    @classmethod
    def parse(cls, raw: bytes) -> "UnsignedSplitScalarBundle":
        raw = bytes(raw)
        fixed = 8 + 2 + 32 + 2
        if len(raw) < fixed or raw[:8] != _MAGIC_UNSIGNED:
            raise SplitScalarLockError("invalid unsigned split-scalar framing")
        version = int.from_bytes(raw[8:10], "big")
        if version != _VERSION:
            raise SplitScalarLockError("unsupported split-scalar bundle version")
        context = raw[10:42]
        count = int.from_bytes(raw[42:44], "big")
        cursor = 44
        contributions: list[SplitScalarContribution] = []
        for _ in range(count):
            if cursor + 4 > len(raw):
                raise SplitScalarLockError("truncated contribution length")
            length = int.from_bytes(raw[cursor : cursor + 4], "big"); cursor += 4
            if length == 0 or cursor + length > len(raw):
                raise SplitScalarLockError("invalid contribution length")
            contribution, end = SplitScalarContribution.parse_from(raw[cursor : cursor + length])
            if end != length:
                raise SplitScalarLockError("contribution framing is non-canonical")
            contributions.append(contribution)
            cursor += length
        if cursor != len(raw):
            raise SplitScalarLockError("trailing bytes after unsigned split-scalar bundle")
        result = cls(context, tuple(contributions))
        if result.encoded != raw:
            raise SplitScalarLockError("non-canonical unsigned split-scalar bundle")
        return result


@dataclass(frozen=True, slots=True)
class SplitScalarBundleSignature:
    """One independently produced signature over a common unsigned bundle.

    This message is the production coordination primitive: a coordinator may
    assemble contributions and distribute the unsigned digest, but it never
    receives any participant signing secret or scalar share.
    """

    unsigned_digest: bytes
    participant_index: int
    participant_pubkey: bytes
    signature: bytes
    schema: str = "ranklock-split-scalar-bundle-signature-v3"

    def __post_init__(self) -> None:
        _d(self.unsigned_digest, _HASH_BYTES, "unsigned bundle digest")
        if not 0 <= int(self.participant_index) < 2**16:
            raise SplitScalarLockError("bundle-signature participant index does not fit u16")
        _d(self.participant_pubkey, _HASH_BYTES, "bundle-signature participant key")
        _d(self.signature, _SIG_BYTES, "bundle signature")

    @property
    def signing_message(self) -> bytes:
        return sha256(_SIGN_DOMAIN + bytes(self.unsigned_digest)).digest()

    @property
    def encoded(self) -> bytes:
        return (
            _MAGIC_BUNDLE_SIGNATURE
            + bytes(self.unsigned_digest)
            + _u(self.participant_index, 2, "participant index")
            + bytes(self.participant_pubkey)
            + bytes(self.signature)
        )

    def verify_for(self, unsigned: UnsignedSplitScalarBundle) -> bool:
        index = int(self.participant_index)
        return bool(
            self.unsigned_digest == unsigned.digest
            and index < len(unsigned.contributions)
            and self.participant_pubkey == unsigned.contributions[index].participant_pubkey
            and verify(self.signing_message, self.participant_pubkey, self.signature)
        )

    @classmethod
    def create(
        cls,
        unsigned: UnsignedSplitScalarBundle,
        *,
        participant_index: int,
        participant_secret: int,
    ) -> "SplitScalarBundleSignature":
        index = int(participant_index)
        if index >= len(unsigned.contributions):
            raise SplitScalarLockError("participant is absent from unsigned bundle")
        contribution = unsigned.contributions[index]
        if public_key(participant_secret) != contribution.participant_pubkey:
            raise SplitScalarLockError("participant secret does not match contribution")
        placeholder = cls(unsigned.digest, index, contribution.participant_pubkey, bytes(_SIG_BYTES))
        result = cls(
            placeholder.unsigned_digest,
            placeholder.participant_index,
            placeholder.participant_pubkey,
            sign(placeholder.signing_message, participant_secret),
        )
        if not result.verify_for(unsigned):  # pragma: no cover
            raise AssertionError("generated bundle signature failed verification")
        return result

    @classmethod
    def parse(cls, raw: bytes) -> "SplitScalarBundleSignature":
        raw = bytes(raw)
        expected = 8 + 32 + 2 + 32 + 64
        if len(raw) != expected or raw[:8] != _MAGIC_BUNDLE_SIGNATURE:
            raise SplitScalarLockError("invalid split-scalar bundle-signature framing")
        result = cls(
            raw[8:40],
            int.from_bytes(raw[40:42], "big"),
            raw[42:74],
            raw[74:138],
        )
        if result.encoded != raw:
            raise SplitScalarLockError("non-canonical split-scalar bundle signature")
        return result


def assemble_signed_split_scalar_bundle(
    unsigned: UnsignedSplitScalarBundle,
    signature_messages: Sequence[SplitScalarBundleSignature],
) -> "SignedSplitScalarBundle":
    """Assemble an N-of-N bundle from independently signed messages."""

    if len(signature_messages) != len(unsigned.contributions):
        raise SplitScalarLockError("one bundle signature per participant is required")
    by_index: dict[int, SplitScalarBundleSignature] = {}
    for message in signature_messages:
        index = int(message.participant_index)
        if index in by_index:
            raise SplitScalarLockError("duplicate participant bundle signature")
        if not message.verify_for(unsigned):
            raise SplitScalarLockError("participant bundle signature failed verification")
        by_index[index] = message
    if set(by_index) != set(range(len(unsigned.contributions))):
        raise SplitScalarLockError("bundle signature set is incomplete")
    result = SignedSplitScalarBundle(
        unsigned, tuple(by_index[index].signature for index in range(len(unsigned.contributions)))
    )
    if not result.verify_signatures():  # pragma: no cover
        raise AssertionError("assembled split-scalar bundle failed verification")
    return result


@dataclass(frozen=True, slots=True)
class SignedSplitScalarBundle:
    unsigned: UnsignedSplitScalarBundle
    signatures: tuple[bytes, ...]
    schema: str = "ranklock-signed-split-scalar-bundle-v3"

    def __post_init__(self) -> None:
        if len(self.signatures) != len(self.unsigned.contributions):
            raise SplitScalarLockError("bundle requires one signature per participant")
        for signature in self.signatures:
            _d(signature, _SIG_BYTES, "bundle signature")

    @property
    def signing_message(self) -> bytes:
        return sha256(_SIGN_DOMAIN + self.unsigned.digest).digest()

    @property
    def encoded(self) -> bytes:
        unsigned = self.unsigned.encoded
        return (
            _MAGIC_SIGNED
            + _u(len(unsigned), 4, "unsigned bundle length")
            + unsigned
            + _u(len(self.signatures), 2, "signature count")
            + b"".join(self.signatures)
        )

    @property
    def digest(self) -> bytes:
        return sha256(_SIGN_DOMAIN + self.encoded).digest()

    @classmethod
    def create(
        cls,
        unsigned: UnsignedSplitScalarBundle,
        *,
        participant_secrets: Sequence[int],
    ) -> "SignedSplitScalarBundle":
        if len(participant_secrets) != len(unsigned.contributions):
            raise SplitScalarLockError("participant secret count mismatch")
        placeholder = cls(unsigned, tuple(bytes(_SIG_BYTES) for _ in participant_secrets))
        signatures: list[bytes] = []
        for contribution, secret in zip(
            unsigned.contributions, participant_secrets, strict=True
        ):
            if public_key(secret) != contribution.participant_pubkey:
                raise SplitScalarLockError("participant signing secret does not match contribution")
            signatures.append(sign(placeholder.signing_message, secret))
        result = cls(unsigned, tuple(signatures))
        if not result.verify_signatures():  # pragma: no cover
            raise AssertionError("generated split-scalar signatures failed verification")
        return result

    def verify_signatures(self) -> bool:
        return all(
            verify(self.signing_message, contribution.participant_pubkey, signature)
            for contribution, signature in zip(
                self.unsigned.contributions, self.signatures, strict=True
            )
        )

    def verify_for_statement(
        self,
        *,
        vk: PositiveGroth16VerifyingKey,
        public_inputs: Iterable[int],
        expected_context_digest: bytes,
    ) -> bool:
        if not self.verify_signatures():
            return False
        try:
            context_digest = _d(
                expected_context_digest,
                _HASH_BYTES,
                "expected split-scalar context digest",
            )
            inputs = tuple(int(value) for value in public_inputs)
            expected_statement = statement_digest(
                vk,
                inputs,
                session_context=context_digest,
            )
        except (BabePositiveLockError, SplitScalarLockError, TypeError, ValueError):
            return False
        if self.unsigned.context_digest != context_digest:
            return False
        if any(
            contribution.positive_lock.vk_digest != vk.digest
            or contribution.positive_lock.statement_digest != expected_statement
            or not contribution.verify_scale_proof(vk)
            for contribution in self.unsigned.contributions
        ):
            return False
        try:
            self.aggregate_r_delta_g2
        except (ValueError, SplitScalarLockError):
            return False
        return True

    @property
    def aggregate_r_delta_g2(self) -> bytes:
        points = tuple(
            decompress_g2(item.positive_lock.r_delta_g2)
            for item in self.unsigned.contributions
        )
        return compress_g2(_sum_points(points, group="g2"))

    @classmethod
    def parse(cls, raw: bytes) -> "SignedSplitScalarBundle":
        raw = bytes(raw)
        if len(raw) < 8 + 4 + 44 + 2 or raw[:8] != _MAGIC_SIGNED:
            raise SplitScalarLockError("invalid signed split-scalar framing")
        unsigned_length = int.from_bytes(raw[8:12], "big")
        if unsigned_length == 0 or 12 + unsigned_length + 2 > len(raw):
            raise SplitScalarLockError("invalid unsigned bundle length")
        unsigned = UnsignedSplitScalarBundle.parse(raw[12 : 12 + unsigned_length])
        cursor = 12 + unsigned_length
        count = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        if count != len(unsigned.contributions) or cursor + count * _SIG_BYTES != len(raw):
            raise SplitScalarLockError("signed bundle signature framing mismatch")
        signatures = tuple(
            raw[cursor + i * _SIG_BYTES : cursor + (i + 1) * _SIG_BYTES]
            for i in range(count)
        )
        result = cls(unsigned, signatures)
        if result.encoded != raw:
            raise SplitScalarLockError("non-canonical signed split-scalar bundle")
        return result


@dataclass(frozen=True, slots=True)
class SplitScalarUnlockResult:
    preimages: tuple[bytes, ...]
    participant_outputs_g1: tuple[bytes, ...]
    aggregate_output_g1: bytes
    aggregate_r_delta_g2: bytes
    schema: str = "ranklock-split-scalar-unlock-result-v1"

    def __post_init__(self) -> None:
        if not self.preimages or len(self.preimages) != len(self.participant_outputs_g1):
            raise SplitScalarLockError("unlock result vector lengths differ")
        for preimage in self.preimages:
            _d(preimage, _PREIMAGE_BYTES, "ACK preimage")
        for output in self.participant_outputs_g1:
            decompress_g1(_d(output, _G1_BYTES, "participant output"))
        decompress_g1(_d(self.aggregate_output_g1, _G1_BYTES, "aggregate output"))
        decompress_g2(_d(self.aggregate_r_delta_g2, _G2_BYTES, "aggregate scaled delta"))


def aggregate_projective_outputs(outputs_g1: Sequence[bytes]) -> bytes:
    points = tuple(decompress_g1(_d(item, _G1_BYTES, "participant output")) for item in outputs_g1)
    return compress_g1(_sum_points(points, group="g1"))


def certify_aggregate_projective_output(
    *,
    vk: PositiveGroth16VerifyingKey,
    proof: PositiveGroth16Proof,
    aggregate_output_g1: bytes,
    aggregate_r_delta_g2: bytes,
) -> bool:
    try:
        residual = pairing_product(
            (
                (decompress_g1(aggregate_output_g1), decompress_g2(vk.delta_g2)),
                (neg(decompress_g1(proof.a_g1)), decompress_g2(aggregate_r_delta_g2)),
            )
        )
        return residual == FQ12.one()
    except (ValueError, ZeroDivisionError, OverflowError):
        return False


def unlock_split_scalar_bundle(
    bundle: SignedSplitScalarBundle,
    *,
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    proof: PositiveGroth16Proof,
    participant_outputs_g1: Sequence[bytes],
    expected_context_digest: bytes,
) -> SplitScalarUnlockResult:
    outputs = tuple(bytes(item) for item in participant_outputs_g1)
    context_digest = _d(
        expected_context_digest,
        _HASH_BYTES,
        "expected split-scalar context digest",
    )
    inputs = tuple(int(value) for value in public_inputs)
    if len(outputs) != len(bundle.unsigned.contributions):
        raise SplitScalarLockError("one projective output is required per participant")
    if not bundle.verify_for_statement(
        vk=vk,
        public_inputs=inputs,
        expected_context_digest=context_digest,
    ):
        raise SplitScalarLockError("split-scalar bundle failed statement qualification")
    preimages: list[bytes] = []
    for contribution, output in zip(bundle.unsigned.contributions, outputs, strict=True):
        try:
            preimage = unlock_positive_lock(
                vk,
                inputs,
                proof,
                contribution.positive_lock,
                output,
                session_context=context_digest,
            )
        except BabePositiveLockError as exc:
            raise SplitScalarLockError(
                f"participant {contribution.participant_index} failed positive-lock unlock: {exc}"
            ) from exc
        if len(preimage) != _PREIMAGE_BYTES:
            raise SplitScalarLockError("unlocked ACK preimage has wrong length")
        if sha256(preimage).digest() != contribution.preimage_hash:
            raise SplitScalarLockError("unlocked payload does not satisfy raw Bitcoin hashlock")
        preimages.append(preimage)
    aggregate_output = aggregate_projective_outputs(outputs)
    aggregate_delta = bundle.aggregate_r_delta_g2
    if not certify_aggregate_projective_output(
        vk=vk,
        proof=proof,
        aggregate_output_g1=aggregate_output,
        aggregate_r_delta_g2=aggregate_delta,
    ):
        raise SplitScalarLockError("aggregate projective output failed public certification")
    return SplitScalarUnlockResult(
        tuple(preimages), outputs, aggregate_output, aggregate_delta
    )


def setup_split_scalar_fixture(
    *,
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    expected_context_digest: bytes,
    participant_secrets: Sequence[int],
    scalar_shares: Sequence[int],
    retained_object_digests: Sequence[bytes],
    retained_object_sizes: Sequence[int],
    preimages: Sequence[bytes] | None = None,
    nonce_namespace_bases: Sequence[int] | None = None,
) -> tuple[SignedSplitScalarBundle, tuple[bytes, ...]]:
    """Single-process conformance helper; production parties run this independently.

    The bundle context is also the positive-lock session context.  Accepting
    those as independent caller inputs previously allowed a correctly signed
    bundle to name one authorization context while its locks targeted another.
    """

    count = len(participant_secrets)
    bound_context_digest = _d(
        expected_context_digest,
        _HASH_BYTES,
        "expected split-scalar context digest",
    )
    inputs = tuple(int(value) for value in public_inputs)
    if not (
        count
        == len(scalar_shares)
        == len(retained_object_digests)
        == len(retained_object_sizes)
        and count >= 2
    ):
        raise SplitScalarLockError("split-scalar fixture vector lengths differ")
    if nonce_namespace_bases is None:
        namespace_bases = tuple(index * 2 for index in range(count))
    else:
        namespace_bases = tuple(int(item) for item in nonce_namespace_bases)
        if len(namespace_bases) != count:
            raise SplitScalarLockError("nonce namespace base vector length differs")
    if preimages is None:
        chosen_preimages = tuple(secrets.token_bytes(_PREIMAGE_BYTES) for _ in range(count))
    else:
        chosen_preimages = tuple(_d(item, _PREIMAGE_BYTES, "ACK preimage") for item in preimages)
    contributions: list[SplitScalarContribution] = []
    for index, (secret, scale, retained_digest, retained_bytes, preimage) in enumerate(
        zip(
            participant_secrets,
            scalar_shares,
            retained_object_digests,
            retained_object_sizes,
            chosen_preimages,
            strict=True,
        )
    ):
        scale = int(scale) % CURVE_ORDER
        if scale == 0:
            raise SplitScalarLockError("scalar shares must be nonzero")
        lock = setup_positive_lock(
            vk,
            inputs,
            preimage,
            scale=scale,
            session_context=bound_context_digest,
        )
        contributions.append(
            SplitScalarContribution.create(
                participant_index=index,
                participant_secret=secret,
                retained_object_digest=retained_digest,
                retained_object_bytes=retained_bytes,
                positive_lock=lock,
                preimage_hash=sha256(preimage).digest(),
                scale=scale,
                vk=vk,
                nonce_namespace_base=namespace_bases[index],
            )
        )
    unsigned = UnsignedSplitScalarBundle(bound_context_digest, tuple(contributions))
    bundle = SignedSplitScalarBundle.create(
        unsigned, participant_secrets=participant_secrets
    )
    if is_inf(
        _sum_points(
            tuple(decompress_g2(item.positive_lock.r_delta_g2) for item in contributions),
            group="g2",
        )
    ):  # pragma: no cover - _sum_points already rejects
        raise SplitScalarLockError("aggregate scalar share is zero")
    return bundle, chosen_preimages


def split_hashlock_ack_leaf_script(
    n_of_n_pubkey: bytes, preimage_hashes: Sequence[bytes]
) -> bytes:
    pubkey = _d(n_of_n_pubkey, 32, "N-of-N ACK public key")
    hashes = tuple(_d(item, 32, "ACK preimage hash") for item in preimage_hashes)
    if not 2 <= len(hashes) <= 64:
        raise SplitScalarLockError("split ACK requires 2..64 preimages")
    if len(set(hashes)) != len(hashes):
        raise SplitScalarLockError("split ACK preimage hashes are duplicated")
    script = bytearray(_push(pubkey) + bytes((_OP_CHECKSIGVERIFY,)))
    # Witness stack: [k_0, ..., k_(n-1), signature].  CHECKSIG consumes the
    # signature, leaving k_(n-1) on top, so checks are encoded in reverse order.
    for reverse_index, digest in enumerate(reversed(hashes)):
        script.extend(bytes((_OP_SHA256,)))
        script.extend(_push(digest))
        script.extend(
            bytes((_OP_EQUAL if reverse_index == len(hashes) - 1 else _OP_EQUALVERIFY,))
        )
    return bytes(script)


@dataclass(frozen=True, slots=True)
class SplitScalarHashlockConnector:
    n_of_n_pubkey: bytes
    preimage_hashes: tuple[bytes, ...]
    relative_delay: int
    value_sat: int
    network: str = "regtest"
    schema: str = "ranklock-split-scalar-hashlock-connector-v1"

    def __post_init__(self) -> None:
        _d(self.n_of_n_pubkey, 32, "N-of-N public key")
        # Validate x-only key through BIP340 verification's lift path.
        from .bip340 import lift_x

        try:
            lift_x(int.from_bytes(self.n_of_n_pubkey, "big"))
        except ValueError as exc:
            raise SplitScalarLockError("N-of-N public key is invalid") from exc
        hashes = tuple(_d(item, 32, "ACK preimage hash") for item in self.preimage_hashes)
        object.__setattr__(self, "preimage_hashes", hashes)
        if not 2 <= len(hashes) <= 64 or len(set(hashes)) != len(hashes):
            raise SplitScalarLockError("split connector needs 2..64 unique preimage hashes")
        if not 1 <= int(self.relative_delay) < 2**31:
            raise SplitScalarLockError("relative delay must be positive")
        if int(self.value_sat) <= 0:
            raise SplitScalarLockError("connector value must be positive")
        if not self.network:
            raise SplitScalarLockError("network identifier is empty")

    @property
    def ack_script(self) -> bytes:
        return split_hashlock_ack_leaf_script(self.n_of_n_pubkey, self.preimage_hashes)

    @property
    def nack_script(self) -> bytes:
        return timeout_nack_leaf_script(self.n_of_n_pubkey, self.relative_delay)

    @property
    def ack_leaf_hash(self) -> bytes:
        return tapleaf_hash(self.ack_script)

    @property
    def nack_leaf_hash(self) -> bytes:
        return tapleaf_hash(self.nack_script)

    @property
    def merkle_root(self) -> bytes:
        return tapbranch_hash(self.ack_leaf_hash, self.nack_leaf_hash)

    @property
    def output_key(self) -> bytes:
        return taproot_output_key(NUMS_INTERNAL_KEY, self.merkle_root)

    @property
    def script_pubkey(self) -> bytes:
        return bytes((0x51, 0x20)) + self.output_key

    @property
    def digest(self) -> bytes:
        return sha256(
            _CONNECTOR_DOMAIN
            + self.n_of_n_pubkey
            + _u(len(self.preimage_hashes), 2, "preimage count")
            + b"".join(self.preimage_hashes)
            + _u(self.relative_delay, 4, "relative delay")
            + _u(self.value_sat, 8, "connector value")
            + _u(len(self.network.encode()), 2, "network length")
            + self.network.encode()
            + self.merkle_root
        ).digest()

    def verify_preimages(self, preimages: Sequence[bytes]) -> bool:
        return len(preimages) == len(self.preimage_hashes) and all(
            len(bytes(preimage)) == _PREIMAGE_BYTES
            and sha256(bytes(preimage)).digest() == digest
            for preimage, digest in zip(preimages, self.preimage_hashes, strict=True)
        )


@dataclass(frozen=True, slots=True)
class SplitScalarPresignedGraph:
    connector: SplitScalarHashlockConnector
    ack: BoundTransaction
    nack: BoundTransaction
    ack_signature: bytes
    nack_signature: bytes
    schema: str = "ranklock-split-scalar-presigned-graph-v1"

    def __post_init__(self) -> None:
        if self.ack.kind != "ack" or self.nack.kind != "nack":
            raise SplitScalarLockError("presigned transaction roles are inverted")
        if self.ack.prevout != self.nack.prevout:
            raise SplitScalarLockError("ACK and NACK must conflict on one outpoint")
        if self.ack.sequence != 0xFFFFFFFF:
            raise SplitScalarLockError("ACK must use the immediate path")
        if self.nack.sequence < self.connector.relative_delay:
            raise SplitScalarLockError("NACK sequence does not satisfy CSV")
        if not verify(
            self.ack.sighash(self.connector),
            self.connector.n_of_n_pubkey,
            self.ack_signature,
        ):
            raise SplitScalarLockError("invalid exact-message ACK signature")
        if not verify(
            self.nack.sighash(self.connector),
            self.connector.n_of_n_pubkey,
            self.nack_signature,
        ):
            raise SplitScalarLockError("invalid exact-message NACK signature")

    def verify_ack_witness(self, preimages: Sequence[bytes]) -> bool:
        return self.connector.verify_preimages(preimages) and verify(
            self.ack.sighash(self.connector),
            self.connector.n_of_n_pubkey,
            self.ack_signature,
        )

    def verify_timeout_nack(self, *, blocks_elapsed: int) -> bool:
        return blocks_elapsed >= self.connector.relative_delay and verify(
            self.nack.sighash(self.connector),
            self.connector.n_of_n_pubkey,
            self.nack_signature,
        )


def presign_split_scalar_graph(
    connector: SplitScalarHashlockConnector,
    ack: BoundTransaction,
    nack: BoundTransaction,
    *,
    n_of_n_secret: int,
) -> SplitScalarPresignedGraph:
    if public_key(n_of_n_secret) != connector.n_of_n_pubkey:
        raise SplitScalarLockError("N-of-N secret does not match connector key")
    return SplitScalarPresignedGraph(
        connector,
        ack,
        nack,
        sign(ack.sighash(connector), n_of_n_secret),
        sign(nack.sighash(connector), n_of_n_secret),
    )
