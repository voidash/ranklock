from __future__ import annotations

"""Bounded-query Embryo construction with an active-MPC activation ceremony.

This module captures a construction-level route around the v0.19 malicious-generator
cut-and-choose wall:

* bounded reuse is implemented with independent one-shot Embryo slots, never by
  reusing one affine encoding;
* an actively secure, dishonest-majority MPC ceremony jointly samples the hidden
  scalar and every slot's random tape, computes the canonical artifacts, and releases
  them only together with an all-participant signature certificate;
* after activation, no ceremony participant remains online;
* every attempted evaluation burns exactly one slot, and the real BN254 pairing
  certificate rejects a wrong ``[r]A`` output.

The serializer, signature certificate, cost arithmetic, replay ledger and pairing
checks are executable.  The repository still does not contain the exact Duty-Free
Bits/Embryo generator or a concrete active-MPC execution of its roughly 5.8 million
hash calls per slot.  The security theorem is therefore conditional on those two
components and on an authenticated adaptively selected one-shot input-label compiler.
"""

from dataclasses import dataclass, field, replace
from hashlib import sha256
from math import ceil
from typing import Iterable, Mapping

from .babe_positive_lock import (
    PositiveGroth16Proof,
    PositiveGroth16VerifyingKey,
    PositiveLock,
    certify_projective_output,
)
from .bip340 import public_key, sign, verify


MIB = 1 << 20
MANIFEST_MAGIC = b"RLBE21\x00\x00"
MANIFEST_VERSION = 1
MANIFEST_FLAGS = 0
SLOT_DESCRIPTOR_BYTES = 4 + 8 + 32 + 32 + 32
CONTRIBUTOR_RECORD_BYTES = 32 + 64
MANIFEST_CHECKSUM_BYTES = 32


class BoundedEmbryoError(ValueError):
    pass


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = sha256(domain)
    for part in parts:
        h.update(bytes(part))
    return h.digest()


@dataclass(frozen=True, slots=True)
class EmbryoPaperCost:
    """Exact byte arithmetic reconstructed from Duty-Free Bits Appendix C.

    Communication terms are converted from bits with ceiling division.  The label
    hash count is the paper's conservative bound using nine output bits per CRT
    prime.  This is a paper-derived cost model, not a serialized implementation.
    """

    security_bits: int = 128
    coordinate_bits: int = 256
    chunk_count: int = 32
    chunk_join_width: int = 29
    chunk_hashes_each: int = 5_886
    residue_count: int = 80
    residue_join_width: int = 99
    residue_subchunk_hashes_each: int = 11_770
    prime_sum: int = 14_697
    residue_fold_count: int = 14
    crt_bit_length: int = 593
    it_dimension: int = 12
    scalar_maps: int = 256
    conservative_prime_bits: int = 9
    curve_check_elements: int = 5
    schema: str = "ranklock-embryo-paper-cost-v1"

    def __post_init__(self) -> None:
        if self.security_bits <= 0 or self.coordinate_bits <= 0:
            raise BoundedEmbryoError("invalid Embryo security/coordinate size")

    @staticmethod
    def _bytes(bits: int) -> int:
        return ceil(bits / 8)

    @property
    def chunk_conversion_bytes_per_coordinate(self) -> int:
        return self._bytes(self.chunk_count * self.chunk_join_width * self.security_bits)

    @property
    def chunk_conversion_hashes_per_coordinate(self) -> int:
        return self.chunk_count * self.chunk_hashes_each

    @property
    def residue_evaluation_bytes_per_coordinate(self) -> int:
        return self._bytes(self.residue_count * self.residue_join_width * self.security_bits)

    @property
    def residue_evaluation_hashes_per_coordinate(self) -> int:
        return (
            self.residue_count * self.residue_subchunk_hashes_each
            + self.residue_fold_count * self.prime_sum
        )

    @property
    def it_label_bytes(self) -> int:
        return self._bytes(self.scalar_maps * self.crt_bit_length * self.it_dimension)

    @property
    def it_label_hashes(self) -> int:
        output_bits = self.it_dimension * self.scalar_maps * self.conservative_prime_bits
        hashes_per_switch = ceil(output_bits / self.security_bits)
        return self.prime_sum * hashes_per_switch

    @property
    def curve_check_bytes(self) -> int:
        return self._bytes(self.crt_bit_length * self.curve_check_elements)

    @property
    def artifact_bytes(self) -> int:
        return (
            2 * self.chunk_conversion_bytes_per_coordinate
            + 2 * self.residue_evaluation_bytes_per_coordinate
            + self.it_label_bytes
            + self.curve_check_bytes
        )

    @property
    def hash_calls(self) -> int:
        return (
            2 * self.chunk_conversion_hashes_per_coordinate
            + 2 * self.residue_evaluation_hashes_per_coordinate
            + self.it_label_hashes
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "chunk_conversion_bytes_per_coordinate": self.chunk_conversion_bytes_per_coordinate,
            "chunk_conversion_hashes_per_coordinate": self.chunk_conversion_hashes_per_coordinate,
            "residue_evaluation_bytes_per_coordinate": self.residue_evaluation_bytes_per_coordinate,
            "residue_evaluation_hashes_per_coordinate": self.residue_evaluation_hashes_per_coordinate,
            "it_label_bytes": self.it_label_bytes,
            "it_label_hashes": self.it_label_hashes,
            "curve_check_bytes": self.curve_check_bytes,
            "artifact_bytes": self.artifact_bytes,
            "hash_calls": self.hash_calls,
            "evidence_class": "paper-derived exact arithmetic; no local DFB serializer",
        }


@dataclass(frozen=True, slots=True)
class ActiveMpcProfile:
    parties: int
    security_bits: int = 128
    protocol_family: bytes = b"dishonest-majority-active-MPC-with-abort"
    all_signatures_required: bool = True
    max_corruptions: int | None = None
    schema: str = "ranklock-active-mpc-profile-v1"

    def __post_init__(self) -> None:
        if self.parties < 2 or self.parties >= 2**16:
            raise BoundedEmbryoError("active-MPC party count must be in 2..65535")
        maximum = self.parties - 1 if self.max_corruptions is None else self.max_corruptions
        if maximum != self.parties - 1:
            raise BoundedEmbryoError("this profile requires security against n-1 corruptions")
        if self.security_bits < 40 or self.security_bits >= 2**16:
            raise BoundedEmbryoError("active-MPC security parameter is outside research bounds")
        if not self.protocol_family:
            raise BoundedEmbryoError("active-MPC protocol family is empty")
        if not self.all_signatures_required:
            raise BoundedEmbryoError("activation must require every registered signature")
        object.__setattr__(self, "max_corruptions", maximum)

    @property
    def digest(self) -> bytes:
        return _sha(
            b"ranklock/active-mpc-profile/v1\x00",
            self.parties.to_bytes(2, "big"),
            int(self.max_corruptions).to_bytes(2, "big"),
            self.security_bits.to_bytes(2, "big"),
            len(self.protocol_family).to_bytes(2, "big"),
            self.protocol_family,
            b"\x01",
        )


@dataclass(frozen=True, slots=True)
class EmbryoSlotDescriptor:
    slot_id: int
    artifact_length: int
    artifact_root: bytes
    input_label_root: bytes
    independence_digest: bytes
    schema: str = "ranklock-embryo-slot-v1"

    def __post_init__(self) -> None:
        if not 0 <= self.slot_id < 2**32:
            raise BoundedEmbryoError("slot id must be a u32")
        if not 0 < self.artifact_length < 2**64:
            raise BoundedEmbryoError("slot artifact length must be a positive u64")
        for name in ("artifact_root", "input_label_root", "independence_digest"):
            if len(getattr(self, name)) != 32:
                raise BoundedEmbryoError(f"{name} must be 32 bytes")

    def encode(self) -> bytes:
        encoded = (
            self.slot_id.to_bytes(4, "big")
            + self.artifact_length.to_bytes(8, "big")
            + self.artifact_root
            + self.input_label_root
            + self.independence_digest
        )
        if len(encoded) != SLOT_DESCRIPTOR_BYTES:  # pragma: no cover
            raise AssertionError("slot descriptor width drift")
        return encoded

    @classmethod
    def parse(cls, raw: bytes) -> "EmbryoSlotDescriptor":
        raw = bytes(raw)
        if len(raw) != SLOT_DESCRIPTOR_BYTES:
            raise BoundedEmbryoError("slot descriptor has wrong length")
        return cls(
            slot_id=int.from_bytes(raw[:4], "big"),
            artifact_length=int.from_bytes(raw[4:12], "big"),
            artifact_root=raw[12:44],
            input_label_root=raw[44:76],
            independence_digest=raw[76:108],
        )


def encode_positive_lock(lock: PositiveLock) -> bytes:
    return (
        lock.vk_digest
        + lock.statement_digest
        + lock.r_delta_g2
        + len(lock.masked_payload).to_bytes(4, "big")
        + lock.masked_payload
        + lock.payload_hash
    )


def decode_positive_lock(raw: bytes, *, offset: int = 0) -> tuple[PositiveLock, int]:
    raw = bytes(raw)
    fixed = 32 + 32 + 64 + 4
    if offset < 0 or offset + fixed > len(raw):
        raise BoundedEmbryoError("truncated positive lock")
    vk_digest = raw[offset : offset + 32]
    statement_digest = raw[offset + 32 : offset + 64]
    r_delta = raw[offset + 64 : offset + 128]
    payload_length = int.from_bytes(raw[offset + 128 : offset + 132], "big")
    end = offset + fixed + payload_length + 32
    if payload_length == 0 or end > len(raw):
        raise BoundedEmbryoError("invalid positive-lock payload length")
    lock = PositiveLock(
        vk_digest=vk_digest,
        statement_digest=statement_digest,
        r_delta_g2=r_delta,
        masked_payload=raw[offset + fixed : offset + fixed + payload_length],
        payload_hash=raw[offset + fixed + payload_length : end],
    )
    return lock, end


@dataclass(frozen=True, slots=True)
class UnsignedBoundedEmbryoManifest:
    context_digest: bytes
    generator_code_hash: bytes
    transcript_digest: bytes
    positive_lock: PositiveLock
    slots: tuple[EmbryoSlotDescriptor, ...]
    contributor_pubkeys: tuple[bytes, ...]
    schema: str = "ranklock-bounded-embryo-manifest-body-v1"

    def __post_init__(self) -> None:
        for name in ("context_digest", "generator_code_hash", "transcript_digest"):
            if len(getattr(self, name)) != 32:
                raise BoundedEmbryoError(f"{name} must be 32 bytes")
        if not 1 <= len(self.slots) < 2**16:
            raise BoundedEmbryoError("slot count must fit a nonzero u16")
        if not 2 <= len(self.contributor_pubkeys) < 2**16:
            raise BoundedEmbryoError("contributor count must be in 2..65535")
        expected_ids = tuple(range(len(self.slots)))
        if tuple(slot.slot_id for slot in self.slots) != expected_ids:
            raise BoundedEmbryoError("slot ids must be canonical consecutive integers")
        if len({slot.artifact_root for slot in self.slots}) != len(self.slots):
            raise BoundedEmbryoError("slot artifact roots are not independent")
        if len({slot.input_label_root for slot in self.slots}) != len(self.slots):
            raise BoundedEmbryoError("slot input-label roots are not independent")
        if len({slot.independence_digest for slot in self.slots}) != len(self.slots):
            raise BoundedEmbryoError("slot independence digests are not unique")
        if any(len(key) != 32 for key in self.contributor_pubkeys):
            raise BoundedEmbryoError("contributor public keys must be 32 bytes")
        if tuple(sorted(self.contributor_pubkeys)) != self.contributor_pubkeys:
            raise BoundedEmbryoError("contributor public keys must be lexicographically canonical")
        if len(set(self.contributor_pubkeys)) != len(self.contributor_pubkeys):
            raise BoundedEmbryoError("duplicate contributor public key")

    @property
    def slot_count(self) -> int:
        return len(self.slots)

    @property
    def contributor_count(self) -> int:
        return len(self.contributor_pubkeys)

    @property
    def body_bytes(self) -> bytes:
        header = (
            MANIFEST_MAGIC
            + MANIFEST_VERSION.to_bytes(2, "big")
            + MANIFEST_FLAGS.to_bytes(2, "big")
            + self.slot_count.to_bytes(2, "big")
            + self.contributor_count.to_bytes(2, "big")
        )
        return (
            header
            + self.context_digest
            + self.generator_code_hash
            + self.transcript_digest
            + encode_positive_lock(self.positive_lock)
            + b"".join(slot.encode() for slot in self.slots)
            + b"".join(self.contributor_pubkeys)
        )

    @property
    def signing_digest(self) -> bytes:
        return _sha(b"ranklock/bounded-embryo-manifest-sign/v1\x00", self.body_bytes)

    @classmethod
    def parse_body(cls, raw: bytes) -> tuple["UnsignedBoundedEmbryoManifest", int]:
        raw = bytes(raw)
        header_bytes = len(MANIFEST_MAGIC) + 8
        if len(raw) < header_bytes + 96:
            raise BoundedEmbryoError("truncated bounded-Embryo manifest")
        if raw[: len(MANIFEST_MAGIC)] != MANIFEST_MAGIC:
            raise BoundedEmbryoError("bounded-Embryo manifest magic mismatch")
        offset = len(MANIFEST_MAGIC)
        version = int.from_bytes(raw[offset : offset + 2], "big")
        flags = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        slot_count = int.from_bytes(raw[offset + 4 : offset + 6], "big")
        contributor_count = int.from_bytes(raw[offset + 6 : offset + 8], "big")
        offset += 8
        if version != MANIFEST_VERSION or flags != MANIFEST_FLAGS:
            raise BoundedEmbryoError("unsupported bounded-Embryo manifest version/flags")
        if slot_count == 0 or contributor_count < 2:
            raise BoundedEmbryoError("invalid bounded-Embryo manifest cardinality")
        context = raw[offset : offset + 32]
        generator = raw[offset + 32 : offset + 64]
        transcript = raw[offset + 64 : offset + 96]
        offset += 96
        lock, offset = decode_positive_lock(raw, offset=offset)
        slots: list[EmbryoSlotDescriptor] = []
        for _ in range(slot_count):
            end = offset + SLOT_DESCRIPTOR_BYTES
            if end > len(raw):
                raise BoundedEmbryoError("truncated slot descriptor list")
            slots.append(EmbryoSlotDescriptor.parse(raw[offset:end]))
            offset = end
        pubkey_end = offset + contributor_count * 32
        if pubkey_end > len(raw):
            raise BoundedEmbryoError("truncated contributor-key list")
        pubkeys = tuple(raw[index : index + 32] for index in range(offset, pubkey_end, 32))
        offset = pubkey_end
        return (
            cls(
                context_digest=context,
                generator_code_hash=generator,
                transcript_digest=transcript,
                positive_lock=lock,
                slots=tuple(slots),
                contributor_pubkeys=pubkeys,
            ),
            offset,
        )


@dataclass(frozen=True, slots=True)
class SignedBoundedEmbryoManifest:
    unsigned: UnsignedBoundedEmbryoManifest
    contributor_signatures: tuple[bytes, ...]
    checksum: bytes
    schema: str = "ranklock-bounded-embryo-manifest-v1"

    def __post_init__(self) -> None:
        if len(self.contributor_signatures) != self.unsigned.contributor_count:
            raise BoundedEmbryoError("contributor signature count mismatch")
        if any(len(signature) != 64 for signature in self.contributor_signatures):
            raise BoundedEmbryoError("contributor signatures must be 64 bytes")
        if len(self.checksum) != MANIFEST_CHECKSUM_BYTES:
            raise BoundedEmbryoError("manifest checksum must be 32 bytes")

    @property
    def signatures_bytes(self) -> bytes:
        return b"".join(self.contributor_signatures)

    @property
    def expected_checksum(self) -> bytes:
        return _sha(
            b"ranklock/bounded-embryo-manifest-checksum/v1\x00",
            self.unsigned.body_bytes,
            self.signatures_bytes,
        )

    @property
    def encoded(self) -> bytes:
        return self.unsigned.body_bytes + self.signatures_bytes + self.checksum

    @property
    def encoded_bytes(self) -> int:
        return len(self.encoded)

    @property
    def retained_bytes(self) -> int:
        return self.encoded_bytes + sum(slot.artifact_length for slot in self.unsigned.slots)

    @property
    def margin_to_one_mib(self) -> int:
        return MIB - self.retained_bytes

    def verify(
        self,
        *,
        required_pubkeys: Iterable[bytes],
        expected_context_digest: bytes | None = None,
        expected_generator_code_hash: bytes | None = None,
    ) -> bool:
        required = tuple(sorted(bytes(key) for key in required_pubkeys))
        if required != self.unsigned.contributor_pubkeys:
            return False
        if expected_context_digest is not None and self.unsigned.context_digest != bytes(
            expected_context_digest
        ):
            return False
        if expected_generator_code_hash is not None and self.unsigned.generator_code_hash != bytes(
            expected_generator_code_hash
        ):
            return False
        if self.checksum != self.expected_checksum:
            return False
        digest = self.unsigned.signing_digest
        return all(
            verify(digest, public, signature)
            for public, signature in zip(
                self.unsigned.contributor_pubkeys,
                self.contributor_signatures,
                strict=True,
            )
        )

    @classmethod
    def parse(cls, raw: bytes) -> "SignedBoundedEmbryoManifest":
        raw = bytes(raw)
        unsigned, offset = UnsignedBoundedEmbryoManifest.parse_body(raw)
        signature_end = offset + unsigned.contributor_count * 64
        checksum_end = signature_end + MANIFEST_CHECKSUM_BYTES
        if checksum_end != len(raw):
            raise BoundedEmbryoError("manifest has trailing or truncated signature bytes")
        signatures = tuple(
            raw[index : index + 64] for index in range(offset, signature_end, 64)
        )
        return cls(unsigned, signatures, raw[signature_end:checksum_end])


def assemble_signed_manifest(
    unsigned: UnsignedBoundedEmbryoManifest,
    signatures_by_pubkey: Mapping[bytes, bytes],
) -> SignedBoundedEmbryoManifest:
    canonical = {bytes(key): bytes(value) for key, value in signatures_by_pubkey.items()}
    if set(canonical) != set(unsigned.contributor_pubkeys):
        raise BoundedEmbryoError("activation requires exactly all registered contributors")
    signatures = tuple(canonical[key] for key in unsigned.contributor_pubkeys)
    provisional = SignedBoundedEmbryoManifest(unsigned, signatures, bytes(32))
    return replace(provisional, checksum=provisional.expected_checksum)


def sign_manifest_fixture(
    unsigned: UnsignedBoundedEmbryoManifest,
    contributor_secrets: Iterable[int],
) -> SignedBoundedEmbryoManifest:
    """Sign a ceremony output in tests; this is not an MPC protocol implementation."""

    secrets = tuple(int(secret) for secret in contributor_secrets)
    key_to_secret = {public_key(secret): secret for secret in secrets}
    if set(key_to_secret) != set(unsigned.contributor_pubkeys):
        raise BoundedEmbryoError("fixture secrets do not match registered contributors")
    return assemble_signed_manifest(
        unsigned,
        {
            key: sign(unsigned.signing_digest, key_to_secret[key])
            for key in unsigned.contributor_pubkeys
        },
    )


def active_mpc_generator_code_hash(profile: ActiveMpcProfile) -> bytes:
    return _sha(
        b"ranklock/bounded-mpc-embryo-generator/v1\x00",
        profile.digest,
        b"Duty-Free-Bits/Embryo/exact-generator-required",
        b"independent-random-tape-per-slot",
        b"all-participant-output-signatures",
    )


def slot_descriptor_from_artifact(
    slot_id: int,
    artifact: bytes,
    *,
    input_label_commitment: bytes,
    independence_nonce: bytes,
) -> EmbryoSlotDescriptor:
    artifact = bytes(artifact)
    if not artifact:
        raise BoundedEmbryoError("slot artifact is empty")
    if len(input_label_commitment) != 32 or len(independence_nonce) < 16:
        raise BoundedEmbryoError("slot commitment/independence nonce length mismatch")
    return EmbryoSlotDescriptor(
        slot_id=slot_id,
        artifact_length=len(artifact),
        artifact_root=_sha(
            b"ranklock/bounded-embryo-artifact-root/v1\x00",
            slot_id.to_bytes(4, "big"),
            artifact,
        ),
        input_label_root=bytes(input_label_commitment),
        independence_digest=_sha(
            b"ranklock/bounded-embryo-independence/v1\x00",
            slot_id.to_bytes(4, "big"),
            independence_nonce,
        ),
    )


@dataclass(frozen=True, slots=True)
class SlotUse:
    slot_id: int
    context_digest: bytes
    input_digest: bytes
    authorization_digest: bytes
    outcome: str
    schema: str = "ranklock-bounded-embryo-slot-use-v1"


@dataclass(slots=True)
class BoundedSlotLedger:
    context_digest: bytes
    slot_count: int
    _uses: dict[int, SlotUse] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self.context_digest = bytes(self.context_digest)
        if len(self.context_digest) != 32 or not 1 <= self.slot_count < 2**16:
            raise BoundedEmbryoError("invalid slot ledger context/count")

    def begin(
        self,
        slot_id: int,
        *,
        context_digest: bytes,
        input_digest: bytes,
        authorization_digest: bytes,
    ) -> SlotUse:
        if not 0 <= slot_id < self.slot_count:
            raise BoundedEmbryoError("slot id is outside the activated range")
        if slot_id in self._uses:
            raise BoundedEmbryoError("slot is already consumed")
        if bytes(context_digest) != self.context_digest:
            raise BoundedEmbryoError("slot attempt is bound to another context")
        if len(input_digest) != 32 or len(authorization_digest) != 32:
            raise BoundedEmbryoError("slot input/authorization digests must be 32 bytes")
        use = SlotUse(
            slot_id=slot_id,
            context_digest=self.context_digest,
            input_digest=bytes(input_digest),
            authorization_digest=bytes(authorization_digest),
            outcome="started-burned",
        )
        # Burn before evaluation: a crash, malformed result, abort, timeout or retry
        # can never reopen the affine/projective state.
        self._uses[slot_id] = use
        return use

    def finalize(self, slot_id: int, *, outcome: str) -> SlotUse:
        if slot_id not in self._uses:
            raise BoundedEmbryoError("slot was not started")
        allowed = {"success", "malformed", "abort", "timeout", "retry-rejected"}
        if outcome not in allowed:
            raise BoundedEmbryoError("unknown slot outcome")
        finalized = replace(self._uses[slot_id], outcome=outcome)
        self._uses[slot_id] = finalized
        return finalized

    def use(self, slot_id: int) -> SlotUse | None:
        return self._uses.get(slot_id)

    @property
    def remaining(self) -> int:
        return self.slot_count - len(self._uses)


def execute_certified_slot(
    *,
    manifest: SignedBoundedEmbryoManifest,
    required_pubkeys: Iterable[bytes],
    ledger: BoundedSlotLedger,
    slot_id: int,
    input_digest: bytes,
    authorization_digest: bytes,
    vk: PositiveGroth16VerifyingKey,
    proof: PositiveGroth16Proof,
    output_r_a_g1: bytes,
) -> SlotUse:
    if not manifest.verify(
        required_pubkeys=required_pubkeys,
        expected_context_digest=ledger.context_digest,
    ):
        raise BoundedEmbryoError("activation manifest failed verification")
    ledger.begin(
        slot_id,
        context_digest=manifest.unsigned.context_digest,
        input_digest=input_digest,
        authorization_digest=authorization_digest,
    )
    if not certify_projective_output(
        vk,
        proof,
        manifest.unsigned.positive_lock,
        bytes(output_r_a_g1),
    ):
        ledger.finalize(slot_id, outcome="malformed")
        raise BoundedEmbryoError("projective output failed the public pairing certificate")
    return ledger.finalize(slot_id, outcome="success")


def recover_affine_state_from_two_queries(
    value_1: int,
    label_1: int,
    value_2: int,
    label_2: int,
    *,
    modulus: int,
) -> tuple[int, int]:
    """Recover ``(a,b)`` from two labels ``label=a+b*value``.

    This executable attack is why one projective affine state cannot service two
    evaluator choices.  Bounded evaluation must allocate independent slots.
    """

    modulus = int(modulus)
    if modulus <= 2:
        raise BoundedEmbryoError("affine-state modulus is invalid")
    v1, v2 = int(value_1) % modulus, int(value_2) % modulus
    if v1 == v2:
        raise BoundedEmbryoError("two distinct affine queries are required")
    t1, t2 = int(label_1) % modulus, int(label_2) % modulus
    b = ((t2 - t1) * pow((v2 - v1) % modulus, -1, modulus)) % modulus
    a = (t1 - b * v1) % modulus
    return a, b


def bounded_embryo_checkpoint(
    *,
    manifest_bytes_for_two_slots_two_contributors: int | None = None,
) -> dict[str, object]:
    cost = EmbryoPaperCost()
    # A 32-byte positive-lock payload gives a 196-byte PositiveLock.  For q=2,
    # n=2 the canonical manifest is exactly 748 bytes in this module.
    default_manifest = 748
    manifest_bytes = (
        default_manifest
        if manifest_bytes_for_two_slots_two_contributors is None
        else manifest_bytes_for_two_slots_two_contributors
    )
    q2 = 2 * cost.artifact_bytes + manifest_bytes
    q3_lower_bound = 3 * cost.artifact_bytes
    return {
        "schema": "ranklock-bounded-mpc-embryo-checkpoint-v1",
        "paper_cost": cost.document(),
        "bounded_query_construction": "q independent one-shot Embryo slots under one hidden scalar",
        "malicious_setup_route": "n-party active dishonest-majority MPC with abort; activate only after all registered signatures",
        "one_honest_party_required": True,
        "online_authority_after_activation": False,
        "wrong_runtime_output_publicly_detected": True,
        "slot_replay_or_retry_rejected": True,
        "q2_manifest_bytes": manifest_bytes,
        "q2_total_retained_bytes": q2,
        "q2_margin_to_one_mib": MIB - q2,
        "q2_hash_calls": 2 * cost.hash_calls,
        "q3_artifacts_only_bytes": q3_lower_bound,
        "q3_cannot_fit_one_mib_even_before_manifest": q3_lower_bound > MIB,
        "construction_target_met_under_assumptions": True,
        "breakthrough_target_met": False,
        "missing_for_unconditional_implementation_claim": [
            "exact serialized Duty-Free-Bits/Embryo generator and artifacts",
            "concrete active-MPC execution/benchmark of the generator",
            "adaptive authenticated one-shot label-release theorem/implementation",
            "full BABE and validity-first transaction-graph byte accounting",
            "end-to-end formal proof and Bitcoin Core regtest integration",
        ],
        "decision": "CONSTRUCTION_LEVEL_BREAKTHROUGH_CANDIDATE_NOT_IMPLEMENTATION_COMPLETE",
    }
