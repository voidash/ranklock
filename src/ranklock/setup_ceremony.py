from __future__ import annotations

"""Signed commit/reveal entropy ceremony for RankLock setup.

This ceremony removes single-party control over the public setup seed: after all
commitments are fixed, one honest 256-bit contribution makes the combined seed
unpredictable.  A corrupt participant may still abort by withholding its reveal,
and a dealer or MPC backend that receives the combined seed may still learn or
bias private intermediate state.  Accordingly this module is a setup-randomness
hardening layer, **not** the missing active-MPC implementation.

For a funded deployment, aborting a ceremony identifier must be terminal.  A
new attempt must use a new context/deposit identifier so selective abort cannot
be used to repeatedly sample favorable setup seeds.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .bip340 import public_key, sign, verify


_COMMIT_DOMAIN = b"ranklock/setup-entropy-commitment/v1\x00"
_COMMIT_SIGN_DOMAIN = b"ranklock/setup-entropy-commitment-sign/v1\x00"
_REVEAL_DOMAIN = b"ranklock/setup-entropy-reveal/v1\x00"
_REVEAL_SIGN_DOMAIN = b"ranklock/setup-entropy-reveal-sign/v1\x00"
_TRANSCRIPT_DOMAIN = b"ranklock/setup-entropy-transcript/v1\x00"
_SEED_DOMAIN = b"ranklock/setup-combined-seed/v1\x00"
_MAGIC_CONFIG = b"RLSC2501"
_MAGIC_COMMIT = b"RLSM2501"
_MAGIC_REVEAL = b"RLSR2501"
_HASH = 32
_SIG = 64


class SetupCeremonyError(ValueError):
    pass


def _u(value: int, width: int, name: str) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (8 * width):
        raise SetupCeremonyError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "big")


def _h(domain: bytes, *parts: bytes) -> bytes:
    digest = sha256(domain)
    for part in parts:
        digest.update(bytes(part))
    return digest.digest()


@dataclass(frozen=True, slots=True)
class SetupCeremonyConfig:
    context_digest: bytes
    generator_code_hash: bytes
    ceremony_epoch: int
    participant_pubkeys: tuple[bytes, ...]
    schema: str = "ranklock-setup-ceremony-config-v1"

    def __post_init__(self) -> None:
        if len(bytes(self.context_digest)) != _HASH:
            raise SetupCeremonyError("context digest must be 32 bytes")
        if len(bytes(self.generator_code_hash)) != _HASH:
            raise SetupCeremonyError("generator code hash must be 32 bytes")
        if not 0 <= int(self.ceremony_epoch) < 2**64:
            raise SetupCeremonyError("ceremony epoch does not fit u64")
        if len(self.participant_pubkeys) < 2:
            raise SetupCeremonyError("setup ceremony requires at least two participants")
        if any(len(bytes(key)) != _HASH for key in self.participant_pubkeys):
            raise SetupCeremonyError("participant public keys must be 32 bytes")
        if tuple(sorted(self.participant_pubkeys)) != self.participant_pubkeys:
            raise SetupCeremonyError("participant public keys must be sorted canonically")
        if len(set(self.participant_pubkeys)) != len(self.participant_pubkeys):
            raise SetupCeremonyError("participant public keys must be unique")

    @property
    def encoded(self) -> bytes:
        return (
            _MAGIC_CONFIG
            + bytes(self.context_digest)
            + bytes(self.generator_code_hash)
            + _u(self.ceremony_epoch, 8, "ceremony epoch")
            + _u(len(self.participant_pubkeys), 2, "participant count")
            + b"".join(bytes(key) for key in self.participant_pubkeys)
        )

    @property
    def ceremony_id(self) -> bytes:
        return _h(_TRANSCRIPT_DOMAIN, self.encoded)

    @classmethod
    def parse(cls, raw: bytes) -> "SetupCeremonyConfig":
        raw = bytes(raw)
        fixed = 8 + 32 + 32 + 8 + 2
        if len(raw) < fixed or raw[:8] != _MAGIC_CONFIG:
            raise SetupCeremonyError("invalid setup-ceremony config framing")
        count = int.from_bytes(raw[80:82], "big")
        if len(raw) != fixed + count * 32:
            raise SetupCeremonyError("setup-ceremony config length mismatch")
        result = cls(
            raw[8:40],
            raw[40:72],
            int.from_bytes(raw[72:80], "big"),
            tuple(raw[82 + 32 * i : 82 + 32 * (i + 1)] for i in range(count)),
        )
        if result.encoded != raw:
            raise SetupCeremonyError("non-canonical setup-ceremony config")
        return result


@dataclass(frozen=True, slots=True)
class SignedEntropyCommitment:
    ceremony_id: bytes
    participant_index: int
    participant_pubkey: bytes
    commitment: bytes
    signature: bytes
    schema: str = "ranklock-signed-entropy-commitment-v1"

    def __post_init__(self) -> None:
        for value, name in (
            (self.ceremony_id, "ceremony id"),
            (self.participant_pubkey, "participant public key"),
            (self.commitment, "entropy commitment"),
        ):
            if len(bytes(value)) != _HASH:
                raise SetupCeremonyError(f"{name} must be 32 bytes")
        if len(bytes(self.signature)) != _SIG:
            raise SetupCeremonyError("commitment signature must be 64 bytes")
        if not 0 <= int(self.participant_index) < 2**16:
            raise SetupCeremonyError("participant index does not fit u16")

    @property
    def unsigned_bytes(self) -> bytes:
        return (
            _MAGIC_COMMIT
            + bytes(self.ceremony_id)
            + _u(self.participant_index, 2, "participant index")
            + bytes(self.participant_pubkey)
            + bytes(self.commitment)
        )

    @property
    def signing_message(self) -> bytes:
        return _h(_COMMIT_SIGN_DOMAIN, self.unsigned_bytes)

    def verify(self, config: SetupCeremonyConfig) -> bool:
        index = self.participant_index
        return bool(
            self.ceremony_id == config.ceremony_id
            and index < len(config.participant_pubkeys)
            and self.participant_pubkey == config.participant_pubkeys[index]
            and verify(self.signing_message, self.participant_pubkey, self.signature)
        )

    @property
    def encoded(self) -> bytes:
        return self.unsigned_bytes + bytes(self.signature)

    @classmethod
    def create(
        cls,
        config: SetupCeremonyConfig,
        *,
        participant_index: int,
        participant_secret: int,
        entropy: bytes,
        nonce: bytes,
    ) -> "SignedEntropyCommitment":
        index = int(participant_index)
        if len(bytes(entropy)) != _HASH or len(bytes(nonce)) != _HASH:
            raise SetupCeremonyError("entropy and nonce must be 32 bytes")
        if index >= len(config.participant_pubkeys):
            raise SetupCeremonyError("participant index is absent")
        if public_key(participant_secret) != config.participant_pubkeys[index]:
            raise SetupCeremonyError("participant secret does not match ceremony config")
        commitment = _h(
            _COMMIT_DOMAIN,
            config.ceremony_id,
            _u(index, 2, "participant index"),
            bytes(entropy),
            bytes(nonce),
        )
        placeholder = cls(
            config.ceremony_id,
            index,
            config.participant_pubkeys[index],
            commitment,
            bytes(_SIG),
        )
        return cls(
            placeholder.ceremony_id,
            placeholder.participant_index,
            placeholder.participant_pubkey,
            placeholder.commitment,
            sign(placeholder.signing_message, participant_secret),
        )

    @classmethod
    def parse(cls, raw: bytes) -> "SignedEntropyCommitment":
        raw = bytes(raw)
        if len(raw) != 8 + 32 + 2 + 32 + 32 + 64 or raw[:8] != _MAGIC_COMMIT:
            raise SetupCeremonyError("invalid entropy commitment framing")
        result = cls(
            raw[8:40],
            int.from_bytes(raw[40:42], "big"),
            raw[42:74],
            raw[74:106],
            raw[106:170],
        )
        if result.encoded != raw:
            raise SetupCeremonyError("non-canonical entropy commitment")
        return result


@dataclass(frozen=True, slots=True)
class SignedEntropyReveal:
    ceremony_id: bytes
    participant_index: int
    participant_pubkey: bytes
    entropy: bytes
    nonce: bytes
    commitment_digest: bytes
    signature: bytes
    schema: str = "ranklock-signed-entropy-reveal-v1"

    def __post_init__(self) -> None:
        for value, name in (
            (self.ceremony_id, "ceremony id"),
            (self.participant_pubkey, "participant public key"),
            (self.entropy, "entropy"),
            (self.nonce, "nonce"),
            (self.commitment_digest, "commitment digest"),
        ):
            if len(bytes(value)) != _HASH:
                raise SetupCeremonyError(f"{name} must be 32 bytes")
        if len(bytes(self.signature)) != _SIG:
            raise SetupCeremonyError("reveal signature must be 64 bytes")
        if not 0 <= int(self.participant_index) < 2**16:
            raise SetupCeremonyError("participant index does not fit u16")

    @property
    def unsigned_bytes(self) -> bytes:
        return (
            _MAGIC_REVEAL
            + bytes(self.ceremony_id)
            + _u(self.participant_index, 2, "participant index")
            + bytes(self.participant_pubkey)
            + bytes(self.entropy)
            + bytes(self.nonce)
            + bytes(self.commitment_digest)
        )

    @property
    def signing_message(self) -> bytes:
        return _h(_REVEAL_SIGN_DOMAIN, self.unsigned_bytes)

    @property
    def encoded(self) -> bytes:
        return self.unsigned_bytes + bytes(self.signature)

    def verify(
        self,
        config: SetupCeremonyConfig,
        commitment: SignedEntropyCommitment,
    ) -> bool:
        index = self.participant_index
        computed = _h(
            _COMMIT_DOMAIN,
            config.ceremony_id,
            _u(index, 2, "participant index"),
            self.entropy,
            self.nonce,
        )
        return bool(
            commitment.verify(config)
            and self.ceremony_id == config.ceremony_id
            and index == commitment.participant_index
            and self.participant_pubkey == commitment.participant_pubkey
            and self.commitment_digest == commitment.commitment
            and computed == commitment.commitment
            and verify(self.signing_message, self.participant_pubkey, self.signature)
        )

    @classmethod
    def create(
        cls,
        config: SetupCeremonyConfig,
        commitment: SignedEntropyCommitment,
        *,
        participant_secret: int,
        entropy: bytes,
        nonce: bytes,
    ) -> "SignedEntropyReveal":
        if not commitment.verify(config):
            raise SetupCeremonyError("commitment failed verification")
        if public_key(participant_secret) != commitment.participant_pubkey:
            raise SetupCeremonyError("participant secret does not match commitment")
        placeholder = cls(
            config.ceremony_id,
            commitment.participant_index,
            commitment.participant_pubkey,
            bytes(entropy),
            bytes(nonce),
            commitment.commitment,
            bytes(_SIG),
        )
        result = cls(
            placeholder.ceremony_id,
            placeholder.participant_index,
            placeholder.participant_pubkey,
            placeholder.entropy,
            placeholder.nonce,
            placeholder.commitment_digest,
            sign(placeholder.signing_message, participant_secret),
        )
        if not result.verify(config, commitment):
            raise SetupCeremonyError("reveal does not open commitment")
        return result

    @classmethod
    def parse(cls, raw: bytes) -> "SignedEntropyReveal":
        raw = bytes(raw)
        if len(raw) != 8 + 2 + 32 * 5 + 64 or raw[:8] != _MAGIC_REVEAL:
            raise SetupCeremonyError("invalid entropy reveal framing")
        cursor = 8
        ceremony_id = raw[cursor : cursor + 32]; cursor += 32
        participant_index = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        participant_pubkey = raw[cursor : cursor + 32]; cursor += 32
        entropy = raw[cursor : cursor + 32]; cursor += 32
        nonce = raw[cursor : cursor + 32]; cursor += 32
        commitment_digest = raw[cursor : cursor + 32]; cursor += 32
        signature = raw[cursor : cursor + 64]
        result = cls(
            ceremony_id,
            participant_index,
            participant_pubkey,
            entropy,
            nonce,
            commitment_digest,
            signature,
        )
        if result.encoded != raw:
            raise SetupCeremonyError("non-canonical entropy reveal")
        return result



@dataclass(frozen=True, slots=True)
class SetupEntropyTranscript:
    config: SetupCeremonyConfig
    commitments: tuple[SignedEntropyCommitment, ...]
    reveals: tuple[SignedEntropyReveal, ...]
    schema: str = "ranklock-setup-entropy-transcript-v1"

    def __post_init__(self) -> None:
        count = len(self.config.participant_pubkeys)
        if len(self.commitments) != count or len(self.reveals) != count:
            raise SetupCeremonyError("complete N-of-N commitments and reveals are required")
        expected = tuple(range(count))
        if tuple(item.participant_index for item in self.commitments) != expected:
            raise SetupCeremonyError("commitments are not canonical")
        if tuple(item.participant_index for item in self.reveals) != expected:
            raise SetupCeremonyError("reveals are not canonical")
        for commitment, reveal in zip(self.commitments, self.reveals, strict=True):
            if not reveal.verify(self.config, commitment):
                raise SetupCeremonyError("setup entropy transcript failed verification")

    @property
    def transcript_digest(self) -> bytes:
        return _h(
            _TRANSCRIPT_DOMAIN,
            self.config.encoded,
            *(item.encoded for item in self.commitments),
            *(item.encoded for item in self.reveals),
        )

    @property
    def combined_seed(self) -> bytes:
        return _h(
            _SEED_DOMAIN,
            self.transcript_digest,
            *(reveal.entropy for reveal in self.reveals),
        )

    @classmethod
    def assemble(
        cls,
        config: SetupCeremonyConfig,
        commitments: Sequence[SignedEntropyCommitment],
        reveals: Sequence[SignedEntropyReveal],
    ) -> "SetupEntropyTranscript":
        by_commit = {item.participant_index: item for item in commitments}
        by_reveal = {item.participant_index: item for item in reveals}
        count = len(config.participant_pubkeys)
        if len(by_commit) != len(commitments) or len(by_reveal) != len(reveals):
            raise SetupCeremonyError("duplicate setup participant message")
        if set(by_commit) != set(range(count)) or set(by_reveal) != set(range(count)):
            raise SetupCeremonyError("setup transcript is incomplete")
        return cls(
            config,
            tuple(by_commit[index] for index in range(count)),
            tuple(by_reveal[index] for index in range(count)),
        )
