from __future__ import annotations

"""Canonical predecessor-only context for one v0.26 participant lock.

This module implements only the fixed-width derivation already specified by
the v0.26 protocol. It does not parse or validate a ``SetupIntentV1`` and must
not be treated as a funding-qualification boundary by itself.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from ranklock.bip340 import BIP340Error, lift_x


PARTICIPANT_LOCK_CONTEXT_DOMAIN: Final = (
    b"ranklock/v026/participant-lock-context\0"
)
_DIGEST_BYTES: Final = 32
_PARTICIPANT_INDEX_BYTES: Final = 2


class ParticipantLockContextError(ValueError):
    pass


def _exact_bytes(value: object, *, size: int, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise ParticipantLockContextError(f"{label} must be immutable bytes")
    if len(value) != size:
        raise ParticipantLockContextError(f"{label} must be exactly {size} bytes")
    return value


@dataclass(frozen=True, slots=True)
class ParticipantLockContextV1:
    """Inputs and digest for a participant-specific positive-lock statement."""

    setup_intent_digest: bytes
    participant_index: int
    participant_pubkey: bytes
    schema: str = "ranklock-v026-participant-lock-context-v1"

    def __post_init__(self) -> None:
        setup_intent_digest = _exact_bytes(
            self.setup_intent_digest,
            size=_DIGEST_BYTES,
            label="setup-intent digest",
        )
        participant_pubkey = _exact_bytes(
            self.participant_pubkey,
            size=_DIGEST_BYTES,
            label="participant public key",
        )
        participant_index = self.participant_index
        if (
            isinstance(participant_index, bool)
            or not isinstance(participant_index, int)
            or not 0 <= participant_index < 2 ** (8 * _PARTICIPANT_INDEX_BYTES)
        ):
            raise ParticipantLockContextError(
                "participant index must be an integer in 0..65535"
            )
        try:
            lift_x(int.from_bytes(participant_pubkey, "big"))
        except BIP340Error as exc:
            raise ParticipantLockContextError(
                "participant public key is not a valid BIP340 x-only key"
            ) from exc
        object.__setattr__(self, "setup_intent_digest", setup_intent_digest)
        object.__setattr__(self, "participant_pubkey", participant_pubkey)

    @property
    def derivation_message(self) -> bytes:
        """Return the exact fixed-width preimage following the domain tag."""

        return (
            self.setup_intent_digest
            + self.participant_index.to_bytes(_PARTICIPANT_INDEX_BYTES, "big")
            + self.participant_pubkey
        )

    @property
    def digest(self) -> bytes:
        """Derive the participant lock context committed by PositiveLock."""

        return sha256(
            PARTICIPANT_LOCK_CONTEXT_DOMAIN + self.derivation_message
        ).digest()
