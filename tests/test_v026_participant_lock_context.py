from __future__ import annotations

from hashlib import sha256

import pytest

from ranklock.bip340 import public_key
from ranklock.v026.participant_lock_context import (
    PARTICIPANT_LOCK_CONTEXT_DOMAIN,
    ParticipantLockContextError,
    ParticipantLockContextV1,
)


SETUP_INTENT_DIGEST = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
PARTICIPANT_PUBKEY = public_key(0x123456789ABCDEF)


def test_context_uses_exact_domain_and_big_endian_u16_index() -> None:
    context = ParticipantLockContextV1(
        setup_intent_digest=SETUP_INTENT_DIGEST,
        participant_index=0x1234,
        participant_pubkey=PARTICIPANT_PUBKEY,
    )
    expected_message = SETUP_INTENT_DIGEST + b"\x12\x34" + PARTICIPANT_PUBKEY
    assert PARTICIPANT_LOCK_CONTEXT_DOMAIN == (
        b"ranklock/v026/participant-lock-context\0"
    )
    assert context.derivation_message == expected_message
    assert sha256(PARTICIPANT_LOCK_CONTEXT_DOMAIN + expected_message).digest() == (
        context.digest
    )
    assert context.digest.hex() == (
        "1d9dc305d37f4fbac9b93a529e9b8d4a409295687e41ccf9d7f7868890bef3eb"
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("setup_intent_digest", bytes(reversed(SETUP_INTENT_DIGEST))),
        ("participant_index", 0x1235),
        ("participant_pubkey", public_key(0x123456789ABCDEE)),
    ),
)
def test_every_authoritative_field_changes_the_context(
    field: str,
    replacement: bytes | int,
) -> None:
    values: dict[str, bytes | int] = {
        "setup_intent_digest": SETUP_INTENT_DIGEST,
        "participant_index": 0x1234,
        "participant_pubkey": PARTICIPANT_PUBKEY,
    }
    baseline = ParticipantLockContextV1(**values).digest  # type: ignore[arg-type]
    values[field] = replacement
    assert ParticipantLockContextV1(**values).digest != baseline  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_index", (-1, 65536, True, 1.0, "1"))
def test_invalid_participant_indices_fail_closed(bad_index: object) -> None:
    with pytest.raises(ParticipantLockContextError, match="participant index"):
        ParticipantLockContextV1(
            setup_intent_digest=SETUP_INTENT_DIGEST,
            participant_index=bad_index,  # type: ignore[arg-type]
            participant_pubkey=PARTICIPANT_PUBKEY,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("setup_intent_digest", b"x" * 31, "exactly 32 bytes"),
        ("setup_intent_digest", bytearray(32), "immutable bytes"),
        ("participant_pubkey", b"x" * 33, "exactly 32 bytes"),
        ("participant_pubkey", bytearray(32), "immutable bytes"),
        ("participant_pubkey", bytes(32), "valid BIP340"),
    ),
)
def test_malformed_fixed_fields_and_non_curve_keys_fail_closed(
    field: str,
    value: object,
    message: str,
) -> None:
    values: dict[str, object] = {
        "setup_intent_digest": SETUP_INTENT_DIGEST,
        "participant_index": 0,
        "participant_pubkey": PARTICIPANT_PUBKEY,
    }
    values[field] = value
    with pytest.raises(ParticipantLockContextError, match=message):
        ParticipantLockContextV1(**values)  # type: ignore[arg-type]
