from dataclasses import replace

import pytest

from ranklock.co_ot import (
    OFFER_BYTES,
    REQUEST_BYTES,
    RESPONSE_BYTES,
    OtError,
    OtOffer,
    OtReceiver,
    OtRequest,
    OtResponse,
    OtSender,
    run_ot,
    transcript_cost,
)
from ranklock.real_secp import DeterministicScalars


def test_both_choices_and_wire_encodings() -> None:
    messages = (bytes.fromhex("11" * 32), bytes.fromhex("22" * 32))
    for choice in (0, 1):
        assert run_ot(*messages, choice, index=choice, seed=bytes([choice])) == messages[choice]
    cost = transcript_cost(1056)
    assert cost.offers == 39_072
    assert cost.requests == 39_072
    assert cost.responses == 105_600
    assert OFFER_BYTES == REQUEST_BYTES == 37 and RESPONSE_BYTES == 100


def test_serialization_roundtrip_and_ciphertext_tampering() -> None:
    session = bytes.fromhex("33" * 32)
    sender = OtSender(
        session_id=session,
        index=7,
        message0=bytes(32),
        message1=bytes.fromhex("ff" * 32),
        scalar_source=DeterministicScalars(b"s"),
    )
    offer = OtOffer.parse(sender.offer.encode())
    receiver = OtReceiver(
        session_id=session,
        offer=offer,
        choice=1,
        scalar_source=DeterministicScalars(b"r"),
    )
    request = OtRequest.parse(receiver.request.encode())
    response = OtResponse.parse(sender.respond(request).encode())
    corrupted = bytearray(response.ciphertext1)
    corrupted[-1] ^= 1
    with pytest.raises(OtError, match="authentication"):
        receiver.finalize(replace(response, ciphertext1=bytes(corrupted)))


def test_sender_and_receiver_states_are_one_shot() -> None:
    session = bytes.fromhex("44" * 32)
    sender = OtSender(
        session_id=session,
        index=9,
        message0=bytes(32),
        message1=bytes.fromhex("01" * 32),
        scalar_source=DeterministicScalars(b"s2"),
    )
    receiver = OtReceiver(
        session_id=session,
        offer=sender.offer,
        choice=0,
        scalar_source=DeterministicScalars(b"r2"),
    )
    response = sender.respond(receiver.request)
    with pytest.raises(OtError, match="consumed"):
        sender.respond(receiver.request)
    assert receiver.finalize(response) == bytes(32)
    with pytest.raises(OtError, match="consumed"):
        receiver.finalize(response)


def test_session_and_index_substitution_fail_closed() -> None:
    session = bytes.fromhex("55" * 32)
    sender = OtSender(
        session_id=session,
        index=10,
        message0=bytes(32),
        message1=bytes.fromhex("02" * 32),
        scalar_source=DeterministicScalars(b"s3"),
    )
    receiver = OtReceiver(
        session_id=bytes.fromhex("56" * 32),
        offer=sender.offer,
        choice=1,
        scalar_source=DeterministicScalars(b"r3"),
    )
    response = sender.respond(receiver.request)
    with pytest.raises(OtError, match="authentication"):
        receiver.finalize(response)
