from __future__ import annotations

"""Executable Chou--Orlandi-style binary OT measurement backend.

This module removes the ideal-OT oracle from the projective-input experiment.  It
is intentionally a *measurement baseline*, not RankLock's final malicious OT:
known proof subtleties around Simplest OT mean the final theorem must instantiate
the malicious-receiver-secure OT/VOLE construction required by Duty-Free Bits.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .real_secp import (
    N,
    DeterministicScalars,
    Point,
    SecpError,
    add,
    base_multiply,
    compress,
    decompress,
    ecdh_x,
    negate,
)

MESSAGE_BYTES = 32
OFFER_BYTES = 4 + 33
REQUEST_BYTES = 4 + 33
RESPONSE_BYTES = 4 + 2 * (MESSAGE_BYTES + 16)


class OtError(RuntimeError):
    pass


def _kdf(shared_x: bytes, *, session_id: bytes, index: int, branch: int) -> tuple[bytes, bytes, bytes]:
    if len(session_id) != 32 or branch not in (0, 1):
        raise OtError("invalid OT KDF context")
    context = (
        b"ranklock/co-ot/kdf/v1\x00"
        + session_id
        + int(index).to_bytes(4, "big")
        + bytes([branch])
    )
    key = sha256(context + b"key\x00" + shared_x).digest()
    nonce = sha256(context + b"nonce\x00" + shared_x).digest()[:12]
    aad = context + b"aad"
    return key, nonce, aad


@dataclass(frozen=True, slots=True)
class OtOffer:
    index: int
    sender_point: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.index < 2**32:
            raise OtError("OT index must fit u32")
        decompress(self.sender_point)

    def encode(self) -> bytes:
        return self.index.to_bytes(4, "big") + self.sender_point

    @classmethod
    def parse(cls, raw: bytes) -> "OtOffer":
        raw = bytes(raw)
        if len(raw) != OFFER_BYTES:
            raise OtError("malformed OT offer")
        return cls(int.from_bytes(raw[:4], "big"), raw[4:])


@dataclass(frozen=True, slots=True)
class OtRequest:
    index: int
    receiver_point: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.index < 2**32:
            raise OtError("OT index must fit u32")
        decompress(self.receiver_point)

    def encode(self) -> bytes:
        return self.index.to_bytes(4, "big") + self.receiver_point

    @classmethod
    def parse(cls, raw: bytes) -> "OtRequest":
        raw = bytes(raw)
        if len(raw) != REQUEST_BYTES:
            raise OtError("malformed OT request")
        return cls(int.from_bytes(raw[:4], "big"), raw[4:])


@dataclass(frozen=True, slots=True)
class OtResponse:
    index: int
    ciphertext0: bytes
    ciphertext1: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.index < 2**32:
            raise OtError("OT index must fit u32")
        if len(self.ciphertext0) != MESSAGE_BYTES + 16 or len(self.ciphertext1) != MESSAGE_BYTES + 16:
            raise OtError("OT ciphertext length differs")

    def encode(self) -> bytes:
        return self.index.to_bytes(4, "big") + self.ciphertext0 + self.ciphertext1

    @classmethod
    def parse(cls, raw: bytes) -> "OtResponse":
        raw = bytes(raw)
        if len(raw) != RESPONSE_BYTES:
            raise OtError("malformed OT response")
        return cls(int.from_bytes(raw[:4], "big"), raw[4:52], raw[52:])


class OtSender:
    def __init__(
        self,
        *,
        session_id: bytes,
        index: int,
        message0: bytes,
        message1: bytes,
        scalar_source: Callable[[], int],
    ) -> None:
        self.session_id = bytes(session_id)
        if len(self.session_id) != 32:
            raise OtError("OT session id must be 32 bytes")
        self.index = int(index)
        self.messages = (bytes(message0), bytes(message1))
        if any(len(message) != MESSAGE_BYTES for message in self.messages):
            raise OtError("OT messages must be 32 bytes")
        self.secret = int(scalar_source()) % N
        if self.secret == 0:
            raise OtError("sender scalar is zero")
        self.offer = OtOffer(self.index, compress(base_multiply(self.secret)))
        self.consumed = False

    def respond(self, request: OtRequest) -> OtResponse:
        if self.consumed:
            raise OtError("OT sender state already consumed")
        if request.index != self.index:
            raise OtError("OT request index mismatch")
        sender_point = decompress(self.offer.sender_point)
        receiver_point = decompress(request.receiver_point)
        second_base = add(receiver_point, negate(sender_point))
        if second_base is None:
            raise OtError("degenerate OT receiver point")
        shared = (
            ecdh_x(self.secret, receiver_point),
            ecdh_x(self.secret, second_base),
        )
        ciphertexts: list[bytes] = []
        for branch in (0, 1):
            key, nonce, aad = _kdf(
                shared[branch], session_id=self.session_id, index=self.index, branch=branch
            )
            ciphertexts.append(
                ChaCha20Poly1305(key).encrypt(nonce, self.messages[branch], aad)
            )
        self.consumed = True
        return OtResponse(self.index, ciphertexts[0], ciphertexts[1])


class OtReceiver:
    def __init__(
        self,
        *,
        session_id: bytes,
        offer: OtOffer,
        choice: int,
        scalar_source: Callable[[], int],
    ) -> None:
        self.session_id = bytes(session_id)
        if len(self.session_id) != 32:
            raise OtError("OT session id must be 32 bytes")
        if choice not in (0, 1):
            raise OtError("OT choice must be one bit")
        self.offer = offer
        self.choice = int(choice)
        self.secret = int(scalar_source()) % N
        if self.secret == 0:
            raise OtError("receiver scalar is zero")
        sender_point = decompress(offer.sender_point)
        own = base_multiply(self.secret)
        request_point = own if choice == 0 else add(sender_point, own)
        if request_point is None:  # negligible, but fail closed
            raise OtError("degenerate OT request")
        self.request = OtRequest(offer.index, compress(request_point))
        self.consumed = False

    def finalize(self, response: OtResponse) -> bytes:
        if self.consumed:
            raise OtError("OT receiver state already consumed")
        if response.index != self.offer.index:
            raise OtError("OT response index mismatch")
        shared = ecdh_x(self.secret, decompress(self.offer.sender_point))
        key, nonce, aad = _kdf(
            shared,
            session_id=self.session_id,
            index=self.offer.index,
            branch=self.choice,
        )
        ciphertext = response.ciphertext0 if self.choice == 0 else response.ciphertext1
        try:
            message = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise OtError("OT authentication failed") from exc
        self.consumed = True
        return message


@dataclass(frozen=True, slots=True)
class OtCost:
    offers: int
    requests: int
    responses: int

    @property
    def total(self) -> int:
        return self.offers + self.requests + self.responses


def transcript_cost(count: int) -> OtCost:
    if count < 0:
        raise OtError("negative OT count")
    return OtCost(count * OFFER_BYTES, count * REQUEST_BYTES, count * RESPONSE_BYTES)


def run_ot(
    message0: bytes,
    message1: bytes,
    choice: int,
    *,
    session_id: bytes = bytes.fromhex("11" * 32),
    index: int = 0,
    seed: bytes = b"ranklock-ot-test",
) -> bytes:
    sender = OtSender(
        session_id=session_id,
        index=index,
        message0=message0,
        message1=message1,
        scalar_source=DeterministicScalars(seed + b"sender"),
    )
    receiver = OtReceiver(
        session_id=session_id,
        offer=sender.offer,
        choice=choice,
        scalar_source=DeterministicScalars(seed + b"receiver"),
    )
    return receiver.finalize(sender.respond(receiver.request))
