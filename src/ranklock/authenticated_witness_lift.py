from __future__ import annotations

"""Move a future input from the WE statement into an authenticated witness.

A static ciphertext cannot generally be encrypted to a KZG commitment that is
created only after setup.  A different route is to fix the *relation* at setup
and make the future input, its authentication token, and the proof all witness
variables.  This is sound only when the token cryptographically binds the input
to the unique protocol event.  Without that binding, the witness can substitute
any convenient invalid input and unlock the secret.

The hash-based one-time signature below is an executable relation model, not a
recommended Strata transport.  Strata's completed adaptor signatures would play
the authentication role in a real construction and would need to be verified by
the outer linearly-verifiable proof.
"""

from dataclasses import dataclass
import hashlib
from typing import Callable, Sequence


DOMAIN = b"ranklock/authenticated-witness-lift/v1\x00"
BITS = 256
CHUNK_BYTES = 32


class AuthenticatedWitnessError(ValueError):
    pass


def _digest(context: bytes, dynamic_input: bytes) -> bytes:
    return hashlib.sha256(DOMAIN + bytes(context) + bytes(dynamic_input)).digest()


def _bits(data: bytes) -> tuple[int, ...]:
    return tuple((byte >> shift) & 1 for byte in data for shift in range(7, -1, -1))


@dataclass(frozen=True, slots=True)
class LamportPublicKey:
    pairs: tuple[tuple[bytes, bytes], ...]

    def __post_init__(self) -> None:
        if len(self.pairs) != BITS:
            raise AuthenticatedWitnessError("Lamport public key must contain 256 pairs")
        if any(len(left) != 32 or len(right) != 32 for left, right in self.pairs):
            raise AuthenticatedWitnessError("Lamport public-key hashes must be 32 bytes")


@dataclass(frozen=True, slots=True)
class LamportSecretKey:
    pairs: tuple[tuple[bytes, bytes], ...]

    @property
    def public_key(self) -> LamportPublicKey:
        return LamportPublicKey(
            tuple(
                (hashlib.sha256(left).digest(), hashlib.sha256(right).digest())
                for left, right in self.pairs
            )
        )


def lamport_keygen(seed: bytes) -> LamportSecretKey:
    seed = bytes(seed)
    if not seed:
        raise AuthenticatedWitnessError("Lamport seed must be nonempty")
    pairs = []
    for index in range(BITS):
        values = []
        for bit in (0, 1):
            values.append(
                hashlib.sha256(
                    DOMAIN + b"lamport-secret" + seed + index.to_bytes(2, "big") + bytes([bit])
                ).digest()
            )
        pairs.append((values[0], values[1]))
    return LamportSecretKey(tuple(pairs))


def lamport_sign(
    secret_key: LamportSecretKey, *, context: bytes, dynamic_input: bytes
) -> tuple[bytes, ...]:
    digest = _digest(context, dynamic_input)
    return tuple(
        secret_key.pairs[index][bit]
        for index, bit in enumerate(_bits(digest))
    )


def lamport_verify(
    public_key: LamportPublicKey,
    signature: Sequence[bytes],
    *,
    context: bytes,
    dynamic_input: bytes,
) -> bool:
    signature = tuple(bytes(value) for value in signature)
    if len(signature) != BITS:
        return False
    digest = _digest(context, dynamic_input)
    return all(
        hashlib.sha256(revealed).digest() == public_key.pairs[index][bit]
        for index, (bit, revealed) in enumerate(zip(_bits(digest), signature, strict=True))
    )


@dataclass(frozen=True, slots=True)
class AuthenticatedDynamicWitness:
    dynamic_input: bytes
    authentication: tuple[bytes, ...]
    proof: bytes


@dataclass(frozen=True, slots=True)
class FixedRelationStatement:
    context: bytes
    authentication_key: LamportPublicKey


def verify_unsafe_fixed_relation(
    dynamic_input: bytes,
    proof: bytes,
    *,
    invalidity_verifier: Callable[[bytes, bytes], bool],
) -> bool:
    """Broken lift: any substituted invalid input is a witness."""

    return bool(invalidity_verifier(bytes(dynamic_input), bytes(proof)))


def verify_authenticated_fixed_relation(
    statement: FixedRelationStatement,
    witness: AuthenticatedDynamicWitness,
    *,
    invalidity_verifier: Callable[[bytes, bytes], bool],
) -> bool:
    if not lamport_verify(
        statement.authentication_key,
        witness.authentication,
        context=statement.context,
        dynamic_input=witness.dynamic_input,
    ):
        return False
    return bool(invalidity_verifier(bytes(witness.dynamic_input), bytes(witness.proof)))


def lift_cost_inventory(*, dynamic_bytes: int, authenticated_chunks: int) -> dict[str, object]:
    if dynamic_bytes <= 0 or authenticated_chunks <= 0:
        raise AuthenticatedWitnessError("lift inventory dimensions must be positive")
    return {
        "schema": "ranklock-authenticated-witness-lift-cost-v1",
        "dynamic_input_bytes": int(dynamic_bytes),
        "authentication_items": int(authenticated_chunks),
        "ciphertext_statement_can_remain_static": True,
        "outer_relation_must_verify": [
            "authentication of every future input item",
            "unique session/deposit binding",
            "invalidity proof for the authenticated input",
        ],
        "strata_candidate": "132 completed adaptor signatures become witness authentication",
        "warning": "constant ciphertext does not imply cheap witness verification or cheap CRS",
    }
