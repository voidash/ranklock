from __future__ import annotations

"""Batched setup proof for the fixed inner-product witness-encryption key.

The reference :mod:`ranklock.inner_product_we` publishes one 64-byte DLEQ proof
per relation coordinate.  This module replaces those proofs with one
Fiat--Shamir random-linear-combination check.

For bases ``U_i`` and alleged scaled bases ``V_i``, derive ``rho`` only after
all ``(U_i,V_i)`` pairs are fixed, form

    U* = sum rho^i U_i,
    V* = sum rho^i V_i,

and prove ``log_G(sG) = log_{U*}(V*)``.  If at least one coordinate is not
scaled by the same ``s``, the aggregate error vanishes with probability at most
``(n-1)/q`` for uniformly random ``rho``.  Fiat--Shamir is used here as a ROM
research instantiation; this is not a malicious distributed-setup proof.

The ciphertext remains 48 bytes.  Retained key material drops from roughly
``130*n`` bytes to ``66*n + 130`` bytes because there is one DLEQ proof rather
than one proof per coordinate.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Sequence

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .inner_product_we import (
    InnerProductCiphertext,
    InnerProductRelation,
    InnerProductWeError,
)
from .real_secp import (
    G,
    N,
    DleqProof,
    DeterministicScalars,
    Point,
    SecpError,
    add,
    base_multiply,
    compress,
    decompress,
    multiply,
    prove_dleq,
    verify_dleq,
)

_BATCH_DOMAIN = b"ranklock/batched-inner-product-we/v1\x00"


class BatchedInnerProductWeError(InnerProductWeError):
    pass


def _sum(points: Sequence[Point]) -> Point:
    result: Point = None
    for point in points:
        result = add(result, point)
    return result


def _hash_scalar(*parts: bytes) -> int:
    for counter in range(2**32):
        digest = sha256(
            _BATCH_DOMAIN
            + b"rho\x00"
            + b"".join(len(part).to_bytes(8, "big") + bytes(part) for part in parts)
            + counter.to_bytes(4, "big")
        ).digest()
        value = int.from_bytes(digest, "big") % N
        if value not in (0, 1):
            return value
    raise BatchedInnerProductWeError("could not derive batching scalar")


def _aggregate_points(
    bases: Sequence[bytes], scaled_bases: Sequence[bytes], statement_digest: bytes
) -> tuple[Point, Point, int]:
    if len(bases) != len(scaled_bases) or not bases:
        raise BatchedInnerProductWeError("batched key dimensions differ")
    transcript = (
        len(bases).to_bytes(8, "big")
        + bytes(statement_digest)
        + b"".join(bytes(value) for value in bases)
        + b"".join(bytes(value) for value in scaled_bases)
    )
    rho = _hash_scalar(transcript)
    power = 1
    left_terms: list[Point] = []
    right_terms: list[Point] = []
    for base_raw, scaled_raw in zip(bases, scaled_bases, strict=True):
        left_terms.append(multiply(decompress(base_raw), power))
        right_terms.append(multiply(decompress(scaled_raw), power))
        power = power * rho % N
    left = _sum(tuple(left_terms))
    right = _sum(tuple(right_terms))
    if left is None or right is None:
        raise BatchedInnerProductWeError("batch aggregate is infinity")
    return left, right, rho


def _kdf(shared: Point, statement_digest: bytes) -> tuple[bytes, bytes, bytes]:
    if shared is None or len(statement_digest) != 32:
        raise BatchedInnerProductWeError("invalid shared point")
    raw = compress(shared)
    domain = _BATCH_DOMAIN + b"kdf\x00" + statement_digest
    return (
        sha256(domain + b"key\x00" + raw).digest(),
        sha256(domain + b"nonce\x00" + raw).digest()[:12],
        domain + b"payload",
    )


@dataclass(frozen=True, slots=True)
class BatchedInnerProductWeKey:
    relation: InnerProductRelation
    s_generator: bytes
    scaled_bases: tuple[bytes, ...]
    aggregate_proof: DleqProof

    def __post_init__(self) -> None:
        decompress(self.s_generator)
        if len(self.scaled_bases) != len(self.relation.bases):
            raise BatchedInnerProductWeError("batched key dimensions differ")
        for encoded in self.scaled_bases:
            decompress(encoded)

    @property
    def encoded_bytes(self) -> int:
        # original bases and target are counted as retained relation material.
        return 33 + 33 + 33 * len(self.relation.bases) + 33 * len(self.scaled_bases) + 64

    @property
    def soundness_error_upper_bound(self) -> tuple[int, int]:
        return max(0, len(self.relation.bases) - 1), N


def setup_batched_inner_product_we(
    relation: InnerProductRelation,
    secret: bytes,
    *,
    scalar_source: Callable[[], int] | None = None,
) -> tuple[BatchedInnerProductWeKey, InnerProductCiphertext]:
    secret = bytes(secret)
    if len(secret) != 32:
        raise BatchedInnerProductWeError("WE payload must be 32 bytes")
    source = scalar_source or DeterministicScalars(relation.digest + b"batch-setup")
    s = int(source()) % N
    if s == 0:
        raise BatchedInnerProductWeError("setup scalar is zero")
    s_generator_point = base_multiply(s)
    scaled = tuple(
        compress(multiply(decompress(base), s)) for base in relation.bases
    )
    aggregate_base, aggregate_scaled, rho = _aggregate_points(
        relation.bases, scaled, relation.digest
    )
    proof = prove_dleq(
        s,
        G,
        s_generator_point,
        aggregate_base,
        aggregate_scaled,
        domain=(
            _BATCH_DOMAIN
            + b"aggregate-dleq\x00"
            + relation.digest
            + rho.to_bytes(32, "big")
        ),
        nonce_source=source,
    )
    shared = multiply(decompress(relation.target), s)
    key_bytes, nonce, aad = _kdf(shared, relation.digest)
    ciphertext = InnerProductCiphertext(
        ChaCha20Poly1305(key_bytes).encrypt(nonce, secret, aad)
    )
    key = BatchedInnerProductWeKey(
        relation, compress(s_generator_point), scaled, proof
    )
    if not verify_batched_inner_product_key(key):
        raise AssertionError("generated batched key failed verification")
    return key, ciphertext


def verify_batched_inner_product_key(key: BatchedInnerProductWeKey) -> bool:
    try:
        aggregate_base, aggregate_scaled, rho = _aggregate_points(
            key.relation.bases, key.scaled_bases, key.relation.digest
        )
        return verify_dleq(
            key.aggregate_proof,
            G,
            decompress(key.s_generator),
            aggregate_base,
            aggregate_scaled,
            domain=(
                _BATCH_DOMAIN
                + b"aggregate-dleq\x00"
                + key.relation.digest
                + rho.to_bytes(32, "big")
            ),
        )
    except (BatchedInnerProductWeError, SecpError, ValueError, OverflowError):
        return False


def decrypt_batched_inner_product_we(
    key: BatchedInnerProductWeKey,
    ciphertext: InnerProductCiphertext,
    witness: Sequence[int],
) -> bytes:
    if not verify_batched_inner_product_key(key):
        raise BatchedInnerProductWeError("batched key is invalid")
    if not key.relation.accepts(witness):
        raise BatchedInnerProductWeError("witness does not satisfy relation")
    shared = _sum(
        tuple(
            multiply(decompress(base), int(value) % N)
            for base, value in zip(key.scaled_bases, witness, strict=True)
        )
    )
    key_bytes, nonce, aad = _kdf(shared, key.relation.digest)
    try:
        return ChaCha20Poly1305(key_bytes).decrypt(nonce, ciphertext.payload, aad)
    except Exception as exc:
        raise BatchedInnerProductWeError("decryption failed") from exc


def key_size_comparison(width: int) -> dict[str, object]:
    width = int(width)
    if width <= 0:
        raise BatchedInnerProductWeError("width must be positive")
    per_coordinate = 66 + 130 * width
    batched = 130 + 66 * width
    return {
        "schema": "ranklock-batched-inner-product-key-size-v1",
        "relation_width": width,
        "per_coordinate_dleq_bytes": per_coordinate,
        "batched_dleq_bytes": batched,
        "saved_bytes": per_coordinate - batched,
        "compression_ratio": per_coordinate / batched,
        "rom_soundness_error_upper_bound": f"{max(0, width-1)}/{N}",
        "security_boundary": (
            "The batch proof is a Fiat-Shamir random-linear-combination check. "
            "It is not a replacement for malicious distributed setup."
        ),
    }
