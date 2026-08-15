from __future__ import annotations

"""Fixed-statement inner-product witness encryption over secp256k1.

For public points ``U_i`` and fixed target ``T``, a witness is a vector ``w`` with
``sum w_i U_i = T``.  Setup samples ``s``, publishes ``sU_i`` with DLEQ proofs,
and encrypts a 32-byte payload under ``H(sT)``.  A valid witness reconstructs
``sT`` by a linear combination of the scaled bases.

The ciphertext is constant-size (48 bytes), but the relation key is linear in the
statement width.  This is an executable instance of the linearly-verifiable
inner-product gadget, not a claim of a new WE primitive.
"""

from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Callable, Sequence

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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


class InnerProductWeError(RuntimeError):
    pass


def _sum(points: Sequence[Point]) -> Point:
    result: Point = None
    for point in points:
        result = add(result, point)
    return result


def _context_digest(bases: Sequence[bytes], target: bytes, context: bytes) -> bytes:
    digest = sha256(b"ranklock/inner-product-we/statement/v1\x00" + bytes(context))
    digest.update(len(bases).to_bytes(8, "big"))
    for base in bases:
        digest.update(base)
    digest.update(target)
    return digest.digest()


def _kdf(shared: Point, statement_digest: bytes) -> tuple[bytes, bytes, bytes]:
    if shared is None or len(statement_digest) != 32:
        raise InnerProductWeError("invalid inner-product WE shared point")
    raw = compress(shared)
    domain = b"ranklock/inner-product-we/kdf/v1\x00" + statement_digest
    return (
        sha256(domain + b"key\x00" + raw).digest(),
        sha256(domain + b"nonce\x00" + raw).digest()[:12],
        domain + b"payload",
    )


@dataclass(frozen=True, slots=True)
class InnerProductRelation:
    bases: tuple[bytes, ...]
    target: bytes
    context: bytes = b""

    def __post_init__(self) -> None:
        if not self.bases:
            raise InnerProductWeError("inner-product relation must have bases")
        for base in self.bases:
            decompress(base)
        decompress(self.target)

    @property
    def digest(self) -> bytes:
        return _context_digest(self.bases, self.target, self.context)

    def accepts(self, witness: Sequence[int]) -> bool:
        if len(witness) != len(self.bases):
            return False
        try:
            result = _sum(
                tuple(
                    multiply(decompress(base), int(value) % N)
                    for base, value in zip(self.bases, witness, strict=True)
                )
            )
            return result == decompress(self.target)
        except (SecpError, ValueError, OverflowError):
            return False


@dataclass(frozen=True, slots=True)
class InnerProductWeKey:
    relation: InnerProductRelation
    s_generator: bytes
    scaled_bases: tuple[bytes, ...]
    proofs: tuple[DleqProof, ...]

    def __post_init__(self) -> None:
        decompress(self.s_generator)
        if len(self.scaled_bases) != len(self.relation.bases) or len(self.proofs) != len(self.relation.bases):
            raise InnerProductWeError("inner-product key dimensions differ")
        for encoded in self.scaled_bases:
            decompress(encoded)

    @property
    def encoded_bytes(self) -> int:
        # Relation is counted because RankLock's strong theorem counts all retained
        # verifier-specific material rather than assuming a free global CRS.
        return (
            33
            + 33
            + len(self.relation.bases) * 33
            + len(self.scaled_bases) * 33
            + len(self.proofs) * 64
        )


@dataclass(frozen=True, slots=True)
class InnerProductCiphertext:
    payload: bytes

    def __post_init__(self) -> None:
        if len(self.payload) != 48:
            raise InnerProductWeError("inner-product WE ciphertext must be 48 bytes")

    @property
    def encoded_bytes(self) -> int:
        return len(self.payload)


def setup_inner_product_we(
    relation: InnerProductRelation,
    secret: bytes,
    *,
    scalar_source: Callable[[], int] | None = None,
) -> tuple[InnerProductWeKey, InnerProductCiphertext]:
    secret = bytes(secret)
    if len(secret) != 32:
        raise InnerProductWeError("WE payload must be 32 bytes")
    source = scalar_source or DeterministicScalars(relation.digest + b"setup")
    s = int(source()) % N
    if s == 0:
        raise InnerProductWeError("WE setup scalar is zero")
    s_generator = base_multiply(s)
    scaled: list[bytes] = []
    proofs: list[DleqProof] = []
    for index, base_raw in enumerate(relation.bases):
        base = decompress(base_raw)
        scaled_point = multiply(base, s)
        if scaled_point is None:
            raise InnerProductWeError("scaled relation base is infinity")
        scaled.append(compress(scaled_point))
        proofs.append(
            prove_dleq(
                s,
                G,
                s_generator,
                base,
                scaled_point,
                domain=(b"ranklock/inner-product-we/dleq/v1\x00" + relation.digest + index.to_bytes(4, "big")),
                nonce_source=source,
            )
        )
    shared = multiply(decompress(relation.target), s)
    key_bytes, nonce, aad = _kdf(shared, relation.digest)
    ciphertext = InnerProductCiphertext(
        ChaCha20Poly1305(key_bytes).encrypt(nonce, secret, aad)
    )
    key = InnerProductWeKey(
        relation, compress(s_generator), tuple(scaled), tuple(proofs)
    )
    if not verify_inner_product_key(key):
        raise AssertionError("generated inner-product WE key failed verification")
    return key, ciphertext


def verify_inner_product_key(key: InnerProductWeKey) -> bool:
    try:
        s_generator = decompress(key.s_generator)
        for index, (base_raw, scaled_raw, proof) in enumerate(
            zip(key.relation.bases, key.scaled_bases, key.proofs, strict=True)
        ):
            if not verify_dleq(
                proof,
                G,
                s_generator,
                decompress(base_raw),
                decompress(scaled_raw),
                domain=(b"ranklock/inner-product-we/dleq/v1\x00" + key.relation.digest + index.to_bytes(4, "big")),
            ):
                return False
        return True
    except (InnerProductWeError, SecpError, ValueError, OverflowError):
        return False


def decrypt_inner_product_we(
    key: InnerProductWeKey,
    ciphertext: InnerProductCiphertext,
    witness: Sequence[int],
) -> bytes:
    if not verify_inner_product_key(key):
        raise InnerProductWeError("inner-product WE key is invalid")
    if not key.relation.accepts(witness):
        raise InnerProductWeError("inner-product witness does not satisfy relation")
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
        raise InnerProductWeError("inner-product WE decryption failed") from exc


def derive_relation(
    witness: Sequence[int], *, context: bytes = b"ranklock-inner-product-example"
) -> InnerProductRelation:
    values = tuple(int(value) % N for value in witness)
    if not values:
        raise InnerProductWeError("empty witness")
    bases = tuple(
        compress(base_multiply(i + 2)) for i in range(len(values))
    )
    target = _sum(
        tuple(
            multiply(decompress(base), value)
            for base, value in zip(bases, values, strict=True)
        )
    )
    if target is None:
        raise InnerProductWeError("derived target is infinity")
    return InnerProductRelation(bases, compress(target), bytes(context))
