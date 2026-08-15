from __future__ import annotations

"""Real BN254 KZG commitments and opening witness encryption.

The group and pairing operations are the dependency-free BN254 implementation retained
from RankVM v0.5.  This is actual elliptic-curve/pairing arithmetic rather than the
formal exponent model used elsewhere in the repository.  It remains variable-time,
unaudited research code and the setup trapdoor is generated locally for experiments.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Sequence

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .bn254_real import (
    CURVE_ORDER,
    FQ12,
    G1,
    G2,
    Point,
    add,
    compress_g1,
    compress_g2,
    decompress_g1,
    decompress_g2,
    eq_points,
    multiply,
    neg,
    pairing_product,
)


class KzgWeError(RuntimeError):
    pass


def _field(value: int) -> int:
    return int(value) % CURVE_ORDER


def _poly_trim(values: Sequence[int]) -> tuple[int, ...]:
    result = [_field(value) for value in values]
    if not result:
        raise KzgWeError("polynomial is empty")
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return tuple(result)


def polynomial_evaluate(coefficients: Sequence[int], point: int) -> int:
    result = 0
    point = _field(point)
    for coefficient in reversed(tuple(coefficients)):
        result = (result * point + int(coefficient)) % CURVE_ORDER
    return result


def opening_quotient(coefficients: Sequence[int], point: int) -> tuple[int, tuple[int, ...]]:
    coefficients = _poly_trim(coefficients)
    point = _field(point)
    value = polynomial_evaluate(coefficients, point)
    if len(coefficients) == 1:
        return value, (0,)
    descending = list(reversed(coefficients))
    quotient_desc = [descending[0]]
    for coefficient in descending[1:-1]:
        quotient_desc.append((coefficient + point * quotient_desc[-1]) % CURVE_ORDER)
    remainder = (descending[-1] + point * quotient_desc[-1]) % CURVE_ORDER
    if remainder != value:
        raise AssertionError("synthetic division failed")
    return value, _poly_trim(tuple(reversed(quotient_desc)))


def _point_sum(points: Sequence[Point]) -> Point:
    result = multiply(G1, 0, group="g1")
    for point in points:
        result = add(result, point, group="g1")
    return result


def _gt_bytes(value: FQ12) -> bytes:
    return b"".join(int(coefficient).to_bytes(32, "big") for coefficient in value.coeffs)


def _session_kdf(session: FQ12, statement_digest: bytes) -> tuple[bytes, bytes, bytes]:
    raw = _gt_bytes(session)
    domain = b"ranklock/kzg-opening-we/kdf/v1\x00" + statement_digest
    return (
        sha256(domain + b"key\x00" + raw).digest(),
        sha256(domain + b"nonce\x00" + raw).digest()[:12],
        domain + b"payload",
    )


@dataclass(frozen=True, slots=True)
class KzgSrs:
    g1_powers: tuple[bytes, ...]
    g2: bytes
    tau_g2: bytes
    schema: str = "ranklock-real-bn254-kzg-srs-v1"

    @classmethod
    def generate(cls, maximum_degree: int, *, tau: int) -> "KzgSrs":
        if not 1 <= maximum_degree <= 1_000_000:
            raise KzgWeError("KZG degree outside local bounds")
        tau = _field(tau)
        if tau == 0:
            raise KzgWeError("KZG tau is zero")
        powers: list[bytes] = []
        current = 1
        for _ in range(maximum_degree + 1):
            powers.append(compress_g1(multiply(G1, current, group="g1")))
            current = current * tau % CURVE_ORDER
        return cls(
            tuple(powers),
            compress_g2(G2),
            compress_g2(multiply(G2, tau, group="g2")),
        )

    @property
    def maximum_degree(self) -> int:
        return len(self.g1_powers) - 1

    @property
    def encoded_bytes(self) -> int:
        return sum(len(value) for value in self.g1_powers) + len(self.g2) + len(self.tau_g2)

    def commit(self, coefficients: Sequence[int]) -> bytes:
        coefficients = _poly_trim(coefficients)
        if len(coefficients) > len(self.g1_powers):
            raise KzgWeError("polynomial exceeds KZG SRS degree")
        points = tuple(
            multiply(decompress_g1(base), coefficient, group="g1")
            for base, coefficient in zip(self.g1_powers, coefficients, strict=False)
            if coefficient % CURVE_ORDER
        )
        return compress_g1(_point_sum(points))

    def open(self, coefficients: Sequence[int], point: int) -> "KzgOpening":
        value, quotient = opening_quotient(coefficients, point)
        return KzgOpening(_field(point), value, self.commit(quotient))


@dataclass(frozen=True, slots=True)
class KzgOpening:
    point: int
    value: int
    proof_g1: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.point < CURVE_ORDER or not 0 <= self.value < CURVE_ORDER:
            raise KzgWeError("KZG opening scalar is non-canonical")
        decompress_g1(self.proof_g1)


@dataclass(frozen=True, slots=True)
class KzgStatement:
    commitment_g1: bytes
    point: int
    value: int

    def __post_init__(self) -> None:
        decompress_g1(self.commitment_g1)
        if not 0 <= self.point < CURVE_ORDER or not 0 <= self.value < CURVE_ORDER:
            raise KzgWeError("KZG statement scalar is non-canonical")

    @property
    def digest(self) -> bytes:
        return sha256(
            b"ranklock/kzg-opening-statement/v1\x00"
            + self.commitment_g1
            + self.point.to_bytes(32, "big")
            + self.value.to_bytes(32, "big")
        ).digest()


@dataclass(frozen=True, slots=True)
class KzgWeCiphertext:
    header_g2: bytes
    payload: bytes

    def __post_init__(self) -> None:
        decompress_g2(self.header_g2)
        if len(self.payload) != 48:
            raise KzgWeError("KZG-WE encrypted payload must be 48 bytes")

    @property
    def encoded_bytes(self) -> int:
        return len(self.header_g2) + len(self.payload)


def verify_opening(srs: KzgSrs, statement: KzgStatement, opening: KzgOpening) -> bool:
    try:
        if opening.point != statement.point or opening.value != statement.value:
            return False
        commitment = decompress_g1(statement.commitment_g1)
        value_g1 = multiply(G1, statement.value, group="g1")
        left = add(commitment, neg(value_g1), group="g1")
        proof = decompress_g1(opening.proof_g1)
        tau_minus_z = add(
            decompress_g2(srs.tau_g2),
            neg(multiply(G2, statement.point, group="g2")),
            group="g2",
        )
        product = pairing_product(
            (
                (left, decompress_g2(srs.g2)),
                (neg(proof), tau_minus_z),
            )
        )
        return product == FQ12.one()
    except (KzgWeError, ValueError, ZeroDivisionError, OverflowError):
        return False


def encrypt_for_opening(
    srs: KzgSrs,
    statement: KzgStatement,
    secret: bytes,
    *,
    randomness: int,
) -> KzgWeCiphertext:
    secret = bytes(secret)
    if len(secret) != 32:
        raise KzgWeError("KZG-WE payload must be 32 bytes")
    r = _field(randomness)
    if r == 0:
        raise KzgWeError("KZG-WE randomness is zero")
    tau_minus_z = add(
        decompress_g2(srs.tau_g2),
        neg(multiply(G2, statement.point, group="g2")),
        group="g2",
    )
    header = multiply(tau_minus_z, r, group="g2")
    commitment_minus_value = add(
        decompress_g1(statement.commitment_g1),
        neg(multiply(G1, statement.value, group="g1")),
        group="g1",
    )
    session = pairing_product(
        ((multiply(commitment_minus_value, r, group="g1"), G2),)
    )
    key, nonce, aad = _session_kdf(session, statement.digest)
    return KzgWeCiphertext(
        compress_g2(header), ChaCha20Poly1305(key).encrypt(nonce, secret, aad)
    )


def decrypt_with_opening(
    statement: KzgStatement,
    ciphertext: KzgWeCiphertext,
    opening: KzgOpening,
) -> bytes:
    if opening.point != statement.point or opening.value != statement.value:
        raise KzgWeError("opening belongs to another KZG statement")
    session = pairing_product(
        ((decompress_g1(opening.proof_g1), decompress_g2(ciphertext.header_g2)),)
    )
    key, nonce, aad = _session_kdf(session, statement.digest)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext.payload, aad)
    except Exception as exc:
        raise KzgWeError("KZG-WE decryption failed") from exc


def aggregate_same_point(
    polynomials: Sequence[Sequence[int]],
    point: int,
    challenge: int,
    srs: KzgSrs,
) -> tuple[tuple[int, ...], KzgStatement, KzgOpening]:
    if not polynomials:
        raise KzgWeError("cannot batch zero polynomials")
    rho = _field(challenge)
    if rho == 0:
        raise KzgWeError("batching challenge is zero")
    maximum = max(len(poly) for poly in polynomials)
    aggregate = [0] * maximum
    power = 1
    for polynomial in polynomials:
        for index, coefficient in enumerate(polynomial):
            aggregate[index] = (aggregate[index] + power * int(coefficient)) % CURVE_ORDER
        power = power * rho % CURVE_ORDER
    coefficients = _poly_trim(aggregate)
    opening = srs.open(coefficients, point)
    statement = KzgStatement(srs.commit(coefficients), opening.point, opening.value)
    return coefficients, statement, opening


def xor_bytes(values: Sequence[bytes]) -> bytes:
    if not values or any(len(value) != 32 for value in values):
        raise KzgWeError("XOR sharing requires nonempty 32-byte shares")
    result = bytearray(32)
    for value in values:
        for index, byte in enumerate(value):
            result[index] ^= byte
    return bytes(result)
