from __future__ import annotations

"""Small secp256k1 research backend used by the concrete RankLock experiments.

The module deliberately separates *real group operations* from production claims.  It
uses OpenSSL through ``cryptography`` for fixed-base multiplication and ECDH, while
arbitrary-point multiplication and DLEQ verification are implemented in Python for
inspectability.  The code is variable-time and unaudited.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable

from cryptography.hazmat.primitives.asymmetric import ec

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = tuple[int, int] | None


class SecpError(ValueError):
    pass


def _inv(value: int) -> int:
    value %= P
    if value == 0:
        raise SecpError("inverse of zero")
    return pow(value, P - 2, P)


def is_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    return 0 <= x < P and 0 <= y < P and y * y % P == (x * x * x + 7) % P


def negate(point: Point) -> Point:
    if point is None:
        return None
    return point[0], (-point[1]) % P


def add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = 3 * x1 * x1 * _inv(2 * y1) % P
    else:
        slope = (y2 - y1) * _inv(x2 - x1) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def _to_jacobian(point: Point) -> tuple[int, int, int]:
    return (0, 1, 0) if point is None else (point[0], point[1], 1)


def _jacobian_double(point: tuple[int, int, int]) -> tuple[int, int, int]:
    x, y, z = point
    if z == 0 or y == 0:
        return 0, 1, 0
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * x * x % P
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * yy * yy) % P
    nz = 2 * y * z % P
    return nx, ny, nz


def _jacobian_add(left: tuple[int, int, int], right: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = left
    x2, y2, z2 = right
    if z1 == 0:
        return right
    if z2 == 0:
        return left
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    if u1 == u2:
        return _jacobian_double(left) if s1 == s2 else (0, 1, 0)
    h = (u2 - u1) % P
    i = (2 * h) ** 2 % P
    j = h * i % P
    r = 2 * (s2 - s1) % P
    v = u1 * i % P
    nx = (r * r - j - 2 * v) % P
    ny = (r * (v - nx) - 2 * s1 * j) % P
    nz = ((z1 + z2) ** 2 - z1z1 - z2z2) * h % P
    return nx, ny, nz


def _from_jacobian(point: tuple[int, int, int]) -> Point:
    x, y, z = point
    if z == 0:
        return None
    iz = _inv(z)
    iz2 = iz * iz % P
    return x * iz2 % P, y * iz2 * iz % P


def multiply(point: Point, scalar: int) -> Point:
    scalar %= N
    if point is None or scalar == 0:
        return None
    if point == G:
        return base_multiply(scalar)
    if not is_on_curve(point):
        raise SecpError("point is not on secp256k1")
    result = (0, 1, 0)
    addend = _to_jacobian(point)
    while scalar:
        if scalar & 1:
            result = _jacobian_add(result, addend)
        scalar >>= 1
        if scalar:
            addend = _jacobian_double(addend)
    return _from_jacobian(result)


def base_multiply(scalar: int) -> Point:
    scalar %= N
    if scalar == 0:
        return None
    key = ec.derive_private_key(scalar, ec.SECP256K1())
    numbers = key.public_key().public_numbers()
    return numbers.x, numbers.y


def compress(point: Point) -> bytes:
    if point is None:
        raise SecpError("infinity has no compressed encoding")
    if not is_on_curve(point):
        raise SecpError("cannot encode off-curve point")
    return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")


def decompress(raw: bytes) -> Point:
    raw = bytes(raw)
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise SecpError("invalid compressed secp256k1 point")
    x = int.from_bytes(raw[1:], "big")
    if x >= P:
        raise SecpError("non-canonical secp256k1 x-coordinate")
    yy = (pow(x, 3, P) + 7) % P
    y = pow(yy, (P + 1) // 4, P)
    if y * y % P != yy:
        raise SecpError("compressed point is not on secp256k1")
    if (y & 1) != (raw[0] & 1):
        y = P - y
    point = (x, y)
    if not is_on_curve(point):  # pragma: no cover - defense in depth
        raise SecpError("decoded point is invalid")
    return point


def ecdh_x(secret: int, point: Point) -> bytes:
    secret %= N
    if secret == 0 or point is None:
        raise SecpError("invalid ECDH input")
    public = ec.EllipticCurvePublicNumbers(point[0], point[1], ec.SECP256K1()).public_key()
    private = ec.derive_private_key(secret, ec.SECP256K1())
    shared = private.exchange(ec.ECDH(), public)
    if len(shared) != 32:
        raise SecpError("unexpected ECDH output")
    return shared


def hash_scalar(domain: bytes, *parts: bytes) -> int:
    for counter in range(2**32):
        digest = sha256(
            b"ranklock/secp/hash-scalar/v1\x00"
            + len(domain).to_bytes(4, "big")
            + bytes(domain)
            + b"".join(len(part).to_bytes(8, "big") + bytes(part) for part in parts)
            + counter.to_bytes(4, "big")
        ).digest()
        value = int.from_bytes(digest, "big") % N
        if value:
            return value
    raise RuntimeError("hash-to-scalar exhausted")


def hash_point(domain: bytes, index: int) -> Point:
    return base_multiply(hash_scalar(domain, int(index).to_bytes(8, "big")))


@dataclass(frozen=True, slots=True)
class DleqProof:
    challenge: int
    response: int

    def __post_init__(self) -> None:
        if not 0 <= self.challenge < N or not 0 <= self.response < N:
            raise SecpError("DLEQ scalar outside secp256k1 order")

    def encode(self) -> bytes:
        return self.challenge.to_bytes(32, "big") + self.response.to_bytes(32, "big")

    @classmethod
    def parse(cls, raw: bytes) -> "DleqProof":
        raw = bytes(raw)
        if len(raw) != 64:
            raise SecpError("DLEQ proof must be 64 bytes")
        c = int.from_bytes(raw[:32], "big")
        z = int.from_bytes(raw[32:], "big")
        if c >= N or z >= N:
            raise SecpError("non-canonical DLEQ scalar")
        return cls(c, z)


def _dleq_challenge(domain: bytes, base1: Point, target1: Point, base2: Point, target2: Point, a1: Point, a2: Point) -> int:
    if any(point is None for point in (base1, target1, base2, target2, a1, a2)):
        raise SecpError("DLEQ does not support infinity")
    return hash_scalar(
        b"ranklock/dleq/v1\x00" + bytes(domain),
        *(compress(point) for point in (base1, target1, base2, target2, a1, a2)),
    )


def prove_dleq(
    witness: int,
    base1: Point,
    target1: Point,
    base2: Point,
    target2: Point,
    *,
    domain: bytes,
    nonce_source: Callable[[], int] | None = None,
) -> DleqProof:
    witness %= N
    if witness == 0:
        raise SecpError("DLEQ witness must be nonzero")
    if multiply(base1, witness) != target1 or multiply(base2, witness) != target2:
        raise SecpError("DLEQ statement does not match witness")
    nonce = (nonce_source() if nonce_source is not None else hash_scalar(
        b"ranklock/dleq/nonce/v1\x00" + bytes(domain),
        witness.to_bytes(32, "big"),
        compress(base1),
        compress(base2),
        compress(target1),
        compress(target2),
    )) % N
    if nonce == 0:
        raise SecpError("DLEQ nonce is zero")
    a1 = multiply(base1, nonce)
    a2 = multiply(base2, nonce)
    challenge = _dleq_challenge(domain, base1, target1, base2, target2, a1, a2)
    return DleqProof(challenge, (nonce + challenge * witness) % N)


def verify_dleq(
    proof: DleqProof,
    base1: Point,
    target1: Point,
    base2: Point,
    target2: Point,
    *,
    domain: bytes,
) -> bool:
    try:
        if any(point is None or not is_on_curve(point) for point in (base1, target1, base2, target2)):
            return False
        a1 = add(multiply(base1, proof.response), negate(multiply(target1, proof.challenge)))
        a2 = add(multiply(base2, proof.response), negate(multiply(target2, proof.challenge)))
        return proof.challenge == _dleq_challenge(
            domain, base1, target1, base2, target2, a1, a2
        )
    except (SecpError, ValueError, OverflowError):
        return False


class DeterministicScalars:
    """Deterministic nonzero scalar stream for reproducible tests/benchmarks."""

    def __init__(self, seed: bytes) -> None:
        self.seed = bytes(seed)
        self.counter = 0

    def __call__(self) -> int:
        value = hash_scalar(
            b"ranklock/deterministic-scalars/v1\x00",
            self.seed,
            self.counter.to_bytes(8, "big"),
        )
        self.counter += 1
        return value
