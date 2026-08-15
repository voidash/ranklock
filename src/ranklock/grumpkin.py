from __future__ import annotations

"""Minimal Grumpkin group for the RankLock IPA reference implementation.

Grumpkin forms a cycle with BN254: its base field is BN254 Fr and its scalar
field is BN254 Fq, exactly matching RankFold's arithmetic field.  This module is
variable-time, dependency-free research code, not a production curve library.
"""

from dataclasses import dataclass
import hashlib
from typing import Iterable, Sequence

from .field import BN254_BASE_FIELD

# Grumpkin base field = BN254 scalar field.
GRUMPKIN_BASE_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# Grumpkin scalar field = BN254 base field.
GRUMPKIN_SCALAR_FIELD = BN254_BASE_FIELD
CURVE_B = -17 % GRUMPKIN_BASE_FIELD

AffinePoint = tuple[int, int] | None
JacobianPoint = tuple[int, int, int]


class GrumpkinError(ValueError):
    pass


def _sqrt_mod(value: int, modulus: int = GRUMPKIN_BASE_FIELD) -> int | None:
    """Tonelli-Shanks square root for an odd prime modulus."""

    value %= modulus
    if value == 0:
        return 0
    if pow(value, (modulus - 1) // 2, modulus) != 1:
        return None
    if modulus % 4 == 3:
        return pow(value, (modulus + 1) // 4, modulus)
    q = modulus - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2
    z = 2
    while pow(z, (modulus - 1) // 2, modulus) != modulus - 1:
        z += 1
    m = s
    c = pow(z, q, modulus)
    t = pow(value, q, modulus)
    r = pow(value, (q + 1) // 2, modulus)
    while t != 1:
        i = 1
        t2 = t * t % modulus
        while i < m and t2 != 1:
            t2 = t2 * t2 % modulus
            i += 1
        if i == m:
            return None
        b = pow(c, 1 << (m - i - 1), modulus)
        r = r * b % modulus
        t = t * b * b % modulus
        c = b * b % modulus
        m = i
    return r


def is_on_curve(point: AffinePoint) -> bool:
    if point is None:
        return True
    x, y = point
    return y * y % GRUMPKIN_BASE_FIELD == (x * x * x + CURVE_B) % GRUMPKIN_BASE_FIELD


def to_jacobian(point: AffinePoint) -> JacobianPoint:
    if point is None:
        return (0, 1, 0)
    return (point[0] % GRUMPKIN_BASE_FIELD, point[1] % GRUMPKIN_BASE_FIELD, 1)


def from_jacobian(point: JacobianPoint) -> AffinePoint:
    x, y, z = point
    if z % GRUMPKIN_BASE_FIELD == 0:
        return None
    inverse = pow(z, -1, GRUMPKIN_BASE_FIELD)
    inverse2 = inverse * inverse % GRUMPKIN_BASE_FIELD
    return (
        x * inverse2 % GRUMPKIN_BASE_FIELD,
        y * inverse2 * inverse % GRUMPKIN_BASE_FIELD,
    )


def jacobian_double(point: JacobianPoint) -> JacobianPoint:
    x, y, z = point
    p = GRUMPKIN_BASE_FIELD
    if z == 0 or y == 0:
        return (0, 1, 0)
    yy = y * y % p
    yyyy = yy * yy % p
    s = 4 * x * yy % p
    m = 3 * x * x % p
    x3 = (m * m - 2 * s) % p
    y3 = (m * (s - x3) - 8 * yyyy) % p
    z3 = 2 * y * z % p
    return x3, y3, z3


def jacobian_add(left: JacobianPoint, right: JacobianPoint) -> JacobianPoint:
    p = GRUMPKIN_BASE_FIELD
    x1, y1, z1 = left
    x2, y2, z2 = right
    if z1 == 0:
        return right
    if z2 == 0:
        return left
    z1z1 = z1 * z1 % p
    z2z2 = z2 * z2 % p
    u1 = x1 * z2z2 % p
    u2 = x2 * z1z1 % p
    s1 = y1 * z2 * z2z2 % p
    s2 = y2 * z1 * z1z1 % p
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return jacobian_double(left)
    h = (u2 - u1) % p
    i = (2 * h) ** 2 % p
    j = h * i % p
    r = 2 * (s2 - s1) % p
    v = u1 * i % p
    x3 = (r * r - j - 2 * v) % p
    y3 = (r * (v - x3) - 2 * s1 * j) % p
    z3 = ((z1 + z2) ** 2 - z1z1 - z2z2) * h % p
    return x3, y3, z3


def add(left: AffinePoint, right: AffinePoint) -> AffinePoint:
    return from_jacobian(jacobian_add(to_jacobian(left), to_jacobian(right)))


def negate(point: AffinePoint) -> AffinePoint:
    if point is None:
        return None
    return point[0], (-point[1]) % GRUMPKIN_BASE_FIELD


def scalar_multiply(point: AffinePoint, scalar: int) -> AffinePoint:
    scalar %= GRUMPKIN_SCALAR_FIELD
    if point is None or scalar == 0:
        return None
    if not is_on_curve(point):
        raise GrumpkinError("scalar multiplication received an off-curve point")
    result = (0, 1, 0)
    addend = to_jacobian(point)
    while scalar:
        if scalar & 1:
            result = jacobian_add(result, addend)
        scalar >>= 1
        if scalar:
            addend = jacobian_double(addend)
    return from_jacobian(result)


def multi_scalar_multiply(points: Sequence[AffinePoint], scalars: Sequence[int]) -> AffinePoint:
    if len(points) != len(scalars):
        raise GrumpkinError("MSM dimensions differ")
    result = (0, 1, 0)
    for point, scalar in zip(points, scalars, strict=True):
        result = jacobian_add(result, to_jacobian(scalar_multiply(point, scalar)))
    return from_jacobian(result)


def compress(point: AffinePoint) -> bytes:
    if point is None:
        return bytes(33)
    if not is_on_curve(point):
        raise GrumpkinError("cannot compress an off-curve point")
    x, y = point
    return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")


def decompress(raw: bytes) -> AffinePoint:
    if raw == bytes(33):
        return None
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise GrumpkinError("invalid compressed Grumpkin point")
    x = int.from_bytes(raw[1:], "big")
    if x >= GRUMPKIN_BASE_FIELD:
        raise GrumpkinError("non-canonical Grumpkin x-coordinate")
    root = _sqrt_mod((x * x * x + CURVE_B) % GRUMPKIN_BASE_FIELD)
    if root is None:
        raise GrumpkinError("compressed Grumpkin point is not on curve")
    y = root if (root & 1) == (raw[0] & 1) else GRUMPKIN_BASE_FIELD - root
    point = (x, y)
    if not is_on_curve(point):
        raise GrumpkinError("decompression produced an off-curve point")
    return point


def hash_to_curve(domain: bytes, index: int) -> AffinePoint:
    for counter in range(2**32):
        digest = hashlib.sha256(
            b"ranklock/grumpkin/hash-to-curve/v1\x00"
            + len(domain).to_bytes(4, "big")
            + domain
            + int(index).to_bytes(8, "big")
            + counter.to_bytes(4, "big")
        ).digest()
        x = int.from_bytes(digest, "big") % GRUMPKIN_BASE_FIELD
        root = _sqrt_mod((x * x * x + CURVE_B) % GRUMPKIN_BASE_FIELD)
        if root is not None:
            y = root if root % 2 == 0 else GRUMPKIN_BASE_FIELD - root
            point = (x, y)
            if point != (0, 0):
                return point
    raise RuntimeError("Grumpkin hash-to-curve exhausted")


GENERATOR_Y = _sqrt_mod(-16 % GRUMPKIN_BASE_FIELD)
if GENERATOR_Y is None:  # pragma: no cover - curve parameter invariant
    raise RuntimeError("Grumpkin generator square root missing")
GENERATOR: AffinePoint = (1, GENERATOR_Y if GENERATOR_Y % 2 == 0 else GRUMPKIN_BASE_FIELD - GENERATOR_Y)
if not is_on_curve(GENERATOR):  # pragma: no cover
    raise RuntimeError("invalid Grumpkin generator")
