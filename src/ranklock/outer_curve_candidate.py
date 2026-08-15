from __future__ import annotations

"""Concrete CP6-style outer-curve candidate for the RankLock wrapper.

The monomial-basis one-sided SNARK can be instantiated on a pairing-friendly
outer curve whose scalar field is the field in which the wrapped computation is
expressed.  For the RankVM/SP1 verifier that target scalar field is BN254 Fq.

This module records one deterministic Cocks--Pinch, embedding-degree-six
*research candidate* with scalar order equal to BN254 Fq.  It is not claimed to
be the parameter set used by Thakur's implementation and it is not an audited
production curve.  The purpose is to replace the old ``64-byte G1`` geometry
with an executable, internally consistent 515-bit outer-field instance.

The module provides:

* exact curve/order/embedding-degree consistency checks;
* canonical 65-byte compressed G1 encoding;
* subgroup tests and cofactor-normalisation;
* a concrete non-subgroup point for adversarial tests.

Primality is checked with a many-base Miller--Rabin test.  That is strong
probabilistic evidence, not a published primality certificate.
"""

from dataclasses import dataclass
from functools import lru_cache
from math import gcd
from typing import Iterable


class OuterCurveCandidateError(ValueError):
    pass


# BN254 base field.  This is the scalar order required of the outer curve.
BN254_FQ = (
    21888242871839275222246405745257275088696311157297823662689037894645226208583
)

# Deterministically generated CP(k=6,D=3) candidate.
OUTER_Q = (
    63719658410210838045411540704743437062171996549765061162909145051755725343381866493046299666105854037248167278148964111125857802392710042714491808663819047
)
OUTER_TRACE = -(
    372100128821267678780392858154521798429255893416888764286687923467849051197876
)
OUTER_CM_Y = (
    196994185846553477000952305202364849772073001663289000304526100804767104427902
)
OUTER_COFACTOR = (
    2911136301954623604587423450426143171775125205955786348069817984191394046620228
)
OUTER_EMBEDDING_DEGREE = 6
OUTER_CM_DISCRIMINANT = 3
OUTER_A = 0
OUTER_B = 3

# G = [h](1,2), where (1,2) is on y^2=x^3+3 but outside the r-subgroup.
OUTER_G1_GENERATOR = (
    61429413484211421777519608039396834595866532523002205586495776912472311766817324563913338497938255631658327363477138088785812876815888768265689978581479573,
    37920939227114141393319897758473590856295825978796622299481961126002438532961879539741170518631123688239190795637746304713221885491273016785532881211935336,
)
OUTER_KNOWN_NON_SUBGROUP_POINT = (1, 2)

COMPRESSED_G1_BYTES = 65
_SIGN_MASK = 0x80
_INFINITY_MASK = 0x40
_RESERVED_MASK = 0x38
_PAYLOAD_TOP_MASK = 0x07

Point = tuple[int, int] | None
JacobianPoint = tuple[int, int, int]


def _miller_rabin_round(n: int, base: int, d: int, s: int) -> bool:
    x = pow(base % n, d, n)
    if x in (1, n - 1):
        return True
    for _ in range(s - 1):
        x = x * x % n
        if x == n - 1:
            return True
    return False


def is_strong_probable_prime(n: int, bases: Iterable[int] | None = None) -> bool:
    """Return strong probabilistic primality evidence.

    The default bases are the first 32 small primes.  This is deliberately
    stronger than a toy check but is not described as a deterministic proof for
    a 515-bit integer.
    """

    n = int(n)
    if n < 2:
        return False
    small_primes = (
        2,
        3,
        5,
        7,
        11,
        13,
        17,
        19,
        23,
        29,
        31,
        37,
        41,
        43,
        47,
        53,
        59,
        61,
        67,
        71,
        73,
        79,
        83,
        89,
        97,
        101,
        103,
        107,
        109,
        113,
        127,
        131,
    )
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    selected = tuple(int(value) for value in (bases or small_primes))
    return all(_miller_rabin_round(n, base, d, s) for base in selected)


def is_on_curve(point: Point) -> bool:
    if point is None:
        return True
    x, y = point
    if not (0 <= x < OUTER_Q and 0 <= y < OUTER_Q):
        return False
    return (y * y - (x * x % OUTER_Q) * x - OUTER_B) % OUTER_Q == 0


def negate(point: Point) -> Point:
    if point is None:
        return None
    x, y = point
    return x, (-y) % OUTER_Q


def _jacobian_from_affine(point: Point) -> JacobianPoint:
    if point is None:
        return (0, 1, 0)
    return point[0], point[1], 1


def _jacobian_to_affine(point: JacobianPoint) -> Point:
    x, y, z = point
    if z % OUTER_Q == 0:
        return None
    z_inv = pow(z, -1, OUTER_Q)
    z2 = z_inv * z_inv % OUTER_Q
    return x * z2 % OUTER_Q, y * z2 * z_inv % OUTER_Q


def _jacobian_double(point: JacobianPoint) -> JacobianPoint:
    x1, y1, z1 = point
    q = OUTER_Q
    if z1 % q == 0 or y1 % q == 0:
        return (0, 1, 0)
    a = x1 * x1 % q
    b = y1 * y1 % q
    c = b * b % q
    d = (2 * (((x1 + b) * (x1 + b) - a - c) % q)) % q
    e = 3 * a % q
    f = e * e % q
    x3 = (f - 2 * d) % q
    y3 = (e * (d - x3) - 8 * c) % q
    z3 = 2 * y1 * z1 % q
    return x3, y3, z3


def _jacobian_add(left: JacobianPoint, right: JacobianPoint) -> JacobianPoint:
    q = OUTER_Q
    x1, y1, z1 = left
    x2, y2, z2 = right
    if z1 % q == 0:
        return right
    if z2 % q == 0:
        return left

    z1z1 = z1 * z1 % q
    z2z2 = z2 * z2 % q
    u1 = x1 * z2z2 % q
    u2 = x2 * z1z1 % q
    s1 = y1 * z2 % q * z2z2 % q
    s2 = y2 * z1 % q * z1z1 % q
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _jacobian_double(left)

    h = (u2 - u1) % q
    i = (2 * h) ** 2 % q
    j = h * i % q
    rr = 2 * (s2 - s1) % q
    v = u1 * i % q
    x3 = (rr * rr - j - 2 * v) % q
    y3 = (rr * (v - x3) - 2 * s1 * j) % q
    z3 = (((z1 + z2) ** 2 - z1z1 - z2z2) * h) % q
    return x3, y3, z3


def add(left: Point, right: Point) -> Point:
    if not is_on_curve(left) or not is_on_curve(right):
        raise OuterCurveCandidateError("cannot add an off-curve point")
    return _jacobian_to_affine(
        _jacobian_add(_jacobian_from_affine(left), _jacobian_from_affine(right))
    )


def multiply(point: Point, scalar: int) -> Point:
    if not is_on_curve(point):
        raise OuterCurveCandidateError("cannot multiply an off-curve point")
    scalar_i = int(scalar)
    if scalar_i < 0:
        return multiply(negate(point), -scalar_i)
    result = (0, 1, 0)
    addend = _jacobian_from_affine(point)
    while scalar_i:
        if scalar_i & 1:
            result = _jacobian_add(result, addend)
        addend = _jacobian_double(addend)
        scalar_i >>= 1
    return _jacobian_to_affine(result)


def is_in_prime_subgroup(point: Point) -> bool:
    return point is not None and is_on_curve(point) and multiply(point, BN254_FQ) is None


def normalise_to_prime_subgroup(point: Point) -> Point:
    """Project an on-curve point into the r-subgroup and act identically there."""

    if point is None:
        return None
    if not is_on_curve(point):
        raise OuterCurveCandidateError("cannot normalise an off-curve point")
    h_inverse = pow(OUTER_COFACTOR % BN254_FQ, -1, BN254_FQ)
    return multiply(multiply(point, OUTER_COFACTOR), h_inverse)


def compress_g1(point: Point) -> bytes:
    if point is None:
        return bytes([_INFINITY_MASK]) + bytes(COMPRESSED_G1_BYTES - 1)
    if not is_on_curve(point):
        raise OuterCurveCandidateError("cannot encode an off-curve point")
    x, y = point
    raw = bytearray(x.to_bytes(COMPRESSED_G1_BYTES, "big"))
    if raw[0] & ~_PAYLOAD_TOP_MASK:
        raise AssertionError("outer x-coordinate exceeds the 515-bit payload")
    if y & 1:
        raw[0] |= _SIGN_MASK
    return bytes(raw)


def decompress_g1(encoded: bytes, *, allow_infinity: bool = True) -> Point:
    raw = bytes(encoded)
    if len(raw) != COMPRESSED_G1_BYTES:
        raise OuterCurveCandidateError("compressed outer G1 encoding has wrong length")
    first = raw[0]
    if first & _RESERVED_MASK:
        raise OuterCurveCandidateError("compressed outer G1 encoding uses reserved flag bits")
    sign = bool(first & _SIGN_MASK)
    infinity = bool(first & _INFINITY_MASK)
    payload = bytearray(raw)
    payload[0] &= _PAYLOAD_TOP_MASK
    x = int.from_bytes(payload, "big")
    if infinity:
        if not allow_infinity:
            raise OuterCurveCandidateError("point at infinity is not allowed here")
        if sign or x != 0:
            raise OuterCurveCandidateError("noncanonical infinity encoding")
        return None
    if x >= OUTER_Q:
        raise OuterCurveCandidateError("outer G1 x-coordinate is not canonical")
    rhs = (x * x % OUTER_Q) * x % OUTER_Q
    rhs = (rhs + OUTER_B) % OUTER_Q
    # OUTER_Q == 3 mod 4.
    y = pow(rhs, (OUTER_Q + 1) // 4, OUTER_Q)
    if y * y % OUTER_Q != rhs:
        raise OuterCurveCandidateError("compressed outer G1 point is not on curve")
    if y == 0 and sign:
        raise OuterCurveCandidateError("noncanonical sign for zero y-coordinate")
    if bool(y & 1) != sign:
        y = (-y) % OUTER_Q
    point = (x, y)
    if compress_g1(point) != raw:
        raise OuterCurveCandidateError("compressed outer G1 encoding is not canonical")
    return point


@dataclass(frozen=True, slots=True)
class OuterCurveCandidate:
    base_modulus: int = OUTER_Q
    scalar_modulus: int = BN254_FQ
    trace: int = OUTER_TRACE
    cm_y: int = OUTER_CM_Y
    cofactor: int = OUTER_COFACTOR
    embedding_degree: int = OUTER_EMBEDDING_DEGREE
    cm_discriminant: int = OUTER_CM_DISCRIMINANT
    curve_a: int = OUTER_A
    curve_b: int = OUTER_B
    generator: tuple[int, int] = OUTER_G1_GENERATOR
    schema: str = "ranklock-cp6-bn254-outer-candidate-v1"

    @property
    def group_order(self) -> int:
        return self.base_modulus + 1 - self.trace

    @property
    def compressed_g1_bytes(self) -> int:
        return COMPRESSED_G1_BYTES

    @property
    def compressed_g2_lower_bound_bytes(self) -> int:
        # A degree-six CP curve normally represents the twist over Fq^3.  This
        # is a geometry lower bound, not a complete G2 serialization spec.
        return 3 * COMPRESSED_G1_BYTES

    @property
    def rho(self) -> float:
        return self.base_modulus.bit_length() / self.scalar_modulus.bit_length()

    @lru_cache(maxsize=1)
    def validate(self) -> dict[str, object]:
        divisors = tuple(
            divisor
            for divisor in range(1, self.embedding_degree)
            if self.embedding_degree % divisor == 0
        )
        checks = {
            "base_probable_prime": is_strong_probable_prime(self.base_modulus),
            "scalar_probable_prime": is_strong_probable_prime(self.scalar_modulus),
            "CM_equation": (
                self.trace * self.trace
                + self.cm_discriminant * self.cm_y * self.cm_y
                == 4 * self.base_modulus
            ),
            "group_order_factorisation": self.group_order
            == self.scalar_modulus * self.cofactor,
            "cofactor_coprime_to_scalar": gcd(self.cofactor, self.scalar_modulus) == 1,
            "embedding_degree_upper": pow(
                self.base_modulus, self.embedding_degree, self.scalar_modulus
            )
            == 1,
            "embedding_degree_exact": all(
                pow(self.base_modulus, divisor, self.scalar_modulus) != 1
                for divisor in divisors
            ),
            "generator_on_curve": is_on_curve(self.generator),
            "generator_nonidentity": self.generator is not None,
            "generator_has_r_order": multiply(self.generator, self.scalar_modulus)
            is None,
            "known_full_curve_point_on_curve": is_on_curve(
                OUTER_KNOWN_NON_SUBGROUP_POINT
            ),
            "known_full_curve_point_not_in_r_subgroup": not is_in_prime_subgroup(
                OUTER_KNOWN_NON_SUBGROUP_POINT
            ),
        }
        if not all(checks.values()):
            failed = [name for name, value in checks.items() if not value]
            raise OuterCurveCandidateError(
                "outer curve candidate validation failed: " + ", ".join(failed)
            )
        return {
            "schema": self.schema,
            "evidence_class": (
                "EXECUTABLE number-theoretic/curve consistency; probabilistic primality; "
                "not an audited production parameter set"
            ),
            "base_modulus": str(self.base_modulus),
            "base_bits": self.base_modulus.bit_length(),
            "scalar_modulus": str(self.scalar_modulus),
            "scalar_bits": self.scalar_modulus.bit_length(),
            "trace": str(self.trace),
            "cofactor": str(self.cofactor),
            "cofactor_bits": self.cofactor.bit_length(),
            "embedding_degree": self.embedding_degree,
            "rho_bit_ratio": self.rho,
            "compressed_G1_bytes": self.compressed_g1_bytes,
            "compressed_G2_geometry_lower_bound_bytes": (
                self.compressed_g2_lower_bound_bytes
            ),
            "checks": checks,
            "source_boundary": (
                "The one-sided-SNARK paper states that outer curves to BN254 can be "
                "constructed with Cocks-Pinch/Brezing-Weng curves whose base field is "
                "about twice the scalar-field size; it does not publish this exact candidate."
            ),
        }


def outer_curve_candidate_report() -> dict[str, object]:
    candidate = OuterCurveCandidate()
    report = candidate.validate()
    projected = normalise_to_prime_subgroup(OUTER_KNOWN_NON_SUBGROUP_POINT)
    report["normalisation"] = {
        "known_point_projects_to_nonidentity": projected is not None,
        "projected_point_in_prime_subgroup": is_in_prime_subgroup(projected),
        "normalisation_is_identity_on_generator": normalise_to_prime_subgroup(
            candidate.generator
        )
        == candidate.generator,
        "security_boundary": (
            "Cofactor normalisation removes torsion at the public group layer but does "
            "not by itself bind the normalised group object to the scalar transcript witness."
        ),
    }
    return report
