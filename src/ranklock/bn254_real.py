from __future__ import annotations

"""Small, dependency-free BN254 implementation used by the RankVM prototype.

This is intentionally an auditable research implementation, not constant-time production
cryptography.  It follows the conventional BN254 tower/optimal-Ate formulas used by py_ecc and
substrate-bn, but keeps a detailed operation counter so the verifier can be lowered to a typed
LIN/TENSOR trace.
"""

from dataclasses import dataclass, field, fields
from typing import ClassVar, Iterable, Sequence, TypeVar, Generic, Any

FIELD_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583
CURVE_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ATE_LOOP_COUNT = 29793968203157093288
LOG_ATE_LOOP_COUNT = 63
PSEUDO_BINARY_ENCODING = (
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1,
    0, 0, 1, 0, -1, 0, 0, 0, 0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
    -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, 1, 1,
)
assert sum(value * (2**index) for index, value in enumerate(PSEUDO_BINARY_ENCODING)) == ATE_LOOP_COUNT


@dataclass(slots=True)
class OpCounter:
    fq_add: int = 0
    fq_sub: int = 0
    fq_neg: int = 0
    fq_mul: int = 0
    fq_square: int = 0
    fq_inv: int = 0
    fq_sqrt: int = 0
    fq2_mul: int = 0
    fq2_square: int = 0
    fq2_inv: int = 0
    fq12_mul: int = 0
    fq12_square: int = 0
    fq12_inv: int = 0
    g1_add: int = 0
    g1_double: int = 0
    g1_scalar_bits: int = 0
    g2_add: int = 0
    g2_double: int = 0
    miller_line: int = 0
    miller_double_step: int = 0
    miller_add_step: int = 0
    final_exp_squares: int = 0
    final_exp_multiplies: int = 0
    metadata: dict[str, int | str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, int | str | dict[str, int | str]]:
        values: dict[str, int | str | dict[str, int | str]] = {}
        for descriptor in fields(self):
            name = descriptor.name
            value = getattr(self, name)
            values[name] = dict(value) if name == "metadata" else value
        return values


_ACTIVE_COUNTER: OpCounter | None = None


class count_ops:
    def __init__(self, counter: OpCounter):
        self.counter = counter
        self.previous: OpCounter | None = None

    def __enter__(self) -> OpCounter:
        global _ACTIVE_COUNTER
        self.previous = _ACTIVE_COUNTER
        _ACTIVE_COUNTER = self.counter
        return self.counter

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        global _ACTIVE_COUNTER
        _ACTIVE_COUNTER = self.previous


def _bump(name: str, amount: int = 1) -> None:
    if _ACTIVE_COUNTER is not None:
        setattr(_ACTIVE_COUNTER, name, getattr(_ACTIVE_COUNTER, name) + amount)


def prime_field_inv(a: int, modulus: int = FIELD_MODULUS) -> int:
    a %= modulus
    if a == 0:
        return 0
    _bump("fq_inv")
    return pow(a, modulus - 2, modulus)


def sqrt_fq(value: int) -> int | None:
    value %= FIELD_MODULUS
    _bump("fq_sqrt")
    if value == 0:
        return 0
    root = pow(value, (FIELD_MODULUS + 1) // 4, FIELD_MODULUS)
    if root * root % FIELD_MODULUS != value:
        return None
    return root


@dataclass(frozen=True, slots=True)
class FQ:
    n: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "n", self.n % FIELD_MODULUS)

    @classmethod
    def zero(cls) -> "FQ":
        return cls(0)

    @classmethod
    def one(cls) -> "FQ":
        return cls(1)

    def __int__(self) -> int:
        return self.n

    def __add__(self, other: int | "FQ") -> "FQ":
        _bump("fq_add")
        return FQ(self.n + (other.n if isinstance(other, FQ) else other))

    __radd__ = __add__

    def __sub__(self, other: int | "FQ") -> "FQ":
        _bump("fq_sub")
        return FQ(self.n - (other.n if isinstance(other, FQ) else other))

    def __rsub__(self, other: int | "FQ") -> "FQ":
        _bump("fq_sub")
        return FQ((other.n if isinstance(other, FQ) else other) - self.n)

    def __mul__(self, other: int | "FQ") -> "FQ":
        _bump("fq_mul")
        return FQ(self.n * (other.n if isinstance(other, FQ) else other))

    __rmul__ = __mul__

    def square(self) -> "FQ":
        _bump("fq_square")
        _bump("fq_mul")
        return FQ(self.n * self.n)

    def __truediv__(self, other: int | "FQ") -> "FQ":
        denominator = other.n if isinstance(other, FQ) else other
        return FQ(self.n * prime_field_inv(denominator))

    def __rtruediv__(self, other: int | "FQ") -> "FQ":
        numerator = other.n if isinstance(other, FQ) else other
        return FQ(numerator * prime_field_inv(self.n))

    def __pow__(self, exponent: int) -> "FQ":
        if exponent < 0:
            return (self.inv()) ** (-exponent)
        result = FQ.one()
        base = self
        e = exponent
        while e:
            if e & 1:
                result = result * base
            e >>= 1
            if e:
                base = base.square()
        return result

    def __neg__(self) -> "FQ":
        _bump("fq_neg")
        return FQ(-self.n)

    def inv(self) -> "FQ":
        return FQ(prime_field_inv(self.n))

    def sqrt(self) -> "FQ | None":
        root = sqrt_fq(self.n)
        return None if root is None else FQ(root)

    def to_bytes(self) -> bytes:
        return self.n.to_bytes(32, "big")


T_FQP = TypeVar("T_FQP", bound="FQP")


def _poly_degree(poly: Sequence[int]) -> int:
    degree = len(poly) - 1
    while degree and poly[degree] % FIELD_MODULUS == 0:
        degree -= 1
    return degree


def _poly_div(high: Sequence[int], low: Sequence[int]) -> list[int]:
    high_work = [x % FIELD_MODULUS for x in high]
    low_degree = _poly_degree(low)
    high_degree = _poly_degree(high_work)
    if low_degree == 0 and low[0] % FIELD_MODULUS == 0:
        raise ZeroDivisionError("polynomial division by zero")
    quotient = [0] * max(1, high_degree - low_degree + 1)
    inv_lead = prime_field_inv(low[low_degree])
    for position in range(high_degree - low_degree, -1, -1):
        coeff = high_work[low_degree + position] * inv_lead % FIELD_MODULUS
        quotient[position] = coeff
        if coeff:
            for index in range(low_degree + 1):
                high_work[index + position] = (
                    high_work[index + position] - coeff * low[index]
                ) % FIELD_MODULUS
    while len(quotient) > 1 and quotient[-1] == 0:
        quotient.pop()
    return quotient


@dataclass(frozen=True, slots=True)
class FQP:
    coeffs: tuple[int, ...]

    modulus_coeffs: ClassVar[tuple[int, ...]] = ()
    degree: ClassVar[int] = 0
    counter_mul_name: ClassVar[str] = "fq2_mul"
    counter_square_name: ClassVar[str] = "fq2_square"
    counter_inv_name: ClassVar[str] = "fq2_inv"

    def __post_init__(self) -> None:
        if len(self.coeffs) != self.degree:
            raise ValueError(f"expected {self.degree} coefficients")
        object.__setattr__(self, "coeffs", tuple(c % FIELD_MODULUS for c in self.coeffs))

    @classmethod
    def zero(cls: type[T_FQP]) -> T_FQP:
        return cls((0,) * cls.degree)

    @classmethod
    def one(cls: type[T_FQP]) -> T_FQP:
        return cls((1,) + (0,) * (cls.degree - 1))

    def __add__(self: T_FQP, other: int | T_FQP) -> T_FQP:
        if isinstance(other, int):
            values = list(self.coeffs)
            values[0] = (values[0] + other) % FIELD_MODULUS
            return type(self)(tuple(values))
        return type(self)(tuple((a + b) % FIELD_MODULUS for a, b in zip(self.coeffs, other.coeffs, strict=True)))

    __radd__ = __add__

    def __sub__(self: T_FQP, other: int | T_FQP) -> T_FQP:
        if isinstance(other, int):
            values = list(self.coeffs)
            values[0] = (values[0] - other) % FIELD_MODULUS
            return type(self)(tuple(values))
        return type(self)(tuple((a - b) % FIELD_MODULUS for a, b in zip(self.coeffs, other.coeffs, strict=True)))

    def __rsub__(self: T_FQP, other: int | T_FQP) -> T_FQP:
        if isinstance(other, int):
            values = [(-a) % FIELD_MODULUS for a in self.coeffs]
            values[0] = (values[0] + other) % FIELD_MODULUS
            return type(self)(tuple(values))
        return other - self

    def __neg__(self: T_FQP) -> T_FQP:
        return type(self)(tuple((-a) % FIELD_MODULUS for a in self.coeffs))

    def __mul__(self: T_FQP, other: int | T_FQP) -> T_FQP:
        if isinstance(other, int):
            # Multiplication by a public scalar is linear for RankVM accounting.
            return type(self)(tuple((a * other) % FIELD_MODULUS for a in self.coeffs))
        if type(self) is not type(other):
            return NotImplemented
        _bump(self.counter_mul_name)
        # Count the base-field tensor products performed by this literal polynomial multiply.
        _bump("fq_mul", self.degree * self.degree)
        product = [0] * (2 * self.degree - 1)
        for i, left in enumerate(self.coeffs):
            for j, right in enumerate(other.coeffs):
                product[i + j] = (product[i + j] + left * right) % FIELD_MODULUS
        while len(product) > self.degree:
            top = product.pop()
            exponent = len(product) - self.degree
            for index, coefficient in enumerate(self.modulus_coeffs):
                product[exponent + index] = (
                    product[exponent + index] - top * coefficient
                ) % FIELD_MODULUS
        return type(self)(tuple(product))

    __rmul__ = __mul__

    def square(self: T_FQP) -> T_FQP:
        _bump(self.counter_square_name)
        return self * self

    def __truediv__(self: T_FQP, other: int | T_FQP) -> T_FQP:
        if isinstance(other, int):
            inverse = prime_field_inv(other)
            return type(self)(tuple((a * inverse) % FIELD_MODULUS for a in self.coeffs))
        return self * other.inv()

    def __rtruediv__(self: T_FQP, other: int | T_FQP) -> T_FQP:
        if isinstance(other, int):
            return self.inv() * other
        return other * self.inv()

    def __pow__(self: T_FQP, exponent: int) -> T_FQP:
        if exponent < 0:
            return (self.inv()) ** (-exponent)
        result = type(self).one()
        base = self
        e = exponent
        is_final_exp = isinstance(self, FQ12) and exponent == FINAL_EXPONENT
        while e:
            if e & 1:
                result = result * base
                if is_final_exp:
                    _bump("final_exp_multiplies")
            e >>= 1
            if e:
                base = base.square()
                if is_final_exp:
                    _bump("final_exp_squares")
        return result

    def inv(self: T_FQP) -> T_FQP:
        _bump(self.counter_inv_name)
        # Extended Euclidean algorithm over Fq[x].
        lm = [1] + [0] * self.degree
        hm = [0] * (self.degree + 1)
        low = list(self.coeffs) + [0]
        high = list(self.modulus_coeffs) + [1]
        while _poly_degree(low):
            ratio = _poly_div(high, low)
            ratio += [0] * (self.degree + 1 - len(ratio))
            nm = hm[:]
            new = high[:]
            for i in range(self.degree + 1):
                if lm[i] == 0 and low[i] == 0:
                    continue
                for j in range(self.degree + 1 - i):
                    if ratio[j] == 0:
                        continue
                    nm[i + j] = (nm[i + j] - lm[i] * ratio[j]) % FIELD_MODULUS
                    new[i + j] = (new[i + j] - low[i] * ratio[j]) % FIELD_MODULUS
            lm, low, hm, high = nm, new, lm, low
        inverse_constant = prime_field_inv(low[0])
        return type(self)(tuple((coefficient * inverse_constant) % FIELD_MODULUS for coefficient in lm[: self.degree]))

    def to_bytes(self) -> bytes:
        return b"".join(c.to_bytes(32, "big") for c in self.coeffs)


@dataclass(frozen=True, slots=True)
class FQ2(FQP):
    modulus_coeffs: ClassVar[tuple[int, ...]] = (1, 0)  # x^2 + 1
    degree: ClassVar[int] = 2
    counter_mul_name: ClassVar[str] = "fq2_mul"
    counter_square_name: ClassVar[str] = "fq2_square"
    counter_inv_name: ClassVar[str] = "fq2_inv"

    @property
    def real(self) -> int:
        return self.coeffs[0]

    @property
    def imag(self) -> int:
        return self.coeffs[1]

    def sqrt(self) -> "FQ2 | None":
        """Square root in Fq[i]/(i^2+1), using two Fq square roots."""
        a, b = self.coeffs
        if a == 0 and b == 0:
            return FQ2.zero()
        norm_root = sqrt_fq((a * a + b * b) % FIELD_MODULUS)
        if norm_root is None:
            return None
        inverse_two = (FIELD_MODULUS + 1) // 2
        candidates = [
            (a + norm_root) * inverse_two % FIELD_MODULUS,
            (a - norm_root) * inverse_two % FIELD_MODULUS,
        ]
        for candidate in candidates:
            x = sqrt_fq(candidate)
            if x is None or x == 0:
                continue
            y = b * prime_field_inv(2 * x) % FIELD_MODULUS
            root = FQ2((x, y))
            if root * root == self:
                return root
            root = FQ2((x, -y))
            if root * root == self:
                return root
        # Purely real special cases.
        if b == 0:
            x = sqrt_fq(a)
            if x is not None:
                return FQ2((x, 0))
            y = sqrt_fq(-a)
            if y is not None:
                return FQ2((0, y))
        return None


@dataclass(frozen=True, slots=True)
class FQ12(FQP):
    modulus_coeffs: ClassVar[tuple[int, ...]] = (82, 0, 0, 0, 0, 0, -18, 0, 0, 0, 0, 0)
    degree: ClassVar[int] = 12
    counter_mul_name: ClassVar[str] = "fq12_mul"
    counter_square_name: ClassVar[str] = "fq12_square"
    counter_inv_name: ClassVar[str] = "fq12_inv"


FINAL_EXPONENT = (FIELD_MODULUS**12 - 1) // CURVE_ORDER


def _compute_frobenius_basis() -> tuple[tuple[int, ...], ...]:
    rows: list[tuple[int, ...]] = []
    # Precomputation happens with no active counter; evaluation is a public linear map.
    for index in range(12):
        basis = FQ12(tuple(1 if coefficient == index else 0 for coefficient in range(12)))
        rows.append((basis ** FIELD_MODULUS).coeffs)
    return tuple(rows)


_FROBENIUS_P_BASIS = _compute_frobenius_basis()


def frobenius_p(value: FQ12) -> FQ12:
    output = [0] * 12
    for scalar, image in zip(value.coeffs, _FROBENIUS_P_BASIS, strict=True):
        if scalar == 0:
            continue
        for index, coefficient in enumerate(image):
            output[index] = (output[index] + scalar * coefficient) % FIELD_MODULUS
    return FQ12(tuple(output))


FieldElement = FQ | FQ2 | FQ12
Point = tuple[FieldElement, FieldElement, FieldElement]


def _field_zero(value: FieldElement) -> FieldElement:
    return type(value).zero()


def _field_one(value: FieldElement) -> FieldElement:
    return type(value).one()


def point_at_infinity(field_type: type[FQ] | type[FQ2] | type[FQ12]) -> Point:
    return (field_type.one(), field_type.one(), field_type.zero())


def is_inf(point: Point) -> bool:
    return point[2] == type(point[2]).zero()


def eq_points(left: Point, right: Point) -> bool:
    if is_inf(left) and is_inf(right):
        return True
    if is_inf(left) or is_inf(right):
        return False
    return left[0] * right[2] == right[0] * left[2] and left[1] * right[2] == right[1] * left[2]


def normalize(point: Point) -> Point:
    if is_inf(point):
        return point_at_infinity(type(point[0]))
    z_inv = point[2].inv()  # type: ignore[attr-defined]
    return (point[0] * z_inv, point[1] * z_inv, type(point[2]).one())


def is_on_curve(point: Point, b: FieldElement) -> bool:
    if is_inf(point):
        return True
    x, y, z = point
    return y * y * z == x * x * x + b * z * z * z


def double(point: Point, *, group: str | None = None) -> Point:
    if is_inf(point):
        return point
    if group == "g1":
        _bump("g1_double")
    elif group == "g2":
        _bump("g2_double")
    x, y, z = point
    w = x * x * 3
    s = y * z
    b = x * y * s
    h = w * w - b * 8
    s_squared = s * s
    new_x = h * s * 2
    new_y = w * (b * 4 - h) - y * y * s_squared * 8
    new_z = s * s_squared * 8
    return (new_x, new_y, new_z)


def add(left: Point, right: Point, *, group: str | None = None) -> Point:
    if is_inf(left):
        return right
    if is_inf(right):
        return left
    if group == "g1":
        _bump("g1_add")
    elif group == "g2":
        _bump("g2_add")
    x1, y1, z1 = left
    x2, y2, z2 = right
    u1 = y2 * z1
    u2 = y1 * z2
    v1 = x2 * z1
    v2 = x1 * z2
    if v1 == v2 and u1 == u2:
        return double(left, group=group)
    if v1 == v2:
        return point_at_infinity(type(x1))
    u = u1 - u2
    v = v1 - v2
    v_squared = v * v
    v_squared_v2 = v_squared * v2
    v_cubed = v * v_squared
    w = z1 * z2
    a = u * u * w - v_cubed - v_squared_v2 * 2
    new_x = v * a
    new_y = u * (v_squared_v2 - a) - v_cubed * u2
    new_z = v_cubed * w
    return (new_x, new_y, new_z)


def neg(point: Point) -> Point:
    return (point[0], -point[1], point[2])


def multiply(point: Point, scalar: int, *, group: str | None = None) -> Point:
    if scalar < 0:
        return multiply(neg(point), -scalar, group=group)
    result = point_at_infinity(type(point[0]))
    addend = point
    bits = scalar.bit_length()
    if group == "g1":
        _bump("g1_scalar_bits", bits)
    value = scalar
    while value:
        if value & 1:
            result = add(result, addend, group=group)
        value >>= 1
        if value:
            addend = double(addend, group=group)
    return result


B = FQ(3)
B2 = FQ2((3, 0)) / FQ2((9, 1))
B12 = FQ12((3,) + (0,) * 11)

G1: Point = (FQ(1), FQ(2), FQ.one())
G2: Point = (
    FQ2((
        10857046999023057135944570762232829481370756359578518086990519993285655852781,
        11559732032986387107991004021392285783925812861821192530917403151452391805634,
    )),
    FQ2((
        8495653923123431417604973247489272438418190587263600148770280649306958101930,
        4082367875863433681332203403145435568316851327593401208105741076214120093531,
    )),
    FQ2.one(),
)


def cast_g1_to_fq12(point: Point) -> Point:
    if is_inf(point):
        return point_at_infinity(FQ12)
    return tuple(
        FQ12((int(coordinate.n),) + (0,) * 11)  # type: ignore[union-attr]
        for coordinate in point
    )  # type: ignore[return-value]


_W = FQ12((0, 1) + (0,) * 10)
_W2 = _W * _W
_W3 = _W2 * _W


def _embed_fq2(value: FQ2) -> FQ12:
    # Map a + bi to (a - 9b) + b*w in the Fq12 representation used by py_ecc.
    a, b = value.coeffs
    return FQ12(((a - 9 * b) % FIELD_MODULUS,) + (0,) * 5 + (b,) + (0,) * 5)


def twist(point: Point) -> Point:
    if is_inf(point):
        return point_at_infinity(FQ12)
    x, y, z = point
    assert isinstance(x, FQ2) and isinstance(y, FQ2) and isinstance(z, FQ2)
    return (_embed_fq2(x) * _W2, _embed_fq2(y) * _W3, _embed_fq2(z))


def linefunc(left: Point, right: Point, target: Point) -> tuple[FQ12, FQ12]:
    _bump("miller_line")
    x1, y1, z1 = left
    x2, y2, z2 = right
    xt, yt, zt = target
    assert isinstance(x1, FQ12) and isinstance(x2, FQ12) and isinstance(xt, FQ12)
    numerator = y2 * z1 - y1 * z2
    denominator = x2 * z1 - x1 * z2
    zero = FQ12.zero()
    if denominator != zero:
        return (
            numerator * (xt * z1 - x1 * zt) - denominator * (yt * z1 - y1 * zt),
            denominator * zt * z1,
        )
    if numerator == zero:
        numerator = x1 * x1 * 3
        denominator = y1 * z1 * 2
        return (
            numerator * (xt * z1 - x1 * zt) - denominator * (yt * z1 - y1 * zt),
            denominator * zt * z1,
        )
    return (xt * z1 - x1 * zt, z1 * zt)


def miller_loop_fraction(q: Point, p: Point) -> tuple[FQ12, FQ12]:
    if is_inf(q) or is_inf(p):
        return FQ12.one(), FQ12.one()
    r = q
    f_num = FQ12.one()
    f_den = FQ12.one()
    for digit in reversed(PSEUDO_BINARY_ENCODING[:64]):
        numerator, denominator = linefunc(r, r, p)
        f_num = f_num * f_num * numerator
        f_den = f_den * f_den * denominator
        r = double(r)
        _bump("miller_double_step")
        if digit == 1:
            numerator, denominator = linefunc(r, q, p)
            f_num = f_num * numerator
            f_den = f_den * denominator
            r = add(r, q)
            _bump("miller_add_step")
        elif digit == -1:
            nq = neg(q)
            numerator, denominator = linefunc(r, nq, p)
            f_num = f_num * numerator
            f_den = f_den * denominator
            r = add(r, nq)
            _bump("miller_add_step")

    q1 = (frobenius_p(q[0]), frobenius_p(q[1]), frobenius_p(q[2]))
    nq2 = (frobenius_p(q1[0]), -frobenius_p(q1[1]), frobenius_p(q1[2]))
    numerator, denominator = linefunc(r, q1, p)
    f_num = f_num * numerator
    f_den = f_den * denominator
    r = add(r, q1)
    numerator, denominator = linefunc(r, nq2, p)
    f_num = f_num * numerator
    f_den = f_den * denominator
    return f_num, f_den


def pairing_product(pairs: Iterable[tuple[Point, Point]], *, final_exponentiate: bool = True) -> FQ12:
    numerator = FQ12.one()
    denominator = FQ12.one()
    for g1_point, g2_point in pairs:
        if not is_on_curve(g1_point, B):
            raise ValueError("G1 point is not on BN254")
        if not is_on_curve(g2_point, B2):
            raise ValueError("G2 point is not on BN254 twist")
        pair_num, pair_den = miller_loop_fraction(twist(g2_point), cast_g1_to_fq12(g1_point))
        numerator = numerator * pair_num
        denominator = denominator * pair_den
    accumulator = numerator / denominator
    return accumulator ** FINAL_EXPONENT if final_exponentiate else accumulator


def affine(point: Point) -> tuple[FieldElement, FieldElement] | None:
    if is_inf(point):
        return None
    normalized = normalize(point)
    return normalized[0], normalized[1]


def fq_from_bytes(raw: bytes) -> FQ:
    if len(raw) != 32:
        raise ValueError("Fq encoding must be 32 bytes")
    value = int.from_bytes(raw, "big")
    if value >= FIELD_MODULUS:
        raise ValueError("non-canonical Fq")
    return FQ(value)


def fr_from_bytes(raw: bytes) -> int:
    if len(raw) != 32:
        raise ValueError("Fr encoding must be 32 bytes")
    value = int.from_bytes(raw, "big")
    if value >= CURVE_ORDER:
        raise ValueError("non-canonical Fr")
    return value


def decompress_g1(raw: bytes) -> Point:
    if len(raw) != 32:
        raise ValueError("compressed G1 must be 32 bytes")
    flag = raw[0] & 0xC0
    if flag not in (0x80, 0xC0):
        raise ValueError("invalid compressed G1 flag")
    x_raw = bytearray(raw)
    x_raw[0] &= 0x3F
    x = fq_from_bytes(bytes(x_raw))
    y_sq = x * x * x + B
    y = y_sq.sqrt()
    if y is None:
        raise ValueError("invalid compressed G1 point")
    neg_y = -y
    smaller, larger = (y, neg_y) if y.n < neg_y.n else (neg_y, y)
    selected = larger if flag == 0xC0 else smaller
    point = (x, selected, FQ.one())
    if not is_on_curve(point, B):
        raise ValueError("G1 decompression produced off-curve point")
    return point


def compress_g1(point: Point) -> bytes:
    coordinates = affine(point)
    if coordinates is None:
        raise ValueError("infinity encoding not supported")
    x, y = coordinates
    assert isinstance(x, FQ) and isinstance(y, FQ)
    neg_y = -y
    flag = 0x80 if y.n < neg_y.n else 0xC0
    raw = bytearray(x.to_bytes())
    raw[0] |= flag
    return bytes(raw)


def decompress_g2(raw: bytes) -> Point:
    if len(raw) != 64:
        raise ValueError("compressed G2 must be 64 bytes")
    flag = raw[0] & 0xC0
    if flag == 0x40:
        raise ValueError("infinity encoding unsupported")
    if flag not in (0x80, 0xC0):
        raise ValueError("invalid compressed G2 flag")
    x1_raw = bytearray(raw[:32])
    x1_raw[0] &= 0x3F
    x1 = fq_from_bytes(bytes(x1_raw)).n
    x0 = fq_from_bytes(raw[32:]).n
    x = FQ2((x0, x1))
    y_sq = x * x * x + B2
    y = y_sq.sqrt()
    if y is None:
        raise ValueError("invalid compressed G2 point")
    neg_y = -y
    y_key = (y.imag, y.real)
    neg_key = (neg_y.imag, neg_y.real)
    smaller, larger = (y, neg_y) if y_key < neg_key else (neg_y, y)
    selected = larger if flag == 0xC0 else smaller
    point = (x, selected, FQ2.one())
    if not is_on_curve(point, B2):
        raise ValueError("G2 decompression produced off-curve point")
    return point


def compress_g2(point: Point) -> bytes:
    coordinates = affine(point)
    if coordinates is None:
        raise ValueError("infinity encoding not supported")
    x, y = coordinates
    assert isinstance(x, FQ2) and isinstance(y, FQ2)
    neg_y = -y
    flag = 0x80 if (y.imag, y.real) < (neg_y.imag, neg_y.real) else 0xC0
    x1 = bytearray(x.imag.to_bytes(32, "big"))
    x1[0] |= flag
    return bytes(x1) + x.real.to_bytes(32, "big")


def parse_g1_uncompressed(raw: bytes) -> Point:
    if len(raw) != 64:
        raise ValueError("uncompressed G1 must be 64 bytes")
    point = (fq_from_bytes(raw[:32]), fq_from_bytes(raw[32:]), FQ.one())
    if not is_on_curve(point, B):
        raise ValueError("off-curve G1")
    return point


def parse_g2_uncompressed(raw: bytes) -> Point:
    if len(raw) != 128:
        raise ValueError("uncompressed G2 must be 128 bytes")
    x1 = fq_from_bytes(raw[:32]).n
    x0 = fq_from_bytes(raw[32:64]).n
    y1 = fq_from_bytes(raw[64:96]).n
    y0 = fq_from_bytes(raw[96:]).n
    point = (FQ2((x0, x1)), FQ2((y0, y1)), FQ2.one())
    if not is_on_curve(point, B2):
        raise ValueError("off-curve G2")
    return point


def serialize_g1_uncompressed(point: Point) -> bytes:
    coordinates = affine(point)
    if coordinates is None:
        raise ValueError("cannot serialize infinity")
    x, y = coordinates
    assert isinstance(x, FQ) and isinstance(y, FQ)
    return x.to_bytes() + y.to_bytes()


def serialize_g2_uncompressed(point: Point) -> bytes:
    coordinates = affine(point)
    if coordinates is None:
        raise ValueError("cannot serialize infinity")
    x, y = coordinates
    assert isinstance(x, FQ2) and isinstance(y, FQ2)
    return (
        x.imag.to_bytes(32, "big")
        + x.real.to_bytes(32, "big")
        + y.imag.to_bytes(32, "big")
        + y.real.to_bytes(32, "big")
    )


# Cheap import-time sanity checks. These do not run a pairing.
assert FIELD_MODULUS % 4 == 3
assert is_on_curve(G1, B)
assert is_on_curve(G2, B2)
