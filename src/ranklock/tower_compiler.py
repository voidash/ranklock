from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .field import BN254_BASE_FIELD
from .rank_ir import LinearForm, OutputExpression, RankDecomposition, RankRecorder

P = BN254_BASE_FIELD


@dataclass(frozen=True, slots=True)
class SideT2:
    a: LinearForm
    b: LinearForm

    def __add__(self, other: "SideT2") -> "SideT2":
        return SideT2(self.a + other.a, self.b + other.b)

    def __sub__(self, other: "SideT2") -> "SideT2":
        return SideT2(self.a - other.a, self.b - other.b)

    def scale(self, scalar: int) -> "SideT2":
        return SideT2(self.a.scale(scalar), self.b.scale(scalar))

    def multiply(self, other: "SideT2", recorder: RankRecorder) -> "OutT2":
        ac = recorder.multiply(self.a, other.a)
        bd = recorder.multiply(self.b, other.b)
        cross = recorder.multiply(self.a + self.b, other.a + other.b)
        return OutT2(ac - bd, cross - ac - bd)

    def square(self, recorder: RankRecorder) -> "OutT2":
        real = recorder.multiply(self.a + self.b, self.a - self.b)
        imag = recorder.multiply(self.a, self.b).scale(2)
        return OutT2(real, imag)


@dataclass(frozen=True, slots=True)
class OutT2:
    a: OutputExpression
    b: OutputExpression

    def __add__(self, other: "OutT2") -> "OutT2":
        return OutT2(self.a + other.a, self.b + other.b)

    def __sub__(self, other: "OutT2") -> "OutT2":
        return OutT2(self.a - other.a, self.b - other.b)

    def __neg__(self) -> "OutT2":
        return OutT2(-self.a, -self.b)

    def scale(self, scalar: int) -> "OutT2":
        return OutT2(self.a.scale(scalar), self.b.scale(scalar))

    def mul_xi(self) -> "OutT2":
        # (a + b*u) * (9 + u) = (9a-b) + (a+9b)u.
        return OutT2(self.a.scale(9) - self.b, self.a + self.b.scale(9))


@dataclass(frozen=True, slots=True)
class SideT6:
    c0: SideT2
    c1: SideT2
    c2: SideT2

    def __add__(self, other: "SideT6") -> "SideT6":
        return SideT6(self.c0 + other.c0, self.c1 + other.c1, self.c2 + other.c2)

    def __sub__(self, other: "SideT6") -> "SideT6":
        return SideT6(self.c0 - other.c0, self.c1 - other.c1, self.c2 - other.c2)

    def multiply(self, other: "SideT6", recorder: RankRecorder) -> "OutT6":
        t0 = self.c0.multiply(other.c0, recorder)
        t1 = self.c1.multiply(other.c1, recorder)
        t2 = self.c2.multiply(other.c2, recorder)
        cross12 = (self.c1 + self.c2).multiply(other.c1 + other.c2, recorder) - t1 - t2
        cross01 = (self.c0 + self.c1).multiply(other.c0 + other.c1, recorder) - t0 - t1
        cross02 = (self.c0 + self.c2).multiply(other.c0 + other.c2, recorder) - t0 - t2
        return OutT6(
            t0 + cross12.mul_xi(),
            cross01 + t2.mul_xi(),
            cross02 + t1,
        )

    def square(self, recorder: RankRecorder) -> "OutT6":
        s0 = self.c0.square(recorder)
        s1 = self.c1.square(recorder)
        s2 = self.c2.square(recorder)
        p01 = self.c0.multiply(self.c1, recorder).scale(2)
        p02 = self.c0.multiply(self.c2, recorder).scale(2)
        p12 = self.c1.multiply(self.c2, recorder).scale(2)
        return OutT6(s0 + p12.mul_xi(), p01 + s2.mul_xi(), s1 + p02)


@dataclass(frozen=True, slots=True)
class OutT6:
    c0: OutT2
    c1: OutT2
    c2: OutT2

    def __add__(self, other: "OutT6") -> "OutT6":
        return OutT6(self.c0 + other.c0, self.c1 + other.c1, self.c2 + other.c2)

    def __sub__(self, other: "OutT6") -> "OutT6":
        return OutT6(self.c0 - other.c0, self.c1 - other.c1, self.c2 - other.c2)

    def scale(self, scalar: int) -> "OutT6":
        return OutT6(self.c0.scale(scalar), self.c1.scale(scalar), self.c2.scale(scalar))

    def mul_by_v(self) -> "OutT6":
        return OutT6(self.c2.mul_xi(), self.c0, self.c1)


@dataclass(frozen=True, slots=True)
class SideT12:
    c0: SideT6
    c1: SideT6

    def multiply(self, other: "SideT12", recorder: RankRecorder) -> "OutT12":
        t0 = self.c0.multiply(other.c0, recorder)
        t1 = self.c1.multiply(other.c1, recorder)
        return OutT12(
            t0 + t1.mul_by_v(),
            (self.c0 + self.c1).multiply(other.c0 + other.c1, recorder) - t0 - t1,
        )

    def square(self, recorder: RankRecorder) -> "OutT12":
        s0 = self.c0.square(recorder)
        s1 = self.c1.square(recorder)
        cross = self.c0.multiply(self.c1, recorder).scale(2)
        return OutT12(s0 + s1.mul_by_v(), cross)


@dataclass(frozen=True, slots=True)
class OutT12:
    c0: OutT6
    c1: OutT6


def _side_t12_from_flat(variables: Sequence[LinearForm]) -> SideT12:
    if len(variables) != 12:
        raise ValueError("FQ12 input must have 12 flat coefficients")

    def component(low_index: int) -> SideT2:
        low = variables[low_index]
        high = variables[low_index + 6]
        return SideT2(low + high.scale(9), high)

    return SideT12(
        SideT6(component(0), component(2), component(4)),
        SideT6(component(1), component(3), component(5)),
    )


def _out_t12_to_flat(value: OutT12) -> tuple[OutputExpression, ...]:
    coefficients: list[OutputExpression | None] = [None] * 12

    def write(index: int, component: OutT2) -> None:
        coefficients[index] = component.a - component.b.scale(9)
        coefficients[index + 6] = component.b

    write(0, value.c0.c0)
    write(2, value.c0.c1)
    write(4, value.c0.c2)
    write(1, value.c1.c0)
    write(3, value.c1.c1)
    write(5, value.c1.c2)
    if any(item is None for item in coefficients):
        raise AssertionError("tower output conversion left a coefficient unset")
    return tuple(item for item in coefficients if item is not None)


def fq12_flat_multiply(
    left: Sequence[int], right: Sequence[int] | None, modulus: int = P
) -> tuple[int, ...]:
    if len(left) != 12 or right is None or len(right) != 12:
        raise ValueError("FQ12 multiplication requires two 12-coefficient inputs")
    polynomial = [0] * 23
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            polynomial[i + j] = (polynomial[i + j] + int(a) * int(b)) % modulus
    # Flat modulus: w^12 - 18*w^6 + 82 = 0.
    for degree in range(22, 11, -1):
        coefficient = polynomial[degree] % modulus
        polynomial[degree] = 0
        polynomial[degree - 6] = (polynomial[degree - 6] + 18 * coefficient) % modulus
        polynomial[degree - 12] = (polynomial[degree - 12] - 82 * coefficient) % modulus
    return tuple(value % modulus for value in polynomial[:12])


def fq12_flat_square(
    value: Sequence[int], _unused: Sequence[int] | None = None, modulus: int = P
) -> tuple[int, ...]:
    return fq12_flat_multiply(value, value, modulus)


def compile_fq12_multiplication(modulus: int = P) -> RankDecomposition:
    recorder = RankRecorder(left_dimension=12, right_dimension=12, modulus=modulus)
    left = _side_t12_from_flat(recorder.left_variables())
    right = _side_t12_from_flat(recorder.right_variables())
    output = left.multiply(right, recorder)
    decomposition = recorder.finish(
        _out_t12_to_flat(output), name="bn254-fq12-multiplication-rank54"
    )
    if decomposition.rank != 54:
        raise AssertionError(f"expected FQ12 multiplication rank 54, got {decomposition.rank}")
    return decomposition


def compile_fq12_square(modulus: int = P) -> RankDecomposition:
    recorder = RankRecorder(
        left_dimension=12,
        right_dimension=12,
        modulus=modulus,
        quadratic=True,
    )
    value = _side_t12_from_flat(recorder.left_variables())
    output = value.square(recorder)
    decomposition = recorder.finish(_out_t12_to_flat(output), name="bn254-fq12-square-rank48")
    if decomposition.rank != 48:
        raise AssertionError(f"expected FQ12 square rank 48, got {decomposition.rank}")
    return decomposition
