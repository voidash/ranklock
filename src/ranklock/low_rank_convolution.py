from __future__ import annotations

"""Fixed-point bilinear-rank convolution for non-native multiplication.

For two ``n``-limb values, schoolbook convolution uses ``n^2`` nonlinear
products.  Viewing the limbs as coefficients of degree-``n-1`` polynomials,
``2n-1`` fixed evaluation products determine all convolution coefficients.
Everything else is native-field linear algebra.

This is the classical evaluation/interpolation (Toom-Cook/Winograd) reduction,
used here as an exact executable constraint model.  It is not a novelty claim.
"""

from dataclasses import dataclass
from functools import lru_cache
import random
from typing import Iterable, Sequence


class LowRankConvolutionError(ValueError):
    pass


def _poly_add(
    left: Sequence[int], right: Sequence[int], modulus: int
) -> tuple[int, ...]:
    length = max(len(left), len(right))
    values = [0] * length
    for index in range(length):
        values[index] = (
            (left[index] if index < len(left) else 0)
            + (right[index] if index < len(right) else 0)
        ) % modulus
    while len(values) > 1 and values[-1] == 0:
        values.pop()
    return tuple(values)


def _poly_scale(values: Sequence[int], scalar: int, modulus: int) -> tuple[int, ...]:
    result = tuple(int(value) * int(scalar) % modulus for value in values)
    result_list = list(result)
    while len(result_list) > 1 and result_list[-1] == 0:
        result_list.pop()
    return tuple(result_list or (0,))


def _poly_mul(
    left: Sequence[int], right: Sequence[int], modulus: int
) -> tuple[int, ...]:
    values = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            values[i + j] = (values[i + j] + int(a) * int(b)) % modulus
    while len(values) > 1 and values[-1] == 0:
        values.pop()
    return tuple(values)


def interpolation_matrix(
    points: Sequence[int], modulus: int
) -> tuple[tuple[int, ...], ...]:
    """Return rows mapping point values to monomial coefficients."""

    normalized = tuple(int(point) % modulus for point in points)
    return _cached_interpolation_matrix(normalized, int(modulus))


@lru_cache(maxsize=64)
def _cached_interpolation_matrix(
    normalized: tuple[int, ...], modulus: int
) -> tuple[tuple[int, ...], ...]:
    if not normalized or len(set(normalized)) != len(normalized):
        raise LowRankConvolutionError("interpolation points must be nonempty and distinct")
    size = len(normalized)
    columns: list[tuple[int, ...]] = []
    for i, point_i in enumerate(normalized):
        basis: tuple[int, ...] = (1,)
        denominator = 1
        for j, point_j in enumerate(normalized):
            if i == j:
                continue
            basis = _poly_mul(basis, (-point_j % modulus, 1), modulus)
            denominator = denominator * (point_i - point_j) % modulus
        try:
            inverse = pow(denominator, -1, modulus)
        except ValueError as exc:
            raise LowRankConvolutionError(
                "interpolation denominator is not invertible"
            ) from exc
        column = list(_poly_scale(basis, inverse, modulus))
        column.extend([0] * (size - len(column)))
        columns.append(tuple(column))
    return tuple(
        tuple(columns[column][row] for column in range(size))
        for row in range(size)
    )


def evaluate_polynomial(
    coefficients: Sequence[int], point: int, modulus: int
) -> int:
    result = 0
    for coefficient in reversed(tuple(coefficients)):
        result = (result * int(point) + int(coefficient)) % modulus
    return result


def exact_convolution(left: Sequence[int], right: Sequence[int]) -> tuple[int, ...]:
    values = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            values[i + j] += int(a) * int(b)
    return tuple(values)


@dataclass(frozen=True, slots=True)
class LowRankConvolutionPlan:
    limbs: int
    native_modulus: int
    points: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.limbs < 2:
            raise LowRankConvolutionError("convolution needs at least two limbs")
        if self.native_modulus <= 2:
            raise LowRankConvolutionError("native modulus must exceed two")
        if len(self.points) != 2 * self.limbs - 1:
            raise LowRankConvolutionError("plan needs exactly 2n-1 evaluation points")
        interpolation_matrix(self.points, self.native_modulus)

    @classmethod
    def consecutive(cls, limbs: int, native_modulus: int) -> "LowRankConvolutionPlan":
        return cls(
            int(limbs),
            int(native_modulus),
            tuple(range(2 * int(limbs) - 1)),
        )

    @property
    def nonlinear_products(self) -> int:
        return len(self.points)

    @property
    def schoolbook_products(self) -> int:
        return self.limbs * self.limbs

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-low-rank-convolution-plan-v1",
            "limbs": self.limbs,
            "native_modulus": str(self.native_modulus),
            "points": list(self.points),
            "native_nonlinear_products": self.nonlinear_products,
            "schoolbook_products": self.schoolbook_products,
            "products_avoided": self.schoolbook_products - self.nonlinear_products,
            "method": "fixed-point evaluation/interpolation",
        }


@dataclass(frozen=True, slots=True)
class LowRankConvolutionWitness:
    left: tuple[int, ...]
    right: tuple[int, ...]
    left_evaluations: tuple[int, ...]
    right_evaluations: tuple[int, ...]
    point_products: tuple[int, ...]
    coefficients: tuple[int, ...]


def _interpolate_values(
    values: Sequence[int], plan: LowRankConvolutionPlan
) -> tuple[int, ...]:
    matrix = interpolation_matrix(plan.points, plan.native_modulus)
    return tuple(
        sum(weight * int(value) for weight, value in zip(row, values, strict=True))
        % plan.native_modulus
        for row in matrix
    )


def build_low_rank_convolution_witness(
    left: Iterable[int],
    right: Iterable[int],
    plan: LowRankConvolutionPlan,
) -> LowRankConvolutionWitness:
    left_values = tuple(int(value) for value in left)
    right_values = tuple(int(value) for value in right)
    if len(left_values) != plan.limbs or len(right_values) != plan.limbs:
        raise LowRankConvolutionError("limb count differs from convolution plan")
    if any(value < 0 for value in left_values + right_values):
        raise LowRankConvolutionError("limbs must be nonnegative integers")

    left_evaluations = tuple(
        evaluate_polynomial(left_values, point, plan.native_modulus)
        for point in plan.points
    )
    right_evaluations = tuple(
        evaluate_polynomial(right_values, point, plan.native_modulus)
        for point in plan.points
    )
    point_products = tuple(
        left_value * right_value % plan.native_modulus
        for left_value, right_value in zip(
            left_evaluations, right_evaluations, strict=True
        )
    )
    coefficients = _interpolate_values(point_products, plan)
    exact = exact_convolution(left_values, right_values)
    if coefficients != tuple(value % plan.native_modulus for value in exact):
        raise AssertionError("low-rank interpolation differs from exact convolution")
    return LowRankConvolutionWitness(
        left_values,
        right_values,
        left_evaluations,
        right_evaluations,
        point_products,
        coefficients,
    )


def verify_low_rank_convolution_witness(
    witness: LowRankConvolutionWitness,
    plan: LowRankConvolutionPlan,
    *,
    limb_upper_bound: int | None = None,
    require_exact_coefficients: bool = True,
) -> bool:
    try:
        size = plan.nonlinear_products
        if len(witness.left) != plan.limbs or len(witness.right) != plan.limbs:
            return False
        if any(
            len(values) != size
            for values in (
                witness.left_evaluations,
                witness.right_evaluations,
                witness.point_products,
                witness.coefficients,
            )
        ):
            return False
        if any(value < 0 for value in witness.left + witness.right):
            return False
        if limb_upper_bound is not None and any(
            value >= limb_upper_bound for value in witness.left + witness.right
        ):
            return False

        expected_left = tuple(
            evaluate_polynomial(witness.left, point, plan.native_modulus)
            for point in plan.points
        )
        expected_right = tuple(
            evaluate_polynomial(witness.right, point, plan.native_modulus)
            for point in plan.points
        )
        if witness.left_evaluations != expected_left:
            return False
        if witness.right_evaluations != expected_right:
            return False
        for left_value, right_value, product in zip(
            witness.left_evaluations,
            witness.right_evaluations,
            witness.point_products,
            strict=True,
        ):
            if left_value * right_value % plan.native_modulus != product:
                return False
        if witness.coefficients != _interpolate_values(witness.point_products, plan):
            return False
        if require_exact_coefficients:
            exact = exact_convolution(witness.left, witness.right)
            if any(value >= plan.native_modulus for value in exact):
                return False
            if witness.coefficients != exact:
                return False
        return True
    except (LowRankConvolutionError, ValueError, OverflowError):
        return False


def randomized_self_test(
    *,
    limbs: int,
    limb_bits: int,
    native_modulus: int,
    cases: int = 100,
    seed: int = 0x544F4F4D,
) -> None:
    if cases <= 0:
        raise LowRankConvolutionError("case count must be positive")
    rng = random.Random(seed)
    plan = LowRankConvolutionPlan.consecutive(limbs, native_modulus)
    base = 1 << limb_bits
    edge_limbs = (
        tuple(0 for _ in range(limbs)),
        tuple(1 for _ in range(limbs)),
        tuple(base - 1 for _ in range(limbs)),
    )
    for left in edge_limbs:
        for right in edge_limbs:
            witness = build_low_rank_convolution_witness(left, right, plan)
            if not verify_low_rank_convolution_witness(
                witness, plan, limb_upper_bound=base
            ):
                raise AssertionError("low-rank edge convolution failed")
    for _ in range(cases):
        left = tuple(rng.randrange(base) for _ in range(limbs))
        right = tuple(rng.randrange(base) for _ in range(limbs))
        witness = build_low_rank_convolution_witness(left, right, plan)
        if not verify_low_rank_convolution_witness(
            witness, plan, limb_upper_bound=base
        ):
            raise AssertionError("low-rank random convolution failed")
