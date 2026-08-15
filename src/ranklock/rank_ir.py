from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import random
from typing import Callable, Iterable, Literal, Sequence

from .field import BN254_BASE_FIELD, basis, dot

Side = Literal["left", "right", "single"]


def _normalize(values: Sequence[int], modulus: int) -> tuple[int, ...]:
    return tuple(int(value) % modulus for value in values)


@dataclass(frozen=True, slots=True)
class LinearForm:
    """A public linear form over one input vector."""

    side: Side
    coefficients: tuple[int, ...]
    modulus: int = BN254_BASE_FIELD

    def __post_init__(self) -> None:
        if self.modulus <= 2:
            raise ValueError("modulus must be greater than two")
        object.__setattr__(self, "coefficients", _normalize(self.coefficients, self.modulus))

    @classmethod
    def variable(
        cls, side: Side, dimension: int, index: int, modulus: int = BN254_BASE_FIELD
    ) -> "LinearForm":
        if not 0 <= index < dimension:
            raise IndexError("variable index outside linear-form dimension")
        return cls(side, tuple(1 if i == index else 0 for i in range(dimension)), modulus)

    @classmethod
    def zero(cls, side: Side, dimension: int, modulus: int = BN254_BASE_FIELD) -> "LinearForm":
        return cls(side, (0,) * dimension, modulus)

    def __add__(self, other: "LinearForm") -> "LinearForm":
        self._compatible(other)
        return LinearForm(
            self.side,
            tuple((a + b) % self.modulus for a, b in zip(self.coefficients, other.coefficients, strict=True)),
            self.modulus,
        )

    def __sub__(self, other: "LinearForm") -> "LinearForm":
        self._compatible(other)
        return LinearForm(
            self.side,
            tuple((a - b) % self.modulus for a, b in zip(self.coefficients, other.coefficients, strict=True)),
            self.modulus,
        )

    def __neg__(self) -> "LinearForm":
        return self.scale(-1)

    def scale(self, scalar: int) -> "LinearForm":
        scalar %= self.modulus
        return LinearForm(
            self.side,
            tuple((scalar * value) % self.modulus for value in self.coefficients),
            self.modulus,
        )

    def evaluate(self, values: Sequence[int]) -> int:
        return dot(self.coefficients, values, self.modulus)

    def _compatible(self, other: "LinearForm") -> None:
        if (
            self.side != other.side
            or self.modulus != other.modulus
            or len(self.coefficients) != len(other.coefficients)
        ):
            raise ValueError("linear forms are incompatible")


@dataclass(frozen=True, slots=True)
class ProductSpec:
    left: LinearForm
    right: LinearForm

    def __post_init__(self) -> None:
        if self.left.modulus != self.right.modulus:
            raise ValueError("product operands use different fields")


@dataclass(frozen=True, slots=True)
class OutputExpression:
    """A linear combination of recorded nonlinear products."""

    coefficients: tuple[int, ...]
    modulus: int = BN254_BASE_FIELD

    def __post_init__(self) -> None:
        object.__setattr__(self, "coefficients", _normalize(self.coefficients, self.modulus))

    @classmethod
    def zero(cls, product_count: int, modulus: int = BN254_BASE_FIELD) -> "OutputExpression":
        return cls((0,) * product_count, modulus)

    @classmethod
    def product(cls, product_count: int, index: int, modulus: int) -> "OutputExpression":
        if not 0 <= index < product_count:
            raise IndexError("product index outside expression")
        return cls(tuple(1 if i == index else 0 for i in range(product_count)), modulus)

    def padded(self, product_count: int) -> "OutputExpression":
        if product_count < len(self.coefficients):
            raise ValueError("cannot truncate output expression")
        return OutputExpression(
            self.coefficients + (0,) * (product_count - len(self.coefficients)), self.modulus
        )

    def __add__(self, other: "OutputExpression") -> "OutputExpression":
        left, right = self._align(other)
        return OutputExpression(
            tuple((a + b) % self.modulus for a, b in zip(left, right, strict=True)), self.modulus
        )

    def __sub__(self, other: "OutputExpression") -> "OutputExpression":
        left, right = self._align(other)
        return OutputExpression(
            tuple((a - b) % self.modulus for a, b in zip(left, right, strict=True)), self.modulus
        )

    def __neg__(self) -> "OutputExpression":
        return self.scale(-1)

    def scale(self, scalar: int) -> "OutputExpression":
        scalar %= self.modulus
        return OutputExpression(
            tuple((scalar * value) % self.modulus for value in self.coefficients), self.modulus
        )

    def _align(self, other: "OutputExpression") -> tuple[tuple[int, ...], tuple[int, ...]]:
        if self.modulus != other.modulus:
            raise ValueError("output expressions use different fields")
        width = max(len(self.coefficients), len(other.coefficients))
        return self.padded(width).coefficients, other.padded(width).coefficients


class RankRecorder:
    """Records products of public linear forms and emits a rank decomposition.

    The recorder is deliberately algebraic: every nonlinear call records one pair of linear forms.
    All subsequent operations on the product outputs must be public linear maps.  This makes the
    resulting rank certificate inspectable and exact.
    """

    def __init__(
        self,
        *,
        left_dimension: int,
        right_dimension: int,
        modulus: int = BN254_BASE_FIELD,
        quadratic: bool = False,
    ) -> None:
        if left_dimension <= 0 or right_dimension <= 0:
            raise ValueError("input dimensions must be positive")
        if quadratic and left_dimension != right_dimension:
            raise ValueError("quadratic recorder dimensions must agree")
        self.left_dimension = left_dimension
        self.right_dimension = right_dimension
        self.modulus = modulus
        self.quadratic = quadratic
        self.products: list[ProductSpec] = []

    def left_variables(self) -> tuple[LinearForm, ...]:
        side: Side = "single" if self.quadratic else "left"
        return tuple(
            LinearForm.variable(side, self.left_dimension, index, self.modulus)
            for index in range(self.left_dimension)
        )

    def right_variables(self) -> tuple[LinearForm, ...]:
        if self.quadratic:
            return self.left_variables()
        return tuple(
            LinearForm.variable("right", self.right_dimension, index, self.modulus)
            for index in range(self.right_dimension)
        )

    def multiply(self, left: LinearForm, right: LinearForm) -> OutputExpression:
        if left.modulus != self.modulus or right.modulus != self.modulus:
            raise ValueError("product uses another field")
        if len(left.coefficients) != self.left_dimension:
            raise ValueError("left product operand has wrong dimension")
        if len(right.coefficients) != self.right_dimension:
            raise ValueError("right product operand has wrong dimension")
        if self.quadratic:
            if left.side != "single" or right.side != "single":
                raise ValueError("quadratic products must use the single input")
        elif left.side != "left" or right.side != "right":
            raise ValueError("bilinear products must be left-by-right")
        index = len(self.products)
        self.products.append(ProductSpec(left, right))
        return OutputExpression.product(index + 1, index, self.modulus)

    def finish(self, outputs: Sequence[OutputExpression], *, name: str) -> "RankDecomposition":
        rank = len(self.products)
        if rank == 0:
            raise ValueError("rank decomposition must contain a nonlinear product")
        padded = tuple(output.padded(rank) for output in outputs)
        terms: list[RankTerm] = []
        for product_index, product in enumerate(self.products):
            output_vector = tuple(output.coefficients[product_index] for output in padded)
            terms.append(RankTerm(product.left, product.right, output_vector))
        return RankDecomposition(
            name=name,
            left_dimension=self.left_dimension,
            right_dimension=self.right_dimension,
            output_dimension=len(outputs),
            terms=tuple(terms),
            modulus=self.modulus,
            quadratic=self.quadratic,
        )


@dataclass(frozen=True, slots=True)
class RankTerm:
    left: LinearForm
    right: LinearForm
    output_vector: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CertificationResult:
    name: str
    passed: bool
    rank: int
    left_dimension: int
    right_dimension: int
    output_dimension: int
    exact_checks: int
    random_checks: int
    digest: str


@dataclass(frozen=True, slots=True)
class RankDecomposition:
    name: str
    left_dimension: int
    right_dimension: int
    output_dimension: int
    terms: tuple[RankTerm, ...]
    modulus: int = BN254_BASE_FIELD
    quadratic: bool = False

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("rank decomposition needs a name")
        if min(self.left_dimension, self.right_dimension, self.output_dimension) <= 0:
            raise ValueError("rank decomposition dimensions must be positive")
        if not self.terms:
            raise ValueError("rank decomposition has no terms")
        for term in self.terms:
            if term.left.modulus != self.modulus or term.right.modulus != self.modulus:
                raise ValueError("term field differs from decomposition field")
            if len(term.left.coefficients) != self.left_dimension:
                raise ValueError("left linear form dimension mismatch")
            if len(term.right.coefficients) != self.right_dimension:
                raise ValueError("right linear form dimension mismatch")
            if len(term.output_vector) != self.output_dimension:
                raise ValueError("output-vector dimension mismatch")

    @property
    def rank(self) -> int:
        return len(self.terms)

    @property
    def digest(self) -> str:
        document = {
            "name": self.name,
            "modulus": str(self.modulus),
            "quadratic": self.quadratic,
            "dimensions": [self.left_dimension, self.right_dimension, self.output_dimension],
            "terms": [
                {
                    "left": list(term.left.coefficients),
                    "right": list(term.right.coefficients),
                    "output": [int(value) % self.modulus for value in term.output_vector],
                }
                for term in self.terms
            ],
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(b"ranklock/rank-decomposition/v1\x00" + payload).hexdigest()

    def evaluate(self, left: Sequence[int], right: Sequence[int] | None = None) -> tuple[int, ...]:
        if len(left) != self.left_dimension:
            raise ValueError("left input dimension differs")
        if self.quadratic:
            if right is not None and tuple(right) != tuple(left):
                raise ValueError("quadratic decomposition accepts one input")
            right_values = left
        else:
            if right is None or len(right) != self.right_dimension:
                raise ValueError("right input dimension differs")
            right_values = right
        output = [0] * self.output_dimension
        for term in self.terms:
            scalar = term.left.evaluate(left) * term.right.evaluate(right_values) % self.modulus
            for index, coefficient in enumerate(term.output_vector):
                output[index] = (output[index] + scalar * coefficient) % self.modulus
        return tuple(output)

    def certify(
        self,
        reference: Callable[[Sequence[int], Sequence[int] | None], Sequence[int]],
        *,
        random_checks: int = 32,
        seed: int = 0x52414E4B4C4F434B,
    ) -> CertificationResult:
        exact_checks = 0
        left_basis = basis(self.left_dimension)
        if self.quadratic:
            # Over an odd-characteristic field, a quadratic map is fixed by Q(e_i) and
            # Q(e_i+e_j)-Q(e_i)-Q(e_j). Checking those points is an exact coefficient check.
            for index, vector in enumerate(left_basis):
                self._check(reference, vector, None)
                exact_checks += 1
            for i in range(self.left_dimension):
                for j in range(i + 1, self.left_dimension):
                    vector = tuple(
                        (left_basis[i][k] + left_basis[j][k]) % self.modulus
                        for k in range(self.left_dimension)
                    )
                    self._check(reference, vector, None)
                    exact_checks += 1
        else:
            right_basis = basis(self.right_dimension)
            for left in left_basis:
                for right in right_basis:
                    self._check(reference, left, right)
                    exact_checks += 1

        rng = random.Random(seed)
        for _ in range(random_checks):
            left = tuple(rng.randrange(self.modulus) for _ in range(self.left_dimension))
            right = None if self.quadratic else tuple(
                rng.randrange(self.modulus) for _ in range(self.right_dimension)
            )
            self._check(reference, left, right)

        return CertificationResult(
            name=self.name,
            passed=True,
            rank=self.rank,
            left_dimension=self.left_dimension,
            right_dimension=self.right_dimension,
            output_dimension=self.output_dimension,
            exact_checks=exact_checks,
            random_checks=random_checks,
            digest=self.digest,
        )

    def _check(
        self,
        reference: Callable[[Sequence[int], Sequence[int] | None], Sequence[int]],
        left: Sequence[int],
        right: Sequence[int] | None,
    ) -> None:
        actual = self.evaluate(left, right)
        expected = tuple(int(value) % self.modulus for value in reference(left, right))
        if len(expected) != self.output_dimension:
            raise AssertionError("reference output dimension differs")
        if actual != expected:
            raise AssertionError(
                f"rank decomposition {self.name!r} failed: expected {expected}, got {actual}"
            )
