from __future__ import annotations

"""Finite-field helpers shared by the RankLock algebraic models."""

from typing import Sequence

# BN254 base field Fq (not the BN254 scalar field Fr).
BN254_BASE_FIELD = (
    21888242871839275222246405745257275088696311157297823662689037894645226208583
)


def polynomial_evaluate(
    coefficients: Sequence[int], point: int, modulus: int = BN254_BASE_FIELD
) -> int:
    """Evaluate a little-endian coefficient polynomial using Horner's rule."""

    if modulus <= 2:
        raise ValueError("modulus must exceed two")
    result = 0
    x = int(point) % modulus
    for coefficient in reversed(tuple(coefficients)):
        result = (result * x + int(coefficient)) % modulus
    return result


def basis(dimension: int) -> tuple[tuple[int, ...], ...]:
    if dimension <= 0:
        raise ValueError("basis dimension must be positive")
    return tuple(
        tuple(1 if row == column else 0 for column in range(dimension))
        for row in range(dimension)
    )


def dot(
    left: Sequence[int], right: Sequence[int], modulus: int = BN254_BASE_FIELD
) -> int:
    if len(left) != len(right):
        raise ValueError("dot-product dimensions differ")
    return sum(
        (int(a) % modulus) * (int(b) % modulus)
        for a, b in zip(left, right, strict=True)
    ) % modulus
