from __future__ import annotations

from dataclasses import replace
import random

import pytest

from ranklock.rank_ir import RankDecomposition, RankTerm
from ranklock.tower_compiler import (
    compile_fq12_multiplication,
    compile_fq12_square,
    fq12_flat_multiply,
    fq12_flat_square,
)


def test_fq12_rank_certificates_are_exact() -> None:
    multiplication = compile_fq12_multiplication()
    square = compile_fq12_square()

    mul_certificate = multiplication.certify(fq12_flat_multiply, random_checks=8)
    square_certificate = square.certify(fq12_flat_square, random_checks=8)

    assert multiplication.rank == 54
    assert square.rank == 48
    assert mul_certificate.exact_checks == 12 * 12
    assert square_certificate.exact_checks == 12 + (12 * 11 // 2)
    assert len(mul_certificate.digest) == 64
    assert len(square_certificate.digest) == 64


def test_compiled_fq12_maps_match_random_native_arithmetic() -> None:
    rng = random.Random(20260803)
    multiplication = compile_fq12_multiplication()
    square = compile_fq12_square()
    for _ in range(12):
        left = tuple(rng.randrange(multiplication.modulus) for _ in range(12))
        right = tuple(rng.randrange(multiplication.modulus) for _ in range(12))
        assert multiplication.evaluate(left, right) == fq12_flat_multiply(left, right)
        assert square.evaluate(left) == fq12_flat_square(left)


def test_one_coefficient_tamper_breaks_exact_certificate() -> None:
    decomposition = compile_fq12_multiplication()
    first = decomposition.terms[0]
    changed_output = list(first.output_vector)
    changed_output[0] = (changed_output[0] + 1) % decomposition.modulus
    tampered_term = RankTerm(first.left, first.right, tuple(changed_output))
    tampered = replace(decomposition, terms=(tampered_term,) + decomposition.terms[1:])
    with pytest.raises(AssertionError):
        tampered.certify(fq12_flat_multiply, random_checks=0)
