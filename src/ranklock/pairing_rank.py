from __future__ import annotations

"""Certified rank inventory for the BN254 Groth16 pairing check.

The original RankVM trace used dense flat :math:`F_{q^{12}}` multiplication for every
Miller line and for the final exponentiation.  That is semantically correct, but it is a
very poor constraint system.  This module reconstructs the sparse formulas used by
``gnark-crypto`` and the residue-witness pairing check from *On Proving Pairings*.

The counts are in base-field nonlinear products.  Additions, multiplication by public
constants, conjugation, and Frobenius maps are public-linear and therefore do not add
Rank-R1CS multiplication rows.

This is an executable cost/certification model, not a production pairing implementation.
"""

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Callable, Sequence

from .field import BN254_BASE_FIELD
from .rank_ir import LinearForm, OutputExpression, RankDecomposition, RankRecorder
from .tower_compiler import OutT2, OutT6, SideT2, SideT6

P = BN254_BASE_FIELD
BN254_ATE_LOOP = 29_793_968_203_157_093_288

E2 = tuple[int, int]
E6 = tuple[E2, E2, E2]
E12 = tuple[E6, E6]


def naf_decomposition(value: int, *, width: int | None = None) -> tuple[int, ...]:
    """Return the little-endian width-2 NAF used by the BN254 Miller loop."""

    if value <= 0:
        raise ValueError("NAF input must be positive")
    digits: list[int] = []
    current = int(value)
    while current:
        if current & 1:
            digit = 2 - current % 4
            current -= digit
        else:
            digit = 0
        digits.append(int(digit))
        current //= 2
    if width is not None:
        if len(digits) > width:
            raise ValueError("requested NAF width is too small")
        digits.extend([0] * (width - len(digits)))
    return tuple(digits)


LOOP_COUNTER = naf_decomposition(BN254_ATE_LOOP, width=66)
assert LOOP_COUNTER[65] == 1
assert LOOP_COUNTER[64] == 0
assert LOOP_COUNTER[63] == -1


def _mod(value: int) -> int:
    return int(value) % P


def e2_add(x: E2, y: E2) -> E2:
    return (_mod(x[0] + y[0]), _mod(x[1] + y[1]))


def e2_sub(x: E2, y: E2) -> E2:
    return (_mod(x[0] - y[0]), _mod(x[1] - y[1]))


def e2_scale(x: E2, scalar: int) -> E2:
    return (_mod(x[0] * scalar), _mod(x[1] * scalar))


def e2_mul(x: E2, y: E2) -> E2:
    # u^2 = -1.
    return (_mod(x[0] * y[0] - x[1] * y[1]), _mod((x[0] + x[1]) * (y[0] + y[1]) - x[0] * y[0] - x[1] * y[1]))


def e2_square(x: E2) -> E2:
    return (_mod((x[0] + x[1]) * (x[0] - x[1])), _mod(2 * x[0] * x[1]))


def e2_mul_xi(x: E2) -> E2:
    # xi = 9 + u.
    return (_mod(9 * x[0] - x[1]), _mod(x[0] + 9 * x[1]))


def e6_add(x: E6, y: E6) -> E6:
    return tuple(e2_add(a, b) for a, b in zip(x, y, strict=True))  # type: ignore[return-value]


def e6_sub(x: E6, y: E6) -> E6:
    return tuple(e2_sub(a, b) for a, b in zip(x, y, strict=True))  # type: ignore[return-value]


def e6_mul_by_v(x: E6) -> E6:
    return (e2_mul_xi(x[2]), x[0], x[1])


def e6_mul(x: E6, y: E6) -> E6:
    t0 = e2_mul(x[0], y[0])
    t1 = e2_mul(x[1], y[1])
    t2 = e2_mul(x[2], y[2])
    cross12 = e2_sub(e2_sub(e2_mul(e2_add(x[1], x[2]), e2_add(y[1], y[2])), t1), t2)
    cross01 = e2_sub(e2_sub(e2_mul(e2_add(x[0], x[1]), e2_add(y[0], y[1])), t0), t1)
    cross02 = e2_sub(e2_sub(e2_mul(e2_add(x[0], x[2]), e2_add(y[0], y[2])), t0), t2)
    return (e2_add(t0, e2_mul_xi(cross12)), e2_add(cross01, e2_mul_xi(t2)), e2_add(cross02, t1))


def e6_mul_by_e2(x: E6, y: E2) -> E6:
    return (e2_mul(x[0], y), e2_mul(x[1], y), e2_mul(x[2], y))


def e6_mul_by_01(x: E6, c0: E2, c1: E2) -> E6:
    a = e2_mul(x[0], c0)
    b = e2_mul(x[1], c1)
    t0 = e2_add(e2_mul_xi(e2_sub(e2_mul(c1, e2_add(x[1], x[2])), b)), a)
    t2 = e2_add(e2_sub(e2_mul(c0, e2_add(x[0], x[2])), a), b)
    t1 = e2_sub(e2_sub(e2_mul(e2_add(c0, c1), e2_add(x[0], x[1])), a), b)
    return (t0, t1, t2)


def e12_mul(x: E12, y: E12) -> E12:
    a = e6_mul(e6_add(x[0], x[1]), e6_add(y[0], y[1]))
    b = e6_mul(x[0], y[0])
    c = e6_mul(x[1], y[1])
    return (e6_add(b, e6_mul_by_v(c)), e6_sub(e6_sub(a, b), c))


def e12_square_optimized(x: E12) -> E12:
    # Algorithm 22 from Devegili et al.; two E6 multiplications = rank 36.
    c0 = e6_sub(x[0], x[1])
    c3 = e6_sub(x[0], e6_mul_by_v(x[1]))
    c2 = e6_mul(x[0], x[1])
    c0_product = e6_add(e6_mul(c0, c3), c2)
    return (e6_add(c0_product, e6_mul_by_v(c2)), tuple(e2_scale(v, 2) for v in c2))  # type: ignore[return-value]


def e12_mul_by_034(a: E12, c0: E2, c3: E2, c4: E2) -> E12:
    left = e6_mul_by_e2(a[0], c0)
    right = e6_mul_by_01(a[1], c3, c4)
    mixed = e6_mul_by_01(e6_add(a[0], a[1]), e2_add(c0, c3), c4)
    return (e6_add(left, e6_mul_by_v(right)), e6_sub(e6_sub(mixed, left), right))


def e12_mul_by_34(a: E12, c3: E2, c4: E2) -> E12:
    one: E2 = (1, 0)
    return e12_mul_by_034(a, one, c3, c4)


def mul034_by034(left: tuple[E2, E2, E2], right: tuple[E2, E2, E2]) -> tuple[E2, E2, E2, E2, E2]:
    c0, c3, c4 = left
    d0, d3, d4 = right
    x0 = e2_mul(c0, d0)
    x3 = e2_mul(c3, d3)
    x4 = e2_mul(c4, d4)
    x04 = e2_sub(e2_sub(e2_mul(e2_add(c0, c4), e2_add(d0, d4)), x0), x4)
    x03 = e2_sub(e2_sub(e2_mul(e2_add(c0, c3), e2_add(d0, d3)), x0), x3)
    x34 = e2_sub(e2_sub(e2_mul(e2_add(c3, c4), e2_add(d3, d4)), x3), x4)
    return (e2_add(x0, e2_mul_xi(x4)), x3, x34, x03, x04)


def mul34_by34(left: tuple[E2, E2], right: tuple[E2, E2]) -> tuple[E2, E2, E2, E2, E2]:
    c3, c4 = left
    d3, d4 = right
    one: E2 = (1, 0)
    return mul034_by034((one, c3, c4), (one, d3, d4))


def e12_mul_by_01234(a: E12, values: tuple[E2, E2, E2, E2, E2]) -> E12:
    x0, x1, x2, x3, x4 = values
    c0: E6 = (x0, x1, x2)
    c1: E6 = (x3, x4, (0, 0))
    mixed = e6_mul(e6_add(a[0], a[1]), e6_add(c0, c1))
    left = e6_mul(a[0], c0)
    right = e6_mul_by_01(a[1], x3, x4)
    return (e6_add(left, e6_mul_by_v(right)), e6_sub(e6_sub(mixed, left), right))


def e12_cyclotomic_square(x: E12) -> E12:
    # Granger--Scott, represented in tower order C0.B0,C0.B1,C0.B2,C1.B0,C1.B1,C1.B2.
    x0, x1, x2 = x[0]
    x3, x4, x5 = x[1]
    t0 = e2_square(x4)
    t1 = e2_square(x0)
    t6 = e2_sub(e2_sub(e2_square(e2_add(x4, x0)), t0), t1)
    t2 = e2_square(x2)
    t3 = e2_square(x3)
    t7 = e2_sub(e2_sub(e2_square(e2_add(x2, x3)), t2), t3)
    t4 = e2_square(x5)
    t5 = e2_square(x1)
    t8 = e2_mul_xi(e2_sub(e2_sub(e2_square(e2_add(x5, x1)), t4), t5))
    z0base = e2_add(e2_mul_xi(t0), t1)
    z1base = e2_add(e2_mul_xi(t2), t3)
    z2base = e2_add(e2_mul_xi(t4), t5)
    z0 = e2_add(e2_scale(e2_sub(z0base, x0), 2), z0base)
    z1 = e2_add(e2_scale(e2_sub(z1base, x1), 2), z1base)
    z2 = e2_add(e2_scale(e2_sub(z2base, x2), 2), z2base)
    z3 = e2_add(e2_scale(e2_add(t8, x3), 2), t8)
    z4 = e2_add(e2_scale(e2_add(t6, x4), 2), t6)
    z5 = e2_add(e2_scale(e2_add(t7, x5), 2), t7)
    return ((z0, z1, z2), (z3, z4, z5))


def _direct_t2(variables: Sequence[LinearForm], offset: int) -> SideT2:
    return SideT2(variables[offset], variables[offset + 1])


def _direct_t6(variables: Sequence[LinearForm], offset: int = 0) -> SideT6:
    return SideT6(_direct_t2(variables, offset), _direct_t2(variables, offset + 2), _direct_t2(variables, offset + 4))


def _direct_t12(variables: Sequence[LinearForm]) -> tuple[SideT6, SideT6]:
    if len(variables) != 12:
        raise ValueError("tower Fq12 input must have 12 coefficients")
    return _direct_t6(variables, 0), _direct_t6(variables, 6)


def _out_t2_values(value: OutT2) -> tuple[OutputExpression, OutputExpression]:
    return value.a, value.b


def _out_t6_values(value: OutT6) -> tuple[OutputExpression, ...]:
    return (*_out_t2_values(value.c0), *_out_t2_values(value.c1), *_out_t2_values(value.c2))


def _out_t12_values(value: tuple[OutT6, OutT6]) -> tuple[OutputExpression, ...]:
    return (*_out_t6_values(value[0]), *_out_t6_values(value[1]))


def _side_t2_mul_xi(value: SideT2) -> SideT2:
    return SideT2(value.a.scale(9) - value.b, value.a + value.b.scale(9))


def _side_t6_mul_by_v(value: SideT6) -> SideT6:
    return SideT6(_side_t2_mul_xi(value.c2), value.c0, value.c1)


def _out_t6_mul_by_v(value: OutT6) -> OutT6:
    return value.mul_by_v()


def _mul_by_e2_symbolic(value: SideT6, scalar: SideT2, recorder: RankRecorder) -> OutT6:
    return OutT6(value.c0.multiply(scalar, recorder), value.c1.multiply(scalar, recorder), value.c2.multiply(scalar, recorder))


def _mul_by_01_symbolic(value: SideT6, c0: SideT2, c1: SideT2, recorder: RankRecorder) -> OutT6:
    a = value.c0.multiply(c0, recorder)
    b = value.c1.multiply(c1, recorder)
    t0 = (value.c1 + value.c2).multiply(c1, recorder) - b
    t0 = t0.mul_xi() + a
    t2 = (value.c0 + value.c2).multiply(c0, recorder) - a + b
    t1 = (value.c0 + value.c1).multiply(c0 + c1, recorder) - a - b
    return OutT6(t0, t1, t2)


def compile_e6_mul_by_e2() -> RankDecomposition:
    recorder = RankRecorder(left_dimension=6, right_dimension=2, modulus=P)
    left = _direct_t6(recorder.left_variables())
    right = _direct_t2(recorder.right_variables(), 0)
    output = _mul_by_e2_symbolic(left, right, recorder)
    result = recorder.finish(_out_t6_values(output), name="bn254-e6-mul-by-e2-rank9")
    if result.rank != 9:
        raise AssertionError(result.rank)
    return result


def compile_e6_mul_by_01() -> RankDecomposition:
    recorder = RankRecorder(left_dimension=6, right_dimension=4, modulus=P)
    left = _direct_t6(recorder.left_variables())
    right = recorder.right_variables()
    output = _mul_by_01_symbolic(left, _direct_t2(right, 0), _direct_t2(right, 2), recorder)
    result = recorder.finish(_out_t6_values(output), name="bn254-e6-mul-by01-rank15")
    if result.rank != 15:
        raise AssertionError(result.rank)
    return result


def compile_e12_square_optimized() -> RankDecomposition:
    recorder = RankRecorder(left_dimension=12, right_dimension=12, modulus=P, quadratic=True)
    c0, c1 = _direct_t12(recorder.left_variables())
    linear0 = c0 - c1
    linear1 = c0 - _side_t6_mul_by_v(c1)
    cross = c0.multiply(c1, recorder)
    product = linear0.multiply(linear1, recorder) + cross
    output = (product + _out_t6_mul_by_v(cross), cross.scale(2))
    result = recorder.finish(_out_t12_values(output), name="bn254-e12-square-rank36")
    if result.rank != 36:
        raise AssertionError(result.rank)
    return result


def compile_e12_mul_by_034() -> RankDecomposition:
    recorder = RankRecorder(left_dimension=12, right_dimension=6, modulus=P)
    a0, a1 = _direct_t12(recorder.left_variables())
    right = recorder.right_variables()
    c0, c3, c4 = _direct_t2(right, 0), _direct_t2(right, 2), _direct_t2(right, 4)
    left = _mul_by_e2_symbolic(a0, c0, recorder)
    sparse = _mul_by_01_symbolic(a1, c3, c4, recorder)
    mixed = _mul_by_01_symbolic(a0 + a1, c0 + c3, c4, recorder)
    output = (left + sparse.mul_by_v(), mixed - left - sparse)
    result = recorder.finish(_out_t12_values(output), name="bn254-e12-mul-by034-rank39")
    if result.rank != 39:
        raise AssertionError(result.rank)
    return result


def compile_mul034_by034() -> RankDecomposition:
    recorder = RankRecorder(left_dimension=6, right_dimension=6, modulus=P)
    left, right = recorder.left_variables(), recorder.right_variables()
    c0, c3, c4 = _direct_t2(left, 0), _direct_t2(left, 2), _direct_t2(left, 4)
    d0, d3, d4 = _direct_t2(right, 0), _direct_t2(right, 2), _direct_t2(right, 4)
    x0 = c0.multiply(d0, recorder)
    x3 = c3.multiply(d3, recorder)
    x4 = c4.multiply(d4, recorder)
    x04 = (c0 + c4).multiply(d0 + d4, recorder) - x0 - x4
    x03 = (c0 + c3).multiply(d0 + d3, recorder) - x0 - x3
    x34 = (c3 + c4).multiply(d3 + d4, recorder) - x3 - x4
    output = (x0 + x4.mul_xi(), x3, x34, x03, x04)
    outputs: list[OutputExpression] = []
    for item in output:
        outputs.extend(_out_t2_values(item))
    result = recorder.finish(outputs, name="bn254-mul034-by034-rank18")
    if result.rank != 18:
        raise AssertionError(result.rank)
    return result


def compile_e12_mul_by_01234() -> RankDecomposition:
    recorder = RankRecorder(left_dimension=12, right_dimension=10, modulus=P)
    a0, a1 = _direct_t12(recorder.left_variables())
    right = recorder.right_variables()
    x0, x1, x2, x3, x4 = (_direct_t2(right, offset) for offset in (0, 2, 4, 6, 8))
    c0 = SideT6(x0, x1, x2)
    # The last C1 coefficient is zero. Build it explicitly with the right-side dimension.
    zero = SideT2(
        LinearForm.zero("right", recorder.right_dimension, P),
        LinearForm.zero("right", recorder.right_dimension, P),
    )
    c1 = SideT6(x3, x4, zero)
    mixed = (a0 + a1).multiply(c0 + c1, recorder)
    left = a0.multiply(c0, recorder)
    sparse = _mul_by_01_symbolic(a1, x3, x4, recorder)
    output = (left + sparse.mul_by_v(), mixed - left - sparse)
    result = recorder.finish(_out_t12_values(output), name="bn254-e12-mul-by01234-rank51")
    if result.rank != 51:
        raise AssertionError(result.rank)
    return result


def compile_cyclotomic_square() -> RankDecomposition:
    recorder = RankRecorder(left_dimension=12, right_dimension=12, modulus=P, quadratic=True)
    c0, c1 = _direct_t12(recorder.left_variables())
    x0, x1, x2 = c0.c0, c0.c1, c0.c2
    x3, x4, x5 = c1.c0, c1.c1, c1.c2
    t0 = x4.square(recorder)
    t1 = x0.square(recorder)
    t6 = (x4 + x0).square(recorder) - t0 - t1
    t2 = x2.square(recorder)
    t3 = x3.square(recorder)
    t7 = (x2 + x3).square(recorder) - t2 - t3
    t4 = x5.square(recorder)
    t5 = x1.square(recorder)
    t8 = ((x5 + x1).square(recorder) - t4 - t5).mul_xi()
    z0base = t0.mul_xi() + t1
    z1base = t2.mul_xi() + t3
    z2base = t4.mul_xi() + t5
    # Express 3*t - 2*x.  x is linear in the original witness and is not part of a
    # homogeneous quadratic map.  In the cyclotomic subgroup formulas the linear terms
    # are an affine bypass; the nonlinear residual below contains exactly the 18 products.
    # Return the nonlinear component 3*t.  ``cyclotomic_linear_correction`` supplies -2*x.
    output = (
        OutT6(z0base.scale(3), z1base.scale(3), z2base.scale(3)),
        OutT6(t8.scale(3), t6.scale(3), t7.scale(3)),
    )
    result = recorder.finish(_out_t12_values(output), name="bn254-cyclotomic-square-nonlinear-rank18")
    if result.rank != 18:
        raise AssertionError(result.rank)
    return result


def _flat_e2(value: E2) -> tuple[int, int]:
    return (_mod(value[0]), _mod(value[1]))


def _flat_e6(value: E6) -> tuple[int, ...]:
    return tuple(component for e in value for component in _flat_e2(e))


def _flat_e12(value: E12) -> tuple[int, ...]:
    return (*_flat_e6(value[0]), *_flat_e6(value[1]))


def _unflat_e2(values: Sequence[int], offset: int) -> E2:
    return (_mod(values[offset]), _mod(values[offset + 1]))


def _unflat_e6(values: Sequence[int], offset: int = 0) -> E6:
    return (_unflat_e2(values, offset), _unflat_e2(values, offset + 2), _unflat_e2(values, offset + 4))


def _unflat_e12(values: Sequence[int]) -> E12:
    if len(values) != 12:
        raise ValueError("expected 12 tower coefficients")
    return (_unflat_e6(values, 0), _unflat_e6(values, 6))


def certify_sparse_kernels(*, random_checks: int = 32) -> dict[str, object]:
    """Run exact-basis plus deterministic random certification for sparse kernels."""

    modules: list[tuple[RankDecomposition, Callable[[Sequence[int], Sequence[int] | None], Sequence[int]]]] = []

    modules.append((compile_e6_mul_by_e2(), lambda left, right: _flat_e6(e6_mul_by_e2(_unflat_e6(left), _unflat_e2(right or (), 0)))))
    modules.append((compile_e6_mul_by_01(), lambda left, right: _flat_e6(e6_mul_by_01(_unflat_e6(left), _unflat_e2(right or (), 0), _unflat_e2(right or (), 2)))))
    modules.append((compile_e12_square_optimized(), lambda left, _right: _flat_e12(e12_square_optimized(_unflat_e12(left)))))
    modules.append((compile_e12_mul_by_034(), lambda left, right: _flat_e12(e12_mul_by_034(_unflat_e12(left), _unflat_e2(right or (), 0), _unflat_e2(right or (), 2), _unflat_e2(right or (), 4)))))
    modules.append((compile_mul034_by034(), lambda left, right: tuple(v for item in mul034_by034((_unflat_e2(left, 0), _unflat_e2(left, 2), _unflat_e2(left, 4)), (_unflat_e2(right or (), 0), _unflat_e2(right or (), 2), _unflat_e2(right or (), 4))) for v in item)))
    modules.append((compile_e12_mul_by_01234(), lambda left, right: _flat_e12(e12_mul_by_01234(_unflat_e12(left), tuple(_unflat_e2(right or (), offset) for offset in (0, 2, 4, 6, 8))))))  # type: ignore[arg-type]

    results = []
    for module, reference in modules:
        result = module.certify(reference, random_checks=random_checks)
        if not result.passed:
            raise AssertionError(f"sparse-kernel certification failed: {module.name}")
        results.append(asdict(result))

    # Cyclotomic square has a public-linear -2*x correction. Certify the nonlinear
    # residual returned by the decomposition against full_square + 2*x.
    cyclo = compile_cyclotomic_square()

    def cyclo_residual(left: Sequence[int], _right: Sequence[int] | None) -> Sequence[int]:
        full = _flat_e12(e12_cyclotomic_square(_unflat_e12(left)))
        # Granger--Scott has ``3*t - 2*x`` on C0 and ``3*t + 2*x`` on C1.
        # Strip those public-linear corrections to isolate the homogeneous
        # quadratic residual certified by the rank-18 decomposition.
        return tuple(
            (value + 2 * int(original)) % P
            if index < 6
            else (value - 2 * int(original)) % P
            for index, (value, original) in enumerate(zip(full, left, strict=True))
        )

    result = cyclo.certify(cyclo_residual, random_checks=random_checks)
    if not result.passed:
        raise AssertionError("cyclotomic-square certification failed")
    results.append(asdict(result))

    digest = hashlib.sha256(
        b"ranklock/sparse-kernel-certificate/v1\x00"
        + json.dumps(results, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return {"passed": True, "kernels": results, "digest": digest}


@dataclass(frozen=True, slots=True)
class PrimitiveRanks:
    fq2_mul: int = 3
    fq2_square: int = 2
    fq2_mul_by_variable_fq: int = 2
    fq6_mul: int = 18
    fq6_mul_by_fq2: int = 9
    fq6_mul_by_01: int = 15
    fq12_mul: int = 54
    fq12_square: int = 36
    fq12_cyclotomic_square: int = 18
    fq12_mul_by_034: int = 39
    fq12_mul_by_34: int = 30
    mul034_by034: int = 18
    mul34_by34: int = 9
    fq12_mul_by_01234: int = 51
    g2_affine_double: int = 10
    g2_affine_add: int = 8
    g2_affine_double_and_add: int = 13
    miller_affine_double_line: int = 13
    miller_affine_double_and_add_lines: int = 19
    miller_affine_add_line: int = 11


@dataclass(frozen=True, slots=True)
class PairingRankBreakdown:
    active_pairings: int
    dynamic_g2_pairings: int
    fixed_g2_pairings: int
    constant_pairings_folded: int
    loop_rounds: int
    zero_digits: int
    nonzero_digits: int
    dynamic_line_count: int
    accumulator_squares: int
    zero_round_sparse_multiplications: int
    nonzero_residue_witness_multiplications: int
    nonzero_line_products: int
    final_line_products: int
    residue_witness_inverse_check: int
    g1_affine_normalization: int
    dynamic_line_evaluation: int
    dynamic_g2_line_generation: int
    residue_check_postlude: int
    total_base_field_products: int
    final_exponentiation_eliminated_products: int
    dense_v05_pairing_products: int

    @property
    def reduction_vs_dense_v05(self) -> float:
        return self.dense_v05_pairing_products / self.total_base_field_products


def groth16_pairing_rank_breakdown() -> PairingRankBreakdown:
    """Return a conservative executable schedule for the four-term SP1 Groth16 check.

    One fixed-fixed term ``e(-alpha, beta)`` is folded into a public constant.  The
    remaining terms are ``e(A,B)`` (dynamic G2), ``e(-K,gamma)`` and
    ``e(-C,delta)`` (fixed G2).  The pairing uses affine precomputed lines and the
    residue-witness check, so no final exponentiation is performed.
    """

    ranks = PrimitiveRanks()
    active_pairings = 3
    dynamic_g2_pairings = 1
    fixed_g2_pairings = 2

    loop_digits = LOOP_COUNTER[:65]  # indices 0..64; index 65 is the leading one.
    zero_digits = loop_digits.count(0)
    nonzero_digits = len(loop_digits) - zero_digits
    if (len(loop_digits), zero_digits, nonzero_digits) != (65, 44, 21):
        raise AssertionError("unexpected BN254 NAF profile")

    # Miller-loop accumulator. Every line is normalized to sparse form (1,c3,c4).
    accumulator_squares = len(loop_digits) * ranks.fq12_square
    zero_round_sparse = zero_digits * active_pairings * ranks.fq12_mul_by_34
    # The residue witness is exponentiated by U=6u+2 inside the loop: at each
    # nonzero NAF digit the accumulator is multiplied by init or init^{-1}.
    nonzero_residue = nonzero_digits * ranks.fq12_mul
    nonzero_lines = nonzero_digits * active_pairings * (
        ranks.mul34_by34 + ranks.fq12_mul_by_01234
    )
    final_lines = active_pairings * (ranks.mul34_by34 + ranks.fq12_mul_by_01234)

    # Witness inverse for the residue initializer: init * init_inv = 1.
    residue_inverse = ranks.fq12_mul

    # Normalize the three active G1 points: y*y_inv=1 and x_over_y=x*y_inv.
    g1_normalization = active_pairings * 2

    # Only the e(A,B) line coefficients are dynamic.  Its 88 lines each multiply
    # two Fq2 coefficients by variable G1 scalars (2 base products each).
    dynamic_line_count = zero_digits + 2 * nonzero_digits + 2
    if dynamic_line_count != 88:
        raise AssertionError(dynamic_line_count)
    dynamic_line_evaluation = dynamic_line_count * 2 * ranks.fq2_mul_by_variable_fq

    # Affine line precomputation for the one dynamic G2 point B.
    # 44 zero digits -> one double-line step; 21 nonzero digits -> fused
    # double-and-add lines; two Frobenius-tail additions.
    dynamic_line_generation = (
        zero_digits * ranks.miller_affine_double_line
        + nonzero_digits * ranks.miller_affine_double_and_add_lines
        + 2 * ranks.miller_affine_add_line
    )

    # Residue check after the loop:
    #   res*cubic_non_residue_power  : E12 by variable E6 = 36
    #   Frob^3(w)/Frob^2(w)          : one checked E12 division = 54
    #   *Frob(w), then *res          : two E12 multiplications = 108
    residue_postlude = 36 + 3 * ranks.fq12_mul

    total = sum(
        (
            accumulator_squares,
            zero_round_sparse,
            nonzero_residue,
            nonzero_lines,
            final_lines,
            residue_inverse,
            g1_normalization,
            dynamic_line_evaluation,
            dynamic_line_generation,
            residue_postlude,
        )
    )

    # Dense v0.5 pairing phase: 11,785 generic Fq12 multiplications, 2,789
    # generic squares, and the four denominator inversions.  This is the
    # witness-check version (inversion itself is one Fq12 product relation), not
    # exponentiation-by-p-2.
    dense_v05_pairing = 11_785 * 54 + 2_789 * 48 + 4

    # The optimized ordinary final exponentiation would cost 6,858 products;
    # the residue witness replaces it with the 198-product postlude plus the
    # U exponent folded into the loop.  Report 6,858 as the eliminated dense
    # final-exponentiation component for auditability.
    final_exp_eliminated = 6_858

    return PairingRankBreakdown(
        active_pairings=active_pairings,
        dynamic_g2_pairings=dynamic_g2_pairings,
        fixed_g2_pairings=fixed_g2_pairings,
        constant_pairings_folded=1,
        loop_rounds=len(loop_digits),
        zero_digits=zero_digits,
        nonzero_digits=nonzero_digits,
        dynamic_line_count=dynamic_line_count,
        accumulator_squares=accumulator_squares,
        zero_round_sparse_multiplications=zero_round_sparse,
        nonzero_residue_witness_multiplications=nonzero_residue,
        nonzero_line_products=nonzero_lines,
        final_line_products=final_lines,
        residue_witness_inverse_check=residue_inverse,
        g1_affine_normalization=g1_normalization,
        dynamic_line_evaluation=dynamic_line_evaluation,
        dynamic_g2_line_generation=dynamic_line_generation,
        residue_check_postlude=residue_postlude,
        total_base_field_products=total,
        final_exponentiation_eliminated_products=final_exp_eliminated,
        dense_v05_pairing_products=dense_v05_pairing,
    )


@dataclass(frozen=True, slots=True)
class Groth16VerifierRankSchedule:
    old_erroneous_rank_terms: int
    corrected_dense_exponentiation_model: int
    corrected_dense_witness_model: int
    sparse_residue_pairing: int
    dynamic_msm_conservative: int
    proof_curve_and_g2_subgroup_checks: int
    known_arithmetic_subtotal: int
    unresolved_sha256_and_byte_binding: bool
    unresolved_canonical_parsing_and_range_checks: bool
    padded_rankfold_domain: int
    rankfold_rounds: int

    @property
    def reduction_vs_corrected_dense_witness(self) -> float:
        return self.corrected_dense_witness_model / self.known_arithmetic_subtotal


def groth16_verifier_rank_schedule() -> Groth16VerifierRankSchedule:
    pairing = groth16_pairing_rank_breakdown()

    # Exact correction of the old v0.10 schedule.
    dense_core = 11_785 * 54 + 2_789 * 48 + 38 * 3 + 12_196
    corrected_dense_witness = dense_core + 5 + 4 + 54
    # Original cost compiler allowed exponentiation-equivalent budgets for five
    # Fq inversions, four square roots and one Fq12 inverse.
    # Match the v0.5 transparent model exactly: straight square-and-multiply
    # upper bounds charge 363 multiplication-equivalents per Fq inverse and
    # 360 per square root, plus 10,000 for the unoptimized Fq12 inverse.
    corrected_dense_exponentiation = dense_core + 5 * 363 + 4 * 360 + 10_000

    # The retained v0.5 phase counter measured 12,150 base-field products for
    # the two non-zero fixed-base MSM terms.  Keep this as a conservative value
    # until the certified GLV/fixed-window compiler replaces it.
    dynamic_msm = 12_150

    # Proof A/C curve checks: 3 products each. Dynamic G2 B: twist equation 7.
    # The short-vector subgroup check uses the gnark affine addition chain:
    # scalarMulBySeed = 46 doubles + 18 adds + 7 fused double-and-add operations;
    # then one double and three subtractions.
    ranks = PrimitiveRanks()
    subgroup = (
        46 * ranks.g2_affine_double
        + 18 * ranks.g2_affine_add
        + 7 * ranks.g2_affine_double_and_add
        + ranks.g2_affine_double
        + 3 * ranks.g2_affine_add
    )
    proof_checks = 2 * 3 + 7 + subgroup
    if proof_checks != 742:
        raise AssertionError(proof_checks)

    subtotal = pairing.total_base_field_products + dynamic_msm + proof_checks
    padded = 1 << (subtotal - 1).bit_length()
    rounds = padded.bit_length() - 1

    return Groth16VerifierRankSchedule(
        old_erroneous_rank_terms=645_221,
        corrected_dense_exponentiation_model=corrected_dense_exponentiation,
        corrected_dense_witness_model=corrected_dense_witness,
        sparse_residue_pairing=pairing.total_base_field_products,
        dynamic_msm_conservative=dynamic_msm,
        proof_curve_and_g2_subgroup_checks=proof_checks,
        known_arithmetic_subtotal=subtotal,
        unresolved_sha256_and_byte_binding=True,
        unresolved_canonical_parsing_and_range_checks=True,
        padded_rankfold_domain=padded,
        rankfold_rounds=rounds,
    )


def write_pairing_rank_results(path: str) -> None:
    pairing = groth16_pairing_rank_breakdown()
    schedule = groth16_verifier_rank_schedule()
    certificate = certify_sparse_kernels(random_checks=16)
    document = {
        "schema": "ranklock-bn254-sparse-pairing-rank-v1",
        "primitive_ranks": asdict(PrimitiveRanks()),
        "loop_counter": {
            "length": len(LOOP_COUNTER),
            "digits": {str(value): LOOP_COUNTER.count(value) for value in (-1, 0, 1)},
            "active_rounds": 65,
        },
        "pairing": {**asdict(pairing), "reduction_vs_dense_v05": pairing.reduction_vs_dense_v05},
        "verifier_schedule": {
            **asdict(schedule),
            "reduction_vs_corrected_dense_witness": schedule.reduction_vs_corrected_dense_witness,
        },
        "kernel_certificate": certificate,
        "security_boundary": [
            "The sparse arithmetic identities are exact and executable.",
            "The schedule uses the residue-witness pairing check and one folded fixed-fixed pairing term.",
            "SHA-256/public-byte binding and canonical parser/range constraints are not in the subtotal.",
            "The dynamic MSM still uses the conservative measured v0.5 product count.",
            "This is a Rank-R1CS schedule, not a conditional-disclosure construction.",
        ],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
