from __future__ import annotations

from dataclasses import asdict
import json
import random

from ranklock.pairing_rank import (
    LOOP_COUNTER,
    PrimitiveRanks,
    certify_sparse_kernels,
    e12_cyclotomic_square,
    e12_mul,
    e12_mul_by_01234,
    e12_mul_by_034,
    e12_mul_by_34,
    e12_square_optimized,
    e6_mul,
    groth16_pairing_rank_breakdown,
    groth16_verifier_rank_schedule,
    mul034_by034,
    mul34_by34,
    naf_decomposition,
)
from ranklock.field import BN254_BASE_FIELD as P


def _e2(rng: random.Random):
    return (rng.randrange(P), rng.randrange(P))


def _e6(rng: random.Random):
    return (_e2(rng), _e2(rng), _e2(rng))


def _e12(rng: random.Random):
    return (_e6(rng), _e6(rng))


def test_bn254_naf_profile_matches_gnark() -> None:
    assert naf_decomposition(29_793_968_203_157_093_288, width=66) == LOOP_COUNTER
    assert len(LOOP_COUNTER) == 66
    assert LOOP_COUNTER[65] == 1
    assert LOOP_COUNTER[64] == 0
    assert LOOP_COUNTER[63] == -1
    assert {digit: LOOP_COUNTER.count(digit) for digit in (-1, 0, 1)} == {-1: 13, 0: 44, 1: 9}


def test_sparse_formulas_match_generic_tower_arithmetic() -> None:
    rng = random.Random(0x535041525345)
    one = (1, 0)
    zero = (0, 0)
    for _ in range(32):
        accumulator = _e12(rng)
        c0, c3, c4 = _e2(rng), _e2(rng), _e2(rng)
        dense034 = (((c0, zero, zero), (c3, c4, zero)))
        assert e12_mul_by_034(accumulator, c0, c3, c4) == e12_mul(accumulator, dense034)

        dense34 = (((one, zero, zero), (c3, c4, zero)))
        assert e12_mul_by_34(accumulator, c3, c4) == e12_mul(accumulator, dense34)

        values = (_e2(rng), _e2(rng), _e2(rng), _e2(rng), _e2(rng))
        dense01234 = ((values[0], values[1], values[2]), (values[3], values[4], zero))
        assert e12_mul_by_01234(accumulator, values) == e12_mul(accumulator, dense01234)

        left034 = (_e2(rng), _e2(rng), _e2(rng))
        right034 = (_e2(rng), _e2(rng), _e2(rng))
        product = mul034_by034(left034, right034)
        dense_left = ((left034[0], zero, zero), (left034[1], left034[2], zero))
        dense_right = ((right034[0], zero, zero), (right034[1], right034[2], zero))
        dense_product = e12_mul(dense_left, dense_right)
        assert product == (
            dense_product[0][0],
            dense_product[0][1],
            dense_product[0][2],
            dense_product[1][0],
            dense_product[1][1],
        )

        left34 = (_e2(rng), _e2(rng))
        right34 = (_e2(rng), _e2(rng))
        product34 = mul34_by34(left34, right34)
        dense_left34 = ((one, zero, zero), (left34[0], left34[1], zero))
        dense_right34 = ((one, zero, zero), (right34[0], right34[1], zero))
        dense_product34 = e12_mul(dense_left34, dense_right34)
        assert product34 == (
            dense_product34[0][0],
            dense_product34[0][1],
            dense_product34[0][2],
            dense_product34[1][0],
            dense_product34[1][1],
        )


def test_optimized_square_and_cyclotomic_identity() -> None:
    rng = random.Random(0x4359434C4F)
    for _ in range(32):
        value = _e12(rng)
        assert e12_square_optimized(value) == e12_mul(value, value)

    # CyclotomicSquare's formula only agrees with generic squaring on the cyclotomic
    # subgroup. The exact rank decomposition is certified algebraically against the
    # formula itself; here we only assert deterministic shape/range on arbitrary input.
    value = _e12(rng)
    result = e12_cyclotomic_square(value)
    assert len(result) == 2 and all(len(component) == 3 for component in result)
    assert all(0 <= coordinate < P for e6 in result for e2 in e6 for coordinate in e2)


def test_sparse_rank_certificates_are_exact() -> None:
    result = certify_sparse_kernels(random_checks=16)
    assert result["passed"] is True
    ranks = {entry["name"]: entry["rank"] for entry in result["kernels"]}
    assert ranks == {
        "bn254-e6-mul-by-e2-rank9": 9,
        "bn254-e6-mul-by01-rank15": 15,
        "bn254-e12-square-rank36": 36,
        "bn254-e12-mul-by034-rank39": 39,
        "bn254-mul034-by034-rank18": 18,
        "bn254-e12-mul-by01234-rank51": 51,
        "bn254-cyclotomic-square-nonlinear-rank18": 18,
    }
    assert len(result["digest"]) == 64


def test_pairing_schedule_replaces_dense_trace() -> None:
    breakdown = groth16_pairing_rank_breakdown()
    assert breakdown.total_base_field_products == 12_997
    assert breakdown.dynamic_line_count == 88
    assert breakdown.zero_digits == 44
    assert breakdown.nonzero_digits == 21
    assert breakdown.dense_v05_pairing_products == 770_266
    assert breakdown.reduction_vs_dense_v05 > 59

    schedule = groth16_verifier_rank_schedule()
    assert schedule.old_erroneous_rank_terms == 645_221
    assert schedule.corrected_dense_exponentiation_model == 795_827
    assert schedule.corrected_dense_witness_model == 782_635
    assert schedule.known_arithmetic_subtotal == 25_889
    assert schedule.padded_rankfold_domain == 32_768
    assert schedule.rankfold_rounds == 15
    assert schedule.reduction_vs_corrected_dense_witness > 30
    assert schedule.unresolved_sha256_and_byte_binding is True


def test_primitive_inventory_is_stable_json() -> None:
    payload = json.dumps(asdict(PrimitiveRanks()), sort_keys=True)
    assert '"fq12_mul_by_34": 30' in payload
    assert '"fq12_square": 36' in payload
