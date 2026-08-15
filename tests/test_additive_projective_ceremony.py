from math import comb

import pytest

from ranklock.additive_projective_ceremony import (
    AdditiveProjectiveError,
    FallbackCutAndChoose,
    aggregate_certified_outputs,
    contributor_share_fixture,
    minimum_balanced_schedule,
)
from ranklock.bn254_real import G1, compress_g1, multiply
from ranklock.babe_positive_lock import deterministic_fixture


def _vk():
    vk, _public_inputs, _proof = deterministic_fixture(context=b"additive-projective-test")
    return vk


def test_additive_share_outputs_aggregate_exactly():
    vk = _vk()
    a = compress_g1(multiply(G1, 1234567, group="g1"))
    outputs, anchors, expected_output, expected_anchor = contributor_share_fixture(
        vk, input_a_g1=a, scales=(17, 29, 43)
    )
    aggregate_output, aggregate_anchor = aggregate_certified_outputs(
        input_a_g1=a,
        outputs_r_i_a_g1=outputs,
        vk=vk,
        r_i_delta_g2=anchors,
    )
    assert aggregate_output == expected_output
    assert aggregate_anchor == expected_anchor


def test_wrong_contributor_output_is_rejected():
    vk = _vk()
    a = compress_g1(multiply(G1, 7654321, group="g1"))
    outputs, anchors, _expected_output, _expected_anchor = contributor_share_fixture(
        vk, input_a_g1=a, scales=(5, 7)
    )
    wrong = list(outputs)
    wrong[1] = compress_g1(multiply(G1, 999, group="g1"))
    with pytest.raises(AdditiveProjectiveError):
        aggregate_certified_outputs(
            input_a_g1=a,
            outputs_r_i_a_g1=wrong,
            vk=vk,
            r_i_delta_g2=anchors,
        )


def test_cut_and_choose_exact_probability():
    schedule = FallbackCutAndChoose(20, 20)
    assert schedule.worst_case_undetected_total_live_failure_probability == 1 / comb(40, 20)
    assert 37.0 < schedule.soundness_bits < 38.0


def test_balanced_minima_hit_targets():
    for target in (40, 64, 80, 128):
        schedule = minimum_balanced_schedule(target)
        assert schedule.soundness_bits >= target
        if schedule.total_copies > 2:
            prev_n = schedule.total_copies - 1
            prev_q = prev_n // 2
            prev_t = prev_n - prev_q
            assert FallbackCutAndChoose(prev_t, prev_q).soundness_bits < target
