from __future__ import annotations

from ranklock.beacon_sumcheck import estimate_naive_beacon_precommit


def test_rankfold_dense_one_beacon_message_precommit_is_quadratic_scale() -> None:
    estimate = estimate_naive_beacon_precommit(15, round_degree=3)
    assert estimate.original_table_size == 32_768
    assert estimate.committed_field_coefficients == (4**16 - 4) // 3
    assert estimate.committed_field_coefficients == 1_431_655_764
    assert estimate.coefficient_bytes == 45_812_984_448
    assert estimate.blowup_vs_table > 40_000


def test_degree_two_precommit_is_still_far_from_near_linear() -> None:
    estimate = estimate_naive_beacon_precommit(15, round_degree=2)
    assert estimate.committed_field_coefficients == (3**16 - 3) // 2
    assert estimate.coefficient_bytes > 600_000_000
    assert estimate.blowup_vs_table > 600
