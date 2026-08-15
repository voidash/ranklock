from __future__ import annotations

import pytest

from ranklock.public_correlation_rank import (
    CorrelationRankError,
    certify_public_correlation_expander,
    demonstrate_rank_dichotomy,
    independent_base_matrix,
    matrix_rank,
    structured_coefficient_matrix,
)


def test_independent_public_correlations_need_one_seed_direction_each() -> None:
    matrix = independent_base_matrix(32)
    exact = certify_public_correlation_expander(matrix, public_seed_elements=32)
    short = certify_public_correlation_expander(matrix, public_seed_elements=31)
    assert exact.coefficient_rank == 32
    assert exact.lower_bound_met
    assert not short.lower_bound_met


def test_structured_verifier_needs_only_its_public_coefficient_rank() -> None:
    matrix = structured_coefficient_matrix(11, 2)
    certificate = certify_public_correlation_expander(
        matrix, public_seed_elements=2
    )
    assert matrix_rank(matrix) == 2
    assert certificate.lower_bound_met
    assert certificate.minimum_seed_bytes == 128
    assert certificate.direct_independent_bytes == 704
    assert certificate.cryptographic_compression_ratio == 5.5


def test_rank_dichotomy_records_scope_and_negative_case() -> None:
    result = demonstrate_rank_dichotomy(
        independent_width=64, term_count=11, anchor_count=2
    )
    assert result["generic_independent"]["coefficient_rank"] == 64
    assert result["generic_one_seed_short"]["lower_bound_met"] is False
    assert result["structured_low_rank"]["coefficient_rank"] == 2
    assert "not a universal" in result["structured_low_rank"]["scope"].lower()


def test_rank_model_rejects_ragged_or_impossible_shapes() -> None:
    with pytest.raises(CorrelationRankError):
        matrix_rank(((1, 2), (3,)))
    with pytest.raises(CorrelationRankError):
        structured_coefficient_matrix(1, 2)
