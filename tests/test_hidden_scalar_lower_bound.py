from __future__ import annotations

import pytest

from ranklock.hidden_scalar_lower_bound import (
    AlgebraicBarrierError,
    FormalGroupExpression,
    demonstrate_hidden_scalar_barrier,
    hidden_scalar_barrier,
    hypothetical_gt_to_g1,
    pairing,
)


def test_hidden_scalar_cross_term_is_unreachable_in_source_group() -> None:
    certificate = hidden_scalar_barrier(setup_r_degree_bound=32)
    assert certificate.barrier_holds
    assert not certificate.target_reachable_in_g1
    assert certificate.target_reachable_in_gt


def test_pairing_creates_r_times_future_point_only_in_target_group() -> None:
    p = FormalGroupExpression.monomial("G1", p_degree=1)
    r_g2 = FormalGroupExpression.monomial("G2", r_degree=1)
    product = pairing(p, r_g2)
    assert product.group == "GT"
    assert product.support == frozenset({(1, 1)})

    mapped = hypothetical_gt_to_g1(product)
    assert mapped.group == "G1"
    assert mapped.support == frozenset({(1, 1)})


def test_source_group_linear_operations_do_not_create_mixed_term() -> None:
    p = FormalGroupExpression.monomial("G1", p_degree=1)
    r = FormalGroupExpression.monomial("G1", r_degree=1)
    expression = p.scale(7) + r.scale(11) + FormalGroupExpression.monomial("G1")
    assert (1, 1) not in expression.support


def test_formal_model_rejects_cross_group_addition() -> None:
    with pytest.raises(AlgebraicBarrierError):
        _ = FormalGroupExpression.monomial("G1") + FormalGroupExpression.monomial("G2")


def test_demonstration_identifies_exact_missing_map() -> None:
    result = demonstrate_hidden_scalar_barrier()
    assert result["barrier_holds"] is True
    assert result["hypothetical_inverse_map_recovers_target"] is True
