from ranklock.one_sided_lva_decomposition import (
    DirectCommonScalarBarrier,
    FinalEquationInventory,
    one_sided_lva_decomposition,
)


def test_public_coefficient_terms_force_scaled_generator_anchor() -> None:
    inventory = FinalEquationInventory()
    assert inventory.fixed_g2_anchor_rank == 2
    assert inventory.direct_two_anchor_requires_scaled_g2_generator
    assert inventory.fixed_statement_session_public_under_direct_scaling


def test_direct_common_scalar_attack_applies() -> None:
    barrier = DirectCommonScalarBarrier()
    assert barrier.attack_applies
    result = barrier.document()
    assert result["attack_applies"] is True
    assert "[r]G2" in result["argument"][0]


def test_richer_lva_gadgets_are_not_ruled_out() -> None:
    result = one_sided_lva_decomposition()
    assert result["breakthrough_target_met"] is False
    assert any("LVA-WE" in route for route in result["surviving_routes"])
