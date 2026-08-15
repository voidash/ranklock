from ranklock.fixed_relation_budget import (
    FixedRelationBudget,
    lva_wrapper_frontier,
)


def test_exact_132_byte_static_budget_matches_concrete_projective_layout() -> None:
    budget = FixedRelationBudget()
    assert budget.projective_public_without_offers == 73_674
    assert budget.offer_bytes == 39_072
    assert budget.projective_static_bytes == 112_746
    assert budget.maximum_reference_relation_width == 14_176
    assert budget.maximum_reference_trace_width == 13_912
    assert budget.retained_bytes_for_width(328) == 134_604


def test_budget_exposes_real_lva_unknowns_without_claiming_compiler() -> None:
    report = lva_wrapper_frontier()
    assert report["fixed_relation"]["post_statement_encapsulator_required"] is False
    assert report["known_gadget_inventory"]["same_point_batched_KZG_opening_gadgets"] == 4
    assert report["known_gadget_inventory"]["RankVM_invalidity_verifier_compiled"] is False
    assert report["byte_budget"]["maximum_reference_trace_width"] == 13_912
