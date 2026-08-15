from __future__ import annotations

from ranklock.outer_g1_binding import (
    LogicalRangeModel,
    OnCurveBindingCost,
    OuterFieldLimbGeometry,
    StandardSubgroupCheckCost,
    outer_g1_binding_report,
)


def test_outer_field_geometry_is_no_wrap_and_rank_nine() -> None:
    geometry = OuterFieldLimbGeometry()
    assert geometry.limbs == 5
    assert geometry.limb_bits == 103
    assert geometry.convolution_rank == 9
    assert geometry.safe_no_wrap
    assert geometry.equation_abs_bound.bit_length() == 211


def test_exact_and_fused_on_curve_ledgers_replace_the_300_guess() -> None:
    exact16 = OnCurveBindingCost(range_model=LogicalRangeModel(16))
    fused20 = OnCurveBindingCost(range_model=LogicalRangeModel(20))

    assert exact16.native_products_only == 27
    assert exact16.optimistic_fused_rows == 355
    assert exact16.exact_logical_rows == 523
    assert fused20.optimistic_fused_rows == 302


def test_conventional_subgroup_check_is_far_over_the_gate() -> None:
    subgroup = StandardSubgroupCheckCost()
    assert subgroup.doublings == 253
    assert subgroup.additions == 110
    assert subgroup.foreign_products == 3_531
    assert subgroup.native_product_rows == 31_779


def test_secure_generic_parser_is_killed_but_specialised_binding_remains_open() -> None:
    report = outer_g1_binding_report()
    assert report["point_binding_threshold_per_G1"] == 325
    assert report["decision"]["generic_full_parser_under_325"] is False
    assert report["decision"]["generic_public_FS_wrapper_size_gate_survives"] is False

    scenarios = {entry["name"]: entry for entry in report["scenarios"]}
    exact = scenarios["16-bit exact canonical/on-curve ledger without subgroup"]
    fused = scenarios["20-bit optimistic fused-carry on-curve ledger without subgroup"]
    full = scenarios["standard full subgroup check, native products only"]

    assert exact["fits_one_MiB"] is False
    assert fused["fits_one_MiB"] is True
    assert fused["security_complete"] is False
    assert full["security_complete"] is True
    assert full["fits_one_MiB"] is False
    assert report["surviving_research_targets"]
