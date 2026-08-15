from __future__ import annotations

from ranklock.hidden_product_crs_frontier import (
    HiddenProductCRSScenario,
    hidden_product_crs_report,
    monomial_count,
    multiply_bivariate_affine_factors,
)


def test_bivariate_affine_product_has_triangular_monomial_growth() -> None:
    modulus = 2**127 - 1
    factors = tuple((1, 2**index + 1, 3**index + 1) for index in range(8))
    coefficients = multiply_bivariate_affine_factors(factors, modulus)
    assert len(coefficients) == monomial_count(8, 2) == 45
    assert max(x + y for x, y in coefficients) == 8


def test_sparse_rankvm_hidden_product_crs_is_tens_of_gibibytes() -> None:
    scenario = HiddenProductCRSScenario("sparse", 25_889)
    assert scenario.required_source_group_directions == 335_158_995
    assert scenario.raw_source_group_bytes == 21_785_334_675
    assert scenario.raw_source_group_bytes > 20 * (1 << 30)


def test_naive_hidden_monomial_route_is_killed_without_claiming_universality() -> None:
    report = hidden_product_crs_report()
    assert report["small_exact_experiment"]["full_generic_support_observed"] is True
    assert "prepublish all hidden-challenge" in report["killed_route"]
    assert "multilinear maps" in report["not_ruled_out"]
    assert report["new_primitive_target"]["constructed"] is False
    assert report["breakthrough_target_met"] is False
