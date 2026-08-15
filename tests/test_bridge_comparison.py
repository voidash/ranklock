from math import isclose

from ranklock.bridge_comparison import compare_bridge_routes, compare_range_widths


def test_bridge_comparison_records_rank_five_cost_relations_and_decision() -> None:
    document = compare_bridge_routes(foreign_products=1)
    routes = {route["name"]: route for route in document["routes"]}
    assert routes["single_field_3x85_rank5"]["logical_lookup_events_per_foreign_product"] == 76
    assert routes["single_field_3x85_rank5"]["native_nonlinear_products_per_foreign_product"] == 5
    assert routes["single_field_3x85_schoolbook_reference"]["native_nonlinear_products_per_foreign_product"] == 9
    assert routes["single_field_2x127_split"]["logical_lookup_events_per_foreign_product"] == 206
    assert routes["dual_field_crt_bounded_quotient_owner_side"]["logical_lookup_events_per_foreign_product"] == 63
    assert routes["dual_field_crt_bounded_quotient_free_shared_table_lower_bound"]["logical_lookup_events_per_foreign_product"] == 49

    relations = document["cost_relation_vs_3x85"]
    schoolbook = relations["single_field_3x85_schoolbook_reference"]
    assert schoolbook["classification"] == "baseline_dominates_cost_point"

    split = relations["single_field_2x127_split"]
    assert split["classification"] == "challenger_wins_above_threshold"
    assert isclose(split["equal_cost_weight"], 130.0)

    crt = relations["dual_field_crt_bounded_quotient_owner_side"]
    assert crt["classification"] == "challenger_dominates_cost_point"
    assert crt["equal_cost_weight"] is None

    lower = relations["dual_field_crt_bounded_quotient_free_shared_table_lower_bound"]
    assert lower["classification"] == "challenger_dominates_cost_point"
    assert lower["equal_cost_weight"] is None

    assert document["decision"]["current_single_field_baseline"] == "single_field_3x85_rank5"
    assert document["decision"]["status"] == "provisional pending a real lookup backend"
    assert document["weighted_rankings_selectable_routes"]["1.0"] == [
        "single_field_3x85_rank5",
        "single_field_2x127_split",
    ]


def test_low_rank_geometry_sweep_keeps_3x85_ahead_of_4x64_and_larger() -> None:
    sweep = compare_bridge_routes(foreign_products=1)[
        "single_field_limb_geometry_sweep"
    ]
    assert (sweep[0]["limbs"], sweep[0]["limb_bits"]) == (3, 85)
    assert (sweep[1]["limbs"], sweep[1]["limb_bits"]) == (4, 64)
    assert sweep[0]["native_nonlinear_products"] == 5
    assert sweep[1]["native_nonlinear_products"] == 7
    assert sweep[0]["simple_row_equivalent"] < sweep[1]["simple_row_equivalent"]


def test_range_width_sensitivity_exposes_table_size_tradeoff() -> None:
    sensitivity = compare_range_widths(foreign_products=1)
    rows = {row["chunk_bits"]: row for row in sensitivity["rows"]}
    assert rows[8]["fixed_table_rows"] == 256
    assert rows[16]["fixed_table_rows"] == 65_536
    assert rows[20]["fixed_table_rows"] == 1_048_576
    assert rows[16]["2x127_equal_cost_multiplication_weight"] == 130.0
