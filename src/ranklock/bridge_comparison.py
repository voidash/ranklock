from __future__ import annotations

"""Apples-to-apples field-bridge comparison and break-even analysis.

The cost points are logical constraint inventories, not backend row counts.  A
backend may pack multiple lookups in one row or charge a multiplication gate
more than one lookup.  The comparison therefore records symbolic break-even
weights and keeps unsound dual-field lower bounds separate from selectable
routes.
"""

from dataclasses import dataclass
from statistics import median
from time import perf_counter
import random
from typing import Callable

from .crt_bridge import (
    build_bound_crt_mul_witness,
    estimate_bounded_quotient_crt_bridge,
    estimate_bounded_quotient_free_shared_table_lower_bound,
    verify_bound_crt_mul_witness,
)
from .field import BN254_BASE_FIELD
from .field_bridge import (
    RangeLookupModel,
    build_bound_foreign_mul_witness,
    estimate_reduced_quotient_limb_bridge,
    verify_bound_foreign_mul_witness,
)
from .low_rank_field_bridge import (
    build_low_rank_bound_foreign_mul_witness,
    estimate_low_rank_reduced_quotient_limb_bridge,
    verify_low_rank_bound_foreign_mul_witness,
)
from .nonnative_field import (
    BLS12_381_SCALAR_FIELD,
    candidate_configs,
    best_config,
)
from .split_limb_field import (
    build_split_limb_mul_witness,
    estimate_split_limb_reduced_quotient_schedule,
    verify_split_limb_mul_witness,
)


@dataclass(frozen=True, slots=True)
class RouteCostPoint:
    name: str
    lookup_events_per_product: int
    nonlinear_products_per_product: int
    proof_fields: int
    sound_cross_field_binding: bool
    selectable: bool
    notes: str

    def weighted_cost(self, multiplication_weight: float) -> float:
        return self.lookup_events_per_product + (
            float(multiplication_weight) * self.nonlinear_products_per_product
        )

    def document(self) -> dict[str, object]:
        return {
            "name": self.name,
            "logical_lookup_events_per_foreign_product": self.lookup_events_per_product,
            "native_nonlinear_products_per_foreign_product": self.nonlinear_products_per_product,
            "proof_fields": self.proof_fields,
            "sound_cross_field_binding": self.sound_cross_field_binding,
            "selectable": self.selectable,
            "notes": self.notes,
        }


def _cost_relation(
    baseline: RouteCostPoint, challenger: RouteCostPoint
) -> dict[str, object]:
    """Describe L + w*M comparison for nonnegative multiplication weight ``w``."""

    lookup_delta = (
        challenger.lookup_events_per_product - baseline.lookup_events_per_product
    )
    multiplication_delta = (
        challenger.nonlinear_products_per_product
        - baseline.nonlinear_products_per_product
    )
    result: dict[str, object] = {
        "lookup_delta": lookup_delta,
        "native_nonlinear_product_delta": multiplication_delta,
        "multiplication_weight_domain": "w >= 0",
    }

    if lookup_delta <= 0 and multiplication_delta <= 0:
        result.update(
            {
                "classification": "challenger_dominates_cost_point",
                "equal_cost_weight": None,
            }
        )
        return result
    if lookup_delta >= 0 and multiplication_delta >= 0:
        result.update(
            {
                "classification": "baseline_dominates_cost_point",
                "equal_cost_weight": None,
            }
        )
        return result
    if multiplication_delta == 0:
        result.update(
            {
                "classification": "parallel_cost_lines",
                "equal_cost_weight": None,
            }
        )
        return result

    threshold = -lookup_delta / multiplication_delta
    if threshold < 0:
        classification = "no_nonnegative_break_even"
    elif multiplication_delta < 0:
        classification = "challenger_wins_above_threshold"
    else:
        classification = "challenger_wins_below_threshold"
    result.update(
        {
            "classification": classification,
            "equal_cost_weight": threshold,
        }
    )
    return result


def _limb_geometry_sweep(
    range_model: RangeLookupModel,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for config in candidate_configs(
        native_modulus=BLS12_381_SCALAR_FIELD, maximum_limbs=8
    ):
        estimate = estimate_low_rank_reduced_quotient_limb_bridge(
            1, config, range_model=range_model
        )
        rows.append(
            {
                "limbs": config.limbs,
                "limb_bits": config.limb_bits,
                "capacity_bits": config.limbs * config.limb_bits,
                "carry_abs_bound_bits": config.carry_abs_bound.bit_length(),
                "native_nonlinear_products": estimate.native_nonlinear_products,
                "logical_lookup_events": estimate.total_lookup_events,
                "simple_row_equivalent": estimate.simple_row_equivalent,
            }
        )
    return sorted(rows, key=lambda row: int(row["simple_row_equivalent"]))


def compare_bridge_routes(
    foreign_products: int = 25_889,
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
) -> dict[str, object]:
    if foreign_products <= 0:
        raise ValueError("foreign-product count must be positive")

    limb_config = best_config(native_modulus=BLS12_381_SCALAR_FIELD)
    limb_schoolbook = estimate_reduced_quotient_limb_bridge(
        foreign_products, limb_config, range_model=range_model
    )
    limb = estimate_low_rank_reduced_quotient_limb_bridge(
        foreign_products, limb_config, range_model=range_model
    )
    split = estimate_split_limb_reduced_quotient_schedule(
        foreign_products, range_model=range_model
    )
    crt = estimate_bounded_quotient_crt_bridge(
        foreign_products, range_model=range_model
    )
    crt_lower = estimate_bounded_quotient_free_shared_table_lower_bound(
        foreign_products, range_model=range_model
    )

    routes = (
        RouteCostPoint(
            "single_field_3x85_rank5",
            limb.total_lookup_events // foreign_products,
            limb.native_nonlinear_products // foreign_products,
            1,
            True,
            True,
            "rank-5 fixed-point convolution; canonical output and 254-bit bounded internal quotient",
        ),
        RouteCostPoint(
            "single_field_3x85_schoolbook_reference",
            limb_schoolbook.total_lookup_events // foreign_products,
            limb_schoolbook.native_nonlinear_products // foreign_products,
            1,
            True,
            False,
            "legacy nine-product reference; strictly dominated by rank-5 convolution",
        ),
        RouteCostPoint(
            "single_field_2x127_split",
            split.total_lookup_events // foreign_products,
            split.native_nonlinear_products // foreign_products,
            1,
            True,
            True,
            "four exact products; product-chunk normalization drives lookup cost",
        ),
        RouteCostPoint(
            "dual_field_crt_bounded_quotient_owner_side",
            crt.total_lookup_events // foreign_products,
            crt.native_nonlinear_products // foreign_products,
            2,
            False,
            False,
            "canonical output plus 254-bit quotient bound are modeled, but no cross-PCS equality proof exists",
        ),
        RouteCostPoint(
            "dual_field_crt_bounded_quotient_free_shared_table_lower_bound",
            crt_lower.total_lookup_events // foreign_products,
            crt_lower.native_nonlinear_products // foreign_products,
            2,
            False,
            False,
            "optimistic lower bound assuming free cross-field table sharing; not a construction",
        ),
    )
    baseline = routes[0]
    weights = (1.0, 4.0, 8.0, 16.0, 32.0)
    selectable = tuple(route for route in routes if route.selectable)
    return {
        "schema": "ranklock-field-bridge-comparison-v4",
        "evidence_class": "ESTIMATE backed by exact executable witness and constraint-inventory models",
        "foreign_products": foreign_products,
        "range_model": range_model.document(),
        "fixed_table_rows_not_amortized_into_event_counts": range_model.document()[
            "table_rows"
        ],
        "routes": [route.document() for route in routes],
        "cost_relation_vs_3x85": {
            route.name: _cost_relation(baseline, route) for route in routes[1:]
        },
        "weighted_rankings_selectable_routes": {
            str(weight): [
                route.name
                for route in sorted(
                    selectable, key=lambda item: item.weighted_cost(weight)
                )
            ]
            for weight in weights
        },
        "weighted_rankings_all_cost_points": {
            str(weight): [
                route.name
                for route in sorted(routes, key=lambda item: item.weighted_cost(weight))
            ]
            for weight in weights
        },
        "single_field_limb_geometry_sweep": _limb_geometry_sweep(range_model),
        "decision": {
            "current_single_field_baseline": "single_field_3x85_rank5",
            "status": "provisional pending a real lookup backend",
            "reason": (
                "rank-5 3x85 is cheapest among safe 3-to-8-limb low-rank convolution "
                "geometries in the 16-bit logical-event model. Removing the redundant "
                "quotient canonical-slack proof lowers it to 76 lookups plus five "
                "multiplications. The exact 2x127 challenger needs a multiplication "
                "gate to cost more than 130 lookup events before its four-product core "
                "wins. Backend packing could still change that result."
            ),
            "dual_field_status": (
                "not selectable: both CRT cost points omit the cryptographic equality proof "
                "that binds the two PCS traces to one canonical table"
            ),
        },
    }


def compare_range_widths(
    foreign_products: int = 25_889,
    *,
    chunk_widths: tuple[int, ...] = (8, 12, 16, 20),
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for chunk_bits in chunk_widths:
        model = RangeLookupModel(chunk_bits)
        comparison = compare_bridge_routes(foreign_products, range_model=model)
        routes = {route["name"]: route for route in comparison["routes"]}
        relation = comparison["cost_relation_vs_3x85"]["single_field_2x127_split"]
        rows.append(
            {
                "chunk_bits": chunk_bits,
                "fixed_table_rows": 1 << chunk_bits,
                "3x85_lookup_events_per_product": routes["single_field_3x85_rank5"][
                    "logical_lookup_events_per_foreign_product"
                ],
                "2x127_lookup_events_per_product": routes[
                    "single_field_2x127_split"
                ]["logical_lookup_events_per_foreign_product"],
                "2x127_equal_cost_multiplication_weight": relation[
                    "equal_cost_weight"
                ],
            }
        )
    return {
        "schema": "ranklock-range-width-sensitivity-v1",
        "foreign_products": foreign_products,
        "rows": rows,
        "warning": (
            "fixed-table rows and backend-specific lookup packing are shown separately; "
            "logical lookup events are not physical proof rows"
        ),
    }


def _time_route(
    pairs: tuple[tuple[int, int], ...],
    build: Callable[[int, int], object],
    verify: Callable[[object], bool],
    *,
    repeats: int,
) -> dict[str, object]:
    elapsed: list[float] = []
    for _ in range(repeats):
        start = perf_counter()
        for x, y in pairs:
            witness = build(x, y)
            if not verify(witness):
                raise AssertionError("field-bridge benchmark witness failed verification")
        elapsed.append(perf_counter() - start)
    seconds = median(elapsed)
    return {
        "cases": len(pairs),
        "repeats": repeats,
        "median_seconds": seconds,
        "witnesses_per_second": len(pairs) / seconds,
        "all_seconds": elapsed,
    }


def benchmark_field_bridges(
    *, cases: int = 300, repeats: int = 3, seed: int = 0x52414E4B
) -> dict[str, object]:
    if cases <= 0 or repeats <= 0:
        raise ValueError("benchmark cases and repeats must be positive")
    rng = random.Random(seed)
    pairs = tuple(
        (rng.randrange(BN254_BASE_FIELD), rng.randrange(BN254_BASE_FIELD))
        for _ in range(cases)
    )
    limb_config = best_config(native_modulus=BLS12_381_SCALAR_FIELD)
    return {
        "schema": "ranklock-field-bridge-native-benchmark-v1",
        "evidence_class": "REPRODUCED native Python witness model; not PCS performance",
        "seed": seed,
        "routes": {
            "single_field_3x85_rank5": _time_route(
                pairs,
                lambda x, y: build_low_rank_bound_foreign_mul_witness(
                    x, y, limb_config
                ),
                lambda witness: verify_low_rank_bound_foreign_mul_witness(
                    witness, limb_config
                ),
                repeats=repeats,
            ),
            "single_field_3x85_schoolbook_reference": _time_route(
                pairs,
                lambda x, y: build_bound_foreign_mul_witness(x, y, limb_config),
                lambda witness: verify_bound_foreign_mul_witness(
                    witness, limb_config
                ),
                repeats=repeats,
            ),
            "single_field_2x127_split": _time_route(
                pairs,
                build_split_limb_mul_witness,
                verify_split_limb_mul_witness,
                repeats=repeats,
            ),
            "dual_field_crt_bounded_quotient_owner_side": _time_route(
                pairs,
                build_bound_crt_mul_witness,
                verify_bound_crt_mul_witness,
                repeats=repeats,
            ),
        },
    }
