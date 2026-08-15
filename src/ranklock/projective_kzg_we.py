from __future__ import annotations

"""Cost-only model for the naive projective KZG/WE input catalog.

The 96-byte row size is the inherited compact formal model used by the v0.12
experiments.  It is not a claim about Duty-Free Bits or a production encoding.
"""

from typing import Sequence


def compact_projective_catalog_cost(cardinalities: Sequence[int]) -> dict[str, int | str]:
    values = tuple(int(value) for value in cardinalities)
    if not values or any(value < 2 for value in values):
        raise ValueError("every projective coordinate needs cardinality at least two")
    row_bytes = 96
    fixed_bytes = 96
    rows = sum(values)
    return {
        "schema": "ranklock-naive-projective-catalog-cost-v1",
        "coordinates": len(values),
        "rows": rows,
        "row_bytes": row_bytes,
        "fixed_bytes": fixed_bytes,
        "total_bytes_excluding_payload": fixed_bytes + rows * row_bytes,
    }
