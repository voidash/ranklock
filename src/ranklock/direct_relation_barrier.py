from __future__ import annotations

"""Concrete barrier for directly locking the full RankVM trace.

The fixed inner-product microprotocol proves that *timing* can be solved by
making future data witness variables of one static relation.  It does not make
relation-specific material succinct: even after batching all setup DLEQs, the
reference key stores two 33-byte points per scalar coordinate.

This module compares that exact byte law against the current foreign-field
verifier inventory.  It is a kill result for direct one-coordinate-per-event
compilation, not a lower bound for every linearly verifiable argument.  A
recursive/folding wrapper or a more structured gadget is required.
"""

from dataclasses import dataclass

from .fixed_relation_budget import (
    FixedRelationBudget,
    INNER_PRODUCT_BYTES_PER_SCALAR,
    INNER_PRODUCT_FIXED_BYTES,
    CIPHERTEXT_BYTES,
    RELATION_ID_BYTES,
)

CURRENT_NATIVE_MULTIPLICATIONS = 129_445
CURRENT_LOGICAL_LOOKUPS = 1_967_564
CURRENT_LINEAR_RELATIONS = 440_113
CURRENT_LOGICAL_EVENTS = (
    CURRENT_NATIVE_MULTIPLICATIONS
    + CURRENT_LOGICAL_LOOKUPS
    + CURRENT_LINEAR_RELATIONS
)


class DirectRelationBarrierError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DirectRelationBarrier:
    input_bytes: int = 132
    native_multiplications: int = CURRENT_NATIVE_MULTIPLICATIONS
    logical_lookups: int = CURRENT_LOGICAL_LOOKUPS
    linear_relations: int = CURRENT_LINEAR_RELATIONS
    cap_bytes: int = 1 << 20

    def __post_init__(self) -> None:
        if min(
            self.input_bytes,
            self.native_multiplications,
            self.logical_lookups,
            self.linear_relations,
            self.cap_bytes,
        ) <= 0:
            raise DirectRelationBarrierError("barrier inputs must be positive")

    @property
    def logical_events(self) -> int:
        return (
            self.native_multiplications + self.logical_lookups + self.linear_relations
        )

    @property
    def input_relation_width(self) -> int:
        return 2 * self.input_bytes

    @property
    def direct_relation_width(self) -> int:
        return self.input_relation_width + self.logical_events

    @property
    def multiplication_only_width(self) -> int:
        return self.input_relation_width + self.native_multiplications

    def _retained(self, width: int) -> int:
        budget = FixedRelationBudget(
            input_bytes=self.input_bytes, cap_bytes=self.cap_bytes
        )
        return (
            budget.projective_static_bytes
            + INNER_PRODUCT_FIXED_BYTES
            + int(width) * INNER_PRODUCT_BYTES_PER_SCALAR
            + CIPHERTEXT_BYTES
            + RELATION_ID_BYTES
        )

    @property
    def direct_retained_bytes(self) -> int:
        return self._retained(self.direct_relation_width)

    @property
    def multiplication_only_retained_bytes(self) -> int:
        return self._retained(self.multiplication_only_width)

    @property
    def maximum_trace_width(self) -> int:
        return FixedRelationBudget(
            input_bytes=self.input_bytes, cap_bytes=self.cap_bytes
        ).maximum_reference_trace_width

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-direct-fixed-relation-barrier-v1",
            "cap_bytes": self.cap_bytes,
            "future_input_bytes": self.input_bytes,
            "input_relation_width": self.input_relation_width,
            "known_verifier_inventory": {
                "native_multiplications": self.native_multiplications,
                "logical_lookups": self.logical_lookups,
                "linear_relations": self.linear_relations,
                "logical_events": self.logical_events,
            },
            "batched_DLEQ_key_bytes_per_scalar": INNER_PRODUCT_BYTES_PER_SCALAR,
            "maximum_trace_width_under_cap": self.maximum_trace_width,
            "multiplication_only": {
                "relation_width": self.multiplication_only_width,
                "retained_bytes": self.multiplication_only_retained_bytes,
                "mib": self.multiplication_only_retained_bytes / (1 << 20),
                "factor_over_cap": self.multiplication_only_retained_bytes / self.cap_bytes,
            },
            "all_logical_events": {
                "relation_width": self.direct_relation_width,
                "retained_bytes": self.direct_retained_bytes,
                "mib": self.direct_retained_bytes / (1 << 20),
                "factor_over_cap": self.direct_retained_bytes / self.cap_bytes,
            },
            "decision": (
                "KILL direct one-coordinate-per-event fixed relation. Even multiplication-only "
                "material exceeds the one-MiB target; use a succinct/folding/recursive wrapper "
                "or a structured gadget whose relation key does not scale with trace events."
            ),
            "scope": (
                "Executable cost barrier for the current concrete inner-product gadget; not a "
                "generic lower bound on all LVA-WE or witness-encryption constructions."
            ),
        }
