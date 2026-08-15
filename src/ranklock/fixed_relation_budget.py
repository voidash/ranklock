from __future__ import annotations

"""Concrete byte envelope for the fixed-relation RankLock route.

The real static-linear microprototype uses 132 future bytes, two witness scalars
per byte, and a DLEQ-protected inner-product WE key.  Its key is intentionally
simple enough that every retained byte can be counted.  This module turns that
measurement into a kill boundary for the real LVA-WE compiler.

The budget is *not* a claim that an arbitrary RankVM verifier can be compiled to
one inner-product equation.  Nonlinear and pairing gadgets have different costs.
It answers a narrower question: how much relation-specific material remains under
the one-MiB target after the projective input layer is paid for?
"""

from dataclasses import dataclass

MIB = 1 << 20
SECP_POINT_BYTES = 33
DLEQ_BYTES = 64
LEGACY_INNER_PRODUCT_BYTES_PER_SCALAR = 2 * SECP_POINT_BYTES + DLEQ_BYTES
LEGACY_INNER_PRODUCT_FIXED_BYTES = 2 * SECP_POINT_BYTES
# One random-linear-combination DLEQ proof verifies all scaled bases.
INNER_PRODUCT_BYTES_PER_SCALAR = 2 * SECP_POINT_BYTES
INNER_PRODUCT_FIXED_BYTES = 2 * SECP_POINT_BYTES + DLEQ_BYTES
CIPHERTEXT_BYTES = 48
RELATION_ID_BYTES = 32
OT_OFFER_BYTES = 37


class FixedRelationBudgetError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FixedRelationBudget:
    input_bytes: int = 132
    cap_bytes: int = MIB
    coordinate_public_bytes: int = 5 * 33 + 2 * 64 + 8 * 33
    projective_global_bytes: int = 4 + 32 + 33 + 33 + 48
    ot_bits_per_byte: int = 8

    def __post_init__(self) -> None:
        if min(
            self.input_bytes,
            self.cap_bytes,
            self.coordinate_public_bytes,
            self.projective_global_bytes,
            self.ot_bits_per_byte,
        ) <= 0:
            raise FixedRelationBudgetError("budget parameters must be positive")

    @property
    def projective_public_without_offers(self) -> int:
        return self.projective_global_bytes + self.input_bytes * self.coordinate_public_bytes

    @property
    def offer_count(self) -> int:
        return self.input_bytes * self.ot_bits_per_byte

    @property
    def offer_bytes(self) -> int:
        return self.offer_count * OT_OFFER_BYTES

    @property
    def projective_static_bytes(self) -> int:
        return self.projective_public_without_offers + self.offer_bytes

    @property
    def input_relation_width(self) -> int:
        return 2 * self.input_bytes

    def retained_bytes_for_width(self, relation_width: int) -> int:
        relation_width = int(relation_width)
        if relation_width < self.input_relation_width:
            raise FixedRelationBudgetError("relation width omits projective input witnesses")
        return (
            self.projective_static_bytes
            + INNER_PRODUCT_FIXED_BYTES
            + relation_width * INNER_PRODUCT_BYTES_PER_SCALAR
            + CIPHERTEXT_BYTES
            + RELATION_ID_BYTES
        )

    @property
    def maximum_reference_relation_width(self) -> int:
        fixed = (
            self.projective_static_bytes
            + INNER_PRODUCT_FIXED_BYTES
            + CIPHERTEXT_BYTES
            + RELATION_ID_BYTES
        )
        if fixed > self.cap_bytes:
            return -1
        return (self.cap_bytes - fixed) // INNER_PRODUCT_BYTES_PER_SCALAR

    @property
    def maximum_reference_trace_width(self) -> int:
        return self.maximum_reference_relation_width - self.input_relation_width

    @property
    def remaining_raw_bytes_after_projective_layer(self) -> int:
        return self.cap_bytes - self.projective_static_bytes

    @property
    def maximum_g1_elements_after_projective_layer(self) -> int:
        return self.remaining_raw_bytes_after_projective_layer // 48

    @property
    def maximum_g2_elements_after_projective_layer(self) -> int:
        return self.remaining_raw_bytes_after_projective_layer // 96

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-fixed-relation-budget-v1",
            "cap_bytes": self.cap_bytes,
            "input_bytes": self.input_bytes,
            "projective_input_relation_width": self.input_relation_width,
            "projective_public_without_offers": self.projective_public_without_offers,
            "projective_offer_count": self.offer_count,
            "projective_offer_bytes": self.offer_bytes,
            "projective_static_bytes": self.projective_static_bytes,
            "remaining_raw_bytes_after_projective_layer": self.remaining_raw_bytes_after_projective_layer,
            "reference_inner_product_bytes_per_scalar": INNER_PRODUCT_BYTES_PER_SCALAR,
            "reference_batched_inner_product_fixed_bytes": INNER_PRODUCT_FIXED_BYTES,
            "legacy_per_coordinate_DLEQ_bytes_per_scalar": LEGACY_INNER_PRODUCT_BYTES_PER_SCALAR,
            "maximum_reference_relation_width": self.maximum_reference_relation_width,
            "maximum_reference_trace_width": self.maximum_reference_trace_width,
            "maximum_48_byte_G1_elements_after_projective_layer": self.maximum_g1_elements_after_projective_layer,
            "maximum_96_byte_G2_elements_after_projective_layer": self.maximum_g2_elements_after_projective_layer,
            "interpretation": (
                "The batched-DLEQ fixed-linear compiler can retain at most this many "
                "scalar bases under one MiB. A real LVA gadget compiler may use a "
                "different mix of G1/G2 elements and must be measured separately."
            ),
            "kill_rule": (
                "Reject the fixed-relation route if relation-specific CRS/key material, "
                "excluding a genuinely universal reusable CRS, exceeds the remaining byte budget."
            ),
        }


def lva_wrapper_frontier(
    *,
    input_bytes: int = 132,
    raw_kzg_openings: int = 72,
    batched_kzg_openings: int = 4,
    input_auth_gadgets: int = 2,
) -> dict[str, object]:
    budget = FixedRelationBudget(input_bytes=input_bytes)
    return {
        "schema": "ranklock-lva-wrapper-frontier-v1",
        "fixed_relation": {
            "future commitments_are_witness_variables": True,
            "post_statement_encapsulator_required": False,
            "future_bytes_are_authenticated_witness_variables": True,
        },
        "known_gadget_inventory": {
            "raw_KZG_openings_before_safe_batching": int(raw_kzg_openings),
            "same_point_batched_KZG_opening_gadgets": int(batched_kzg_openings),
            "aggregate_input_authentication_gadgets": int(input_auth_gadgets),
            "RankVM_invalidity_verifier_compiled": False,
            "Fiat_Shmir_or_beacon_binding_compiled": False,
        },
        "byte_budget": budget.document(),
        "decisive_unknowns": [
            "exact LVA-WE encryption-key/CRS elements per KZG, multiplication, hash, and range gadget",
            "whether the CRS is universal/reusable or verifier-specific retained material",
            "malicious setup and extractability of the composed relation",
            "actual RankVM proof-verifier width including transcript hashing",
        ],
    }
