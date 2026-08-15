from __future__ import annotations

"""Symbolic LVA decomposition of the one-sided SNARK's final pairing equation.

The final check in Protocol 3.1 has the form

    Q^(s-alpha) = B * product_i a_i^xi_i * g^(-beta).

The tempting direct split-basis lock scales the two fixed G2 bases [s]G2 and
G2 by a common secret r.  Because the right hand side contains freely varying
future G1 proof terms with public coefficient 1, this publishes [r]G2.  Any
fixed statement-side G1 contribution can then be paired with [r]G2 by anyone,
so it cannot serve as the hidden accepting session.

This is a scoped barrier for the direct common-scalar two-anchor lift.  It does
not rule out the richer gadget construction of an LVA-WE framework.
"""

from dataclasses import dataclass


class LVADecompositionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FinalEquationInventory:
    q_terms_with_hidden_s_coefficient: int = 1
    future_g1_terms_with_public_g2_coefficient: int = 9
    fixed_statement_g1_terms_with_public_g2_coefficient: int = 7
    generator_scalar_terms: int = 1
    fixed_g2_anchor_rank: int = 2
    schema: str = "ranklock-one-sided-final-equation-inventory-v1"

    def __post_init__(self) -> None:
        if min(
            self.q_terms_with_hidden_s_coefficient,
            self.future_g1_terms_with_public_g2_coefficient,
            self.fixed_statement_g1_terms_with_public_g2_coefficient,
            self.generator_scalar_terms,
            self.fixed_g2_anchor_rank,
        ) < 0:
            raise LVADecompositionError("negative final-equation inventory")

    @property
    def direct_two_anchor_requires_scaled_g2_generator(self) -> bool:
        return self.future_g1_terms_with_public_g2_coefficient > 0

    @property
    def fixed_statement_session_public_under_direct_scaling(self) -> bool:
        return (
            self.direct_two_anchor_requires_scaled_g2_generator
            and self.fixed_statement_g1_terms_with_public_g2_coefficient > 0
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "Q_terms_with_(s-alpha)_coefficient": self.q_terms_with_hidden_s_coefficient,
            "future_G1_terms_with_public_G2_coefficient": (
                self.future_g1_terms_with_public_g2_coefficient
            ),
            "fixed_statement_G1_terms_with_public_G2_coefficient": (
                self.fixed_statement_g1_terms_with_public_g2_coefficient
            ),
            "generator_scalar_terms": self.generator_scalar_terms,
            "fixed_G2_anchor_rank": self.fixed_g2_anchor_rank,
            "direct_two_anchor_requires_[r]G2": (
                self.direct_two_anchor_requires_scaled_g2_generator
            ),
            "fixed_statement_session_is_public_under_direct_scaling": (
                self.fixed_statement_session_public_under_direct_scaling
            ),
        }


@dataclass(frozen=True, slots=True)
class DirectCommonScalarBarrier:
    inventory: FinalEquationInventory = FinalEquationInventory()
    schema: str = "ranklock-direct-common-scalar-lva-barrier-v1"

    @property
    def attack_applies(self) -> bool:
        return self.inventory.fixed_statement_session_public_under_direct_scaling

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "inventory": self.inventory.document(),
            "attack_applies": self.attack_applies,
            "argument": [
                "To scale every public-coefficient future G1 term by the same hidden r, the lock publishes [r]G2.",
                "The fixed verifier commitments and transcript-derived scalars are public G1 elements.",
                "Anyone can pair their fixed aggregate with [r]G2 and recover the proposed statement-side session without a valid proof.",
            ],
            "scope": (
                "Kills only the direct common-scalar split-basis construction.  A gadget "
                "may hide correlated verifier coefficients without exposing [r]G2."
            ),
        }


def one_sided_lva_decomposition() -> dict[str, object]:
    barrier = DirectCommonScalarBarrier()
    return {
        "schema": "ranklock-one-sided-lva-decomposition-v1",
        "direct_split_basis": barrier.document(),
        "surviving_routes": [
            "instantiate the concrete LVA-WE gadget for the full fixed relation",
            "construct a predictable/witness-PRF token for fixed RankVM invalidity",
            "redesign the wrapper so no freely varying proof term has a public-coefficient G2 anchor",
        ],
        "breakthrough_target_met": False,
    }
