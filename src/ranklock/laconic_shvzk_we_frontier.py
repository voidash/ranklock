from __future__ import annotations

"""Concrete frontier for the generic laconic-SHVZK -> witness-encryption route.

The Liu--Mazor--Pass characterization is an existence theorem: an efficient-
prover laconic SHVZK argument for a language implies witness encryption for
that language.  Its generic probabilistic-prover construction estimates the
simulated and real next-message distributions with histograms and then uses
correlated sampling.

This module does *not* implement that construction as production cryptography.
It records the concrete support-size barrier for the current one-sided RankLock
wrapper and audits whether the source protocol establishes the prerequisite
SHVZK property.
"""

from dataclasses import dataclass
import math


class LaconicFrontierError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProverCommunicationProfile:
    g1_elements: int = 10
    scalar_elements: int = 20
    g1_bytes: int = 64
    scalar_bytes: int = 32
    prover_speaking_phases: int = 9
    schema: str = "ranklock-prover-communication-profile-v1"

    def __post_init__(self) -> None:
        if min(
            self.g1_elements,
            self.scalar_elements,
            self.g1_bytes,
            self.scalar_bytes,
            self.prover_speaking_phases,
        ) <= 0:
            raise LaconicFrontierError("communication profile values must be positive")

    @property
    def bytes(self) -> int:
        return self.g1_elements * self.g1_bytes + self.scalar_elements * self.scalar_bytes

    @property
    def bits(self) -> int:
        return 8 * self.bytes

    @property
    def support_log2_upper_bound(self) -> int:
        # A distribution over ell-bit messages has support of size at most 2^ell.
        return self.bits

    @property
    def decimal_digits_in_support_bound(self) -> int:
        return math.floor(self.bits * math.log10(2)) + 1

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "g1_elements": self.g1_elements,
            "scalar_elements": self.scalar_elements,
            "proof_bytes": self.bytes,
            "prover_communication_bits": self.bits,
            "prover_speaking_phases": self.prover_speaking_phases,
            "next_message_support_upper_bound": f"2^{self.bits}",
            "support_bound_decimal_digits": self.decimal_digits_in_support_bound,
        }


@dataclass(frozen=True, slots=True)
class OneSidedSHVZKAudit:
    """Evidence audit for the monomial-basis one-sided SNARK used in v0.17.

    The source protocol commits directly to L, R, O, and L hadamard R and its
    security theorem proves soundness in the AGM.  The paper does not state an
    HVZK/SHVZK theorem or provide a simulator.  Absence of such a theorem is not
    an impossibility result, but it prevents invoking the generic WE theorem.
    """

    direct_wire_commitments: bool = True
    explicit_commitment_blinding: bool = False
    stated_hvzk_theorem: bool = False
    stated_shvzk_theorem: bool = False
    simulator_specified: bool = False
    source_security_theorem: str = "soundness/knowledge soundness in the algebraic group model"
    schema: str = "ranklock-one-sided-shvzk-audit-v1"

    @property
    def generic_we_prerequisite_established(self) -> bool:
        return self.stated_shvzk_theorem and self.simulator_specified

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "direct_wire_commitments": self.direct_wire_commitments,
            "explicit_commitment_blinding": self.explicit_commitment_blinding,
            "stated_HVZK_theorem": self.stated_hvzk_theorem,
            "stated_SHVZK_theorem": self.stated_shvzk_theorem,
            "simulator_specified": self.simulator_specified,
            "source_security_theorem": self.source_security_theorem,
            "generic_WE_prerequisite_established": self.generic_we_prerequisite_established,
            "decision": (
                "The current one-sided SNARK cannot be fed into the generic "
                "laconic-SHVZK-to-WE theorem without first constructing and proving "
                "a special-HVZK simulator (or replacing the proof system)."
            ),
        }


@dataclass(frozen=True, slots=True)
class HistogramCompilerCost:
    communication: ProverCommunicationProfile = ProverCommunicationProfile()
    histogram_counter_bytes: int = 8
    schema: str = "ranklock-generic-histogram-we-cost-v1"

    def __post_init__(self) -> None:
        if self.histogram_counter_bytes <= 0:
            raise LaconicFrontierError("histogram counter width must be positive")

    @property
    def support_log2(self) -> int:
        return self.communication.support_log2_upper_bound

    @property
    def explicit_histogram_log2_bytes(self) -> float:
        # log2(2^ell * counter_bytes) = ell + log2(counter_bytes)
        return self.support_log2 + math.log2(self.histogram_counter_bytes)

    @property
    def explicit_histogram_feasible(self) -> bool:
        # A deliberately generous research ceiling: one TiB.
        return self.explicit_histogram_log2_bytes <= 40

    @property
    def minimum_instance_bits_for_unit_laconic_constant_log2(self) -> int:
        # ell <= log2(n) requires n >= 2^ell.  Return log2(n), since n itself is huge.
        return self.communication.bits

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "communication": self.communication.document(),
            "generic_construction_mechanism": [
                "sample a simulator transcript prefix at fixed verifier coins",
                "estimate the simulator next-message distribution by repeated sampling",
                "estimate the honest-prover next-message distribution during decryption",
                "correlated-sample from the two estimated histograms",
            ],
            "explicit_histogram_entries_upper_bound": f"2^{self.support_log2}",
            "explicit_histogram_bytes_upper_bound": (
                f"2^{self.explicit_histogram_log2_bytes:.3f}"
            ),
            "explicit_histogram_feasible_under_one_TiB": self.explicit_histogram_feasible,
            "unit_constant_laconicity_would_require_instance_bits_at_least": (
                f"2^{self.minimum_instance_bits_for_unit_laconic_constant_log2}"
            ),
            "warning": (
                "The asymptotic theorem does not require explicit enumeration of a full "
                "2^ell table in every optimized realization; this figure evaluates the "
                "paper's generic histogram/correlated-sampling route at RankLock's concrete "
                "10-G1 + 20-scalar proof length."
            ),
        }


def laconic_shvzk_we_frontier() -> dict[str, object]:
    communication = ProverCommunicationProfile()
    audit = OneSidedSHVZKAudit()
    compiler = HistogramCompilerCost(communication)
    return {
        "schema": "ranklock-laconic-shvzk-we-frontier-v1",
        "theoretical_result": (
            "A laconic efficient-prover SHVZK argument would imply witness encryption "
            "for the fixed RankVM-invalidity language, so the identity-normalised final "
            "pairing is not a universal impossibility barrier."
        ),
        "source_protocol_audit": audit.document(),
        "generic_compiler_cost": compiler.document(),
        "concrete_decision": (
            "THEORETICAL_BYPASS_ONLY: the current source proof lacks an established "
            "SHVZK simulator, and the generic probabilistic-prover histogram compiler "
            "is not a practical path at 10,240 prover-message bits."
        ),
        "next_target": (
            "Construct a special-purpose, directly coupled/projective simulator for the "
            "fixed RankVM wrapper, or instantiate the concrete LVA-WE gadgets.  Either "
            "route must avoid enumerating the prover-message support."
        ),
        "breakthrough_target_met": False,
    }
