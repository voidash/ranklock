from __future__ import annotations

"""One-sided pairing-SNARK frontier for a static RankLock witness lift.

This module records a concrete verifier shape that is materially better suited to
RankLock than Groth16: every prover-defined group element is in G1 and the final
pairing equation uses only the two fixed G2 directions ``[s]G2`` and ``G2``.

The reference profile follows the public parameters reported for *A flexible
Snark via the monomial basis* (ePrint 2023/1255): 10 G1 proof elements, 20 scalar
field elements, two pairings, a proof-size-optimised CRS of length
``3 * |Circuit|``, a prover-time-optimised CRS of length ``|Circuit|``, and a
combined G1 MSM length of ``22 * |Circuit|``.

The code does not implement that SNARK, an outer curve to BN254, or the 2025
LVA-to-WE compiler.  It provides:

* a real BN254 model of the final rank-two pairing equation;
* exact coefficient-rank certification;
* parameterised proof/CRS/MSM cost envelopes;
* a transcript strategy audit explaining why public Fiat--Shamir cannot simply
  be omitted from a static conditional lock;
* an explicit list of the remaining construction gates.

The decisive candidate is to compile the *interactive* linearly verifiable
protocol, with verifier challenges hidden in the static WE key, rather than to
verify a public Fiat--Shamir transcript inside the lock.  Whether the monomial
SNARK's prover messages satisfy the exact linear-response interface required by
that compiler remains open.
"""

from dataclasses import dataclass
from math import ceil
from typing import Sequence

from .bn254_real import (
    CURVE_ORDER,
    FQ12,
    G1,
    G2,
    Point,
    add,
    compress_g1,
    decompress_g1,
    multiply,
    neg,
    pairing_product,
)
from .public_correlation_rank import matrix_rank

MIB = 1 << 20
KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL = 25_889
CURRENT_PROJECTIVE_INPUT_BYTES = 257_418
DFB_LEADING_EXPRESSION_BYTES = 8_288


class OneSidedWrapperError(ValueError):
    pass


def _field(value: int) -> int:
    return int(value) % CURVE_ORDER


def _ceil_mib(value: int) -> float:
    return int(value) / MIB


@dataclass(frozen=True, slots=True)
class OneSidedFinalPairingEquation:
    """Real BN254 model of the final one-sided KZG-style pairing equation.

    The verifier checks

        e(Q, [s]G2) = e(R + alpha^{-1} Q, G2).

    Both future proof elements ``Q`` and ``R`` are in G1.  The fixed G2
    coefficient basis is ``([s]G2, G2)`` and has rank two.
    """

    trapdoor_s: int
    challenge_alpha: int
    schema: str = "ranklock-one-sided-final-pairing-v1"

    def __post_init__(self) -> None:
        s = _field(self.trapdoor_s)
        alpha = _field(self.challenge_alpha)
        if s == 0:
            raise OneSidedWrapperError("one-sided pairing trapdoor is zero")
        if alpha == 0:
            raise OneSidedWrapperError("one-sided pairing challenge is zero")
        object.__setattr__(self, "trapdoor_s", s)
        object.__setattr__(self, "challenge_alpha", alpha)

    @property
    def alpha_inverse(self) -> int:
        return pow(self.challenge_alpha, -1, CURVE_ORDER)

    @property
    def coefficient_matrix(self) -> tuple[tuple[int, int], tuple[int, int]]:
        # Move the right-hand side to the left:
        # e(Q, [s-alpha^-1]G2) * e(R, [-1]G2) = 1.
        return (
            (1, (-self.alpha_inverse) % CURVE_ORDER),
            (0, (-1) % CURVE_ORDER),
        )

    @property
    def fixed_g2_anchor_rank(self) -> int:
        return matrix_rank(self.coefficient_matrix, modulus=CURVE_ORDER)

    @property
    def fixed_g2_anchors(self) -> tuple[Point, Point]:
        return (
            multiply(G2, self.trapdoor_s, group="g2"),
            G2,
        )

    def accepting_witness(self, q_scalar: int) -> tuple[bytes, bytes]:
        q = _field(q_scalar)
        if q == 0:
            raise OneSidedWrapperError("one-sided Q scalar is zero")
        q_point = multiply(G1, q, group="g1")
        r_scalar = (self.trapdoor_s - self.alpha_inverse) * q % CURVE_ORDER
        if r_scalar == 0:
            raise OneSidedWrapperError("derived one-sided R point is infinity")
        r_point = multiply(G1, r_scalar, group="g1")
        return compress_g1(q_point), compress_g1(r_point)

    def accepts(self, witness: Sequence[bytes]) -> bool:
        if len(witness) != 2:
            return False
        try:
            q_point = decompress_g1(bytes(witness[0]))
            r_point = decompress_g1(bytes(witness[1]))
            right = add(
                r_point,
                multiply(q_point, self.alpha_inverse, group="g1"),
                group="g1",
            )
            residual = pairing_product(
                (
                    (q_point, multiply(G2, self.trapdoor_s, group="g2")),
                    (neg(right), G2),
                )
            )
            return residual == FQ12.one()
        except (TypeError, ValueError, OverflowError):
            return False

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "dynamic_G1_terms": 2,
            "dynamic_G2_terms": 0,
            "fixed_G2_anchor_rank": self.fixed_g2_anchor_rank,
            "coefficient_matrix": [list(row) for row in self.coefficient_matrix],
            "normalised_target": "identity",
            "direct_static_lock": False,
            "static_witness_lift_candidate": True,
            "reason_direct_lock_fails": (
                "Both sides of the identity-normalised pairing equation are future proof "
                "elements. A statement-specific KZG-WE session is not known at activation."
            ),
        }


@dataclass(frozen=True, slots=True)
class OneSidedSnarkProfile:
    name: str = "flexible monomial-basis one-sided pairing SNARK profile"
    proof_g1_elements: int = 10
    proof_scalar_elements: int = 20
    verification_pairings: int = 2
    prover_defined_g2_elements: int = 0
    fixed_g2_anchor_rank: int = 2
    combined_msm_terms_per_gate: int = 22
    proof_size_crs_multiplier: int = 3
    prover_time_crs_multiplier: int = 1
    universal_updateable_crs: bool = True
    verifier_storage_constant_in_circuit_size: bool = True
    public_fiat_shamir_transcript: bool = True
    outer_curve_to_bn254_claimed_by_source: bool = True
    implementation_in_repository: bool = False
    lva_hidden_challenge_compiler_constructed: bool = False
    schema: str = "ranklock-one-sided-snark-profile-v1"

    def __post_init__(self) -> None:
        for value in (
            self.proof_g1_elements,
            self.proof_scalar_elements,
            self.verification_pairings,
            self.prover_defined_g2_elements,
            self.fixed_g2_anchor_rank,
            self.combined_msm_terms_per_gate,
            self.proof_size_crs_multiplier,
            self.prover_time_crs_multiplier,
        ):
            if value < 0:
                raise OneSidedWrapperError("one-sided SNARK profile count is negative")
        if not self.name:
            raise OneSidedWrapperError("one-sided SNARK profile name is empty")

    @property
    def one_sided_pairing_interface_holds(self) -> bool:
        return (
            self.proof_g1_elements > 0
            and self.prover_defined_g2_elements == 0
            and self.fixed_g2_anchor_rank > 0
            and self.verification_pairings == 2
        )

    def proof_bytes(self, *, g1_bytes: int, scalar_bytes: int = 32) -> int:
        if g1_bytes <= 0 or scalar_bytes <= 0:
            raise OneSidedWrapperError("invalid point/scalar byte size")
        return self.proof_g1_elements * g1_bytes + self.proof_scalar_elements * scalar_bytes

    def shared_crs_bytes(
        self,
        circuit_gates: int,
        *,
        g1_bytes: int,
        g2_bytes: int,
        mode: str,
    ) -> int:
        if circuit_gates <= 0:
            raise OneSidedWrapperError("circuit gate count must be positive")
        if g1_bytes <= 0 or g2_bytes <= 0:
            raise OneSidedWrapperError("invalid point byte size")
        if mode == "proof_size":
            multiplier = self.proof_size_crs_multiplier
        elif mode == "prover_time":
            multiplier = self.prover_time_crs_multiplier
        else:
            raise OneSidedWrapperError("CRS mode must be 'proof_size' or 'prover_time'")
        # The paper quotes the dominant G1 CRS length. Add the fixed G2 pair
        # [1]G2,[s]G2 explicitly to avoid counting them as free.
        return multiplier * int(circuit_gates) * g1_bytes + 2 * g2_bytes

    def prover_msm_terms(self, circuit_gates: int) -> int:
        if circuit_gates <= 0:
            raise OneSidedWrapperError("circuit gate count must be positive")
        return self.combined_msm_terms_per_gate * int(circuit_gates)

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "name": self.name,
            "proof_G1_elements": self.proof_g1_elements,
            "proof_scalar_elements": self.proof_scalar_elements,
            "verification_pairings": self.verification_pairings,
            "prover_defined_G2_elements": self.prover_defined_g2_elements,
            "fixed_G2_anchor_rank": self.fixed_g2_anchor_rank,
            "combined_MSM_terms_per_gate": self.combined_msm_terms_per_gate,
            "proof_size_CRS_multiplier": self.proof_size_crs_multiplier,
            "prover_time_CRS_multiplier": self.prover_time_crs_multiplier,
            "universal_updateable_CRS": self.universal_updateable_crs,
            "verifier_storage_constant_in_circuit_size": (
                self.verifier_storage_constant_in_circuit_size
            ),
            "public_Fiat_Shamir_transcript": self.public_fiat_shamir_transcript,
            "outer_curve_to_BN254_claimed_by_source": (
                self.outer_curve_to_bn254_claimed_by_source
            ),
            "one_sided_pairing_interface_holds": self.one_sided_pairing_interface_holds,
            "implementation_in_repository": self.implementation_in_repository,
            "LVA_hidden_challenge_compiler_constructed": (
                self.lva_hidden_challenge_compiler_constructed
            ),
        }


@dataclass(frozen=True, slots=True)
class TranscriptStrategy:
    name: str
    static_ciphertext_compatible: bool
    hash_inside_lock_required: bool
    authentic_future_beacon_required: bool
    hidden_linear_response_audit_required: bool
    constructed: bool

    @property
    def blockers(self) -> tuple[str, ...]:
        blockers: list[str] = []
        if self.hash_inside_lock_required:
            blockers.append("Fiat-Shamir hash consistency must be verified inside the lock")
        if self.authentic_future_beacon_required:
            blockers.append("future beacon authenticity must be enforced inside the relation")
        if self.hidden_linear_response_audit_required:
            blockers.append(
                "prover responses must be linear in encoded hidden verifier challenges"
            )
        if not self.static_ciphertext_compatible:
            blockers.append("strategy does not yield a setup-time static ciphertext")
        if not self.constructed:
            blockers.append("strategy is not constructed for complete RankVM invalidity")
        return tuple(blockers)

    def document(self) -> dict[str, object]:
        return {
            "name": self.name,
            "static_ciphertext_compatible": self.static_ciphertext_compatible,
            "hash_inside_lock_required": self.hash_inside_lock_required,
            "authentic_future_beacon_required": self.authentic_future_beacon_required,
            "hidden_linear_response_audit_required": (
                self.hidden_linear_response_audit_required
            ),
            "constructed": self.constructed,
            "blockers": list(self.blockers),
        }


def transcript_strategy_frontier() -> tuple[TranscriptStrategy, ...]:
    return (
        TranscriptStrategy(
            "public Fiat-Shamir proof as witness",
            static_ciphertext_compatible=True,
            hash_inside_lock_required=True,
            authentic_future_beacon_required=False,
            hidden_linear_response_audit_required=False,
            constructed=False,
        ),
        TranscriptStrategy(
            "underlying interactive LVA with hidden verifier challenges",
            static_ciphertext_compatible=True,
            hash_inside_lock_required=False,
            authentic_future_beacon_required=False,
            hidden_linear_response_audit_required=True,
            constructed=False,
        ),
        TranscriptStrategy(
            "future Bitcoin beacon replaces Fiat-Shamir",
            static_ciphertext_compatible=True,
            hash_inside_lock_required=False,
            authentic_future_beacon_required=True,
            hidden_linear_response_audit_required=False,
            constructed=False,
        ),
    )


def _cost_scenario(
    profile: OneSidedSnarkProfile,
    *,
    name: str,
    circuit_gates: int,
    g1_bytes: int,
    g2_bytes: int,
    scalar_bytes: int,
) -> dict[str, object]:
    proof_bytes = profile.proof_bytes(g1_bytes=g1_bytes, scalar_bytes=scalar_bytes)
    proof_size_crs = profile.shared_crs_bytes(
        circuit_gates,
        g1_bytes=g1_bytes,
        g2_bytes=g2_bytes,
        mode="proof_size",
    )
    prover_time_crs = profile.shared_crs_bytes(
        circuit_gates,
        g1_bytes=g1_bytes,
        g2_bytes=g2_bytes,
        mode="prover_time",
    )
    return {
        "name": name,
        "circuit_gate_assumption": int(circuit_gates),
        "proof_bytes": proof_bytes,
        "proof_size_optimised_shared_CRS_bytes": proof_size_crs,
        "proof_size_optimised_shared_CRS_MiB": _ceil_mib(proof_size_crs),
        "prover_time_optimised_shared_CRS_bytes": prover_time_crs,
        "prover_time_optimised_shared_CRS_MiB": _ceil_mib(prover_time_crs),
        "combined_prover_MSM_terms": profile.prover_msm_terms(circuit_gates),
        "current_projective_layer_plus_proof_bytes": (
            CURRENT_PROJECTIVE_INPUT_BYTES + proof_bytes
        ),
        "DFB_leading_expression_plus_proof_bytes": (
            DFB_LEADING_EXPRESSION_BYTES + proof_bytes
        ),
    }


def one_sided_wrapper_frontier(
    *,
    g1_bytes: int = 64,
    g2_bytes: int = 128,
    scalar_bytes: int = 32,
) -> dict[str, object]:
    """Return a parameterised v0.17 candidate/kill frontier.

    ``64``-byte G1 and ``128``-byte G2 encodings are explicit planning
    assumptions for an outer pairing curve whose base field is roughly twice the
    254-bit scalar field.  They are not measured curve parameters.
    """

    profile = OneSidedSnarkProfile()
    equation = OneSidedFinalPairingEquation(trapdoor_s=17, challenge_alpha=19)
    circuit_scenarios = (
        ("known sparse BN254-Fq product subtotal only", KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL),
        ("4x subtotal envelope", 4 * KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL),
        ("16x subtotal envelope", 16 * KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL),
        ("64x subtotal envelope", 64 * KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL),
    )
    scenarios = [
        _cost_scenario(
            profile,
            name=name,
            circuit_gates=gates,
            g1_bytes=g1_bytes,
            g2_bytes=g2_bytes,
            scalar_bytes=scalar_bytes,
        )
        for name, gates in circuit_scenarios
    ]
    return {
        "schema": "ranklock-one-sided-wrapper-frontier-v1",
        "evidence_class": (
            "REAL BN254 final-equation model + exact parameterised cost formulas; "
            "external SNARK/LVA-WE implementation not present"
        ),
        "profile": profile.document(),
        "final_pairing_equation": equation.document(),
        "encoding_assumptions": {
            "outer_curve_G1_compressed_bytes": int(g1_bytes),
            "outer_curve_G2_compressed_bytes": int(g2_bytes),
            "scalar_bytes": int(scalar_bytes),
            "measured_curve_parameters": False,
        },
        "circuit_scenarios": scenarios,
        "transcript_strategies": [
            strategy.document() for strategy in transcript_strategy_frontier()
        ],
        "positive_result": (
            "A native-BN254-Fq outer wrapper can plausibly reduce the known 25,889-product "
            "kernel to a roughly 1.6 MiB shared CRS in prover-time mode under the explicit "
            "64-byte-G1 planning assumption, while retaining a ~1.25 KiB proof and a rank-two "
            "fixed-G2 final verifier."
        ),
        "critical_boundary": (
            "The proof shape passes, but a setup-time static lock still requires either a real "
            "LVA-WE compiler for the underlying interactive protocol or a relation that verifies "
            "Fiat-Shamir/beacon consistency. Neither is constructed."
        ),
        "breakthrough_gates": {
            "all_future_group_elements_in_G1": True,
            "fixed_G2_rank_two": True,
            "native_BN254_Fq_outer_curve_source_candidate": True,
            "concrete_outer_curve_parameters_and_library": False,
            "complete_RankVM_invalidity_circuit": False,
            "linear_response_LVA_audit": False,
            "static_LVA_WE_compiler_instantiated": False,
            "malicious_n_minus_1_activation": False,
            "ciphertext_share_consistency_proof": False,
            "breakthrough_target_met": False,
        },
        "next_decisive_task": (
            "Audit the interactive monomial-basis prover message by message for linear response "
            "to hidden verifier queries. If it passes, instantiate the 2025 LVA-WE compiler on a "
            "small native-Fq RankVM invalidity circuit; otherwise kill this wrapper candidate."
        ),
    }
