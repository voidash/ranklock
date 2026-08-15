from __future__ import annotations

"""Integrated fixed-statement RankLock wrapper candidate.

This module composes the strongest surviving v0.17 ingredients as a *measured
architecture candidate*:

1. 132 future Strata bytes are delivered as authenticated witness variables;
2. a one-sided pairing SNARK proves the fixed relation "authenticated bytes feed
   a complete RankVM execution that reaches INVALID";
3. a compact in-relation transcript gadget binds the public Fiat--Shamir proof;
4. the final proof equation has future G1 elements and a rank-two fixed G2 basis;
5. the accepting pairing session derives a secp256k1 fault key directly, so no
   encrypted payload can be substituted.

The module cleanly separates per-deposit retained material from a reusable
universal one-sided-SNARK CRS.  It does not implement the one-sided SNARK, the
real transcript gadget, the LVA-WE compiler, or the activation NIZK.  Passing a
byte envelope is therefore a feasibility result, not the breakthrough theorem.
"""

from dataclasses import dataclass

from .one_sided_wrapper_frontier import OneSidedSnarkProfile
from .transcript_mini_lock import (
    MIB,
    ONE_SIDED_PROOF_BYTES,
    PROJECTIVE_INPUT_RELATION_WIDTH,
    PROJECTIVE_STATIC_BYTES,
    REFERENCE_BYTES_PER_SCALAR_COORDINATE,
    REFERENCE_FIXED_KEY_BYTES,
    TranscriptConstraintScenario,
)

REFERENCE_DERIVED_FAULT_SHARE_BYTES = 1_547
REFERENCE_MANIFEST_AND_DOMAIN_BYTES = 2_048
CURRENT_PROJECTIVE_COMPLETE_BYTES = 257_418
DFB_LEADING_EXPRESSION_BYTES = 8_288


class FixedStatementWrapperError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CircuitScaleScenario:
    name: str
    circuit_gate_assumption: int
    interpretation: str
    schema: str = "ranklock-wrapper-circuit-scale-v1"

    def __post_init__(self) -> None:
        if not self.name or not self.interpretation or self.circuit_gate_assumption <= 0:
            raise FixedStatementWrapperError("invalid wrapper circuit scenario")

    def document(self, profile: OneSidedSnarkProfile) -> dict[str, object]:
        prover_time_crs = profile.shared_crs_bytes(
            self.circuit_gate_assumption,
            g1_bytes=64,
            g2_bytes=128,
            mode="prover_time",
        )
        proof_size_crs = profile.shared_crs_bytes(
            self.circuit_gate_assumption,
            g1_bytes=64,
            g2_bytes=128,
            mode="proof_size",
        )
        return {
            "schema": self.schema,
            "name": self.name,
            "circuit_gate_assumption": self.circuit_gate_assumption,
            "interpretation": self.interpretation,
            "prover_time_optimised_reusable_CRS_bytes": prover_time_crs,
            "prover_time_optimised_reusable_CRS_MiB": prover_time_crs / MIB,
            "proof_size_optimised_reusable_CRS_bytes": proof_size_crs,
            "proof_size_optimised_reusable_CRS_MiB": proof_size_crs / MIB,
            "prover_MSM_terms": profile.prover_msm_terms(
                self.circuit_gate_assumption
            ),
            "proof_bytes": profile.proof_bytes(g1_bytes=64, scalar_bytes=32),
            "storage_classification": (
                "reusable universal/system CRS; not counted as per-deposit retained material"
            ),
        }


@dataclass(frozen=True, slots=True)
class PerDepositCandidateCost:
    transcript: TranscriptConstraintScenario
    fault_share_bytes: int = REFERENCE_DERIVED_FAULT_SHARE_BYTES
    manifest_and_domain_bytes: int = REFERENCE_MANIFEST_AND_DOMAIN_BYTES
    schema: str = "ranklock-per-deposit-wrapper-cost-v1"

    def __post_init__(self) -> None:
        if self.fault_share_bytes <= 0 or self.manifest_and_domain_bytes < 0:
            raise FixedStatementWrapperError("invalid per-deposit byte allowance")

    @property
    def fixed_relation_key_bytes(self) -> int:
        return (
            REFERENCE_FIXED_KEY_BYTES
            + REFERENCE_BYTES_PER_SCALAR_COORDINATE
            * (PROJECTIVE_INPUT_RELATION_WIDTH + self.transcript.wrapper_trace_width)
        )

    @property
    def activation_static_bytes(self) -> int:
        return (
            PROJECTIVE_STATIC_BYTES
            + self.fixed_relation_key_bytes
            + self.fault_share_bytes
            + self.manifest_and_domain_bytes
        )

    @property
    def activation_plus_future_proof_bytes(self) -> int:
        return self.activation_static_bytes + ONE_SIDED_PROOF_BYTES

    @property
    def margin_to_one_mib(self) -> int:
        return MIB - self.activation_plus_future_proof_bytes

    @property
    def fits_one_mib(self) -> bool:
        return self.margin_to_one_mib >= 0

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_class": "COMPOSED COST ENVELOPE; several components remain uninstantiated",
            "projective_static_bytes": PROJECTIVE_STATIC_BYTES,
            "projective_input_relation_width": PROJECTIVE_INPUT_RELATION_WIDTH,
            "transcript_wrapper_trace_width": self.transcript.wrapper_trace_width,
            "fixed_relation_key_bytes": self.fixed_relation_key_bytes,
            "derived_fault_share_bytes": self.fault_share_bytes,
            "manifest_and_domain_allowance_bytes": self.manifest_and_domain_bytes,
            "activation_static_bytes": self.activation_static_bytes,
            "future_one_sided_proof_bytes": ONE_SIDED_PROOF_BYTES,
            "activation_plus_future_proof_bytes": (
                self.activation_plus_future_proof_bytes
            ),
            "one_MiB_cap_bytes": MIB,
            "margin_to_one_MiB_bytes": self.margin_to_one_mib,
            "fits_one_MiB": self.fits_one_mib,
            "transcript_scenario": self.transcript.document(),
        }


def fixed_statement_wrapper_candidate() -> dict[str, object]:
    profile = OneSidedSnarkProfile()
    transcript_scenarios = tuple(
        TranscriptConstraintScenario(value) for value in (200, 300, 400)
    )
    costs = tuple(PerDepositCandidateCost(value) for value in transcript_scenarios)
    circuit_scales = (
        CircuitScaleScenario(
            "optimistic sparse native-Fq nonlinear subtotal",
            25_889,
            "Only the known sparse pairing/MSM/curve-check product subtotal; excludes the physical field bridge, parsing, SHA and range constraints.",
        ),
        CircuitScaleScenario(
            "safe 3x85 rank-5 native multiplication subtotal",
            129_445,
            "Uses the current single-field bridge's nonlinear products but excludes its lookup and linear-relation events.",
        ),
        CircuitScaleScenario(
            "all current logical events upper envelope",
            2_537_122,
            "Treats every currently inventoried multiplication, lookup and linear event as one arithmetic-circuit gate; deliberately conservative.",
        ),
    )
    medium = costs[1]
    return {
        "schema": "ranklock-fixed-statement-wrapper-candidate-v1",
        "architecture": [
            "fixed relation places future Strata bytes and their projective authentication tokens in the witness",
            "one-sided SNARK proves authenticated-input binding plus complete RankVM INVALID execution",
            "Poseidon2-style mini-lock verifies the public Fiat-Shamir transcript",
            "rank-two fixed-G2 final pairing relation exposes the accepting session",
            "session-derived secp256k1 scalar is the Bitcoin fault key; no encrypted payload is retained",
        ],
        "one_sided_SNARK_profile": profile.document(),
        "per_deposit_scenarios": [cost.document() for cost in costs],
        "reference_surviving_scenario": medium.document(),
        "reusable_CRS_scenarios": [
            scale.document(profile) for scale in circuit_scales
        ],
        "projective_transport": {
            "current_online_OT_complete_public_and_interactive_bytes": (
                CURRENT_PROJECTIVE_COMPLETE_BYTES
            ),
            "current_preprocessed_static_bytes": PROJECTIVE_STATIC_BYTES,
            "Duty_Free_Bits_leading_expression_bytes_only": (
                DFB_LEADING_EXPRESSION_BYTES
            ),
            "DFB_warning": (
                "The leading expression is not a complete concrete protocol byte count and is not used in the one-MiB decision."
            ),
        },
        "positive_result": (
            "The storage target is not killed: the 300-constraint-per-G1 planning "
            "scenario leaves a positive one-MiB margin even after the future proof and "
            "a conservative manifest allowance."
        ),
        "tightness_warning": (
            "The reference margin is small. A point-binding gadget above 325 constraints "
            "per G1 element, or unmodelled relation-key overhead, kills the current envelope."
        ),
        "constructed_components": [
            "real projective 132-byte online-OT measurement path",
            "real BN254 split-basis pairing session",
            "real rank-two one-sided final pairing equation model",
            "real secp256k1 session-derived fault-key recovery",
            "exact hidden-challenge route audit",
            "parameterised transcript and CRS cost envelopes",
        ],
        "missing_load_bearing_components": [
            "complete one-sided SNARK implementation on a curve/field compatible with the RankVM wrapper",
            "complete RankVM-invalidity circuit including projective authentication, parsing, SHA and range checks",
            "real Poseidon2 transcript and canonical G1 encoding gadget below the 325-constraint threshold",
            "real LVA-WE/gadget compiler replacing the 66-byte scalar-coordinate proxy",
            "public zero-knowledge activation proof binding scaled anchors to the session-derived Bitcoin key",
            "final noninteractive Duty-Free-Bits projective delivery",
            "malicious n-1-corrupt setup theorem and implementation",
            "Strata regtest NACK execution and independent security review",
        ],
        "practical_breakthrough_size_gate_survives": medium.fits_one_mib,
        "cryptographic_breakthrough_target_met": False,
    }
