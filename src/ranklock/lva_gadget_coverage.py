from __future__ import annotations

"""Semantic coverage audit for the v0.18 fixed-relation byte envelope.

The existing ``66 bytes per coordinate`` slope comes from the executable
batched secp256k1 inner-product WE gadget.  That gadget accepts *known scalar
coordinates* ``w_i`` satisfying ``sum w_i U_i = T``.  It does not automatically
compile arbitrary BN254 G1 proof elements, canonical point parsing, Poseidon2
S-boxes, field inversions, or a pairing-product equation into conditional
disclosure.

This module prevents a systems cost proxy from being mistaken for an actual
LVA-WE serialization.  It inventories each load-bearing wrapper component and
states whether a real conditional gadget with matching witness semantics exists
in the repository.
"""

from dataclasses import dataclass
from enum import Enum


class GadgetCoverageError(ValueError):
    pass


class WitnessKind(str, Enum):
    KNOWN_SCALAR = "known_scalar"
    AUTHENTICATED_BYTE = "authenticated_byte"
    BN254_G1_ELEMENT = "bn254_g1_element_unknown_discrete_log"
    FIELD_TRACE = "bn254_fr_field_trace"
    PAIRING_WITNESS = "pairing_product_witness"
    ACCEPTING_SESSION = "accepting_session"


@dataclass(frozen=True, slots=True)
class ConditionalGadgetCoverage:
    component: str
    witness_kind: WitnessKind
    executable_semantics: bool
    real_conditional_gadget: bool
    directly_composable: bool
    evidence_module: str
    blocker: str
    load_bearing: bool = True
    schema: str = "ranklock-conditional-gadget-coverage-item-v1"

    def __post_init__(self) -> None:
        if not self.component or not self.evidence_module or not self.blocker:
            raise GadgetCoverageError("coverage item text must be nonempty")

    @property
    def fully_covered(self) -> bool:
        return (
            self.executable_semantics
            and self.real_conditional_gadget
            and self.directly_composable
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "component": self.component,
            "witness_kind": self.witness_kind.value,
            "executable_semantics": self.executable_semantics,
            "real_conditional_gadget": self.real_conditional_gadget,
            "directly_composable_into_complete_wrapper": self.directly_composable,
            "fully_covered": self.fully_covered,
            "load_bearing": self.load_bearing,
            "evidence_module": self.evidence_module,
            "blocker": self.blocker,
        }


@dataclass(frozen=True, slots=True)
class InnerProductGadgetApplicability:
    reference_bytes_per_coordinate: int = 66
    fixed_overhead_bytes: int = 130
    schema: str = "ranklock-inner-product-gadget-applicability-v1"

    def __post_init__(self) -> None:
        if self.reference_bytes_per_coordinate <= 0 or self.fixed_overhead_bytes <= 0:
            raise GadgetCoverageError("inner-product key costs must be positive")

    def accepts_witness_kind(self, kind: WitnessKind) -> bool:
        return kind is WitnessKind.KNOWN_SCALAR

    def estimated_key_bytes(self, scalar_coordinates: int) -> int:
        if scalar_coordinates <= 0:
            raise GadgetCoverageError("coordinate count must be positive")
        return self.fixed_overhead_bytes + self.reference_bytes_per_coordinate * scalar_coordinates

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "implemented_relation": "sum_i w_i U_i = T over secp256k1",
            "accepted_witness_kind": WitnessKind.KNOWN_SCALAR.value,
            "reference_bytes_per_scalar_coordinate": self.reference_bytes_per_coordinate,
            "fixed_overhead_bytes": self.fixed_overhead_bytes,
            "rejects_arbitrary_BN254_G1_proof_elements": (
                not self.accepts_witness_kind(WitnessKind.BN254_G1_ELEMENT)
            ),
            "reason": (
                "The one-sided proof publishes group elements whose discrete logarithms are neither public nor known to the prover. Treating their encodings as scalar coordinates does not preserve the verifier relation."
            ),
        }


def _coverage_items() -> tuple[ConditionalGadgetCoverage, ...]:
    return (
        ConditionalGadgetCoverage(
            "projective future-byte authentication",
            WitnessKind.AUTHENTICATED_BYTE,
            True,
            False,
            False,
            "projective_vole_lock.py / vole_input_auth.py",
            "The measured OT/VOLE path produces authenticated byte witnesses, but no real static WPRF/LVA gadget yet consumes them together with the wrapper proof.",
        ),
        ConditionalGadgetCoverage(
            "batched scalar inner-product WE",
            WitnessKind.KNOWN_SCALAR,
            True,
            True,
            True,
            "batched_inner_product_we.py",
            "This is a real gadget only for a public fixed scalar inner-product relation; it is a baseline primitive rather than coverage of the one-sided proof.",
            load_bearing=False,
        ),
        ConditionalGadgetCoverage(
            "canonical BN254 G1 proof parsing and on-curve binding",
            WitnessKind.BN254_G1_ELEMENT,
            True,
            False,
            False,
            "bn254_direct_wrapper.py",
            "The 267-row relation is executable, but no conditional gadget maps those nonlinear limb/curve constraints to a hidden session.",
        ),
        ConditionalGadgetCoverage(
            "typed Poseidon2 Fiat-Shamir transcript",
            WitnessKind.FIELD_TRACE,
            True,
            False,
            False,
            "poseidon2_bn254_transcript.py",
            "The 32-permutation transcript is executable and KAT checked; its x^5 trace has not been compiled into a concrete hard-YES conditional token.",
        ),
        ConditionalGadgetCoverage(
            "one-sided scalar verifier Steps 23-29",
            WitnessKind.FIELD_TRACE,
            True,
            False,
            False,
            "one_sided_scalar_verifier.py",
            "The 161 nonlinear rows are counted/executed, but multiplication and inversion checks have no matching LVA-WE gadget.",
        ),
        ConditionalGadgetCoverage(
            "ten future one-sided proof G1 elements",
            WitnessKind.BN254_G1_ELEMENT,
            True,
            False,
            False,
            "shared_proof_binding.py / bn254_direct_wrapper.py",
            "The scalar inner-product gadget cannot consume unknown-discrete-log G1 elements, and publishing a common scaled G2 generator leaks the direct split-basis session.",
        ),
        ConditionalGadgetCoverage(
            "identity-normalised final pairing equation",
            WitnessKind.PAIRING_WITNESS,
            True,
            False,
            False,
            "one_sided_static_session_gap.py / one_sided_lva_decomposition.py",
            "The direct residual is public 1_GT; public affine target shifts are reconstructible from scaled anchors; a richer witness-dependent token is missing.",
        ),
        ConditionalGadgetCoverage(
            "accepting-session to secp256k1 fault key",
            WitnessKind.ACCEPTING_SESSION,
            True,
            True,
            True,
            "ciphertext_free_fault_key.py",
            "This final derivation is real once a hidden accepting session exists; the upstream session is the missing primitive.",
            load_bearing=False,
        ),
    )


def lva_gadget_coverage() -> dict[str, object]:
    applicability = InnerProductGadgetApplicability()
    items = _coverage_items()
    load_bearing = tuple(item for item in items if item.load_bearing)
    uncovered = tuple(item for item in load_bearing if not item.fully_covered)
    return {
        "schema": "ranklock-lva-gadget-coverage-v1",
        "inner_product_baseline": applicability.document(),
        "components": [item.document() for item in items],
        "summary": {
            "components_total": len(items),
            "load_bearing_components": len(load_bearing),
            "load_bearing_components_fully_covered": len(load_bearing) - len(uncovered),
            "load_bearing_components_uncovered": len(uncovered),
            "complete_conditional_compiler_instantiated": not uncovered,
        },
        "byte_envelope_classification": {
            "activation_plus_future_proof_bytes": 862_693,
            "margin_to_one_MiB_bytes": 185_883,
            "classification": "ARITHMETIC_AND_TRANSCRIPT_COORDINATE_ENVELOPE",
            "is_actual_serialized_full_LVA_key": False,
            "warning": (
                "The 66-byte slope is valid for the scalar inner-product baseline only. Applying it to every wrapper row is not a semantic compiler or a cryptographic serialization result."
            ),
        },
        "next_gate": (
            "Construct a group-aware, hard-YES-secure predictable token/WPRF for the typed one-sided verifier, or replace the wrapper with a proof whose public-evaluation token is already covered by a concrete standard-assumption gadget."
        ),
        "breakthrough_target_met": False,
    }
