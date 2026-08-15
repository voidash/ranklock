from __future__ import annotations

"""Polarity inversion for Strata's counterproof connector.

The current graph puts a conditionally released ``wt_fault`` key on the
*immediate* key-path of ``CounterproofConnector``.  An invalid counterproof
reveals that key and authorises NACK; if no NACK confirms before the relative
``nack_timelock``, a pre-signed N/N timeout transaction ACKs the counterproof.

A validity-first graph swaps the economic meaning of those two mutually
exclusive paths:

* a proof-conditioned key authorises an immediate ACK for a *valid*
  counterproof;
* the N/N timeout path authorises NACK when no valid-proof spend confirms.

This module is an executable protocol model, not a Rust/Bitcoin implementation.
It also records an important limitation: polarity inversion aligns Strata with
positive-predicate proof-verification schemes such as BABE/Embryo, but a static
projective lock still needs a real projective garbling construction.  Ordinary
NO-instance witness-encryption security does not by itself cover the fixed
setup-time relation containing all future input choices.
"""

from dataclasses import dataclass
from enum import Enum


class ValidityFirstGraphError(ValueError):
    pass


class CounterproofStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    ABSENT = "absent"


class Resolution(str, Enum):
    ACK_AND_SLASH = "ack_and_slash_operator"
    NACK_AND_CONTESTED_PAYOUT = "nack_and_continue_contested_payout"
    UNRESOLVED = "unresolved"


class GraphPolarity(str, Enum):
    CURRENT_INVALIDITY_FIRST = "current_invalidity_first"
    VALIDITY_FIRST = "validity_first"


@dataclass(frozen=True, slots=True)
class CounterproofResolution:
    polarity: GraphPolarity
    status: CounterproofStatus
    immediate_spend_confirms: bool
    conditioned_key_available: bool
    resolution: Resolution
    correct_resolution: Resolution
    safety_preserved: bool
    path: str
    schema: str = "ranklock-counterproof-resolution-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "polarity": self.polarity.value,
            "counterproof_status": self.status.value,
            "conditioned_key_available": self.conditioned_key_available,
            "immediate_spend_confirms_before_timeout": self.immediate_spend_confirms,
            "path": self.path,
            "resolution": self.resolution.value,
            "correct_resolution": self.correct_resolution.value,
            "safety_preserved": self.safety_preserved,
        }


def _correct_resolution(status: CounterproofStatus) -> Resolution:
    return (
        Resolution.ACK_AND_SLASH
        if status is CounterproofStatus.VALID
        else Resolution.NACK_AND_CONTESTED_PAYOUT
    )


def resolve_counterproof(
    polarity: GraphPolarity,
    status: CounterproofStatus,
    *,
    immediate_spend_confirms: bool,
) -> CounterproofResolution:
    """Resolve one connector under the two graph polarities.

    ``immediate_spend_confirms`` models the only censorship-sensitive event:
    whether a transaction carrying the conditionally derived key confirms before
    the relative timeout.  The N/N timeout transaction is assumed to be
    pre-signed and publicly publishable once mature, matching the current graph.
    """

    correct = _correct_resolution(status)

    # No CounterproofTx means the per-watchtower CounterproofConnector output is
    # never created.  Both polarities therefore fall through to the existing
    # contested-payout path; there is no immediate/timeout connector race.
    if status is CounterproofStatus.ABSENT:
        return CounterproofResolution(
            polarity=polarity,
            status=status,
            immediate_spend_confirms=False,
            conditioned_key_available=False,
            resolution=Resolution.NACK_AND_CONTESTED_PAYOUT,
            correct_resolution=correct,
            safety_preserved=True,
            path="no CounterproofTx; contested-payout timeout path",
        )

    if polarity is GraphPolarity.CURRENT_INVALIDITY_FIRST:
        key_available = status is CounterproofStatus.INVALID
        if key_available and immediate_spend_confirms:
            resolution = Resolution.NACK_AND_CONTESTED_PAYOUT
            path = "immediate wt_fault key-path NACK"
        else:
            resolution = Resolution.ACK_AND_SLASH
            path = "N/N timeout ACK"
    elif polarity is GraphPolarity.VALIDITY_FIRST:
        key_available = status is CounterproofStatus.VALID
        if key_available and immediate_spend_confirms:
            resolution = Resolution.ACK_AND_SLASH
            path = "immediate valid-proof key-path ACK"
        else:
            resolution = Resolution.NACK_AND_CONTESTED_PAYOUT
            path = "N/N timeout NACK"
    else:  # pragma: no cover - exhaustive Enum guard
        raise ValidityFirstGraphError(f"unsupported polarity: {polarity!r}")

    return CounterproofResolution(
        polarity=polarity,
        status=status,
        immediate_spend_confirms=bool(immediate_spend_confirms),
        conditioned_key_available=key_available,
        resolution=resolution,
        correct_resolution=correct,
        safety_preserved=resolution is correct,
        path=path,
    )


@dataclass(frozen=True, slots=True)
class GraphRewrite:
    current: str
    validity_first: str
    reason: str
    schema: str = "ranklock-validity-first-rewrite-item-v1"

    def document(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "current": self.current,
            "validity_first": self.validity_first,
            "reason": self.reason,
        }


def graph_rewrites() -> tuple[GraphRewrite, ...]:
    return (
        GraphRewrite(
            "CounterproofConnector internal key = wt_fault_pubkey",
            "CounterproofConnector internal key = valid_counterproof_pubkey",
            "the immediate key path changes from complement verification to positive verification",
        ),
        GraphRewrite(
            "CounterproofNackTx spends Normal/key path with Mosaic evaluate_and_sign",
            "CounterproofAckTx spends Normal/key path with the public valid-proof-derived signature",
            "a confirmed valid counterproof should win immediately",
        ),
        GraphRewrite(
            "CounterproofAckTx spends Timeout/script path with pre-signed N/N signatures",
            "CounterproofNackTx spends Timeout/script path with a pre-signed N/N signature",
            "absence of a valid immediate spend should reject the counterproof after the same deadline",
        ),
        GraphRewrite(
            "Mosaic computes INVALID(counterproof) and releases wt_fault",
            "positive projective backend computes VALID(counterproof) and releases ack key",
            "positive Groth16 verification matches BABE/Embryo; the complement verifier disappears",
        ),
        GraphRewrite(
            "counterproof_ack input 0 sequence = Timeout",
            "counterproof_ack input 0 sequence = Normal",
            "ACK moves to the immediate Taproot key path",
        ),
        GraphRewrite(
            "counterproof_nack input 0 uses key-path signing_info_partial",
            "counterproof_nack input 0 uses Timeout sequence and N/N script-path signing info",
            "NACK becomes the publicly publishable default transaction",
        ),
    )


@dataclass(frozen=True, slots=True)
class PositiveBackendFit:
    backend: str = "BABE + Duty-Free-Bits Embryo"
    predicate: str = "valid Groth16/SP1 counterproof"
    projective_scalar_multiplication_encoding_bytes: int = 500 * 1024
    current_mosaic_predicate: str = "invalid Groth16/SP1 counterproof"
    full_strata_object_measured: bool = False
    malicious_activation_integrated: bool = False
    schema: str = "ranklock-positive-backend-fit-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "candidate_backend": self.backend,
            "native_predicate": self.predicate,
            "current_mosaic_predicate": self.current_mosaic_predicate,
            "reported_projective_scalar_multiplication_encoding_bytes": (
                self.projective_scalar_multiplication_encoding_bytes
            ),
            "reported_size_scope": (
                "Embryo projective scalar-multiplication encoding only; not a measured complete Strata lock"
            ),
            "full_strata_object_measured": self.full_strata_object_measured,
            "malicious_activation_integrated": self.malicious_activation_integrated,
            "fit": (
                "polarity inversion aligns the Bitcoin graph with the backend's positive proof predicate"
            ),
        }


def validity_first_graph_checkpoint() -> dict[str, object]:
    matrix = [
        resolve_counterproof(polarity, status, immediate_spend_confirms=confirms).document()
        for polarity in GraphPolarity
        for status in CounterproofStatus
        for confirms in (False, True)
    ]
    current_failures = [
        row
        for row in matrix
        if row["polarity"] == GraphPolarity.CURRENT_INVALIDITY_FIRST.value
        and not row["safety_preserved"]
    ]
    inverted_failures = [
        row
        for row in matrix
        if row["polarity"] == GraphPolarity.VALIDITY_FIRST.value
        and not row["safety_preserved"]
    ]
    return {
        "schema": "ranklock-validity-first-graph-checkpoint-v1",
        "source_graph_facts": {
            "current_immediate_path": "wt_fault key-path NACK",
            "current_timeout_path": "N/N script-path ACK",
            "counterproof_transaction_publishes_authenticated_proof_bytes": True,
            "counterproof_ack_also_consumes_contest_payout_connector": True,
        },
        "rewrite": [item.document() for item in graph_rewrites()],
        "exhaustive_resolution_matrix": matrix,
        "censorship_symmetry": {
            "current_safety_failures": len(current_failures),
            "validity_first_safety_failures": len(inverted_failures),
            "current_failure_case": "invalid proof immediate NACK censored until timeout",
            "validity_first_failure_case": "valid proof immediate ACK censored until timeout",
            "same_deadline_assumption": True,
            "public_publishability": (
                "after the proof transaction confirms, any observer that evaluates the projective lock can publish the immediate ACK"
            ),
        },
        "positive_backend": PositiveBackendFit().document(),
        "semantic_boundary": {
            "ordinary_fixed_statement_WE_alone_is_sufficient": False,
            "reason": (
                "the connector and conditioned key are fixed before future proof bytes are selected; a real projective garbling/encoding layer is still required"
            ),
            "hard_yes_WPRF_required_if_using_old_fixed_relation_model": True,
            "hard_yes_WPRF_avoided_by_instantiated_projective_positive_backend": (
                "candidate, contingent on BABE/Embryo security and complete Strata integration"
            ),
        },
        "decision": "PROMISING_PROTOCOL_PIVOT_NOT_YET_A_COMPLETE_REPLACEMENT",
        "breakthrough_target_met": False,
    }
