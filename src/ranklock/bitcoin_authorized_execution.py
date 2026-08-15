from __future__ import annotations

"""Public evaluator entry point for a Bitcoin-selected RankLock point."""

from dataclasses import dataclass
from typing import Iterable, Sequence

from .bitcoin_witness_selection import (
    BitcoinWitnessSelection,
    SignedBitcoinWitnessPolicy,
    verify_request_matches_witness,
)
from .bounded_mpc_embryo import SignedBoundedEmbryoManifest
from .committee_authorization import (
    CommitteeAuthorizationRequest,
    CommitteeFusedSlotExecution,
    CommitteeLabelGuide,
    ParticipantShareResponse,
    SignedCommitteeActivation,
    execute_committee_authorized_fused_slot,
)
from .dfb_real import DfbProfile


@dataclass(frozen=True, slots=True)
class BitcoinAuthorizedFusedSlotExecution:
    witness_selection: BitcoinWitnessSelection
    committee_execution: CommitteeFusedSlotExecution
    schema: str = "ranklock-bitcoin-authorized-fused-slot-execution-v1"


def execute_bitcoin_authorized_fused_slot(
    *,
    manifest: SignedBoundedEmbryoManifest,
    required_manifest_pubkeys: Iterable[bytes],
    activation: SignedCommitteeActivation,
    witness_policy: SignedBitcoinWitnessPolicy,
    request: CommitteeAuthorizationRequest,
    raw_transaction: bytes,
    responses: Sequence[ParticipantShareResponse],
    slot_artifact: bytes,
    profile: DfbProfile,
    guide: CommitteeLabelGuide | None = None,
) -> BitcoinAuthorizedFusedSlotExecution:
    """Verify the Bitcoin-selected point before reconstructing any aggregate label.

    This order matters: participant responses are public once released, so an
    evaluator must not accept an off-chain point that differs from the witness
    choices that triggered those releases.
    """

    selection = verify_request_matches_witness(
        request,
        raw_transaction=raw_transaction,
        policy=witness_policy,
        activation=activation,
    )
    execution = execute_committee_authorized_fused_slot(
        manifest=manifest,
        required_manifest_pubkeys=required_manifest_pubkeys,
        activation=activation,
        request=request,
        responses=responses,
        guide=guide,
        slot_artifact=slot_artifact,
        profile=profile,
    )
    return BitcoinAuthorizedFusedSlotExecution(selection, execution)
