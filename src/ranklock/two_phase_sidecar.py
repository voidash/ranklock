from __future__ import annotations

"""Crash-durable participant sidecar for two-phase Bitcoin authorization.

The phase-one response contains only selected label shares.  The program-seed
share is emitted only after the exact witness transaction is confirmed by the
configured Bitcoin Core node.  Every transition is anchored at all configured
rollback witnesses before response bytes become visible.
"""

from dataclasses import dataclass
import os
from typing import Sequence

from .authorization_transaction_plan import AuthorizationTransactionPlan
from .bitcoin_witness_selection import SignedBitcoinWitnessPolicy, derive_witness_selection
from .committee_authorization import (
    CommitteeAuthorizationRequest,
    ParticipantSlotSecrets,
    SignedCommitteeActivation,
)
from .durable_slot_ledger import DurableSlotLedger
from .release_sidecar import (
    BitcoinCoreReader,
    ConfirmedBitcoinObservation,
    ReleaseSidecarError,
    atomic_write_once,
    verify_confirmed_bitcoin_binding,
)
from .rollback_witness import (
    RollbackWitnessClient,
    RollbackWitnessError,
    RollbackWitnessReceipt,
    anchor_ledger_at_all_witnesses,
    require_rollback_witness_set,
)
from .two_phase_authorization import (
    ParticipantSeedResponse,
    ParticipantWitnessShareResponse,
    TwoPhaseAuthorizationError,
    WitnessPreauthorizationRequest,
    prepare_seed_response,
    prepare_witness_share_response,
)


class TwoPhaseSidecarError(RuntimeError):
    pass


@dataclass(slots=True)
class TwoPhaseParticipantSidecar:
    activation: SignedCommitteeActivation
    plan: AuthorizationTransactionPlan
    witness_policy: SignedBitcoinWitnessPolicy
    participant: ParticipantSlotSecrets
    ledger: DurableSlotLedger
    rollback_witnesses: tuple[RollbackWitnessClient, ...]
    bitcoin_core: BitcoinCoreReader | None
    minimum_confirmations: int

    def __post_init__(self) -> None:
        if not self.activation.verify():
            raise TwoPhaseSidecarError("committee activation failed verification")
        unsigned = self.activation.unsigned
        if (
            self.plan.chain_genesis_hash != unsigned.chain_genesis_hash
            or unsigned.slot_id >= len(self.plan.templates)
            or self.plan.templates[unsigned.slot_id].txid != unsigned.counterproof_txid
        ):
            raise TwoPhaseSidecarError("transaction plan does not match activation")
        if not self.witness_policy.verify(self.activation):
            raise TwoPhaseSidecarError("Bitcoin witness policy failed verification")
        if (
            self.participant.context_digest != unsigned.context_digest
            or self.participant.slot_id != unsigned.slot_id
            or self.ledger.context_digest != unsigned.context_digest
        ):
            raise TwoPhaseSidecarError("participant/ledger context does not match activation")
        if int(self.minimum_confirmations) < int(unsigned.minimum_confirmations):
            raise TwoPhaseSidecarError(
                "configured confirmation depth is below the signed activation minimum"
            )
        try:
            require_rollback_witness_set(
                self.rollback_witnesses,
                expected_digest=unsigned.rollback_witness_set_digest,
            )
            anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant.participant_secret,
                witnesses=self.rollback_witnesses,
            )
        except RollbackWitnessError as exc:
            raise TwoPhaseSidecarError(f"rollback-witness bootstrap failed: {exc}") from exc

    def issue_witness_shares(
        self,
        *,
        preauthorization: WitnessPreauthorizationRequest,
        output_path: str | os.PathLike[str],
    ) -> tuple[
        ParticipantWitnessShareResponse,
        tuple[RollbackWitnessReceipt, ...],
        bool,
    ]:
        """Burn the slot and publish only the phase-one selected label shares."""

        try:
            response = prepare_witness_share_response(
                activation=self.activation,
                preauthorization=preauthorization,
                plan=self.plan,
                policy=self.witness_policy,
                participant=self.participant,
                ledger=self.ledger,
            )
            receipts = anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant.participant_secret,
                witnesses=self.rollback_witnesses,
            )
        except (TwoPhaseAuthorizationError, RollbackWitnessError) as exc:
            # The slot may already be burned, but no response bytes are emitted.
            raise TwoPhaseSidecarError(f"phase-one authorization failed: {exc}") from exc
        created = atomic_write_once(output_path, response.compact_bytes)
        return response, receipts, created

    def issue_seed_share(
        self,
        *,
        preauthorization: WitnessPreauthorizationRequest,
        confirmation_request: CommitteeAuthorizationRequest,
        raw_transaction: bytes,
        block_hash: str,
        output_path: str | os.PathLike[str],
    ) -> tuple[
        ParticipantSeedResponse,
        ConfirmedBitcoinObservation,
        tuple[RollbackWitnessReceipt, ...],
        bool,
    ]:
        """Release the program-seed share after stable Core confirmation.

        Phase one must already have durably burned the slot.  The Core view is
        checked before and after rollback-witness anchoring so a concurrent
        reorg burns/aborts the slot without exposing the seed share.
        """

        if self.bitcoin_core is None:
            raise TwoPhaseSidecarError("Bitcoin Core reader is required for phase two")
        use = self.ledger.use(preauthorization.slot_id)
        if use.state == "available":
            raise TwoPhaseSidecarError("phase one has not burned this slot")
        if use.state not in {"burned", "success"}:
            raise TwoPhaseSidecarError(f"slot already terminated as {use.state}")
        if (
            use.context_digest != preauthorization.context_digest
            or use.input_digest != preauthorization.input_digest
            or use.authorization_digest != preauthorization.digest
            or use.chain_binding_digest != preauthorization.stripped_transaction_digest
        ):
            raise TwoPhaseSidecarError("ledger binding differs from preauthorization")

        try:
            observation = verify_confirmed_bitcoin_binding(
                self.bitcoin_core,
                binding=confirmation_request.bitcoin_binding,
                raw_transaction=raw_transaction,
                block_hash=block_hash,
                minimum_confirmations=self.minimum_confirmations,
            )
            response = prepare_seed_response(
                activation=self.activation,
                preauthorization=preauthorization,
                confirmation_request=confirmation_request,
                raw_transaction=raw_transaction,
                plan=self.plan,
                policy=self.witness_policy,
                participant=self.participant,
                ledger=self.ledger,
            )
            self.ledger.record_chain_observation(
                preauthorization.slot_id,
                event_type="confirmed",
                block_hash=bytes.fromhex(observation.block_hash),
                height=observation.block_height,
            )
            anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant.participant_secret,
                witnesses=self.rollback_witnesses,
            )

            final_observation = verify_confirmed_bitcoin_binding(
                self.bitcoin_core,
                binding=confirmation_request.bitcoin_binding,
                raw_transaction=raw_transaction,
                block_hash=block_hash,
                minimum_confirmations=self.minimum_confirmations,
            )
            selection = derive_witness_selection(
                raw_transaction,
                policy=self.witness_policy,
                activation=self.activation,
            )
            if selection.point_encoding != preauthorization.point_encoding:
                raise TwoPhaseSidecarError("confirmed witness changed the preauthorized point")
            if (
                final_observation.txid != observation.txid
                or final_observation.wtxid != observation.wtxid
                or final_observation.block_hash != observation.block_hash
                or final_observation.block_height != observation.block_height
            ):
                raise TwoPhaseSidecarError(
                    "Bitcoin Core inclusion changed while authorizing the seed share"
                )
        except Exception as exc:
            try:
                self.ledger.finalize(preauthorization.slot_id, outcome="abort")
                anchor_ledger_at_all_witnesses(
                    self.ledger,
                    participant_secret=self.participant.participant_secret,
                    witnesses=self.rollback_witnesses,
                )
            except Exception:
                pass
            if isinstance(exc, TwoPhaseSidecarError):
                raise
            if isinstance(exc, (ReleaseSidecarError, TwoPhaseAuthorizationError, RollbackWitnessError)):
                raise TwoPhaseSidecarError(f"phase-two authorization failed: {exc}") from exc
            raise TwoPhaseSidecarError(f"phase-two recheck failed: {exc}") from exc

        self.ledger.finalize(preauthorization.slot_id, outcome="success")
        try:
            receipts = anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant.participant_secret,
                witnesses=self.rollback_witnesses,
            )
        except RollbackWitnessError as exc:
            raise TwoPhaseSidecarError(
                f"terminal rollback-witness anchor failed: {exc}"
            ) from exc
        created = atomic_write_once(output_path, response.compact_bytes)
        return response, final_observation, receipts, created
