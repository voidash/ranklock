from __future__ import annotations

"""Executable transaction-state model for the hashlocked validity-first graph."""

from dataclasses import dataclass, replace
from enum import Enum

from .predicate_locked_hashlock import HashlockPresignedGraph


class HashlockedGraphError(RuntimeError):
    pass


class PositiveProofStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    ABSENT = "absent"


class GraphOutcome(str, Enum):
    ACK_SLASH = "ack_then_slash"
    TIMEOUT_NACK_CONTESTED_PAYOUT = "timeout_nack_then_contested_payout"
    NO_COUNTERPROOF_CONTESTED_PAYOUT = "no_counterproof_then_contested_payout"
    PENDING = "pending"


@dataclass(frozen=True, slots=True)
class ChainState:
    height: int
    counterproof_confirmed_height: int | None = None
    connector_unspent: bool = False
    ack_confirmed: bool = False
    nack_confirmed: bool = False
    outcome: GraphOutcome = GraphOutcome.PENDING
    schema: str = "ranklock-hashlocked-chain-state-v1"

    def __post_init__(self) -> None:
        if self.height < 0:
            raise HashlockedGraphError("negative chain height")
        if self.ack_confirmed and self.nack_confirmed:
            raise HashlockedGraphError("conflicting ACK and NACK cannot both confirm")


@dataclass(frozen=True, slots=True)
class HashlockedValidityMachine:
    graph: HashlockPresignedGraph
    status: PositiveProofStatus
    preimage_available: bool
    state: ChainState = ChainState(0)
    schema: str = "ranklock-hashlocked-validity-machine-v1"

    def confirm_counterproof(self, height: int) -> "HashlockedValidityMachine":
        if self.status is PositiveProofStatus.ABSENT:
            raise HashlockedGraphError("absent counterproof cannot confirm")
        if self.state.counterproof_confirmed_height is not None:
            raise HashlockedGraphError("counterproof already confirmed")
        if height < self.state.height:
            raise HashlockedGraphError("chain height moved backwards")
        return replace(
            self,
            state=ChainState(
                height=height,
                counterproof_confirmed_height=height,
                connector_unspent=True,
            ),
        )

    def mine_to(self, height: int) -> "HashlockedValidityMachine":
        if height < self.state.height:
            raise HashlockedGraphError("use reorg() to move chain backwards")
        if self.status is PositiveProofStatus.ABSENT:
            return replace(
                self,
                state=replace(
                    self.state,
                    height=height,
                    outcome=GraphOutcome.NO_COUNTERPROOF_CONTESTED_PAYOUT,
                ),
            )
        return replace(self, state=replace(self.state, height=height))

    @property
    def blocks_since_counterproof(self) -> int:
        if self.state.counterproof_confirmed_height is None:
            return 0
        return max(0, self.state.height - self.state.counterproof_confirmed_height)

    def publish_ack(self) -> "HashlockedValidityMachine":
        if not self.state.connector_unspent:
            raise HashlockedGraphError("connector is absent or already spent")
        if self.status is not PositiveProofStatus.VALID or not self.preimage_available:
            raise HashlockedGraphError("positive proof did not release the ACK preimage")
        return replace(
            self,
            state=replace(
                self.state,
                connector_unspent=False,
                ack_confirmed=True,
                outcome=GraphOutcome.ACK_SLASH,
            ),
        )

    def publish_timeout_nack(self) -> "HashlockedValidityMachine":
        if not self.state.connector_unspent:
            raise HashlockedGraphError("connector is absent or already spent")
        if not self.graph.verify_timeout_nack(blocks_elapsed=self.blocks_since_counterproof):
            raise HashlockedGraphError("timeout NACK is not mature")
        return replace(
            self,
            state=replace(
                self.state,
                connector_unspent=False,
                nack_confirmed=True,
                outcome=GraphOutcome.TIMEOUT_NACK_CONTESTED_PAYOUT,
            ),
        )

    def reorg(self, new_height: int, *, remove_counterproof: bool = False) -> "HashlockedValidityMachine":
        if not 0 <= new_height <= self.state.height:
            raise HashlockedGraphError("invalid reorg height")
        if remove_counterproof:
            return replace(
                self,
                state=ChainState(height=new_height),
            )
        confirmed = self.state.counterproof_confirmed_height
        if confirmed is not None and new_height < confirmed:
            return replace(self, state=ChainState(height=new_height))
        # Research model conservatively rolls back connector spends whenever the
        # reorg reaches their confirmation height.
        return replace(
            self,
            state=ChainState(
                height=new_height,
                counterproof_confirmed_height=confirmed,
                connector_unspent=confirmed is not None,
            ),
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "status": self.status.value,
            "preimage_available": self.preimage_available,
            "height": self.state.height,
            "counterproof_confirmed_height": self.state.counterproof_confirmed_height,
            "connector_unspent": self.state.connector_unspent,
            "ack_confirmed": self.state.ack_confirmed,
            "nack_confirmed": self.state.nack_confirmed,
            "outcome": self.state.outcome.value,
            "ack_and_nack_conflict_on_same_outpoint": self.graph.ack.prevout == self.graph.nack.prevout,
        }
