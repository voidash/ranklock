from __future__ import annotations

"""Semantic binding for the validity-first counterproof predicate.

The positive counterproof relation is not "this exact randomized Groth16 byte string".
It is "there exists a valid proof for the authenticated challenged bridge transaction and
fixed game context".  Groth16 proofs may be publicly rerandomized; all valid proofs for the
same authenticated statement imply the same ACK/slash outcome.
"""

from dataclasses import dataclass
from hashlib import sha256

from .bip340 import public_key, sign, verify


class CounterproofSemanticsError(ValueError):
    pass


def _lp(value: bytes) -> bytes:
    value = bytes(value)
    return len(value).to_bytes(8, "big") + value


@dataclass(frozen=True, slots=True)
class CounterproofContext:
    program_id: bytes
    verifier_key_digest: bytes
    deposit_id: bytes
    game_index: int
    operator_index: int
    bridge_proof_txid: bytes
    schema: str = "ranklock-counterproof-context-v1"

    def __post_init__(self) -> None:
        for name in ("program_id", "verifier_key_digest", "deposit_id", "bridge_proof_txid"):
            if not getattr(self, name):
                raise CounterproofSemanticsError(f"{name} is empty")
        if not 0 < self.game_index < 2**32:
            raise CounterproofSemanticsError("game index must be a nonzero u32")
        if not 0 <= self.operator_index < 2**32:
            raise CounterproofSemanticsError("operator index must be a u32")

    @property
    def digest(self) -> bytes:
        h = sha256(b"ranklock/counterproof-context/v1\x00")
        for value in (
            self.program_id,
            self.verifier_key_digest,
            self.deposit_id,
            self.bridge_proof_txid,
        ):
            h.update(_lp(value))
        h.update(self.game_index.to_bytes(4, "big"))
        h.update(self.operator_index.to_bytes(4, "big"))
        return h.digest()


@dataclass(frozen=True, slots=True)
class AuthenticatedBridgeProof:
    transaction: bytes
    operator_pubkey: bytes
    operator_signature: bytes
    context: CounterproofContext
    schema: str = "ranklock-authenticated-bridge-proof-v1"

    @property
    def transaction_digest(self) -> bytes:
        return sha256(b"ranklock/bridge-proof-tx/v1\x00" + bytes(self.transaction)).digest()

    @property
    def signing_message(self) -> bytes:
        return sha256(
            b"ranklock/bridge-proof-operator-signature/v1\x00"
            + self.context.digest
            + self.transaction_digest
        ).digest()

    def verify(self) -> bool:
        return (
            len(self.operator_pubkey) == 32
            and len(self.operator_signature) == 64
            and self.context.bridge_proof_txid == self.transaction_digest
            and verify(self.signing_message, self.operator_pubkey, self.operator_signature)
        )


@dataclass(frozen=True, slots=True)
class PositiveCounterproofStatement:
    authenticated_bridge_proof: AuthenticatedBridgeProof
    counterproof_public_values: bytes
    relation_tag: bytes = b"invalid-bridge-proof"
    schema: str = "ranklock-positive-counterproof-statement-v1"

    def __post_init__(self) -> None:
        if not self.counterproof_public_values:
            raise CounterproofSemanticsError("counterproof public values are empty")
        if not self.relation_tag:
            raise CounterproofSemanticsError("counterproof relation tag is empty")

    @property
    def digest(self) -> bytes:
        h = sha256(b"ranklock/positive-counterproof-statement/v1\x00")
        h.update(self.authenticated_bridge_proof.context.digest)
        h.update(self.authenticated_bridge_proof.transaction_digest)
        h.update(_lp(self.counterproof_public_values))
        h.update(_lp(self.relation_tag))
        return h.digest()

    def accepts_semantic_witness(
        self,
        *,
        proof_verifies: bool,
        proves_relation_for_statement_digest: bytes,
    ) -> bool:
        return (
            self.authenticated_bridge_proof.verify()
            and proof_verifies
            and bytes(proves_relation_for_statement_digest) == self.digest
        )


def authenticate_bridge_proof(
    transaction: bytes,
    *,
    operator_secret: int,
    context_without_txid: CounterproofContext,
) -> AuthenticatedBridgeProof:
    tx_digest = sha256(b"ranklock/bridge-proof-tx/v1\x00" + bytes(transaction)).digest()
    context = CounterproofContext(
        program_id=context_without_txid.program_id,
        verifier_key_digest=context_without_txid.verifier_key_digest,
        deposit_id=context_without_txid.deposit_id,
        game_index=context_without_txid.game_index,
        operator_index=context_without_txid.operator_index,
        bridge_proof_txid=tx_digest,
    )
    placeholder = AuthenticatedBridgeProof(
        transaction=bytes(transaction),
        operator_pubkey=public_key(operator_secret),
        operator_signature=bytes(64),
        context=context,
    )
    return AuthenticatedBridgeProof(
        transaction=placeholder.transaction,
        operator_pubkey=placeholder.operator_pubkey,
        operator_signature=sign(placeholder.signing_message, operator_secret),
        context=context,
    )


def proof_byte_identity_required() -> bool:
    """Proof rerandomization is safe once the authenticated statement is fixed."""

    return False
