from __future__ import annotations

"""Reduce malicious activation consistency to an ordinary public ZK proof.

The session-derived fault key removes the encrypted payload, so activation no
longer needs a bespoke witness-encryption correctness proof.  Each contributor
only has to prove knowledge of its setup scalar ``r`` satisfying a fixed public
NP relation:

* one scalar multiplies every fixed G2 anchor;
* the same scalar determines the accepting statement-side pairing session;
* hashing that session with the relation/epoch/signer context yields the
  published secp256k1 fault-share key.

This proof is checked during the ceremony, before the Bitcoin graph is funded.
It is *not* conditionally evaluated later, so a conventional transparent proof,
zkVM proof, or SNARK can instantiate it.  This module specifies the exact public
statement and witness relation and the ceremony state machine.  It does not
implement the ZK proof system.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .ciphertext_free_fault_key import (
    DerivedFaultKeyShare,
    verify_activation_witness,
)


class ActivationNizkError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ActivationPublicStatement:
    relation_digest: bytes
    epoch: bytes
    signer_id: bytes
    base_scale_g2: bytes
    scaled_anchors_g2: tuple[bytes, ...]
    fault_public_key: bytes
    activation_statement_digest: bytes
    schema: str = "ranklock-activation-public-statement-v1"

    def __post_init__(self) -> None:
        if len(self.relation_digest) != 32 or len(self.epoch) != 32:
            raise ActivationNizkError("invalid activation digest/epoch")
        if not self.signer_id or not self.scaled_anchors_g2:
            raise ActivationNizkError("activation statement is incomplete")
        if len(self.activation_statement_digest) != 32:
            raise ActivationNizkError("activation statement digest is invalid")

    @classmethod
    def from_share(cls, share: DerivedFaultKeyShare) -> "ActivationPublicStatement":
        return cls(
            share.relation.digest,
            share.epoch,
            share.signer_id,
            share.ppe_key.base_scale_g2,
            share.ppe_key.scaled_witness_anchors_g2,
            share.fault_public_key,
            share.activation_statement_digest,
        )

    @property
    def encoded_bytes(self) -> int:
        return (
            len(self.relation_digest)
            + len(self.epoch)
            + len(self.signer_id)
            + len(self.base_scale_g2)
            + sum(len(value) for value in self.scaled_anchors_g2)
            + len(self.fault_public_key)
            + len(self.activation_statement_digest)
        )


@dataclass(frozen=True, slots=True)
class ActivationProgramInventory:
    scaled_g2_equalities: int
    statement_pairings: int
    sha256_to_scalar: int = 1
    secp256k1_fixed_base_multiplications: int = 1
    schema: str = "ranklock-activation-program-inventory-v1"

    def __post_init__(self) -> None:
        if self.scaled_g2_equalities <= 0 or self.statement_pairings <= 0:
            raise ActivationNizkError("activation program inventory is empty")

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "scaled_G2_equalities": self.scaled_g2_equalities,
            "statement_pairings": self.statement_pairings,
            "SHA256_to_scalar": self.sha256_to_scalar,
            "secp256k1_fixed_base_multiplications": (
                self.secp256k1_fixed_base_multiplications
            ),
            "execution_class": "one-time setup proof; never evaluated by the conditional lock",
        }


@dataclass(frozen=True, slots=True)
class CeremonyContribution:
    statement: ActivationPublicStatement
    proof_bytes: bytes
    proof_system_id: bytes
    schema: str = "ranklock-activation-ceremony-contribution-v1"

    def __post_init__(self) -> None:
        if not self.proof_bytes or not self.proof_system_id:
            raise ActivationNizkError("activation contribution lacks a proof")

    @property
    def receipt_digest(self) -> bytes:
        return sha256(
            b"ranklock/activation-receipt/v1\x00"
            + self.statement.activation_statement_digest
            + len(self.proof_system_id).to_bytes(4, "big")
            + self.proof_system_id
            + len(self.proof_bytes).to_bytes(8, "big")
            + self.proof_bytes
        ).digest()


@dataclass(frozen=True, slots=True)
class CeremonyDecision:
    accepted_receipts: tuple[bytes, ...]
    funded: bool
    reason: str
    schema: str = "ranklock-activation-ceremony-decision-v1"


def evaluate_visible_activation_relation(
    share: DerivedFaultKeyShare, scale_witness: int
) -> bool:
    """Executable NP relation used to validate fixtures and future guest code."""

    return verify_activation_witness(share, scale_witness)


def ceremony_decision(
    contributions: Sequence[CeremonyContribution],
    *,
    expected_signer_ids: Sequence[bytes],
    proof_verdicts: Sequence[bool],
) -> CeremonyDecision:
    """Fail closed before funding if any proof or roster entry is invalid.

    ``proof_verdicts`` stands for results from an external ordinary proof
    verifier.  The ceremony itself does not need to understand or conditionally
    garble that verifier.
    """

    contributions = tuple(contributions)
    expected = tuple(sorted(bytes(value) for value in expected_signer_ids))
    if len(contributions) != len(proof_verdicts):
        raise ActivationNizkError("proof verdict count mismatch")
    actual = tuple(sorted(item.statement.signer_id for item in contributions))
    if actual != expected:
        return CeremonyDecision((), False, "contributor roster mismatch")
    if len(set(actual)) != len(actual):
        return CeremonyDecision((), False, "duplicate contributor id")
    if not all(bool(value) for value in proof_verdicts):
        return CeremonyDecision((), False, "at least one activation proof failed")
    relation_digests = {item.statement.relation_digest for item in contributions}
    epochs = {item.statement.epoch for item in contributions}
    if len(relation_digests) != 1 or len(epochs) != 1:
        return CeremonyDecision((), False, "contributors disagree on relation or epoch")
    receipts = tuple(sorted(item.receipt_digest for item in contributions))
    return CeremonyDecision(receipts, True, "all rostered activation proofs accepted")


def activation_nizk_frontier(share: DerivedFaultKeyShare) -> dict[str, object]:
    statement = ActivationPublicStatement.from_share(share)
    inventory = ActivationProgramInventory(
        scaled_g2_equalities=1 + share.relation.witness_anchor_count,
        statement_pairings=share.relation.statement_term_count,
    )
    return {
        "schema": "ranklock-activation-nizk-frontier-v1",
        "public_statement_bytes": statement.encoded_bytes,
        "activation_statement_digest": statement.activation_statement_digest.hex(),
        "program_inventory": inventory.document(),
        "ciphertext_or_payload_consistency_needed": False,
        "public_key_consistency_relation_executable": True,
        "ordinary_ZK_proof_system_can_instantiate_relation": True,
        "ordinary_ZK_proof_implemented_here": False,
        "ceremony_rule": (
            "verify every rostered contribution before graph funding; any invalid proof or "
            "abort invalidates the epoch and restarts with fresh setup scalars"
        ),
        "security_effect": [
            "malicious contributors cannot substitute an unlock-dead fault key without breaking proof soundness",
            "one honest contributor keeps the aggregate pre-witness signing scalar hidden",
            "all accepted contributors remain necessary for liveness in the n-of-n variant",
        ],
        "remaining_engineering": [
            "write the fixed activation guest/circuit",
            "select and pin the public proof verifier",
            "bind proof-system version and program digest into the ceremony manifest",
            "benchmark setup proof generation and verification",
        ],
        "breakthrough_target_met": False,
    }
