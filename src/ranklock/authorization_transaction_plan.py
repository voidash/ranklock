from __future__ import annotations

"""Canonical precommitment to the ordered RankLock authorization transactions.

SegWit/Taproot deliberately excludes witness data from ``txid``.  RankLock uses
that property to precommit transaction ids while choosing the 512 selector
witness items only after the corresponding proof point is known.  A list of
transaction ids alone, however, does not prove that the transactions form the
intended deposit -> slot 0 -> slot 1 chain or that their non-witness bytes are
otherwise fixed.

This module commits the exact stripped serialization of every authorization
transaction and verifies the continuation outpoint between adjacent slots.  The
plan digest is what v0.25 places in the historical 32-byte
``EvaluationContext.counterproof_txid`` field.  Each per-slot committee
activation additionally binds the exact transaction id for that slot.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .bitcoin_authorization import ParsedBitcoinTransaction, parse_bitcoin_transaction


_MAGIC = b"RLATP251"
_DOMAIN = b"ranklock/authorization-transaction-plan/v1\x00"
_STRIPPED_DOMAIN = b"ranklock/authorization-stripped-transaction/v1\x00"
_HASH_BYTES = 32
_OUTPOINT_BYTES = 36
_NONE_OUTPUT = 0xFFFFFFFF


class AuthorizationTransactionPlanError(ValueError):
    pass


def _u(value: int, width: int, name: str) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (8 * width):
        raise AuthorizationTransactionPlanError(f"{name} does not fit u{8 * width}")
    return value.to_bytes(width, "big")


def _hash_stripped(parsed: ParsedBitcoinTransaction) -> bytes:
    return sha256(_STRIPPED_DOMAIN + parsed.stripped).digest()


@dataclass(frozen=True, slots=True)
class AuthorizationTransactionTemplate:
    slot_id: int
    txid: bytes
    stripped_digest: bytes
    authorization_input_index: int
    authorization_outpoint: bytes
    continuation_output_index: int | None
    continuation_output_value_sat: int | None
    continuation_output_script_hash: bytes | None
    schema: str = "ranklock-authorization-transaction-template-v1"

    def __post_init__(self) -> None:
        if not 0 <= int(self.slot_id) < 2**32:
            raise AuthorizationTransactionPlanError("slot id does not fit u32")
        for value, name in (
            (self.txid, "transaction id"),
            (self.stripped_digest, "stripped transaction digest"),
        ):
            if len(bytes(value)) != _HASH_BYTES:
                raise AuthorizationTransactionPlanError(f"{name} must be 32 bytes")
        if not 0 <= int(self.authorization_input_index) < 2**32:
            raise AuthorizationTransactionPlanError(
                "authorization input index does not fit u32"
            )
        if len(bytes(self.authorization_outpoint)) != _OUTPOINT_BYTES:
            raise AuthorizationTransactionPlanError(
                "authorization outpoint must be 36 bytes"
            )
        fields = (
            self.continuation_output_index,
            self.continuation_output_value_sat,
            self.continuation_output_script_hash,
        )
        if all(value is None for value in fields):
            return
        if any(value is None for value in fields):
            raise AuthorizationTransactionPlanError(
                "continuation output fields must be all present or all absent"
            )
        output_index = self.continuation_output_index
        output_value = self.continuation_output_value_sat
        output_script_hash = self.continuation_output_script_hash
        if output_index is None or output_value is None or output_script_hash is None:
            raise AuthorizationTransactionPlanError(
                "continuation output fields must be all present or all absent"
            )
        if not 0 <= int(output_index) < 2**32:
            raise AuthorizationTransactionPlanError(
                "continuation output index does not fit u32"
            )
        if not 0 <= int(output_value) < 2**64:
            raise AuthorizationTransactionPlanError(
                "continuation output value does not fit u64"
            )
        if len(bytes(output_script_hash)) != _HASH_BYTES:
            raise AuthorizationTransactionPlanError(
                "continuation output script hash must be 32 bytes"
            )

    @property
    def encoded(self) -> bytes:
        if self.continuation_output_index is None:
            continuation = _u(_NONE_OUTPUT, 4, "absent continuation output") + bytes(8 + 32)
        else:
            output_value = self.continuation_output_value_sat
            output_script_hash = self.continuation_output_script_hash
            if output_value is None or output_script_hash is None:
                raise AuthorizationTransactionPlanError(
                    "continuation output fields must be all present or all absent"
                )
            continuation = (
                _u(self.continuation_output_index, 4, "continuation output index")
                + _u(output_value, 8, "continuation output value")
                + bytes(output_script_hash)
            )
        return (
            _u(self.slot_id, 4, "slot id")
            + bytes(self.txid)
            + bytes(self.stripped_digest)
            + _u(self.authorization_input_index, 4, "authorization input index")
            + bytes(self.authorization_outpoint)
            + continuation
        )

    @classmethod
    def from_raw_transaction(
        cls,
        raw_transaction: bytes,
        *,
        slot_id: int,
        authorization_input_index: int,
        continuation_output_index: int | None,
    ) -> "AuthorizationTransactionTemplate":
        parsed = parse_bitcoin_transaction(raw_transaction)
        input_index = int(authorization_input_index)
        if not 0 <= input_index < len(parsed.input_outpoints):
            raise AuthorizationTransactionPlanError(
                "authorization input is absent from transaction"
            )
        if continuation_output_index is None:
            value: int | None = None
            script_hash: bytes | None = None
        else:
            output_index = int(continuation_output_index)
            if not 0 <= output_index < len(parsed.output_scripts):
                raise AuthorizationTransactionPlanError(
                    "continuation output is absent from transaction"
                )
            value = parsed.output_values[output_index]
            script_hash = sha256(parsed.output_scripts[output_index]).digest()
        return cls(
            slot_id=int(slot_id),
            txid=parsed.txid,
            stripped_digest=_hash_stripped(parsed),
            authorization_input_index=input_index,
            authorization_outpoint=parsed.input_outpoints[input_index],
            continuation_output_index=continuation_output_index,
            continuation_output_value_sat=value,
            continuation_output_script_hash=script_hash,
        )

    def verify_raw_transaction(self, raw_transaction: bytes) -> bool:
        try:
            parsed = parse_bitcoin_transaction(raw_transaction)
        except Exception:
            return False
        index = self.authorization_input_index
        if not (
            index < len(parsed.input_outpoints)
            and parsed.txid == bytes(self.txid)
            and _hash_stripped(parsed) == bytes(self.stripped_digest)
            and parsed.input_outpoints[index] == bytes(self.authorization_outpoint)
        ):
            return False
        if self.continuation_output_index is None:
            return True
        output_index = self.continuation_output_index
        output_value = self.continuation_output_value_sat
        output_script_hash = self.continuation_output_script_hash
        if output_value is None or output_script_hash is None:
            return False
        return bool(
            output_index < len(parsed.output_scripts)
            and parsed.output_values[output_index] == output_value
            and sha256(parsed.output_scripts[output_index]).digest()
            == bytes(output_script_hash)
        )

    @classmethod
    def parse(cls, raw: bytes) -> "AuthorizationTransactionTemplate":
        raw = bytes(raw)
        expected = 4 + 32 + 32 + 4 + 36 + 4 + 8 + 32
        if len(raw) != expected:
            raise AuthorizationTransactionPlanError(
                "authorization template length mismatch"
            )
        cursor = 0
        slot_id = int.from_bytes(raw[cursor : cursor + 4], "big"); cursor += 4
        txid = raw[cursor : cursor + 32]; cursor += 32
        stripped = raw[cursor : cursor + 32]; cursor += 32
        input_index = int.from_bytes(raw[cursor : cursor + 4], "big"); cursor += 4
        outpoint = raw[cursor : cursor + 36]; cursor += 36
        output_index = int.from_bytes(raw[cursor : cursor + 4], "big"); cursor += 4
        output_value = int.from_bytes(raw[cursor : cursor + 8], "big"); cursor += 8
        output_script_hash = raw[cursor : cursor + 32]
        if output_index == _NONE_OUTPUT:
            if output_value != 0 or output_script_hash != bytes(32):
                raise AuthorizationTransactionPlanError(
                    "absent continuation output has nonzero fields"
                )
            values: tuple[int | None, int | None, bytes | None] = (None, None, None)
        else:
            values = (output_index, output_value, output_script_hash)
        result = cls(
            slot_id,
            txid,
            stripped,
            input_index,
            outpoint,
            values[0],
            values[1],
            values[2],
        )
        if result.encoded != raw:
            raise AuthorizationTransactionPlanError(
                "non-canonical authorization transaction template"
            )
        return result


_TEMPLATE_BYTES = len(
    AuthorizationTransactionTemplate(
        0,
        bytes(32),
        bytes(32),
        0,
        bytes(36),
        None,
        None,
        None,
    ).encoded
)


@dataclass(frozen=True, slots=True)
class AuthorizationTransactionPlan:
    chain_genesis_hash: bytes
    deposit_outpoint: bytes
    templates: tuple[AuthorizationTransactionTemplate, ...]
    schema: str = "ranklock-authorization-transaction-plan-v1"

    def __post_init__(self) -> None:
        if len(bytes(self.chain_genesis_hash)) != _HASH_BYTES:
            raise AuthorizationTransactionPlanError(
                "chain genesis hash must be 32 bytes"
            )
        if len(bytes(self.deposit_outpoint)) != _OUTPOINT_BYTES:
            raise AuthorizationTransactionPlanError("deposit outpoint must be 36 bytes")
        if not 1 <= len(self.templates) < 2**16:
            raise AuthorizationTransactionPlanError(
                "authorization plan must contain at least one slot"
            )
        if tuple(template.slot_id for template in self.templates) != tuple(
            range(len(self.templates))
        ):
            raise AuthorizationTransactionPlanError(
                "authorization templates must have canonical consecutive slot ids"
            )
        if self.templates[0].authorization_outpoint != bytes(self.deposit_outpoint):
            raise AuthorizationTransactionPlanError(
                "first authorization transaction does not spend the deposit outpoint"
            )
        for previous, following in zip(self.templates, self.templates[1:], strict=False):
            if previous.continuation_output_index is None:
                raise AuthorizationTransactionPlanError(
                    "nonterminal authorization transaction lacks continuation output"
                )
            expected = previous.txid + int(previous.continuation_output_index).to_bytes(
                4, "little"
            )
            if following.authorization_outpoint != expected:
                raise AuthorizationTransactionPlanError(
                    "authorization transactions do not form the committed chain"
                )
        if self.templates[-1].continuation_output_index is not None:
            raise AuthorizationTransactionPlanError(
                "terminal authorization transaction must not name another slot output"
            )
        if len({template.txid for template in self.templates}) != len(self.templates):
            raise AuthorizationTransactionPlanError(
                "authorization transaction ids must be unique"
            )

    @property
    def encoded(self) -> bytes:
        return (
            _MAGIC
            + bytes(self.chain_genesis_hash)
            + bytes(self.deposit_outpoint)
            + _u(len(self.templates), 2, "authorization template count")
            + b"".join(template.encoded for template in self.templates)
        )

    @property
    def digest(self) -> bytes:
        return sha256(_DOMAIN + self.encoded).digest()

    @property
    def txids(self) -> tuple[bytes, ...]:
        return tuple(template.txid for template in self.templates)

    def verify_raw_transaction(self, slot_id: int, raw_transaction: bytes) -> bool:
        slot_id = int(slot_id)
        return bool(
            0 <= slot_id < len(self.templates)
            and self.templates[slot_id].verify_raw_transaction(raw_transaction)
        )

    def verify_transactions(self, raw_transactions: Sequence[bytes]) -> bool:
        return bool(
            len(raw_transactions) == len(self.templates)
            and all(
                template.verify_raw_transaction(raw)
                for template, raw in zip(self.templates, raw_transactions, strict=True)
            )
        )

    @classmethod
    def parse(cls, raw: bytes) -> "AuthorizationTransactionPlan":
        raw = bytes(raw)
        fixed = 8 + 32 + 36 + 2
        if len(raw) < fixed or raw[:8] != _MAGIC:
            raise AuthorizationTransactionPlanError(
                "invalid authorization transaction plan framing"
            )
        count = int.from_bytes(raw[76:78], "big")
        if len(raw) != fixed + count * _TEMPLATE_BYTES:
            raise AuthorizationTransactionPlanError(
                "authorization transaction plan length mismatch"
            )
        templates = tuple(
            AuthorizationTransactionTemplate.parse(
                raw[fixed + i * _TEMPLATE_BYTES : fixed + (i + 1) * _TEMPLATE_BYTES]
            )
            for i in range(count)
        )
        result = cls(raw[8:40], raw[40:76], templates)
        if result.encoded != raw:
            raise AuthorizationTransactionPlanError(
                "non-canonical authorization transaction plan"
            )
        return result


def build_authorization_transaction_plan(
    *,
    chain_genesis_hash: bytes,
    deposit_outpoint: bytes,
    raw_transactions: Sequence[bytes],
    authorization_input_index: int = 0,
    continuation_output_index: int = 0,
) -> AuthorizationTransactionPlan:
    if not raw_transactions:
        raise AuthorizationTransactionPlanError("authorization transaction list is empty")
    templates = tuple(
        AuthorizationTransactionTemplate.from_raw_transaction(
            raw,
            slot_id=slot_id,
            authorization_input_index=authorization_input_index,
            continuation_output_index=(
                continuation_output_index if slot_id + 1 < len(raw_transactions) else None
            ),
        )
        for slot_id, raw in enumerate(raw_transactions)
    )
    return AuthorizationTransactionPlan(
        bytes(chain_genesis_hash), bytes(deposit_outpoint), templates
    )
