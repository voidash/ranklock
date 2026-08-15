from __future__ import annotations

"""Minimal canonical Bitcoin transaction and Taproot sighash primitives.

This module deliberately implements only the serialization and BIP341/BIP342
surface needed by the RankLock release-carrier regtest.  It is independent of a
wallet and does not attempt to replace Bitcoin Core policy or consensus checks.
"""

from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import Iterable, Sequence

from .bip340 import tagged_hash


class BitcoinTxError(ValueError):
    pass


SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
_ALLOWED_SIGHASHES = frozenset({0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83})

# RankLock accepts only standard-sized carrier transactions.  These limits
# are checked before allocation/iteration so malformed network input cannot
# turn the canonical parser into an unbounded CPU or memory sink.
MAX_PARSE_TRANSACTION_BYTES = 400_000
MAX_PARSE_INPUTS = 4_096
MAX_PARSE_OUTPUTS = 4_096
MAX_PARSE_BASE_SCRIPT_BYTES = 10_000
MAX_PARSE_WITNESS_ITEMS_PER_INPUT = 1_000
MAX_PARSE_WITNESS_ITEM_BYTES = 100_000
MAX_PARSE_TOTAL_WITNESS_BYTES = 400_000


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(bytes(data)).digest()).digest()


def compact_size(value: int) -> bytes:
    value = int(value)
    if value < 0:
        raise BitcoinTxError("compact-size value is negative")
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise BitcoinTxError("compact-size value exceeds u64")


def ser_string(value: bytes) -> bytes:
    raw = bytes(value)
    return compact_size(len(raw)) + raw


@dataclass(frozen=True, slots=True)
class OutPoint:
    """An outpoint using conventional display-order txid bytes."""

    txid: bytes
    vout: int

    def __post_init__(self) -> None:
        if len(bytes(self.txid)) != 32:
            raise BitcoinTxError("outpoint txid must be 32 bytes")
        if not 0 <= int(self.vout) <= 0xFFFFFFFF:
            raise BitcoinTxError("outpoint vout must fit u32")

    @property
    def wire(self) -> bytes:
        return bytes(self.txid)[::-1] + int(self.vout).to_bytes(4, "little")


@dataclass(frozen=True, slots=True)
class TxIn:
    previous_output: OutPoint
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFD
    witness: tuple[bytes, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not 0 <= int(self.sequence) <= 0xFFFFFFFF:
            raise BitcoinTxError("input sequence must fit u32")
        object.__setattr__(self, "script_sig", bytes(self.script_sig))
        object.__setattr__(self, "witness", tuple(bytes(item) for item in self.witness))

    @property
    def base_serialization(self) -> bytes:
        return (
            self.previous_output.wire
            + ser_string(self.script_sig)
            + int(self.sequence).to_bytes(4, "little")
        )

    @property
    def witness_serialization(self) -> bytes:
        return compact_size(len(self.witness)) + b"".join(
            ser_string(item) for item in self.witness
        )


@dataclass(frozen=True, slots=True)
class TxOut:
    value: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if not 0 <= int(self.value) <= 21_000_000 * 100_000_000:
            raise BitcoinTxError("transaction output value is outside MoneyRange")
        object.__setattr__(self, "script_pubkey", bytes(self.script_pubkey))

    @property
    def serialization(self) -> bytes:
        return int(self.value).to_bytes(8, "little") + ser_string(self.script_pubkey)


@dataclass(frozen=True, slots=True)
class Transaction:
    version: int
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    lock_time: int = 0

    def __post_init__(self) -> None:
        if not -(2**31) <= int(self.version) < 2**31:
            raise BitcoinTxError("transaction version must fit i32")
        if not self.inputs:
            raise BitcoinTxError("transaction requires at least one input")
        if not self.outputs:
            raise BitcoinTxError("transaction requires at least one output")
        if not 0 <= int(self.lock_time) <= 0xFFFFFFFF:
            raise BitcoinTxError("transaction lock time must fit u32")
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "outputs", tuple(self.outputs))

    @property
    def has_witness(self) -> bool:
        return any(txin.witness for txin in self.inputs)

    def serialize(self, *, include_witness: bool = True) -> bytes:
        marker_flag = b"\x00\x01" if include_witness and self.has_witness else b""
        raw = int(self.version).to_bytes(4, "little", signed=True) + marker_flag
        raw += compact_size(len(self.inputs))
        raw += b"".join(txin.base_serialization for txin in self.inputs)
        raw += compact_size(len(self.outputs))
        raw += b"".join(txout.serialization for txout in self.outputs)
        if marker_flag:
            raw += b"".join(txin.witness_serialization for txin in self.inputs)
        raw += int(self.lock_time).to_bytes(4, "little")
        return raw

    @property
    def txid(self) -> bytes:
        return sha256d(self.serialize(include_witness=False))[::-1]

    @property
    def wtxid(self) -> bytes:
        return sha256d(self.serialize(include_witness=True))[::-1]

    @property
    def stripped_size(self) -> int:
        return len(self.serialize(include_witness=False))

    @property
    def total_size(self) -> int:
        return len(self.serialize(include_witness=True))

    @property
    def weight(self) -> int:
        return self.stripped_size * 3 + self.total_size

    @property
    def vsize(self) -> int:
        return (self.weight + 3) // 4

    @classmethod
    def parse(cls, raw: bytes) -> "Transaction":
        return parse_transaction(raw)

    def with_input_witness(self, input_index: int, witness: Sequence[bytes]) -> "Transaction":
        if not 0 <= int(input_index) < len(self.inputs):
            raise BitcoinTxError("input index is outside transaction")
        updated = list(self.inputs)
        updated[input_index] = replace(updated[input_index], witness=tuple(witness))
        return replace(self, inputs=tuple(updated))


def _sha_concat(parts: Iterable[bytes]) -> bytes:
    return sha256(b"".join(bytes(part) for part in parts)).digest()


def taproot_script_path_sighash(
    transaction: Transaction,
    *,
    input_index: int,
    spent_outputs: Sequence[TxOut],
    tapleaf_hash: bytes,
    hash_type: int = SIGHASH_DEFAULT,
    annex: bytes | None = None,
    key_version: int = 0,
    codesep_position: int = 0xFFFFFFFF,
) -> bytes:
    """Compute BIP341 SigMsg with the BIP342 script-path extension."""

    hash_type = int(hash_type)
    if hash_type not in _ALLOWED_SIGHASHES:
        raise BitcoinTxError("unsupported Taproot sighash type")
    if not 0 <= int(input_index) < len(transaction.inputs):
        raise BitcoinTxError("Taproot sighash input index is outside transaction")
    if len(spent_outputs) != len(transaction.inputs):
        raise BitcoinTxError("one spent output is required for every transaction input")
    leaf = bytes(tapleaf_hash)
    if len(leaf) != 32:
        raise BitcoinTxError("TapLeaf hash must be 32 bytes")
    if not 0 <= int(key_version) <= 0xFF:
        raise BitcoinTxError("Taproot key version must fit a byte")
    if not 0 <= int(codesep_position) <= 0xFFFFFFFF:
        raise BitcoinTxError("code-separator position must fit u32")

    anyone_can_pay = bool(hash_type & SIGHASH_ANYONECANPAY)
    base_type = hash_type & 0x03
    annex_bytes = None if annex is None else bytes(annex)
    if annex_bytes is not None and (not annex_bytes or annex_bytes[0] != 0x50):
        raise BitcoinTxError("Taproot annex must start with 0x50")

    message = bytearray()
    message.append(hash_type)
    message += int(transaction.version).to_bytes(4, "little", signed=True)
    message += int(transaction.lock_time).to_bytes(4, "little")

    if not anyone_can_pay:
        message += _sha_concat(txin.previous_output.wire for txin in transaction.inputs)
        message += _sha_concat(
            int(spent.value).to_bytes(8, "little") for spent in spent_outputs
        )
        message += _sha_concat(ser_string(spent.script_pubkey) for spent in spent_outputs)
        message += _sha_concat(
            int(txin.sequence).to_bytes(4, "little") for txin in transaction.inputs
        )

    # SIGHASH_DEFAULT (0) has SIGHASH_ALL output semantics.
    if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        message += _sha_concat(output.serialization for output in transaction.outputs)

    ext_flag = 1  # tapscript extension
    spend_type = ext_flag * 2 + int(annex_bytes is not None)
    message.append(spend_type)

    current_input = transaction.inputs[input_index]
    current_spent = spent_outputs[input_index]
    if anyone_can_pay:
        message += current_input.previous_output.wire
        message += int(current_spent.value).to_bytes(8, "little")
        message += ser_string(current_spent.script_pubkey)
        message += int(current_input.sequence).to_bytes(4, "little")
    else:
        message += int(input_index).to_bytes(4, "little")

    if annex_bytes is not None:
        message += sha256(ser_string(annex_bytes)).digest()

    if base_type == SIGHASH_SINGLE:
        if input_index >= len(transaction.outputs):
            raise BitcoinTxError("SIGHASH_SINGLE input has no corresponding output")
        message += sha256(transaction.outputs[input_index].serialization).digest()

    message += leaf
    message.append(int(key_version))
    message += int(codesep_position).to_bytes(4, "little")
    return tagged_hash("TapSighash", b"\x00" + bytes(message))


def read_compact_size(raw: bytes, offset: int = 0) -> tuple[int, int]:
    data = bytes(raw)
    if not 0 <= int(offset) < len(data):
        raise BitcoinTxError("truncated compact-size value")
    prefix = data[offset]
    if prefix < 0xFD:
        return prefix, offset + 1
    widths = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    width = widths[prefix]
    end = offset + 1 + width
    if end > len(data):
        raise BitcoinTxError("truncated compact-size payload")
    value = int.from_bytes(data[offset + 1 : end], "little")
    minimum = {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[prefix]
    if value < minimum:
        raise BitcoinTxError("non-minimal compact-size value")
    return value, end


def _read_bytes(raw: bytes, offset: int, length: int, name: str) -> tuple[bytes, int]:
    if length < 0 or offset < 0 or offset + length > len(raw):
        raise BitcoinTxError(f"truncated {name}")
    return raw[offset : offset + length], offset + length


def parse_transaction(raw: bytes) -> Transaction:
    data = bytes(raw)
    if len(data) > MAX_PARSE_TRANSACTION_BYTES:
        raise BitcoinTxError("serialized transaction exceeds RankLock size limit")
    if len(data) < 10:
        raise BitcoinTxError("serialized transaction is too short")
    cursor = 0
    version_raw, cursor = _read_bytes(data, cursor, 4, "transaction version")
    version = int.from_bytes(version_raw, "little", signed=True)

    has_witness_encoding = False
    if cursor + 2 <= len(data) and data[cursor] == 0:
        if data[cursor + 1] != 1:
            raise BitcoinTxError("unsupported SegWit marker/flag")
        has_witness_encoding = True
        cursor += 2

    input_count, cursor = read_compact_size(data, cursor)
    if input_count == 0:
        raise BitcoinTxError("transaction has no inputs")
    if input_count > MAX_PARSE_INPUTS:
        raise BitcoinTxError("transaction input count exceeds parser limit")
    inputs: list[TxIn] = []
    for _ in range(input_count):
        txid_wire, cursor = _read_bytes(data, cursor, 32, "outpoint txid")
        vout_raw, cursor = _read_bytes(data, cursor, 4, "outpoint index")
        script_size, cursor = read_compact_size(data, cursor)
        if script_size > MAX_PARSE_BASE_SCRIPT_BYTES:
            raise BitcoinTxError("scriptSig exceeds parser limit")
        script_sig, cursor = _read_bytes(data, cursor, script_size, "scriptSig")
        sequence_raw, cursor = _read_bytes(data, cursor, 4, "input sequence")
        inputs.append(
            TxIn(
                previous_output=OutPoint(
                    txid=txid_wire[::-1], vout=int.from_bytes(vout_raw, "little")
                ),
                script_sig=script_sig,
                sequence=int.from_bytes(sequence_raw, "little"),
            )
        )

    output_count, cursor = read_compact_size(data, cursor)
    if output_count == 0:
        raise BitcoinTxError("transaction has no outputs")
    if output_count > MAX_PARSE_OUTPUTS:
        raise BitcoinTxError("transaction output count exceeds parser limit")
    outputs: list[TxOut] = []
    for _ in range(output_count):
        value_raw, cursor = _read_bytes(data, cursor, 8, "output value")
        script_size, cursor = read_compact_size(data, cursor)
        if script_size > MAX_PARSE_BASE_SCRIPT_BYTES:
            raise BitcoinTxError("scriptPubKey exceeds parser limit")
        script_pubkey, cursor = _read_bytes(data, cursor, script_size, "scriptPubKey")
        outputs.append(TxOut(int.from_bytes(value_raw, "little"), script_pubkey))

    if has_witness_encoding:
        witnessed_inputs: list[TxIn] = []
        any_witness = False
        total_witness_bytes = 0
        for txin in inputs:
            item_count, cursor = read_compact_size(data, cursor)
            if item_count > MAX_PARSE_WITNESS_ITEMS_PER_INPUT:
                raise BitcoinTxError("witness item count exceeds parser limit")
            items: list[bytes] = []
            for _ in range(item_count):
                item_size, cursor = read_compact_size(data, cursor)
                if item_size > MAX_PARSE_WITNESS_ITEM_BYTES:
                    raise BitcoinTxError("witness item exceeds parser limit")
                total_witness_bytes += item_size
                if total_witness_bytes > MAX_PARSE_TOTAL_WITNESS_BYTES:
                    raise BitcoinTxError("witness bytes exceed parser limit")
                item, cursor = _read_bytes(data, cursor, item_size, "witness item")
                items.append(item)
            any_witness |= bool(items)
            witnessed_inputs.append(replace(txin, witness=tuple(items)))
        if not any_witness:
            raise BitcoinTxError("superfluous SegWit marker/flag")
        inputs = witnessed_inputs

    lock_time_raw, cursor = _read_bytes(data, cursor, 4, "transaction lock time")
    if cursor != len(data):
        raise BitcoinTxError("trailing bytes after transaction")
    transaction = Transaction(
        version=version,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        lock_time=int.from_bytes(lock_time_raw, "little"),
    )
    if transaction.serialize(include_witness=True) != data:
        raise BitcoinTxError("non-canonical transaction serialization")
    return transaction
