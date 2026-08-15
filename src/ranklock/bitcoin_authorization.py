from __future__ import annotations

"""Strict Bitcoin transaction/witness binding for RankLock authorization.

A Bitcoin transaction ID excludes SegWit witness data.  RankLock input labels
are carried by witness signatures, so authorizing only a ``txid`` permits two
transactions with the same txid and different witnesses to select different
labels.  This module parses canonical transaction serialization and binds the
release to all of:

* the chain genesis hash;
* the exact spent authorization outpoint and input index;
* txid;
* wtxid;
* the complete transaction witness serialization digest.

The parser is intentionally narrow and fail-closed.  It is not a replacement
for Bitcoin Core's consensus decoder; production integration must compare its
results with Core RPC before release.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Final


_BINDING_DOMAIN: Final = b"ranklock/bitcoin-authorization-binding/v1\x00"
_WITNESS_DOMAIN: Final = b"ranklock/bitcoin-witness-serialization/v1\x00"
_MAX_VECTOR_ITEMS: Final = 1_000_000
_MAX_SCRIPT_BYTES: Final = 4_000_000
_MAX_TRANSACTION_BYTES: Final = 4_000_000


class BitcoinAuthorizationError(ValueError):
    pass


def _dsha(data: bytes) -> bytes:
    return sha256(sha256(data).digest()).digest()


def _display_hash(data: bytes) -> bytes:
    """Return the byte order used by Bitcoin RPC/display txids."""

    return _dsha(data)[::-1]


def _u(value: int, width: int) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (width * 8):
        raise BitcoinAuthorizationError(f"integer does not fit u{width * 8}")
    return value.to_bytes(width, "big")


def _compact_size(value: int) -> bytes:
    value = int(value)
    if value < 0:
        raise BitcoinAuthorizationError("negative CompactSize")
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise BitcoinAuthorizationError("CompactSize exceeds u64")


class _Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = bytes(raw)
        self.cursor = 0

    def take(self, count: int) -> bytes:
        count = int(count)
        if count < 0 or self.cursor + count > len(self.raw):
            raise BitcoinAuthorizationError("truncated Bitcoin transaction")
        result = self.raw[self.cursor : self.cursor + count]
        self.cursor += count
        return result

    def compact_size(self) -> tuple[int, bytes]:
        prefix = self.take(1)[0]
        if prefix < 0xFD:
            return prefix, bytes((prefix,))
        width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[prefix]
        body = self.take(width)
        value = int.from_bytes(body, "little")
        minimum = {2: 0xFD, 4: 0x10000, 8: 0x100000000}[width]
        if value < minimum:
            raise BitcoinAuthorizationError("non-canonical CompactSize")
        return value, bytes((prefix,)) + body

    def varbytes(self) -> tuple[bytes, bytes]:
        length, prefix = self.compact_size()
        if length > _MAX_SCRIPT_BYTES:
            raise BitcoinAuthorizationError("Bitcoin vector exceeds parser limit")
        body = self.take(length)
        return body, prefix + body


@dataclass(frozen=True, slots=True)
class ParsedBitcoinTransaction:
    raw: bytes
    stripped: bytes
    witness_serialization: bytes
    version: int
    input_outpoints: tuple[bytes, ...]
    input_sequences: tuple[int, ...]
    output_values: tuple[int, ...]
    output_scripts: tuple[bytes, ...]
    witness_stacks: tuple[tuple[bytes, ...], ...]
    lock_time: int
    txid: bytes
    wtxid: bytes
    has_witness: bool
    schema: str = "ranklock-parsed-bitcoin-transaction-v2"

    @property
    def witness_digest(self) -> bytes:
        return sha256(_WITNESS_DOMAIN + self.witness_serialization).digest()


def parse_bitcoin_transaction(raw: bytes) -> ParsedBitcoinTransaction:
    encoded = bytes(raw)
    if not encoded or len(encoded) > _MAX_TRANSACTION_BYTES:
        raise BitcoinAuthorizationError("Bitcoin transaction exceeds parser limit")
    reader = _Reader(encoded)
    version = reader.take(4)
    version_value = int.from_bytes(version, "little")

    has_witness = False
    marker_flag = b""
    if reader.cursor + 2 <= len(encoded) and encoded[reader.cursor] == 0:
        marker = reader.take(1)
        flag = reader.take(1)
        # Bitcoin Core's transaction decoder currently recognizes only the
        # canonical marker/flag pair 00 01.  Accepting arbitrary nonzero flags
        # would let the local binding parser disagree with Core about the same
        # byte string.
        if flag != b"\x01":
            raise BitcoinAuthorizationError("unsupported SegWit marker/flag")
        has_witness = True
        marker_flag = marker + flag

    vin_count, vin_prefix = reader.compact_size()
    if vin_count == 0 or vin_count > _MAX_VECTOR_ITEMS:
        raise BitcoinAuthorizationError("invalid Bitcoin input count")
    stripped_inputs = bytearray(vin_prefix)
    outpoints: list[bytes] = []
    input_sequences: list[int] = []
    for _ in range(vin_count):
        previous_txid_wire = reader.take(32)
        vout_wire = reader.take(4)
        script, script_encoded = reader.varbytes()
        sequence = reader.take(4)
        input_sequences.append(int.from_bytes(sequence, "little"))
        # Library outpoints are txid in RPC byte order followed by vout little
        # endian, matching EvaluationContext's historical 36-byte convention.
        outpoints.append(previous_txid_wire[::-1] + vout_wire)
        stripped_inputs.extend(previous_txid_wire)
        stripped_inputs.extend(vout_wire)
        stripped_inputs.extend(script_encoded)
        stripped_inputs.extend(sequence)

    vout_count, vout_prefix = reader.compact_size()
    if vout_count > _MAX_VECTOR_ITEMS:
        raise BitcoinAuthorizationError("invalid Bitcoin output count")
    stripped_outputs = bytearray(vout_prefix)
    output_values: list[int] = []
    output_scripts: list[bytes] = []
    for _ in range(vout_count):
        value = reader.take(8)
        script, script_encoded = reader.varbytes()
        output_values.append(int.from_bytes(value, "little"))
        output_scripts.append(script)
        stripped_outputs.extend(value)
        stripped_outputs.extend(script_encoded)

    witness = bytearray()
    witness_stacks: list[tuple[bytes, ...]] = []
    any_witness_stack = False
    if has_witness:
        for _ in range(vin_count):
            count, count_encoded = reader.compact_size()
            if count > _MAX_VECTOR_ITEMS:
                raise BitcoinAuthorizationError("invalid witness item count")
            witness.extend(count_encoded)
            stack: list[bytes] = []
            for _ in range(count):
                item, item_encoded = reader.varbytes()
                stack.append(item)
                witness.extend(item_encoded)
            # A stack containing one zero-length item is not an empty witness.
            # Core's superfluous-witness rule is based on an empty stack, not
            # whether any item contains a nonzero byte.
            any_witness_stack |= bool(stack)
            witness_stacks.append(tuple(stack))
        if not any_witness_stack:
            raise BitcoinAuthorizationError("superfluous empty SegWit serialization")
    else:
        witness_stacks = [tuple() for _ in range(vin_count)]

    lock_time = reader.take(4)
    lock_time_value = int.from_bytes(lock_time, "little")
    if reader.cursor != len(encoded):
        raise BitcoinAuthorizationError("Bitcoin transaction has trailing bytes")

    stripped = version + bytes(stripped_inputs) + bytes(stripped_outputs) + lock_time
    canonical = (
        version
        + marker_flag
        + bytes(stripped_inputs)
        + bytes(stripped_outputs)
        + bytes(witness)
        + lock_time
        if has_witness
        else stripped
    )
    if canonical != encoded:
        raise BitcoinAuthorizationError("non-canonical Bitcoin transaction serialization")
    return ParsedBitcoinTransaction(
        raw=encoded,
        stripped=stripped,
        witness_serialization=bytes(witness),
        version=version_value,
        input_outpoints=tuple(outpoints),
        input_sequences=tuple(input_sequences),
        output_values=tuple(output_values),
        output_scripts=tuple(output_scripts),
        witness_stacks=tuple(witness_stacks),
        lock_time=lock_time_value,
        txid=_display_hash(stripped),
        wtxid=_display_hash(encoded),
        has_witness=has_witness,
    )


@dataclass(frozen=True, slots=True)
class BitcoinAuthorizationBinding:
    chain_genesis_hash: bytes
    authorization_outpoint: bytes
    authorization_input_index: int
    counterproof_txid: bytes
    counterproof_wtxid: bytes
    witness_digest: bytes
    schema: str = "ranklock-bitcoin-authorization-binding-v1"

    def __post_init__(self) -> None:
        for name in (
            "chain_genesis_hash",
            "counterproof_txid",
            "counterproof_wtxid",
            "witness_digest",
        ):
            if len(bytes(getattr(self, name))) != 32:
                raise BitcoinAuthorizationError(f"{name} must be 32 bytes")
        if len(bytes(self.authorization_outpoint)) != 36:
            raise BitcoinAuthorizationError("authorization outpoint must be 36 bytes")
        if not 0 <= int(self.authorization_input_index) < 2**32:
            raise BitcoinAuthorizationError("authorization input index must fit u32")

    @property
    def canonical_bytes(self) -> bytes:
        return (
            bytes(self.chain_genesis_hash)
            + bytes(self.authorization_outpoint)
            + _u(self.authorization_input_index, 4)
            + bytes(self.counterproof_txid)
            + bytes(self.counterproof_wtxid)
            + bytes(self.witness_digest)
        )

    @property
    def digest(self) -> bytes:
        return sha256(_BINDING_DOMAIN + self.canonical_bytes).digest()

    @classmethod
    def from_raw_transaction(
        cls,
        raw_transaction: bytes,
        *,
        chain_genesis_hash: bytes,
        authorization_input_index: int,
    ) -> "BitcoinAuthorizationBinding":
        parsed = parse_bitcoin_transaction(raw_transaction)
        index = int(authorization_input_index)
        if not 0 <= index < len(parsed.input_outpoints):
            raise BitcoinAuthorizationError("authorization input index is absent")
        return cls(
            chain_genesis_hash=bytes(chain_genesis_hash),
            authorization_outpoint=parsed.input_outpoints[index],
            authorization_input_index=index,
            counterproof_txid=parsed.txid,
            counterproof_wtxid=parsed.wtxid,
            witness_digest=parsed.witness_digest,
        )

    def verify_raw_transaction(self, raw_transaction: bytes) -> bool:
        try:
            parsed = parse_bitcoin_transaction(raw_transaction)
        except BitcoinAuthorizationError:
            return False
        index = self.authorization_input_index
        return bool(
            index < len(parsed.input_outpoints)
            and parsed.input_outpoints[index] == bytes(self.authorization_outpoint)
            and parsed.txid == bytes(self.counterproof_txid)
            and parsed.wtxid == bytes(self.counterproof_wtxid)
            and parsed.witness_digest == bytes(self.witness_digest)
        )
