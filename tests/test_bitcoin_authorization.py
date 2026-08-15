from __future__ import annotations

from hashlib import sha256

import pytest

from ranklock.bitcoin_authorization import (
    BitcoinAuthorizationBinding,
    BitcoinAuthorizationError,
    parse_bitcoin_transaction,
)


def _compact(value: int) -> bytes:
    if value < 0xFD:
        return bytes((value,))
    raise AssertionError("fixture only uses short vectors")


def witness_transaction(*, first_item: bytes, second_item: bytes = b"proof") -> bytes:
    version = (2).to_bytes(4, "little")
    marker_flag = b"\x00\x01"
    previous_txid_wire = bytes(range(32))
    vout = (3).to_bytes(4, "little")
    script_sig = b""
    sequence = bytes.fromhex("fdffffff")
    txin = previous_txid_wire + vout + _compact(0) + script_sig + sequence
    script_pubkey = b"\x51\x20" + b"K" * 32
    txout = (100_000).to_bytes(8, "little") + _compact(len(script_pubkey)) + script_pubkey
    witness = (
        _compact(2)
        + _compact(len(first_item))
        + first_item
        + _compact(len(second_item))
        + second_item
    )
    return (
        version
        + marker_flag
        + _compact(1)
        + txin
        + _compact(1)
        + txout
        + witness
        + (0).to_bytes(4, "little")
    )


def test_witness_mutation_preserves_txid_but_changes_wtxid_and_binding():
    left_raw = witness_transaction(first_item=b"A" * 64)
    right_raw = witness_transaction(first_item=b"B" * 64)
    left = parse_bitcoin_transaction(left_raw)
    right = parse_bitcoin_transaction(right_raw)

    assert left.has_witness and right.has_witness
    assert left.stripped == right.stripped
    assert left.txid == right.txid
    assert left.wtxid != right.wtxid
    assert left.witness_digest != right.witness_digest

    chain = sha256(b"regtest genesis").digest()
    binding = BitcoinAuthorizationBinding.from_raw_transaction(
        left_raw, chain_genesis_hash=chain, authorization_input_index=0
    )
    assert binding.counterproof_txid == left.txid
    assert binding.counterproof_wtxid == left.wtxid
    assert binding.verify_raw_transaction(left_raw)
    assert not binding.verify_raw_transaction(right_raw)


def test_outpoint_uses_rpc_txid_byte_order_and_wire_vout():
    raw = witness_transaction(first_item=b"A")
    parsed = parse_bitcoin_transaction(raw)
    assert parsed.input_outpoints == (bytes(range(32))[::-1] + (3).to_bytes(4, "little"),)


def test_noncanonical_compact_size_and_empty_segwit_witness_are_rejected():
    raw = bytearray(witness_transaction(first_item=b"A"))
    # Replace the canonical one-byte vin count with fd0100.
    malformed = raw[:6] + b"\xfd\x01\x00" + raw[7:]
    with pytest.raises(BitcoinAuthorizationError, match="non-canonical"):
        parse_bitcoin_transaction(bytes(malformed))

    # A marker/flag transaction with zero witness items is superfluous.
    version = (2).to_bytes(4, "little")
    txin = bytes(32) + bytes(4) + b"\x00" + bytes(4)
    txout = (1).to_bytes(8, "little") + b"\x00"
    empty_witness = (
        version
        + b"\x00\x01"
        + b"\x01"
        + txin
        + b"\x01"
        + txout
        + b"\x00"
        + bytes(4)
    )
    with pytest.raises(BitcoinAuthorizationError, match="superfluous"):
        parse_bitcoin_transaction(empty_witness)


def test_empty_and_oversized_transactions_fail_before_parsing():
    with pytest.raises(BitcoinAuthorizationError, match="parser limit"):
        parse_bitcoin_transaction(b"")
    with pytest.raises(BitcoinAuthorizationError, match="parser limit"):
        parse_bitcoin_transaction(bytes(4_000_001))


def test_zero_length_witness_item_is_not_a_superfluous_witness():
    raw = witness_transaction(first_item=b"", second_item=b"")
    parsed = parse_bitcoin_transaction(raw)
    assert parsed.has_witness
    assert parsed.witness_stacks == ((b"", b""),)


def test_unknown_segwit_flag_is_rejected_before_local_core_disagreement():
    raw = bytearray(witness_transaction(first_item=b"A"))
    assert raw[4:6] == b"\x00\x01"
    raw[5] = 2
    with pytest.raises(BitcoinAuthorizationError, match="unsupported SegWit"):
        parse_bitcoin_transaction(bytes(raw))
