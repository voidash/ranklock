from __future__ import annotations

from hashlib import sha256

import pytest

from ranklock.bitcoin_tx import (
    BitcoinTxError,
    OutPoint,
    Transaction,
    TxIn,
    TxOut,
    compact_size,
    taproot_script_path_sighash,
)


def _tagged_hash(tag: str, message: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii")).digest()
    return sha256(tag_hash + tag_hash + message).digest()


def _ser_string(value: bytes) -> bytes:
    return compact_size(len(value)) + value


def test_bip342_sighash_matches_bitcoin_core_v31_1_reference_vector() -> None:
    """Fixed vector independently transcribed from Core's TaprootSignatureMsg.

    The expected digest was generated with Bitcoin Core v31.1's functional-test
    reference construction.  It intentionally does not call RankLock's helper.
    """

    previous_txid = bytes(range(32))
    sequence = 0xFFFFFFFD
    spent_output = TxOut(200_000, b"\x51\x20" + bytes.fromhex("11" * 32))
    output = TxOut(190_000, b"\x51\x20" + bytes.fromhex("22" * 32))
    leaf_script = b"\x20" + bytes.fromhex("33" * 32) + b"\xad\x51"
    tapleaf_hash = _tagged_hash(
        "TapLeaf", b"\xc0" + _ser_string(leaf_script)
    )
    transaction = Transaction(
        version=2,
        inputs=(TxIn(OutPoint(previous_txid, 3), sequence=sequence),),
        outputs=(output,),
        lock_time=17,
    )

    expected = bytes.fromhex(
        "8836c0151fca4b058a72f82aff1ba32ad241262d511d8f180383c97c13b84e97"
    )
    assert tapleaf_hash.hex() == (
        "e92da37e30ad4e2cae1e742a3f4018093f9a154f246e9765860707628d8766f1"
    )
    assert taproot_script_path_sighash(
        transaction,
        input_index=0,
        spent_outputs=(spent_output,),
        tapleaf_hash=tapleaf_hash,
    ) == expected


def test_transaction_parser_rejects_oversized_and_count_bomb_inputs() -> None:
    with pytest.raises(BitcoinTxError, match="size limit"):
        Transaction.parse(bytes(400_001))

    # version + a minimally encoded but policy-impossible input count.  The
    # parser must reject before entering the input loop.
    count_bomb = (2).to_bytes(4, "little", signed=True) + b"\xfd\x01\x10" + bytes(3)
    with pytest.raises(BitcoinTxError, match="input count"):
        Transaction.parse(count_bomb)
