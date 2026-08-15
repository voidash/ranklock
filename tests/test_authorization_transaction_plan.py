from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock.authorization_transaction_plan import (
    AuthorizationTransactionPlan,
    AuthorizationTransactionPlanError,
    build_authorization_transaction_plan,
)
from ranklock.bitcoin_core_regtest import _serialize_transaction
from ranklock.bitcoin_authorization import parse_bitcoin_transaction


def _tx(previous_txid: bytes, *, witness: bytes, output_script: bytes) -> bytes:
    return _serialize_transaction(
        previous_txid=previous_txid,
        previous_vout=0,
        output_value_sat=100_000,
        output_script=output_script,
        witness_stack=(witness,),
    )


def _fixture():
    genesis = bytes.fromhex("aa" * 32)
    deposit_txid = bytes.fromhex("11" * 32)
    continuation = b"\x51\x20" + bytes.fromhex("22" * 32)
    final = b"\x51\x20" + bytes.fromhex("33" * 32)
    raw0 = _tx(deposit_txid, witness=b"slot-0", output_script=continuation)
    txid0 = parse_bitcoin_transaction(raw0).txid
    raw1 = _tx(txid0, witness=b"slot-1", output_script=final)
    plan = build_authorization_transaction_plan(
        chain_genesis_hash=genesis,
        deposit_outpoint=deposit_txid + bytes(4),
        raw_transactions=(raw0, raw1),
    )
    return plan, raw0, raw1


def test_plan_roundtrip_binds_stripped_templates_and_chain():
    plan, raw0, raw1 = _fixture()
    assert len(plan.templates) == 2
    assert plan.templates[1].authorization_outpoint == plan.templates[0].txid + bytes(4)
    assert plan.verify_transactions((raw0, raw1))
    assert AuthorizationTransactionPlan.parse(plan.encoded) == plan
    assert AuthorizationTransactionPlan.parse(plan.encoded).digest == plan.digest


def test_adaptive_witness_preserves_plan_but_stripped_mutation_fails():
    plan, raw0, raw1 = _fixture()
    parsed0 = parse_bitcoin_transaction(raw0)
    adaptive0 = _serialize_transaction(
        previous_txid=bytes.fromhex("11" * 32),
        previous_vout=0,
        output_value_sat=100_000,
        output_script=parsed0.output_scripts[0],
        witness_stack=(b"another adaptive witness",),
    )
    assert parse_bitcoin_transaction(adaptive0).txid == parsed0.txid
    assert plan.verify_raw_transaction(0, adaptive0)

    changed_output = _serialize_transaction(
        previous_txid=bytes.fromhex("11" * 32),
        previous_vout=0,
        output_value_sat=99_999,
        output_script=parsed0.output_scripts[0],
        witness_stack=(b"another adaptive witness",),
    )
    assert not plan.verify_raw_transaction(0, changed_output)
    assert not plan.verify_transactions((changed_output, raw1))


def test_reordered_or_redirected_chain_is_rejected():
    plan, raw0, raw1 = _fixture()
    with pytest.raises(AuthorizationTransactionPlanError):
        AuthorizationTransactionPlan(
            plan.chain_genesis_hash,
            plan.deposit_outpoint,
            tuple(reversed(plan.templates)),
        )
    redirected = replace(
        plan.templates[1], authorization_outpoint=bytes.fromhex("44" * 32) + bytes(4)
    )
    with pytest.raises(AuthorizationTransactionPlanError, match="committed chain"):
        AuthorizationTransactionPlan(
            plan.chain_genesis_hash,
            plan.deposit_outpoint,
            (plan.templates[0], redirected),
        )


def test_noncanonical_plan_encoding_is_rejected():
    plan, *_ = _fixture()
    with pytest.raises(AuthorizationTransactionPlanError):
        AuthorizationTransactionPlan.parse(plan.encoded + b"\x00")
