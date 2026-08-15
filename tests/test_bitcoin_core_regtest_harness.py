from __future__ import annotations

import pytest

from ranklock.bitcoin_core_regtest import (
    EXPECTED_CORE_RELEASE,
    EXPECTED_CORE_VERSION,
    INPUT_BITS,
    BitcoinCoreRegtestError,
    _encoding,
    _selector_material,
    _serialize_transaction,
    _taproot_script_output,
    _tree_selector_material,
    run_bitcoin_core_regtest,
)
from ranklock.authorized_labels import LabelCommitmentTree
from ranklock.bitcoin_authorization import parse_bitcoin_transaction
from ranklock.bitcoin_witness_selection import selector_validation_tapscript
from ranklock.bn254_real import G1, multiply


def test_regtest_builder_emits_canonical_full_width_taproot_witness():
    point = multiply(G1, 123456789, group="g1")
    rules, selected = _selector_material(point, slot_id=0)
    assert len(rules) == len(selected) == 2 * INPUT_BITS == 512
    assert all(len(item) == 64 for item in selected)
    script = selector_validation_tapscript(rules)
    script_pubkey, control, address = _taproot_script_output(script, internal_secret=0x12345)
    assert script_pubkey[:2] == b"\x51\x20"
    assert len(control) == 33 and control[0] & 0xFE == 0xC0
    assert address.startswith("bcrt1p")

    raw = _serialize_transaction(
        previous_txid=bytes.fromhex("11" * 32),
        previous_vout=2,
        output_value_sat=900_000,
        output_script=b"\x51\x20" + bytes(32),
        witness_stack=selected + (script, control),
    )
    parsed = parse_bitcoin_transaction(raw)
    assert len(parsed.witness_stacks[0]) == 514
    assert parsed.witness_stacks[0][-2:] == (script, control)
    assert parsed.has_witness


def test_selector_namespaces_are_slot_separated_and_high_bits_zero():
    point = multiply(G1, 123456789, group="g1")
    rules0, selected0 = _selector_material(point, slot_id=0)
    rules1, selected1 = _selector_material(point, slot_id=1)
    assert tuple(rule.encoded for rule in rules0) != tuple(rule.encoded for rule in rules1)
    assert selected0 != selected1
    # Canonical BN254 coordinates are < 2^254, so bits 254 and 255 select zero.
    for coordinate in (0, 1):
        base = coordinate * INPUT_BITS
        assert rules0[base + 254].zero_hash != rules0[base + 254].one_hash
        assert rules0[base + 255].zero_hash != rules0[base + 255].one_hash
        assert selected0[base + 254] != selected0[base + 255]  # domain-separated zero items


def test_real_regtest_selector_uses_activated_16_byte_dfb_labels():
    context = bytes.fromhex("42" * 32)
    tree = LabelCommitmentTree.from_input_encodings(
        (_encoding(INPUT_BITS, 100), _encoding(INPUT_BITS, 1000)),
        context_digest=context,
        slot_id=0,
        input_bits=INPUT_BITS,
        program_seed=bytes.fromhex("24" * 32),
    )
    point = multiply(G1, 123456789, group="g1")
    rules, selected = _tree_selector_material(tree, point)
    assert len(rules) == len(selected) == 512
    assert all(len(item) == 16 for item in selected)
    assert all(item in pair for item, pair in zip(selected, tree.label_pairs, strict=True))
    script = selector_validation_tapscript(rules)
    _script_pubkey, control, _address = _taproot_script_output(
        script, internal_secret=0x12345
    )
    raw = _serialize_transaction(
        previous_txid=bytes.fromhex("12" * 32),
        previous_vout=0,
        output_value_sat=100_000,
        output_script=b"\x51\x20" + bytes(32),
        witness_stack=selected + (script, control),
    )
    parsed = parse_bitcoin_transaction(raw)
    assert parsed.witness_stacks[0][:-2] == selected


def test_missing_bitcoind_fails_explicitly(tmp_path):
    with pytest.raises(BitcoinCoreRegtestError, match="not installed"):
        run_bitcoin_core_regtest(
            bitcoind=tmp_path / "definitely-missing-bitcoind",
            working_directory=tmp_path / "node",
        )


def test_release_harness_is_pinned_to_current_core_31_1_release():
    assert EXPECTED_CORE_RELEASE == "31.1"
    assert EXPECTED_CORE_VERSION == 310100
