from __future__ import annotations

"""The authorization carrier must bind its transaction at consensus level.

Before v0.25.2 the selector tapscript validated label preimages and nothing
else.  Those labels become public the instant the authorization transaction is
broadcast, so anyone who saw them could re-spend the same input into a
transaction with different outputs or fee.  This was verified to be genuinely
exploitable against real Bitcoin Core: the redirected transaction confirmed.

The fix prefixes the script with ``OP_CHECKSIGVERIFY`` against the request
authorizer's key, over the BIP341 script-path sighash -- which commits to
version, locktime, every input outpoint and sequence, every spent amount and
scriptPubKey, and every output (and therefore the fee).

The Core-backed tests below skip when no ``bitcoind`` is available so the
package suite still runs on machines without one.  They are *correctness*
regressions, not qualification evidence: qualification additionally requires
the hash-pinned Core 31.1 release (CORE-001).
"""

from hashlib import sha256
import os
import shutil
import tempfile
from pathlib import Path

import pytest

from ranklock.bip340 import public_key, verify
from ranklock.bitcoin_core_regtest import _serialize_transaction, _taproot_script_output
from ranklock.bitcoin_witness_selection import (
    BitcoinWitnessSelectionError,
    WitnessItemRule,
    authorization_sighash,
    selector_validation_tapscript,
    sign_authorization_witness,
)
from ranklock.predicate_locked_hashlock import NUMS_INTERNAL_KEY
from ranklock.regtest_node import RegtestNode

AUTHORIZER_SECRET = 211
AUTHORIZER_PUBKEY = public_key(AUTHORIZER_SECRET)


def _selector_material(bits: int = 4):
    rules, selected = [], []
    for coordinate in (0, 1):
        for bit in range(bits):
            header = bytes((coordinate,)) + bit.to_bytes(2, "big")
            zero = b"Z" + header + sha256(b"zero" + header).digest()[:12]
            one = b"O" + header + sha256(b"one" + header).digest()[:12]
            rules.append(
                WitnessItemRule.selector(
                    coordinate=coordinate, bit=bit, zero_item=zero, one_item=one
                )
            )
            selected.append(zero)
    return tuple(rules), tuple(selected)


def _bitcoind_or_skip() -> str:
    candidate = os.environ.get("RANKLOCK_BITCOIND") or shutil.which("bitcoind")
    if candidate is None:
        pytest.skip("no bitcoind available for the Core-backed carrier tests")
    return candidate


# --------------------------------------------------------------------------
# Pure unit properties (no Bitcoin Core required)
# --------------------------------------------------------------------------


def test_script_requires_a_signature_before_any_label_check():
    rules, _selected = _selector_material()
    script = selector_validation_tapscript(rules, authorizer_pubkey=AUTHORIZER_PUBKEY)
    # PUSH32 <pubkey> OP_CHECKSIGVERIFY, before any OP_SHA256 label work.
    assert script[:1] == b"\x20"
    assert script[1:33] == AUTHORIZER_PUBKEY
    assert script[33:34] == b"\xad"
    assert script.index(b"\xa8") > 33


def test_script_rejects_a_non_xonly_authorizer_key():
    rules, _selected = _selector_material()
    with pytest.raises(BitcoinWitnessSelectionError, match="32-byte"):
        selector_validation_tapscript(rules, authorizer_pubkey=b"\x01" * 31)


def test_sighash_changes_when_any_committed_field_changes():
    """Every field the carrier must pin has to move the signed message."""

    rules, selected = _selector_material()
    script = selector_validation_tapscript(rules, authorizer_pubkey=AUTHORIZER_PUBKEY)
    spent_script, _control, _address = _taproot_script_output(script)
    base_kwargs = dict(
        previous_txid=bytes.fromhex("11" * 32),
        previous_vout=0,
        output_value_sat=90_000,
        output_script=b"\x51\x20" + b"O" * 32,
        witness_stack=selected + (bytes(64), script, b"\xc0" + b"T" * 32),
    )
    raw = _serialize_transaction(**base_kwargs)

    def sighash_for(raw_tx: bytes, *, value: int = 100_000, spk: bytes = spent_script) -> bytes:
        return authorization_sighash(
            raw_tx,
            authorization_input_index=0,
            spent_values_sat=(value,),
            spent_scripts=(spk,),
            tapscript=script,
        )

    baseline = sighash_for(raw)

    # A different destination must change the signed message.
    redirected = _serialize_transaction(
        **{**base_kwargs, "output_script": b"\x51\x20" + b"X" * 32}
    )
    assert sighash_for(redirected) != baseline

    # A different fee (via output value) must change the signed message.
    refeed = _serialize_transaction(**{**base_kwargs, "output_value_sat": 70_000})
    assert sighash_for(refeed) != baseline

    # A different input must change the signed message.
    reinput = _serialize_transaction(
        **{**base_kwargs, "previous_txid": bytes.fromhex("22" * 32)}
    )
    assert sighash_for(reinput) != baseline

    # The spent amount is committed even though it is not in the tx bytes,
    # so a lie about the input's value cannot be signed over.
    assert sighash_for(raw, value=999_999) != baseline


def test_signature_verifies_against_the_exact_transaction_only():
    rules, selected = _selector_material()
    script = selector_validation_tapscript(rules, authorizer_pubkey=AUTHORIZER_PUBKEY)
    spent_script, _control, _address = _taproot_script_output(script)
    kwargs = dict(
        previous_txid=bytes.fromhex("33" * 32),
        previous_vout=1,
        output_value_sat=80_000,
        output_script=b"\x51\x20" + b"P" * 32,
        witness_stack=selected + (bytes(64), script, b"\xc0" + b"T" * 32),
    )
    raw = _serialize_transaction(**kwargs)
    signature = sign_authorization_witness(
        raw,
        authorization_input_index=0,
        spent_values_sat=(100_000,),
        spent_scripts=(spent_script,),
        tapscript=script,
        request_authorizer_secret=AUTHORIZER_SECRET,
    )
    message = authorization_sighash(
        raw,
        authorization_input_index=0,
        spent_values_sat=(100_000,),
        spent_scripts=(spent_script,),
        tapscript=script,
    )
    assert verify(message, AUTHORIZER_PUBKEY, signature)

    mutated = _serialize_transaction(**{**kwargs, "output_value_sat": 60_000})
    mutated_message = authorization_sighash(
        mutated,
        authorization_input_index=0,
        spent_values_sat=(100_000,),
        spent_scripts=(spent_script,),
        tapscript=script,
    )
    assert not verify(mutated_message, AUTHORIZER_PUBKEY, signature)


def test_carrier_output_uses_the_unspendable_nums_internal_key():
    """A derivable internal key would leave a key-path spend bypassing the script."""

    rules, _selected = _selector_material()
    script = selector_validation_tapscript(rules, authorizer_pubkey=AUTHORIZER_PUBKEY)
    _script_pubkey, control, _address = _taproot_script_output(script)
    assert control[1:33] == NUMS_INTERNAL_KEY


# --------------------------------------------------------------------------
# Consensus-backed properties (require a bitcoind binary)
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def carrier_scenario():
    """Fund one carrier output and hand back everything needed to spend it."""

    bitcoind = _bitcoind_or_skip()
    root = Path(tempfile.mkdtemp(prefix="ranklock-carrier-test-"))
    node = RegtestNode.create(bitcoind=bitcoind, root=root)
    rpc = node.start()
    try:
        rpc.call("createwallet", "carrier")
        mining = str(rpc.call("getnewaddress", "", "bech32m"))
        rpc.call("generatetoaddress", 101, mining)

        rules, selected = _selector_material()
        script = selector_validation_tapscript(rules, authorizer_pubkey=AUTHORIZER_PUBKEY)
        script_pubkey, control, address = _taproot_script_output(script)

        funding_txid = str(rpc.call("sendtoaddress", address, 0.01))
        rpc.call("generatetoaddress", 1, mining)
        funding = rpc.call("getrawtransaction", funding_txid, True)
        vout = next(
            row
            for row in funding["vout"]
            if bytes.fromhex(str(row["scriptPubKey"]["hex"])) == script_pubkey
        )

        def new_script() -> bytes:
            address = str(rpc.call("getnewaddress", "", "bech32m"))
            return bytes.fromhex(str(rpc.call("getaddressinfo", address)["scriptPubKey"]))

        yield {
            "rpc": rpc,
            "script": script,
            "control": control,
            "script_pubkey": script_pubkey,
            "selected": selected,
            "funding_txid": funding_txid,
            "vout_n": int(vout["n"]),
            "vout_value": int(round(float(vout["value"]) * 100_000_000)),
            "honest_script": new_script(),
            "attacker_script": new_script(),
        }
    finally:
        node.stop()
        shutil.rmtree(root, ignore_errors=True)


def _build(scenario, *, value: int, script_pubkey: bytes, signature: bytes | None):
    witness = scenario["selected"]
    if signature is not None:
        witness = witness + (signature,)
    return _serialize_transaction(
        previous_txid=bytes.fromhex(scenario["funding_txid"]),
        previous_vout=scenario["vout_n"],
        output_value_sat=value,
        output_script=script_pubkey,
        witness_stack=witness + (scenario["script"], scenario["control"]),
    )


def _honest_signature(scenario, *, value: int, script_pubkey: bytes) -> bytes:
    unsigned = _build(scenario, value=value, script_pubkey=script_pubkey, signature=bytes(64))
    return sign_authorization_witness(
        unsigned,
        authorization_input_index=0,
        spent_values_sat=(scenario["vout_value"],),
        spent_scripts=(scenario["script_pubkey"],),
        tapscript=scenario["script"],
        request_authorizer_secret=AUTHORIZER_SECRET,
    )


def test_core_accepts_the_honestly_signed_carrier(carrier_scenario):
    scenario = carrier_scenario
    value = scenario["vout_value"] - 5_000
    signature = _honest_signature(scenario, value=value, script_pubkey=scenario["honest_script"])
    raw = _build(
        scenario, value=value, script_pubkey=scenario["honest_script"], signature=signature
    )
    result = scenario["rpc"].call("testmempoolaccept", [raw.hex()])[0]
    assert result.get("allowed") is True, result.get("reject-reason")


def test_core_rejects_output_redirection_reusing_revealed_labels(carrier_scenario):
    """The exact attack that previously confirmed on chain."""

    scenario = carrier_scenario
    value = scenario["vout_value"] - 5_000
    signature = _honest_signature(scenario, value=value, script_pubkey=scenario["honest_script"])
    redirected = _build(
        scenario, value=value, script_pubkey=scenario["attacker_script"], signature=signature
    )
    result = scenario["rpc"].call("testmempoolaccept", [redirected.hex()])[0]
    assert result.get("allowed") is False
    assert "Invalid Schnorr signature" in str(result.get("reject-reason"))


def test_core_rejects_fee_mutation_reusing_revealed_labels(carrier_scenario):
    scenario = carrier_scenario
    value = scenario["vout_value"] - 5_000
    signature = _honest_signature(scenario, value=value, script_pubkey=scenario["honest_script"])
    inflated_fee = _build(
        scenario,
        value=value - 20_000,
        script_pubkey=scenario["honest_script"],
        signature=signature,
    )
    result = scenario["rpc"].call("testmempoolaccept", [inflated_fee.hex()])[0]
    assert result.get("allowed") is False
    assert "Invalid Schnorr signature" in str(result.get("reject-reason"))


def test_core_rejects_the_pre_fix_unsigned_witness_shape(carrier_scenario):
    """A witness with no signature item is the shape that used to succeed."""

    scenario = carrier_scenario
    unsigned = _build(
        scenario,
        value=scenario["vout_value"] - 5_000,
        script_pubkey=scenario["attacker_script"],
        signature=None,
    )
    result = scenario["rpc"].call("testmempoolaccept", [unsigned.hex()])[0]
    assert result.get("allowed") is False


def test_signing_over_an_annex_bearing_input_is_refused():
    """BIP341 annex: refuse rather than sign a message the network won't check.

    Found by adversarial review. `authorization_sighash` did not pass an annex
    through to the sighash helper, so an annex-bearing input was signed over
    the no-annex message -- a signature that looks valid but can never be
    spent. The parser already rejects annexes, so refusing here keeps the
    signer and the parser in agreement.
    """

    from ranklock.bip340 import public_key
    from ranklock.bitcoin_core_regtest import _serialize_transaction, _taproot_script_output
    from ranklock.bitcoin_witness_selection import (
        BitcoinWitnessSelectionError,
        WitnessItemRule,
        authorization_sighash,
        selector_validation_tapscript,
    )

    rule = WitnessItemRule.selector(coordinate=0, bit=0, zero_item=b"z", one_item=b"o")
    script = selector_validation_tapscript((rule,), authorizer_pubkey=public_key(1))
    spent_script, control, _address = _taproot_script_output(script)

    def raw_with(witness_stack):
        return _serialize_transaction(
            previous_txid=bytes.fromhex("11" * 32),
            previous_vout=0,
            output_value_sat=90_000,
            output_script=b"\x51\x20" + b"Z" * 32,
            witness_stack=witness_stack,
        )

    kwargs = dict(
        authorization_input_index=0,
        spent_values_sat=(100_000,),
        spent_scripts=(spent_script,),
        tapscript=script,
    )

    # Without an annex the helper still works.
    honest = raw_with((b"z", bytes(64), script, control))
    assert len(authorization_sighash(honest, **kwargs)) == 32

    # With one it must refuse rather than sign the wrong message.
    annexed = raw_with((b"z", bytes(64), script, control, b"\x50annex"))
    with pytest.raises(BitcoinWitnessSelectionError, match="annex"):
        authorization_sighash(annexed, **kwargs)
