from __future__ import annotations

from hashlib import sha256

import numpy as np
import pytest

from ranklock.authorized_labels import LabelCommitmentTree
from ranklock.bip340 import public_key, sign
from ranklock.bitcoin_authorization import BitcoinAuthorizationBinding, parse_bitcoin_transaction
from ranklock.bitcoin_witness_selection import (
    BitcoinWitnessSelectionError,
    SignedBitcoinWitnessPolicy,
    UnsignedBitcoinWitnessPolicy,
    WitnessItemRule,
    derive_witness_selection,
    selector_validation_tapscript,
    verify_request_matches_witness,
    witness_control_hash,
    witness_script_hash,
)
from ranklock.bn254_real import FIELD_MODULUS, G1, affine, compress_g1, multiply
from ranklock.bounded_mpc_embryo import slot_descriptor_from_artifact
from ranklock.committee_authorization import dealer_split_fixture, issue_committee_request
from ranklock.dfb_real import CoordinateInputEncoding


def _compact(value: int) -> bytes:
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    raise AssertionError("fixture vector is unexpectedly large")


def _encoding(bits: int, offset: int) -> CoordinateInputEncoding:
    words = (np.arange(bits * 2, dtype=np.uint64) + np.uint64(offset)).reshape(bits, 2)
    return CoordinateInputEncoding(
        masks=words.copy(), labels=words.copy(), delta=offset + 0xABCDEF123456789
    )


def _selector_material(point):
    coordinates = affine(point)
    assert coordinates is not None
    input_bits = FIELD_MODULUS.bit_length()
    rules: list[WitnessItemRule] = []
    selected: list[bytes] = []
    alternatives: list[tuple[bytes, bytes]] = []
    for coordinate, value in enumerate(int(item.n) for item in coordinates):
        for bit in range(input_bits):
            suffix = bytes((coordinate,)) + bit.to_bytes(2, "big")
            zero = b"ranklock/selector/zero/" + suffix
            one = b"ranklock/selector/one/" + suffix
            alternatives.append((zero, one))
            rules.append(
                WitnessItemRule.selector(
                    coordinate=coordinate,
                    bit=bit,
                    zero_item=zero,
                    one_item=one,
                )
            )
            selected.append(one if (value >> bit) & 1 else zero)
    tapscript = b"\x51"
    control = b"\xc0" + b"T" * 32
    return input_bits, tuple(rules), tuple(selected), tuple(alternatives), tapscript, control


def _raw_tx(items: tuple[bytes, ...]) -> bytes:
    version = (3).to_bytes(4, "little")
    txin = bytes(range(32)) + (1).to_bytes(4, "little") + b"\x00" + bytes.fromhex("fdffffff")
    output_script = b"\x51\x20" + b"O" * 32
    txout = (75_000).to_bytes(8, "little") + _compact(len(output_script)) + output_script
    witness = _compact(len(items)) + b"".join(_compact(len(item)) + item for item in items)
    return version + b"\x00\x01" + b"\x01" + txin + b"\x01" + txout + witness + bytes(4)


def _fixture():
    point = multiply(G1, 123_456, group="g1")
    input_bits, rules, selected, alternatives, tapscript, control = _selector_material(point)
    raw = _raw_tx(selected + (tapscript, control))
    parsed = parse_bitcoin_transaction(raw)
    chain = sha256(b"witness-policy-regtest").digest()
    context = sha256(b"witness-policy-context").digest()
    tree = LabelCommitmentTree.from_input_encodings(
        (_encoding(input_bits, 7), _encoding(input_bits, 7000)),
        context_digest=context,
        slot_id=0,
        input_bits=input_bits,
        program_seed=sha256(b"program seed").digest(),
    )
    artifact = b"sealed program" * 16
    descriptor = slot_descriptor_from_artifact(
        0,
        artifact,
        input_label_commitment=tree.root,
        independence_nonce=b"witness-policy-independent-slot",
    )
    authorizer_secret = 47
    participant_secrets = (11, 13, 17)
    activation, _guide, _participants = dealer_split_fixture(
        tree,
        chain_genesis_hash=chain,
        counterproof_txid=parsed.txid,
        artifact_root=descriptor.artifact_root,
        participant_secrets=participant_secrets,
        request_authorizer_pubkey=public_key(authorizer_secret),
        rollback_witness_pubkeys=(public_key(307),),
        deterministic_seed=b"witness-policy-dealer-fixture",
    )
    binding = BitcoinAuthorizationBinding.from_raw_transaction(
        raw,
        chain_genesis_hash=chain,
        authorization_input_index=0,
    )
    request = issue_committee_request(
        activation,
        point=point,
        bitcoin_binding=binding,
        request_authorizer_secret=authorizer_secret,
    )
    unsigned = UnsignedBitcoinWitnessPolicy(
        context_digest=context,
        activation_digest=activation.digest,
        slot_id=0,
        authorization_input_index=0,
        input_bits=input_bits,
        tapscript_hash=witness_script_hash(tapscript),
        control_block_hash=witness_control_hash(control),
        rules=rules,
    )
    policy = SignedBitcoinWitnessPolicy.create(
        unsigned,
        activation=activation,
        participant_secrets=participant_secrets,
    )
    return {
        "activation": activation,
        "request": request,
        "policy": policy,
        "raw": raw,
        "point": point,
        "selected": selected,
        "alternatives": alternatives,
        "tapscript": tapscript,
        "control": control,
        "participant_secrets": participant_secrets,
        "authorizer_secret": authorizer_secret,
    }


def test_policy_round_trip_and_witness_derives_exact_requested_point():
    row = _fixture()
    policy = SignedBitcoinWitnessPolicy.parse_compact(row["policy"].compact_bytes)
    assert policy == row["policy"]
    assert policy.verify(row["activation"])

    selection = verify_request_matches_witness(
        row["request"],
        raw_transaction=row["raw"],
        policy=policy,
        activation=row["activation"],
    )
    assert selection.point_encoding == compress_g1(row["point"])
    assert len(selection.selected_bits) == 2 * FIELD_MODULUS.bit_length()
    assert selection.transaction.witness_stacks[0][-2:] == (
        row["tapscript"],
        row["control"],
    )


def test_signed_offchain_request_cannot_choose_point_different_from_bitcoin_witness():
    row = _fixture()
    wrong_request = issue_committee_request(
        row["activation"],
        point=multiply(G1, 654_321, group="g1"),
        bitcoin_binding=row["request"].bitcoin_binding,
        request_authorizer_secret=row["authorizer_secret"],
    )
    assert wrong_request.verify(row["activation"])
    with pytest.raises(BitcoinWitnessSelectionError, match="off-chain request point"):
        verify_request_matches_witness(
            wrong_request,
            raw_transaction=row["raw"],
            policy=row["policy"],
            activation=row["activation"],
        )


def test_unauthorized_selector_item_and_wrong_control_block_are_rejected():
    row = _fixture()
    changed = list(row["selected"])
    changed[0] = b"not one of the signed alternatives"
    bad_selector = _raw_tx(tuple(changed) + (row["tapscript"], row["control"]))
    with pytest.raises(BitcoinWitnessSelectionError, match="neither authorized alternative"):
        derive_witness_selection(
            bad_selector,
            policy=row["policy"],
            activation=row["activation"],
        )

    bad_control = _raw_tx(
        tuple(row["selected"]) + (row["tapscript"], b"\xc0" + b"X" * 32)
    )
    with pytest.raises(BitcoinWitnessSelectionError, match="control block"):
        derive_witness_selection(
            bad_control,
            policy=row["policy"],
            activation=row["activation"],
        )


def test_policy_cannot_redirect_selection_to_another_transaction_input():
    row = _fixture()
    unsigned = row["policy"].unsigned
    redirected = UnsignedBitcoinWitnessPolicy(
        context_digest=unsigned.context_digest,
        activation_digest=unsigned.activation_digest,
        slot_id=unsigned.slot_id,
        authorization_input_index=1,
        input_bits=unsigned.input_bits,
        tapscript_hash=unsigned.tapscript_hash,
        control_block_hash=unsigned.control_block_hash,
        rules=unsigned.rules,
    )
    signatures = tuple(
        sign(redirected.signing_message, secret)
        for secret in row["participant_secrets"]
    )
    policy = SignedBitcoinWitnessPolicy(redirected, signatures)
    assert policy.verify(row["activation"])
    with pytest.raises(BitcoinWitnessSelectionError, match="different authorization inputs"):
        verify_request_matches_witness(
            row["request"],
            raw_transaction=row["raw"],
            policy=policy,
            activation=row["activation"],
        )


def test_selector_rules_must_use_canonical_coordinate_major_order():
    row = _fixture()
    unsigned = row["policy"].unsigned
    with pytest.raises(BitcoinWitnessSelectionError, match="canonical coordinate-major"):
        UnsignedBitcoinWitnessPolicy(
            context_digest=unsigned.context_digest,
            activation_digest=unsigned.activation_digest,
            slot_id=unsigned.slot_id,
            authorization_input_index=unsigned.authorization_input_index,
            input_bits=unsigned.input_bits,
            tapscript_hash=unsigned.tapscript_hash,
            control_block_hash=unsigned.control_block_hash,
            rules=tuple(reversed(unsigned.rules)),
        )


def test_annex_and_non_tapscript_leaf_are_rejected():
    row = _fixture()
    annexed = _raw_tx(
        tuple(row["selected"])
        + (row["tapscript"], row["control"], b"\x50annex")
    )
    with pytest.raises(BitcoinWitnessSelectionError, match="annex"):
        derive_witness_selection(
            annexed,
            policy=row["policy"],
            activation=row["activation"],
        )

    wrong_leaf = _raw_tx(
        tuple(row["selected"]) + (row["tapscript"], b"\x80" + b"T" * 32)
    )
    # The signed control-block commitment fails before the leaf-version check.
    with pytest.raises(BitcoinWitnessSelectionError, match="control block"):
        derive_witness_selection(
            wrong_leaf,
            policy=row["policy"],
            activation=row["activation"],
        )


def test_independent_selector_tapscript_stack_model():
    from ranklock.bitcoin_witness_selection import execute_selector_tapscript_model

    row = _fixture()
    rules = row["policy"].unsigned.rules
    selected = tuple(row["selected"])
    assert len(rules) == len(selected) > 1
    script = selector_validation_tapscript(rules)
    assert execute_selector_tapscript_model(script, selected)
    assert not execute_selector_tapscript_model(script, selected[:-1])
    assert not execute_selector_tapscript_model(script, selected + (b"extra",))

    wrong = list(selected)
    wrong[len(wrong) // 2] = b"not-an-authorized-selector"
    assert not execute_selector_tapscript_model(script, tuple(wrong))

    mutated = bytearray(script)
    mutated[len(mutated) // 2] = 0x6A  # OP_RETURN is outside the allowed subset.
    assert not execute_selector_tapscript_model(bytes(mutated), selected)
