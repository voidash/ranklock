from __future__ import annotations

"""CORE-005 and CORE-009: wrong opening and wrong slot must be rejected.

These are binding properties of the authorization protocol rather than of
Bitcoin consensus: a share opening that does not reconstruct the committed
root, or a policy bound to a different slot, must be refused before anything
is released. Both are checked off-chain, so a live node would add nothing --
Core never sees a malformed opening.
"""

from hashlib import sha256

import numpy as np
import pytest

from ranklock.authorized_labels import LabelCommitmentTree
from ranklock.bip340 import public_key
from ranklock.bitcoin_witness_selection import (
    BitcoinWitnessSelectionError,
    SignedBitcoinWitnessPolicy,
    UnsignedBitcoinWitnessPolicy,
    derive_unsigned_witness_selection,
    selector_validation_tapscript,
    witness_control_hash,
    witness_rules_from_label_pairs,
    witness_script_hash,
)
from ranklock.bn254_real import G1, affine, multiply
from ranklock.committee_authorization import (
    CommitteeAuthorizationError,
    dealer_split_fixture,
)
from ranklock.dfb_real import CoordinateInputEncoding

INPUT_BITS = 8
AUTHORIZER_SECRET = 47
PARTICIPANT_SECRETS = (11, 13, 17)
PLACEHOLDER_SIGNATURE = bytes(64)


def _encoding(bits: int, offset: int) -> CoordinateInputEncoding:
    words = (np.arange(bits * 2, dtype=np.uint64) + np.uint64(offset)).reshape(bits, 2)
    return CoordinateInputEncoding(
        masks=words.copy(), labels=words.copy(), delta=offset + 0xABCDEF
    )


def _tree(slot_id: int) -> LabelCommitmentTree:
    return LabelCommitmentTree.from_input_encodings(
        (_encoding(INPUT_BITS, 7 + slot_id), _encoding(INPUT_BITS, 7000 + slot_id)),
        context_digest=sha256(b"protocol-negatives-context").digest(),
        slot_id=slot_id,
        input_bits=INPUT_BITS,
        program_seed=sha256(b"protocol-negatives-seed").digest(),
    )


def _compact(value: int) -> bytes:
    if value < 0xFD:
        return bytes((value,))
    return b"\xfd" + value.to_bytes(2, "little")


def _raw_tx(items: tuple[bytes, ...]) -> bytes:
    version = (3).to_bytes(4, "little")
    txin = bytes(range(32)) + (1).to_bytes(4, "little") + b"\x00" + bytes.fromhex("fdffffff")
    output_script = b"\x51\x20" + b"O" * 32
    txout = (75_000).to_bytes(8, "little") + _compact(len(output_script)) + output_script
    witness = _compact(len(items)) + b"".join(_compact(len(item)) + item for item in items)
    return version + b"\x00\x01" + b"\x01" + txin + b"\x01" + txout + witness + bytes(4)


def _selected(tree: LabelCommitmentTree, point) -> tuple[bytes, ...]:
    coordinates = affine(point)
    assert coordinates is not None
    values = (int(coordinates[0].n), int(coordinates[1].n))
    return tuple(
        tree.label_pairs[coordinate * INPUT_BITS + bit][(values[coordinate] >> bit) & 1]
        for coordinate in (0, 1)
        for bit in range(INPUT_BITS)
    )


def _policy(tree: LabelCommitmentTree, *, slot_id: int, activation_digest: bytes):
    rules = witness_rules_from_label_pairs(tree.label_pairs, input_bits=INPUT_BITS)
    script = selector_validation_tapscript(
        rules, authorizer_pubkey=public_key(AUTHORIZER_SECRET)
    )
    control = b"\xc0" + sha256(b"protocol-negatives-control").digest()
    unsigned = UnsignedBitcoinWitnessPolicy(
        context_digest=sha256(b"protocol-negatives-context").digest(),
        activation_digest=activation_digest,
        slot_id=slot_id,
        authorization_input_index=0,
        input_bits=INPUT_BITS,
        tapscript_hash=witness_script_hash(script),
        control_block_hash=witness_control_hash(control),
        authorizer_pubkey=public_key(AUTHORIZER_SECRET),
        rules=rules,
    )
    return unsigned, script, control


# --------------------------------------------------------------------------
# CORE-009: wrong slot
# --------------------------------------------------------------------------


def test_a_policy_bound_to_another_slot_cannot_authorize_this_one():
    """CORE-009: the slot id is part of the signed policy body."""

    tree = _tree(0)
    activation_digest = sha256(b"activation").digest()
    unsigned_slot0, _script, _control = _policy(tree, slot_id=0, activation_digest=activation_digest)
    unsigned_slot1, _s1, _c1 = _policy(tree, slot_id=1, activation_digest=activation_digest)

    # Same labels and tapscript, different slot: the encoded body and thus the
    # digest the committee signs must differ.
    assert unsigned_slot0.slot_id != unsigned_slot1.slot_id
    assert unsigned_slot0.encoded != unsigned_slot1.encoded
    assert unsigned_slot0.digest != unsigned_slot1.digest
    assert unsigned_slot0.signing_message != unsigned_slot1.signing_message


def test_slot_id_survives_policy_serialization_round_trip():
    """A parsed policy must not silently lose or coerce its slot binding."""

    tree = _tree(0)
    for slot_id in (0, 1, 2, 4096):
        unsigned, _script, _control = _policy(
            tree, slot_id=slot_id, activation_digest=sha256(b"activation").digest()
        )
        reparsed = UnsignedBitcoinWitnessPolicy.parse(unsigned.encoded)
        assert reparsed.slot_id == slot_id
        assert reparsed == unsigned


def test_a_witness_for_one_slot_does_not_verify_under_another_slots_policy():
    """The label sets are slot-separated, so cross-slot reuse cannot decode."""

    tree0, tree1 = _tree(0), _tree(1)
    point = multiply(G1, 123_456, group="g1")
    unsigned1, script1, control1 = _policy(
        tree1, slot_id=1, activation_digest=sha256(b"activation").digest()
    )
    # Present slot 0's labels against slot 1's policy.
    raw = _raw_tx(_selected(tree0, point) + (PLACEHOLDER_SIGNATURE, script1, control1))
    with pytest.raises(BitcoinWitnessSelectionError, match="neither authorized alternative"):
        derive_unsigned_witness_selection(raw, unsigned=unsigned1)


# --------------------------------------------------------------------------
# CORE-005: wrong sibling / opening
# --------------------------------------------------------------------------


def test_a_share_opening_that_does_not_reconstruct_the_root_is_rejected():
    """CORE-005: an opening must reconstruct the committed share root."""

    tree = _tree(0)
    activation, _guide, participants = dealer_split_fixture(
        tree,
        chain_genesis_hash=sha256(b"genesis").digest(),
        counterproof_txid=sha256(b"txid").digest(),
        artifact_root=sha256(b"artifact").digest(),
        participant_secrets=PARTICIPANT_SECRETS,
        request_authorizer_pubkey=public_key(AUTHORIZER_SECRET),
        rollback_witness_pubkeys=(public_key(307),),
        deterministic_seed=b"protocol-negatives-dealer",
    )
    state = participants[0]

    # share_root commits to the label-share pairs. Corrupting one pair while
    # keeping the committed root must fail reconstruction rather than yield a
    # usable opening.
    corrupted = list(state.label_share_pairs)
    zero, one = corrupted[0]
    corrupted[0] = (bytes([zero[0] ^ 0xFF]) + zero[1:], one)
    with pytest.raises(CommitteeAuthorizationError, match="share root"):
        type(state)(
            context_digest=state.context_digest,
            slot_id=state.slot_id,
            input_bits=state.input_bits,
            participant_index=state.participant_index,
            participant_secret=state.participant_secret,
            program_seed_share=state.program_seed_share,
            label_share_pairs=tuple(corrupted),
            share_root=state.share_root,
        )


def test_each_participant_commits_to_a_distinct_share_root():
    """Openings are participant-scoped, so one opening cannot serve another."""

    tree = _tree(0)
    _activation, _guide, participants = dealer_split_fixture(
        tree,
        chain_genesis_hash=sha256(b"genesis").digest(),
        counterproof_txid=sha256(b"txid").digest(),
        artifact_root=sha256(b"artifact").digest(),
        participant_secrets=PARTICIPANT_SECRETS,
        request_authorizer_pubkey=public_key(AUTHORIZER_SECRET),
        rollback_witness_pubkeys=(public_key(307),),
        deterministic_seed=b"protocol-negatives-dealer",
    )
    roots = [state.share_root for state in participants]
    assert len(set(roots)) == len(roots), "participants must not share an opening root"
