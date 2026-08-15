from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import numpy as np
import pytest

from ranklock.authorized_labels import LabelCommitmentTree
from ranklock.bip340 import public_key, sign
from ranklock.bitcoin_authorization import BitcoinAuthorizationBinding, parse_bitcoin_transaction
from ranklock.bn254_real import G1, affine, multiply
from ranklock.bounded_mpc_embryo import slot_descriptor_from_artifact
from ranklock.committee_authorization import (
    CommitteeAuthorizationError,
    CommitteeAuthorizationRequest,
    CommitteeLabelGuide,
    ParticipantShareResponse,
    SignedCommitteeActivation,
    dealer_split_fixture,
    issue_committee_request,
    issue_participant_response,
    reconstruct_committee_release,
)
from ranklock.dfb_real import CoordinateInputEncoding
from ranklock.durable_slot_ledger import DurableSlotLedger, SlotConflictError


def _compact(value: int) -> bytes:
    assert value < 0xFD
    return bytes((value,))


def _raw_tx(witness_tag: bytes) -> bytes:
    version = (3).to_bytes(4, "little")
    previous = bytes(range(32)) + (7).to_bytes(4, "little")
    txin = previous + b"\x00" + bytes.fromhex("fdffffff")
    script = b"\x51\x20" + b"O" * 32
    txout = (80_000).to_bytes(8, "little") + _compact(len(script)) + script
    witness = _compact(2) + _compact(len(witness_tag)) + witness_tag + b"\x01\x51"
    return (
        version
        + b"\x00\x01"
        + b"\x01"
        + txin
        + b"\x01"
        + txout
        + witness
        + bytes(4)
    )


def _encoding(bits: int, offset: int) -> CoordinateInputEncoding:
    words = (np.arange(bits * 2, dtype=np.uint64) + np.uint64(offset)).reshape(bits, 2)
    return CoordinateInputEncoding(
        masks=words.copy(),
        labels=words.copy(),
        delta=0xD6E8FEB86659FD93A5A3564E27F88691 ^ offset,
    )


def _fixture(tmp_path, *, bits: int = 8, participants: int = 3):
    raw = _raw_tx(b"witness-A" * 8)
    parsed = parse_bitcoin_transaction(raw)
    chain = sha256(b"regtest genesis").digest()
    context = sha256(b"ranklock committee context" + parsed.txid).digest()
    tree = LabelCommitmentTree.from_input_encodings(
        (_encoding(bits, 100), _encoding(bits, 1000)),
        context_digest=context,
        slot_id=0,
        input_bits=bits,
        program_seed=sha256(b"program seed").digest(),
    )
    artifact = b"sealed-slot-fixture" * 41
    descriptor = slot_descriptor_from_artifact(
        0,
        artifact,
        input_label_commitment=tree.root,
        independence_nonce=b"committee-independent-slot-0",
    )
    participant_secrets = tuple(101 + 2 * index for index in range(participants))
    authorizer_secret = 211
    activation, guide, states = dealer_split_fixture(
        tree,
        chain_genesis_hash=chain,
        counterproof_txid=parsed.txid,
        artifact_root=descriptor.artifact_root,
        participant_secrets=participant_secrets,
        request_authorizer_pubkey=public_key(authorizer_secret),
        rollback_witness_pubkeys=(public_key(307),),
        deterministic_seed=b"ranklock-v025-dealer-test-seed",
    )
    binding = BitcoinAuthorizationBinding.from_raw_transaction(
        raw,
        chain_genesis_hash=chain,
        authorization_input_index=0,
    )
    point = multiply(G1, 123456789, group="g1")
    request = issue_committee_request(
        activation,
        point=point,
        bitcoin_binding=binding,
        request_authorizer_secret=authorizer_secret,
    )
    ledgers = tuple(
        DurableSlotLedger(
            tmp_path / f"participant-{index}.sqlite",
            context_digest=context,
            slot_count=1,
        )
        for index in range(participants)
    )
    return {
        "raw": raw,
        "parsed": parsed,
        "chain": chain,
        "context": context,
        "tree": tree,
        "artifact": artifact,
        "descriptor": descriptor,
        "authorizer_secret": authorizer_secret,
        "activation": activation,
        "guide": guide,
        "states": states,
        "binding": binding,
        "point": point,
        "request": request,
        "ledgers": ledgers,
    }


def _responses(fixture):
    return tuple(
        issue_participant_response(
            activation=fixture["activation"],
            request=fixture["request"],
            observed_raw_transaction=fixture["raw"],
            participant=state,
            guide=fixture["guide"],
            ledger=ledger,
        )
        for state, ledger in zip(fixture["states"], fixture["ledgers"], strict=True)
    )


def test_activation_guide_request_and_responses_are_canonical(tmp_path):
    fixture = _fixture(tmp_path)
    activation = fixture["activation"]
    guide = fixture["guide"]
    request = fixture["request"]
    assert activation.verify()
    assert SignedCommitteeActivation.parse_compact(activation.encoded) == activation
    assert CommitteeLabelGuide.parse_compact(guide.compact_bytes) == guide
    assert CommitteeAuthorizationRequest.parse_compact(request.compact_bytes) == request

    responses = _responses(fixture)
    for response in responses:
        assert response.verify_signature()
        assert ParticipantShareResponse.parse_compact(response.compact_bytes) == response
    reconstructed = reconstruct_committee_release(
        activation=activation,
        guide=guide,
        request=request,
        responses=responses,
    )
    assert reconstructed.program_seed == fixture["tree"].program_seed

    # The aggregate selected labels are exactly the labels selected from the
    # trusted tree, while no participant response contains an aggregate label.
    coordinates = affine(fixture["point"])
    assert coordinates is not None
    x, y = coordinates
    values = (int(x.n), int(y.n))
    expected = []
    for flat_index, pair in enumerate(fixture["tree"].label_pairs):
        coordinate, bit = divmod(flat_index, fixture["tree"].input_bits)
        expected.append(pair[(values[coordinate] >> bit) & 1])
    assert [opening.label for opening in reconstructed.openings] == expected

    # The evaluator does not need the 32 KiB private guide: every signed
    # participant response carries the selected aggregate sibling hashes and
    # the final root is reconstructed from the activated 32-byte root.
    public_reconstruction = reconstruct_committee_release(
        activation=activation,
        request=request,
        responses=responses,
    )
    assert public_reconstruction == reconstructed
    assert responses[0].compact_bytes
    assert len(responses[0].compact_bytes) == 174 + 2 * fixture["tree"].input_bits * 80 + 64


def test_n_minus_one_corrupt_responses_are_structurally_insufficient(tmp_path):
    fixture = _fixture(tmp_path)
    responses = _responses(fixture)
    with pytest.raises(CommitteeAuthorizationError, match="all n-of-n"):
        reconstruct_committee_release(
            activation=fixture["activation"],
            guide=fixture["guide"],
            request=fixture["request"],
            responses=responses[:-1],
        )

    # For any desired 128-bit aggregate, the missing XOR share can be chosen to
    # make the same corrupt view reconstruct to that aggregate.
    corrupt = [response.openings[0].selected_share for response in responses[:-1]]
    corrupt_xor = bytes(
        value
        for value in (
            __import__("functools").reduce(
                lambda left, right: bytes(a ^ b for a, b in zip(left, right, strict=True)),
                corrupt,
            )
        )
    )
    targets = (bytes(16), bytes([0xA5]) * 16)
    missing = tuple(bytes(a ^ b for a, b in zip(corrupt_xor, target, strict=True)) for target in targets)
    assert missing[0] != missing[1]


def test_exact_replay_after_restart_returns_identical_signed_share(tmp_path):
    fixture = _fixture(tmp_path, participants=2)
    first = issue_participant_response(
        activation=fixture["activation"],
        request=fixture["request"],
        observed_raw_transaction=fixture["raw"],
        participant=fixture["states"][0],
        guide=fixture["guide"],
        ledger=fixture["ledgers"][0],
    )
    reopened = DurableSlotLedger(
        fixture["ledgers"][0].path,
        context_digest=fixture["context"],
        slot_count=1,
    )
    second = issue_participant_response(
        activation=fixture["activation"],
        request=fixture["request"],
        observed_raw_transaction=fixture["raw"],
        participant=fixture["states"][0],
        guide=fixture["guide"],
        ledger=reopened,
    )
    assert first.compact_bytes == second.compact_bytes
    assert reopened.use(0).state == "success"
    assert reopened.verify_audit_chain()


def test_conflicting_witness_on_fork_is_rejected_even_with_same_txid(tmp_path):
    fixture = _fixture(tmp_path, participants=2)
    first = issue_participant_response(
        activation=fixture["activation"],
        request=fixture["request"],
        observed_raw_transaction=fixture["raw"],
        participant=fixture["states"][0],
        guide=fixture["guide"],
        ledger=fixture["ledgers"][0],
    )
    assert first.verify_signature()

    fork_raw = _raw_tx(b"witness-B" * 8)
    fork_parsed = parse_bitcoin_transaction(fork_raw)
    assert fork_parsed.txid == fixture["parsed"].txid
    assert fork_parsed.wtxid != fixture["parsed"].wtxid
    fork_binding = BitcoinAuthorizationBinding.from_raw_transaction(
        fork_raw,
        chain_genesis_hash=fixture["chain"],
        authorization_input_index=0,
    )
    fork_request = issue_committee_request(
        fixture["activation"],
        point=multiply(G1, 987654321, group="g1"),
        bitcoin_binding=fork_binding,
        request_authorizer_secret=fixture["authorizer_secret"],
    )
    with pytest.raises(SlotConflictError):
        issue_participant_response(
            activation=fixture["activation"],
            request=fork_request,
            observed_raw_transaction=fork_raw,
            participant=fixture["states"][0],
            guide=fixture["guide"],
            ledger=fixture["ledgers"][0],
        )
    assert fixture["ledgers"][0].use(0).chain_binding_digest == fixture["binding"].digest


def test_outsider_tamper_does_not_burn_but_signed_malformed_point_does(tmp_path):
    fixture = _fixture(tmp_path, participants=2)
    forged = replace(fixture["request"], request_signature=bytes(64))
    with pytest.raises(CommitteeAuthorizationError, match="request"):
        issue_participant_response(
            activation=fixture["activation"],
            request=forged,
            observed_raw_transaction=fixture["raw"],
            participant=fixture["states"][0],
            guide=fixture["guide"],
            ledger=fixture["ledgers"][0],
        )
    assert fixture["ledgers"][0].remaining == 1

    placeholder = CommitteeAuthorizationRequest(
        context_digest=fixture["context"],
        activation_digest=fixture["activation"].digest,
        slot_id=0,
        point_encoding=bytes([0xFF]) * 32,
        bitcoin_binding=fixture["binding"],
        request_authorizer_pubkey=public_key(fixture["authorizer_secret"]),
        request_signature=bytes(64),
    )
    malformed = replace(
        placeholder,
        request_signature=sign(placeholder.signing_message, fixture["authorizer_secret"]),
    )
    with pytest.raises(CommitteeAuthorizationError, match="point"):
        issue_participant_response(
            activation=fixture["activation"],
            request=malformed,
            observed_raw_transaction=fixture["raw"],
            participant=fixture["states"][0],
            guide=fixture["guide"],
            ledger=fixture["ledgers"][0],
        )
    assert fixture["ledgers"][0].use(0).state == "malformed"
    with pytest.raises(CommitteeAuthorizationError, match="previously terminated"):
        issue_participant_response(
            activation=fixture["activation"],
            request=malformed,
            observed_raw_transaction=fixture["raw"],
            participant=fixture["states"][0],
            guide=fixture["guide"],
            ledger=fixture["ledgers"][0],
        )


def test_tampered_participant_share_or_signature_is_rejected(tmp_path):
    fixture = _fixture(tmp_path)
    responses = list(_responses(fixture))
    first_opening = responses[0].openings[0]
    responses[0] = replace(
        responses[0],
        openings=(replace(first_opening, selected_share=bytes(16)),) + responses[0].openings[1:],
    )
    with pytest.raises(CommitteeAuthorizationError, match="participant response"):
        reconstruct_committee_release(
            activation=fixture["activation"],
            guide=fixture["guide"],
            request=fixture["request"],
            responses=responses,
        )
