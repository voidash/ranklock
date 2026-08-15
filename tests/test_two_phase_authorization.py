from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import numpy as np
import pytest

from ranklock.authorization_transaction_plan import build_authorization_transaction_plan
from ranklock.authorized_labels import LabelCommitmentTree
from ranklock.bip340 import public_key
from ranklock.bitcoin_authorization import BitcoinAuthorizationBinding, parse_bitcoin_transaction
from ranklock.bitcoin_core_regtest import _serialize_transaction
from ranklock.bitcoin_witness_selection import (
    SignedBitcoinWitnessPolicy,
    UnsignedBitcoinWitnessPolicy,
    selector_validation_tapscript,
    witness_control_hash,
    witness_rules_from_label_pairs,
    witness_script_hash,
)
from ranklock.bn254_real import G1, affine, multiply
from ranklock.bounded_mpc_embryo import slot_descriptor_from_artifact
from ranklock.committee_authorization import dealer_split_fixture, issue_committee_request
from ranklock.dfb_real import CoordinateInputEncoding
from ranklock.durable_slot_ledger import DurableSlotLedger, SlotConflictError
from ranklock.two_phase_authorization import (
    ParticipantSeedResponse,
    ParticipantWitnessShareResponse,
    TwoPhaseAuthorizationError,
    WitnessPreauthorizationRequest,
    issue_witness_preauthorization_request,
    prepare_seed_response,
    prepare_witness_share_response,
    reconstruct_program_seed,
    reconstruct_witness_labels,
)


# The two-phase protocol tests exercise share reconstruction and ledger
# ordering, not consensus signature validity, so a structurally valid
# 64-byte placeholder is sufficient for the witness layout here.
PLACEHOLDER_SIGNATURE = bytes(64)


def _encoding(bits: int, offset: int) -> CoordinateInputEncoding:
    words = (np.arange(bits * 2, dtype=np.uint64) + np.uint64(offset)).reshape(bits, 2)
    return CoordinateInputEncoding(
        masks=words.copy(),
        labels=words.copy(),
        delta=offset + 0xABCDEF123456789,
    )


def _fixture(tmp_path):
    input_bits = 256
    point = multiply(G1, 123_456, group="g1")
    coordinates = affine(point)
    assert coordinates is not None
    context = sha256(b"two-phase/context").digest()
    chain = sha256(b"two-phase/regtest-genesis").digest()
    program_seed = sha256(b"two-phase/program-seed").digest()
    tree = LabelCommitmentTree.from_input_encodings(
        (_encoding(input_bits, 11), _encoding(input_bits, 7000)),
        context_digest=context,
        slot_id=0,
        input_bits=input_bits,
        program_seed=program_seed,
    )
    rules = witness_rules_from_label_pairs(tree.label_pairs, input_bits=input_bits)
    authorizer_secret = 41
    script = selector_validation_tapscript(
        rules, authorizer_pubkey=public_key(authorizer_secret)
    )
    control = b"\xc0" + sha256(b"two-phase/control").digest()
    selected = tuple(
        tree.label_pairs[coordinate * input_bits + bit][
            (int(coordinates[coordinate].n) >> bit) & 1
        ]
        for coordinate in range(2)
        for bit in range(input_bits)
    )
    deposit_txid = sha256(b"two-phase/deposit").digest()
    output_script = b"\x51\x20" + sha256(b"two-phase/output").digest()
    raw = _serialize_transaction(
        previous_txid=deposit_txid,
        previous_vout=0,
        output_value_sat=100_000,
        output_script=output_script,
        witness_stack=selected + (PLACEHOLDER_SIGNATURE, script, control),
    )
    parsed = parse_bitcoin_transaction(raw)
    artifact = b"sealed two-phase program" * 16
    descriptor = slot_descriptor_from_artifact(
        0,
        artifact,
        input_label_commitment=tree.root,
        independence_nonce=b"two-phase-independent-slot",
    )
    participant_secrets = (11, 13, 17)
    activation, guide, participants = dealer_split_fixture(
        tree,
        chain_genesis_hash=chain,
        counterproof_txid=parsed.txid,
        artifact_root=descriptor.artifact_root,
        participant_secrets=participant_secrets,
        request_authorizer_pubkey=public_key(authorizer_secret),
        rollback_witness_pubkeys=(public_key(97),),
        deterministic_seed=b"two-phase-dealer-fixture",
    )
    policy = SignedBitcoinWitnessPolicy.create(
        UnsignedBitcoinWitnessPolicy(
            context_digest=context,
            activation_digest=activation.digest,
            slot_id=0,
            authorization_input_index=0,
            input_bits=input_bits,
            tapscript_hash=witness_script_hash(script),
            control_block_hash=witness_control_hash(control),
            authorizer_pubkey=public_key(authorizer_secret),
            rules=rules,
        ),
        activation=activation,
        participant_secrets=participant_secrets,
    )
    plan = build_authorization_transaction_plan(
        chain_genesis_hash=chain,
        deposit_outpoint=deposit_txid + bytes(4),
        raw_transactions=(raw,),
    )
    preauthorization = issue_witness_preauthorization_request(
        activation,
        plan,
        point=point,
        request_authorizer_secret=authorizer_secret,
    )
    ledgers = tuple(
        DurableSlotLedger(
            tmp_path / f"participant-{index}.sqlite",
            context_digest=context,
            slot_count=1,
        )
        for index in range(len(participants))
    )
    binding = BitcoinAuthorizationBinding.from_raw_transaction(
        raw,
        chain_genesis_hash=chain,
        authorization_input_index=0,
    )
    confirmation = issue_committee_request(
        activation,
        point=point,
        bitcoin_binding=binding,
        request_authorizer_secret=authorizer_secret,
    )
    return {
        "activation": activation,
        "guide": guide,
        "tree": tree,
        "participants": participants,
        "ledgers": ledgers,
        "policy": policy,
        "plan": plan,
        "preauthorization": preauthorization,
        "confirmation": confirmation,
        "raw": raw,
        "script": script,
        "control": control,
        "selected": selected,
        "program_seed": program_seed,
        "point": point,
        "authorizer_secret": authorizer_secret,
    }


def test_two_phase_roundtrip_burns_before_labels_and_releases_seed_only_after_confirmation(tmp_path):
    row = _fixture(tmp_path)
    pre = WitnessPreauthorizationRequest.parse_compact(
        row["preauthorization"].compact_bytes
    )
    assert pre == row["preauthorization"]

    witness_responses = tuple(
        prepare_witness_share_response(
            activation=row["activation"],
            preauthorization=pre,
            plan=row["plan"],
            policy=row["policy"],
            participant=participant,
            ledger=ledger,
        )
        for participant, ledger in zip(row["participants"], row["ledgers"], strict=True)
    )
    assert all(ledger.use(0).state == "burned" for ledger in row["ledgers"])
    assert all(
        not hasattr(response, "program_seed_share") for response in witness_responses
    )
    assert all(
        ParticipantWitnessShareResponse.parse_compact(response.compact_bytes) == response
        for response in witness_responses
    )
    reconstructed = reconstruct_witness_labels(
        activation=row["activation"],
        preauthorization=pre,
        plan=row["plan"],
        policy=row["policy"],
        responses=witness_responses,
    )
    assert reconstructed.witness_stack_items == row["selected"]

    seed_responses = tuple(
        prepare_seed_response(
            activation=row["activation"],
            preauthorization=pre,
            confirmation_request=row["confirmation"],
            raw_transaction=row["raw"],
            plan=row["plan"],
            policy=row["policy"],
            participant=participant,
            ledger=ledger,
        )
        for participant, ledger in zip(row["participants"], row["ledgers"], strict=True)
    )
    assert all(
        ParticipantSeedResponse.parse_compact(response.compact_bytes) == response
        for response in seed_responses
    )
    assert reconstruct_program_seed(
        activation=row["activation"],
        preauthorization=pre,
        confirmation_request=row["confirmation"],
        responses=seed_responses,
    ) == row["program_seed"]

    for ledger in row["ledgers"]:
        ledger.finalize(0, outcome="success")
        assert ledger.use(0).state == "success"
        assert ledger.remaining == 0


def test_exact_phase_one_retry_is_stable_but_another_point_cannot_rebind_slot(tmp_path):
    row = _fixture(tmp_path)
    participant = row["participants"][0]
    ledger = row["ledgers"][0]
    first = prepare_witness_share_response(
        activation=row["activation"],
        preauthorization=row["preauthorization"],
        plan=row["plan"],
        policy=row["policy"],
        participant=participant,
        ledger=ledger,
    )
    replay = prepare_witness_share_response(
        activation=row["activation"],
        preauthorization=row["preauthorization"],
        plan=row["plan"],
        policy=row["policy"],
        participant=participant,
        ledger=ledger,
    )
    assert replay.compact_bytes == first.compact_bytes

    other = issue_witness_preauthorization_request(
        row["activation"],
        row["plan"],
        point=multiply(G1, 654_321, group="g1"),
        request_authorizer_secret=row["authorizer_secret"],
    )
    with pytest.raises((SlotConflictError, TwoPhaseAuthorizationError)):
        prepare_witness_share_response(
            activation=row["activation"],
            preauthorization=other,
            plan=row["plan"],
            policy=row["policy"],
            participant=participant,
            ledger=ledger,
        )
    # CORE-014: an authenticated conflicting binding is terminal, not a
    # recoverable rejection.  Only a validly signed preauthorization gets this
    # far, so a conflict means one one-shot slot was bound to two different
    # transactions; the slot must fail closed permanently.
    conflicted = ledger.use(0)
    assert conflicted.state == "retry-rejected"
    assert conflicted.terminal

    # Even the original, honest request can no longer drive the slot forward.
    with pytest.raises((SlotConflictError, TwoPhaseAuthorizationError)):
        prepare_witness_share_response(
            activation=row["activation"],
            preauthorization=row["preauthorization"],
            plan=row["plan"],
            policy=row["policy"],
            participant=participant,
            ledger=ledger,
        )
    assert ledger.use(0).state == "retry-rejected"
    # The slot never returns to available and the audit chain stays intact.
    assert ledger.remaining == 0
    assert ledger.verify_audit_chain()


def test_seed_share_is_withheld_for_tampered_or_point_mismatched_confirmation(tmp_path):
    row = _fixture(tmp_path)
    participant = row["participants"][0]
    ledger = row["ledgers"][0]
    prepare_witness_share_response(
        activation=row["activation"],
        preauthorization=row["preauthorization"],
        plan=row["plan"],
        policy=row["policy"],
        participant=participant,
        ledger=ledger,
    )

    tampered_items = list(row["selected"])
    zero, one = row["tree"].label_pairs[0]
    tampered_items[0] = one if tampered_items[0] == zero else zero
    tampered_raw = _serialize_transaction(
        previous_txid=parse_bitcoin_transaction(row["raw"]).input_outpoints[0][:32],
        previous_vout=0,
        output_value_sat=parse_bitcoin_transaction(row["raw"]).output_values[0],
        output_script=parse_bitcoin_transaction(row["raw"]).output_scripts[0],
        witness_stack=tuple(tampered_items)
        + (PLACEHOLDER_SIGNATURE, row["script"], row["control"]),
    )
    # Witness mutation preserves txid/stripped plan but selects a different point.
    assert parse_bitcoin_transaction(tampered_raw).txid == parse_bitcoin_transaction(row["raw"]).txid
    with pytest.raises(TwoPhaseAuthorizationError, match="confirmation does not continue"):
        prepare_seed_response(
            activation=row["activation"],
            preauthorization=row["preauthorization"],
            confirmation_request=row["confirmation"],
            raw_transaction=tampered_raw,
            plan=row["plan"],
            policy=row["policy"],
            participant=participant,
            ledger=ledger,
        )

    wrong_confirmation = replace(
        row["confirmation"],
        point_encoding=issue_committee_request(
            row["activation"],
            point=multiply(G1, 777, group="g1"),
            bitcoin_binding=row["confirmation"].bitcoin_binding,
            request_authorizer_secret=row["authorizer_secret"],
        ).point_encoding,
    )
    with pytest.raises(TwoPhaseAuthorizationError, match="confirmation request failed"):
        prepare_seed_response(
            activation=row["activation"],
            preauthorization=row["preauthorization"],
            confirmation_request=wrong_confirmation,
            raw_transaction=row["raw"],
            plan=row["plan"],
            policy=row["policy"],
            participant=participant,
            ledger=ledger,
        )
    assert ledger.use(0).state == "burned"


class _FakeCore:
    def __init__(
        self,
        *,
        raw: bytes,
        chain_genesis_hash: bytes,
        block_hash: str,
        confirmations: int = 6,
    ) -> None:
        self.raw = bytes(raw)
        self.parsed = parse_bitcoin_transaction(raw)
        self.chain_genesis_hash = bytes(chain_genesis_hash)
        self.block_hash = str(block_hash)
        self.confirmations = int(confirmations)
        self.header_calls = 0
        self.change_height_after_first = False

    def call(self, method: str, *params: object) -> object:
        if method == "getblockhash":
            assert params == (0,)
            return self.chain_genesis_hash.hex()
        if method == "getrawtransaction":
            return {
                "hex": self.raw.hex(),
                "txid": self.parsed.txid.hex(),
                "hash": self.parsed.wtxid.hex(),
                "blockhash": self.block_hash,
                "confirmations": self.confirmations,
            }
        if method == "getblockheader":
            self.header_calls += 1
            height = 900
            if self.change_height_after_first and self.header_calls > 1:
                height += 1
            return {"height": height, "confirmations": self.confirmations}
        raise AssertionError(method)


def test_two_phase_sidecar_anchors_phase_one_and_releases_seed_after_stable_core(tmp_path):
    from ranklock.rollback_witness import SqliteRollbackWitness
    from ranklock.two_phase_sidecar import TwoPhaseParticipantSidecar, TwoPhaseSidecarError

    row = _fixture(tmp_path)
    block_hash = "ab" * 32
    witness = SqliteRollbackWitness(tmp_path / "rollback.sqlite", witness_secret=97)
    core = _FakeCore(
        raw=row["raw"],
        chain_genesis_hash=row["plan"].chain_genesis_hash,
        block_hash=block_hash,
    )
    sidecar = TwoPhaseParticipantSidecar(
        activation=row["activation"],
        plan=row["plan"],
        witness_policy=row["policy"],
        participant=row["participants"][0],
        ledger=row["ledgers"][0],
        rollback_witnesses=(witness,),
        bitcoin_core=core,
        minimum_confirmations=6,
    )

    with pytest.raises(TwoPhaseSidecarError, match="phase one"):
        sidecar.issue_seed_share(
            preauthorization=row["preauthorization"],
            confirmation_request=row["confirmation"],
            raw_transaction=row["raw"],
            block_hash=block_hash,
            output_path=tmp_path / "too-early.seed",
        )

    phase_one, phase_one_receipts, created = sidecar.issue_witness_shares(
        preauthorization=row["preauthorization"],
        output_path=tmp_path / "labels.bin",
    )
    assert created and phase_one_receipts[-1].verify()
    assert (tmp_path / "labels.bin").read_bytes() == phase_one.compact_bytes
    assert row["ledgers"][0].use(0).state == "burned"

    seed, observation, terminal_receipts, seed_created = sidecar.issue_seed_share(
        preauthorization=row["preauthorization"],
        confirmation_request=row["confirmation"],
        raw_transaction=row["raw"],
        block_hash=block_hash,
        output_path=tmp_path / "seed.bin",
    )
    assert seed_created and terminal_receipts[-1].verify()
    assert observation.txid == parse_bitcoin_transaction(row["raw"]).txid.hex()
    assert (tmp_path / "seed.bin").read_bytes() == seed.compact_bytes
    assert row["ledgers"][0].use(0).state == "success"

    replay, _observation, _receipts, replay_created = sidecar.issue_seed_share(
        preauthorization=row["preauthorization"],
        confirmation_request=row["confirmation"],
        raw_transaction=row["raw"],
        block_hash=block_hash,
        output_path=tmp_path / "seed.bin",
    )
    assert not replay_created
    assert replay.compact_bytes == seed.compact_bytes


def test_two_phase_sidecar_reorg_race_aborts_without_seed_output(tmp_path):
    from ranklock.rollback_witness import SqliteRollbackWitness
    from ranklock.two_phase_sidecar import TwoPhaseParticipantSidecar, TwoPhaseSidecarError

    row = _fixture(tmp_path)
    block_hash = "cd" * 32
    witness = SqliteRollbackWitness(tmp_path / "rollback-race.sqlite", witness_secret=97)
    core = _FakeCore(
        raw=row["raw"],
        chain_genesis_hash=row["plan"].chain_genesis_hash,
        block_hash=block_hash,
    )
    sidecar = TwoPhaseParticipantSidecar(
        activation=row["activation"],
        plan=row["plan"],
        witness_policy=row["policy"],
        participant=row["participants"][0],
        ledger=row["ledgers"][0],
        rollback_witnesses=(witness,),
        bitcoin_core=core,
        minimum_confirmations=6,
    )
    sidecar.issue_witness_shares(
        preauthorization=row["preauthorization"],
        output_path=tmp_path / "labels-race.bin",
    )
    core.change_height_after_first = True
    output = tmp_path / "must-not-exist.seed"
    with pytest.raises(TwoPhaseSidecarError, match="inclusion changed"):
        sidecar.issue_seed_share(
            preauthorization=row["preauthorization"],
            confirmation_request=row["confirmation"],
            raw_transaction=row["raw"],
            block_hash=block_hash,
            output_path=output,
        )
    assert not output.exists()
    assert row["ledgers"][0].use(0).state == "abort"
