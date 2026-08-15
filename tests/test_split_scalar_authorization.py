from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import os

import numpy as np
import pytest

from ranklock.authorization_transaction_plan import build_authorization_transaction_plan
from ranklock.authorized_labels import EvaluationContext, LabelCommitmentTree
from ranklock.babe_positive_lock import deterministic_fixture, setup_positive_lock
from ranklock.bip340 import public_key
from ranklock.bitcoin_authorization import parse_bitcoin_transaction
from ranklock.bitcoin_witness_selection import (
    UnsignedBitcoinWitnessPolicy,
    WitnessItemRule,
    selector_validation_tapscript,
    witness_control_hash,
    witness_script_hash,
)
from ranklock.bn254_real import G1, affine, compress_g1, multiply
from ranklock.bounded_mpc_embryo import (
    UnsignedBoundedEmbryoManifest,
    sign_manifest_fixture,
    slot_descriptor_from_artifact,
)
from ranklock.dfb_real import CoordinateInputEncoding
from ranklock.durable_slot_ledger import DurableSlotLedger
from ranklock.embryo_mask_fusion import FusedRetainedObject
from ranklock.rollback_witness import SqliteRollbackWitness
from ranklock.split_scalar_authorization import (
    SignedSplitScalarWitnessPolicy,
    SplitScalarAuthorizationError,
    SplitScalarParticipantReleaseSidecar,
    SplitScalarWitnessPolicySet,
    derive_split_scalar_witness_selection,
)
from ranklock.split_scalar_lock import (
    SignedSplitScalarBundle,
    SplitScalarContribution,
    UnsignedSplitScalarBundle,
)


INPUT_BITS = 256


def _compact(value: int) -> bytes:
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    raise AssertionError("test vector too large")


def _encoding(bits: int, offset: int) -> CoordinateInputEncoding:
    words = (np.arange(bits * 2, dtype=np.uint64) + np.uint64(offset)).reshape(bits, 2)
    return CoordinateInputEncoding(
        masks=words.copy(),
        labels=words.copy(),
        delta=0xD6E8FEB86659FD93A5A3564E27F88691 ^ offset,
    )


def _selected_items(tree: LabelCommitmentTree, point: object) -> tuple[bytes, ...]:
    coordinates = affine(point)  # type: ignore[arg-type]
    assert coordinates is not None
    values = tuple(int(item.n) for item in coordinates)
    result = []
    for flat_index, pair in enumerate(tree.label_pairs):
        coordinate, bit = divmod(flat_index, tree.input_bits)
        result.append(pair[(values[coordinate] >> bit) & 1])
    return tuple(result)



def _common_selector_material(point: object) -> tuple[
    tuple[WitnessItemRule, ...],
    tuple[bytes, ...],
    tuple[tuple[bytes, bytes], ...],
]:
    coordinates = affine(point)  # type: ignore[arg-type]
    assert coordinates is not None
    values = tuple(int(item.n) for item in coordinates)
    rules: list[WitnessItemRule] = []
    selected: list[bytes] = []
    alternatives: list[tuple[bytes, bytes]] = []
    for coordinate in (0, 1):
        for bit in range(INPUT_BITS):
            suffix = bytes((coordinate,)) + bit.to_bytes(2, "big")
            zero = b"RLS0" + suffix + sha256(b"split-selector-zero" + suffix).digest()
            one = b"RLS1" + suffix + sha256(b"split-selector-one" + suffix).digest()
            alternatives.append((zero, one))
            rules.append(
                WitnessItemRule.selector(
                    coordinate=coordinate,
                    bit=bit,
                    zero_item=zero,
                    one_item=one,
                )
            )
            selected.append((zero, one)[(values[coordinate] >> bit) & 1])
    return tuple(rules), tuple(selected), tuple(alternatives)


def _select_common_items(
    alternatives: tuple[tuple[bytes, bytes], ...], point: object
) -> tuple[bytes, ...]:
    coordinates = affine(point)  # type: ignore[arg-type]
    assert coordinates is not None
    values = tuple(int(item.n) for item in coordinates)
    result: list[bytes] = []
    for flat_index, pair in enumerate(alternatives):
        coordinate, bit = divmod(flat_index, INPUT_BITS)
        result.append(pair[(values[coordinate] >> bit) & 1])
    return tuple(result)

# The split-scalar tests cover per-participant policy binding and release
# ordering, not consensus signature validity, so a structurally valid
# 64-byte placeholder is sufficient for the witness layout here.
PLACEHOLDER_SIGNATURE = bytes(64)


def _raw_tx(
    *,
    previous_txid: bytes,
    previous_vout: int,
    witness_items: tuple[bytes, ...],
    output_script: bytes,
    output_value: int,
) -> bytes:
    witness = _compact(len(witness_items)) + b"".join(
        _compact(len(item)) + item for item in witness_items
    )
    return (
        (3).to_bytes(4, "little")
        + b"\x00\x01"
        + b"\x01"
        + bytes(previous_txid)[::-1]
        + int(previous_vout).to_bytes(4, "little")
        + b"\x00"
        + bytes.fromhex("fdffffff")
        + b"\x01"
        + int(output_value).to_bytes(8, "little")
        + _compact(len(output_script))
        + bytes(output_script)
        + witness
        + bytes(4)
    )


class FakeCore:
    def __init__(
        self,
        raw: bytes,
        *,
        chain_genesis: bytes,
        block_hash: str,
        confirmations: int = 6,
        replacement_after_first_read: bytes | None = None,
    ) -> None:
        self.raw = bytes(raw)
        self.chain_genesis = bytes(chain_genesis)
        self.block_hash = block_hash
        self.confirmations = confirmations
        self.replacement_after_first_read = replacement_after_first_read
        self.raw_reads = 0

    def call(self, method: str, *params: object) -> object:
        if method == "getblockhash":
            assert params == (0,)
            return self.chain_genesis.hex()
        if method == "getrawtransaction":
            self.raw_reads += 1
            raw = (
                self.replacement_after_first_read
                if self.replacement_after_first_read is not None and self.raw_reads > 1
                else self.raw
            )
            parsed = parse_bitcoin_transaction(raw)
            return {
                "hex": raw.hex(),
                "txid": parsed.txid.hex(),
                "hash": parsed.wtxid.hex(),
                "blockhash": self.block_hash,
                "confirmations": self.confirmations,
            }
        if method == "getblockheader":
            return {"height": 1234, "confirmations": self.confirmations}
        raise AssertionError(method)


def _fixture(tmp_path):
    participant_secrets = (101, 103)
    scalar_shares = (41, 73)
    manifest_secrets = (151, 157)
    required_manifest_pubkeys = tuple(sorted(public_key(value) for value in manifest_secrets))
    authorizer_secret = participant_secrets[0]
    chain = sha256(b"split-scalar regtest genesis").digest()

    point = multiply(G1, 777, group="g1")
    rules, selected, selector_alternatives = _common_selector_material(point)
    tapscript = selector_validation_tapscript(
        rules, authorizer_pubkey=public_key(authorizer_secret)
    )
    control = b"\xc0" + b"I" * 32
    continuation_script = b"\x51\x20" + sha256(b"continuation").digest()
    final_script = b"\x51\x20" + sha256(b"final").digest()
    deposit_txid = sha256(b"split-scalar-deposit").digest()
    raw0 = _raw_tx(
        previous_txid=deposit_txid,
        previous_vout=2,
        witness_items=selected + (PLACEHOLDER_SIGNATURE, tapscript, control),
        output_script=continuation_script,
        output_value=90_000,
    )
    txid0 = parse_bitcoin_transaction(raw0).txid
    raw1 = _raw_tx(
        previous_txid=txid0,
        previous_vout=0,
        witness_items=selected + (PLACEHOLDER_SIGNATURE, tapscript, control),
        output_script=final_script,
        output_value=80_000,
    )
    plan = build_authorization_transaction_plan(
        chain_genesis_hash=chain,
        deposit_outpoint=deposit_txid + (2).to_bytes(4, "little"),
        raw_transactions=(raw0, raw1),
    )
    vk, public_inputs, _proof = deterministic_fixture(
        public_inputs=(17,), context=b"split-scalar authorization fixture"
    )
    context = EvaluationContext(
        chain_genesis_hash=chain,
        program_id=sha256(b"program").digest(),
        verifier_key_digest=vk.digest,
        deposit_outpoint=plan.deposit_outpoint,
        game_index=7,
        operator_index=2,
        counterproof_txid=plan.digest,
        epoch=12,
        deadline_height=900_144,
    )
    trees = tuple(
        LabelCommitmentTree.from_input_encodings(
            (_encoding(INPUT_BITS, 100 + slot * 100_000), _encoding(INPUT_BITS, 10_000 + slot * 100_000)),
            context_digest=context.digest,
            slot_id=slot,
            input_bits=INPUT_BITS,
            program_seed=sha256(b"split scalar seed" + bytes((slot,))).digest(),
        )
        for slot in range(2)
    )
    payloads = (sha256(b"payload0").digest(), sha256(b"payload1").digest())
    locks = tuple(
        setup_positive_lock(
            vk,
            public_inputs,
            payloads[index],
            scale=scalar_shares[index],
            session_context=b"split-scalar authorization fixture",
        )
        for index in range(2)
    )
    slot_artifacts = (b"sealed-slot-zero" * 31, b"sealed-slot-one" * 31)
    descriptors = tuple(
        slot_descriptor_from_artifact(
            slot,
            slot_artifacts[slot],
            input_label_commitment=trees[slot].root,
            independence_nonce=b"split scalar sidecar" + bytes((slot,)),
        )
        for slot in range(2)
    )
    unsigned_manifest = UnsignedBoundedEmbryoManifest(
        context_digest=context.digest,
        generator_code_hash=sha256(b"generator").digest(),
        transcript_digest=sha256(b"transcript").digest(),
        positive_lock=locks[0],
        slots=descriptors,
        contributor_pubkeys=required_manifest_pubkeys,
    )
    manifest = sign_manifest_fixture(unsigned_manifest, manifest_secrets)
    retained = FusedRetainedObject(manifest=manifest, slots=slot_artifacts)
    retained_raw = retained.encoded

    contribution0 = SplitScalarContribution.create(
        participant_index=0,
        participant_secret=participant_secrets[0],
        retained_object_digest=sha256(retained_raw).digest(),
        retained_object_bytes=len(retained_raw),
        positive_lock=locks[0],
        preimage_hash=sha256(payloads[0]).digest(),
        scale=scalar_shares[0],
        vk=vk,
        nonce_namespace_base=0,
    )
    contribution1 = SplitScalarContribution.create(
        participant_index=1,
        participant_secret=participant_secrets[1],
        retained_object_digest=sha256(b"participant-1-retained").digest(),
        retained_object_bytes=1_044_952,
        positive_lock=locks[1],
        preimage_hash=sha256(payloads[1]).digest(),
        scale=scalar_shares[1],
        vk=vk,
        nonce_namespace_base=2,
    )
    unsigned_bundle = UnsignedSplitScalarBundle(
        context.digest, (contribution0, contribution1)
    )
    bundle = SignedSplitScalarBundle.create(
        unsigned_bundle, participant_secrets=participant_secrets
    )
    unsigned_policy = UnsignedBitcoinWitnessPolicy(
        context_digest=context.digest,
        activation_digest=bundle.digest,
        slot_id=0,
        authorization_input_index=0,
        input_bits=INPUT_BITS,
        tapscript_hash=witness_script_hash(tapscript),
        control_block_hash=witness_control_hash(control),
        authorizer_pubkey=public_key(authorizer_secret),
        rules=rules,
    )
    policies = tuple(
        SignedSplitScalarWitnessPolicy.create(
            unsigned_policy,
            bundle=bundle,
            plan=plan,
            participant_index=index,
            participant_secret=participant_secrets[index],
            rollback_witness_pubkeys=(public_key(191),),
        )
        for index in range(len(participant_secrets))
    )
    policy_set = SplitScalarWitnessPolicySet.assemble(
        policies, bundle=bundle, plan=plan
    )
    policy = policy_set.policy_for(0)
    ledger = DurableSlotLedger(
        tmp_path / "split-scalar-ledger.sqlite",
        context_digest=context.digest,
        slot_count=2,
    )
    rollback = SqliteRollbackWitness(
        tmp_path / "split-scalar-rollback.sqlite", witness_secret=191
    )
    block_hash = "ab" * 32
    return {
        "participant_secret": authorizer_secret,
        "required_manifest_pubkeys": required_manifest_pubkeys,
        "retained_raw": retained_raw,
        "bundle": bundle,
        "context": context,
        "plan": plan,
        "tree": trees[0],
        "policy": policy,
        "policy_set": policy_set,
        "selector_alternatives": selector_alternatives,
        "participant_secrets": participant_secrets,
        "ledger": ledger,
        "rollback": rollback,
        "raw": raw0,
        "point": point,
        "block_hash": block_hash,
        "chain": chain,
        "tapscript": tapscript,
        "control": control,
    }


def _service(fixture, core):
    return SplitScalarParticipantReleaseSidecar(
        bundle=fixture["bundle"],
        participant_index=0,
        retained_object_bytes=fixture["retained_raw"],
        required_manifest_pubkeys=fixture["required_manifest_pubkeys"],
        context=fixture["context"],
        plan=fixture["plan"],
        witness_policy_set=fixture["policy_set"],
        tree=fixture["tree"],
        participant_secret=fixture["participant_secret"],
        ledger=fixture["ledger"],
        rollback_witnesses=(fixture["rollback"],),
        bitcoin_core=core,
        minimum_confirmations=6,
    )


def test_split_scalar_policy_roundtrip_and_exact_witness_selection(tmp_path):
    fixture = _fixture(tmp_path)
    policy = fixture["policy"]
    assert SignedSplitScalarWitnessPolicy.parse_compact(policy.compact_bytes) == policy
    policy_set = fixture["policy_set"]
    assert SplitScalarWitnessPolicySet.parse_compact(policy_set.compact_bytes) == policy_set
    assert policy_set.verify(bundle=fixture["bundle"], plan=fixture["plan"])
    assert policy.verify(bundle=fixture["bundle"], plan=fixture["plan"])
    selection = derive_split_scalar_witness_selection(
        fixture["raw"],
        policy=policy,
        bundle=fixture["bundle"],
        plan=fixture["plan"],
    )
    assert selection.point_encoding == compress_g1(fixture["point"])

    tampered = replace(policy, participant_signature=bytes(64))
    assert not tampered.verify(bundle=fixture["bundle"], plan=fixture["plan"])


def test_split_scalar_sidecar_releases_once_and_replays_identically(tmp_path):
    fixture = _fixture(tmp_path)
    core = FakeCore(
        fixture["raw"],
        chain_genesis=fixture["chain"],
        block_hash=fixture["block_hash"],
    )
    service = _service(fixture, core)
    output = tmp_path / "participant-release.bin"
    release, observation, receipts, created = service.issue(
        raw_transaction=fixture["raw"],
        block_hash=fixture["block_hash"],
        output_path=output,
    )
    assert created
    assert output.read_bytes() == release.compact_bytes
    assert os.stat(output).st_mode & 0o777 == 0o600
    assert observation.wtxid == parse_bitcoin_transaction(fixture["raw"]).wtxid.hex()
    assert release.authorization_txid == parse_bitcoin_transaction(fixture["raw"]).wtxid
    assert release.reconstruct_root() == fixture["tree"].root
    assert release.verify_signature(public_key(fixture["participant_secret"]))
    assert len(receipts) == 1 and receipts[0].verify()
    assert fixture["ledger"].use(0).state == "success"

    replay, _observation, replay_receipts, created_again = service.issue(
        raw_transaction=fixture["raw"],
        block_hash=fixture["block_hash"],
        output_path=output,
    )
    assert not created_again
    assert replay.compact_bytes == release.compact_bytes
    assert replay_receipts[0].generation >= receipts[0].generation
    assert fixture["ledger"].verify_audit_chain()


def test_alternate_valid_point_same_txid_is_permanently_rejected(tmp_path):
    fixture = _fixture(tmp_path)
    first_core = FakeCore(
        fixture["raw"],
        chain_genesis=fixture["chain"],
        block_hash=fixture["block_hash"],
    )
    service = _service(fixture, first_core)
    service.issue(
        raw_transaction=fixture["raw"],
        block_hash=fixture["block_hash"],
        output_path=tmp_path / "first.bin",
    )

    alternate_point = multiply(G1, 779, group="g1")
    alternate_items = _select_common_items(
        fixture["selector_alternatives"], alternate_point
    )
    parsed = parse_bitcoin_transaction(fixture["raw"])
    alternate_raw = _raw_tx(
        previous_txid=parsed.input_outpoints[0][:32],
        previous_vout=int.from_bytes(parsed.input_outpoints[0][32:], "little"),
        witness_items=alternate_items
        + (PLACEHOLDER_SIGNATURE, fixture["tapscript"], fixture["control"]),
        output_script=parsed.output_scripts[0],
        output_value=parsed.output_values[0],
    )
    alternate_parsed = parse_bitcoin_transaction(alternate_raw)
    assert alternate_parsed.txid == parsed.txid
    assert alternate_parsed.wtxid != parsed.wtxid
    alternate_service = _service(
        fixture,
        FakeCore(
            alternate_raw,
            chain_genesis=fixture["chain"],
            block_hash="cd" * 32,
        ),
    )
    with pytest.raises(SplitScalarAuthorizationError, match="bound|recheck"):
        alternate_service.issue(
            raw_transaction=alternate_raw,
            block_hash="cd" * 32,
            output_path=tmp_path / "alternate.bin",
        )
    assert not (tmp_path / "alternate.bin").exists()
    assert fixture["ledger"].use(0).state == "success"


def test_core_change_after_burn_aborts_without_emitting_release(tmp_path):
    fixture = _fixture(tmp_path)
    parsed = parse_bitcoin_transaction(fixture["raw"])
    replacement = fixture["raw"].replace(
        parsed.output_values[0].to_bytes(8, "little"),
        (parsed.output_values[0] + 1).to_bytes(8, "little"),
        1,
    )
    core = FakeCore(
        fixture["raw"],
        chain_genesis=fixture["chain"],
        block_hash=fixture["block_hash"],
        replacement_after_first_read=replacement,
    )
    service = _service(fixture, core)
    output = tmp_path / "must-not-exist.bin"
    with pytest.raises(SplitScalarAuthorizationError, match="failed|recheck|raw transaction"):
        service.issue(
            raw_transaction=fixture["raw"],
            block_hash=fixture["block_hash"],
            output_path=output,
        )
    assert not output.exists()
    assert fixture["ledger"].use(0).state == "abort"
    assert fixture["ledger"].verify_audit_chain()


def test_policy_set_rejects_participant_specific_selector_rules(tmp_path):
    fixture = _fixture(tmp_path)
    base = fixture["policy_set"].unsigned
    changed_rules = list(base.rules)
    first = changed_rules[0]
    changed_rules[0] = WitnessItemRule.selector(
        coordinate=first.coordinate,
        bit=first.bit,
        zero_item=b"different-zero-selector",
        one_item=b"different-one-selector",
    )
    divergent_unsigned = UnsignedBitcoinWitnessPolicy(
        context_digest=base.context_digest,
        activation_digest=base.activation_digest,
        slot_id=base.slot_id,
        authorization_input_index=base.authorization_input_index,
        input_bits=base.input_bits,
        tapscript_hash=base.tapscript_hash,
        control_block_hash=base.control_block_hash,
        authorizer_pubkey=base.authorizer_pubkey,
        rules=tuple(changed_rules),
    )
    divergent = SignedSplitScalarWitnessPolicy.create(
        divergent_unsigned,
        bundle=fixture["bundle"],
        plan=fixture["plan"],
        participant_index=1,
        participant_secret=fixture["participant_secrets"][1],
        rollback_witness_pubkeys=(public_key(191),),
    )
    with pytest.raises(SplitScalarAuthorizationError, match="common selector policy"):
        SplitScalarWitnessPolicySet((fixture["policy"], divergent))

    depth_divergent = replace(
        fixture["policy_set"].policies[1],
        minimum_confirmations=fixture["policy"].minimum_confirmations + 1,
    )
    with pytest.raises(SplitScalarAuthorizationError, match="confirmation-depth policy"):
        SplitScalarWitnessPolicySet((fixture["policy"], depth_divergent))


def test_policy_or_retained_object_mismatch_fails_at_startup(tmp_path):
    fixture = _fixture(tmp_path)
    core = FakeCore(
        fixture["raw"],
        chain_genesis=fixture["chain"],
        block_hash=fixture["block_hash"],
    )
    bad_policy = replace(fixture["policy"], participant_signature=bytes(64))
    with pytest.raises(SplitScalarAuthorizationError, match="policy"):
        SplitScalarParticipantReleaseSidecar(
            bundle=fixture["bundle"],
            participant_index=0,
            retained_object_bytes=fixture["retained_raw"],
            required_manifest_pubkeys=fixture["required_manifest_pubkeys"],
            context=fixture["context"],
            plan=fixture["plan"],
            witness_policy_set=SplitScalarWitnessPolicySet((bad_policy, fixture["policy_set"].policies[1])),
            tree=fixture["tree"],
            participant_secret=fixture["participant_secret"],
            ledger=fixture["ledger"],
            rollback_witnesses=(fixture["rollback"],),
            bitcoin_core=core,
            minimum_confirmations=6,
        )
    with pytest.raises(SplitScalarAuthorizationError, match="signed split-scalar minimum"):
        SplitScalarParticipantReleaseSidecar(
            bundle=fixture["bundle"],
            participant_index=0,
            retained_object_bytes=fixture["retained_raw"],
            required_manifest_pubkeys=fixture["required_manifest_pubkeys"],
            context=fixture["context"],
            plan=fixture["plan"],
            witness_policy_set=fixture["policy_set"],
            tree=fixture["tree"],
            participant_secret=fixture["participant_secret"],
            ledger=fixture["ledger"],
            rollback_witnesses=(fixture["rollback"],),
            bitcoin_core=core,
            minimum_confirmations=fixture["policy"].minimum_confirmations - 1,
        )
    with pytest.raises(SplitScalarAuthorizationError, match="retained object"):
        SplitScalarParticipantReleaseSidecar(
            bundle=fixture["bundle"],
            participant_index=0,
            retained_object_bytes=fixture["retained_raw"][:-1] + b"X",
            required_manifest_pubkeys=fixture["required_manifest_pubkeys"],
            context=fixture["context"],
            plan=fixture["plan"],
            witness_policy_set=fixture["policy_set"],
            tree=fixture["tree"],
            participant_secret=fixture["participant_secret"],
            ledger=fixture["ledger"],
            rollback_witnesses=(fixture["rollback"],),
            bitcoin_core=core,
            minimum_confirmations=6,
        )


def test_split_scalar_sidecar_rejects_unpinned_rollback_witness_identity(tmp_path):
    fixture = _fixture(tmp_path)
    substituted = SqliteRollbackWitness(
        tmp_path / "split-substituted-rollback.sqlite", witness_secret=193
    )
    core = FakeCore(
        fixture["raw"],
        chain_genesis=fixture["chain"],
        block_hash=fixture["block_hash"],
    )
    with pytest.raises(SplitScalarAuthorizationError, match="differ from the signed activation"):
        SplitScalarParticipantReleaseSidecar(
            bundle=fixture["bundle"],
            participant_index=0,
            retained_object_bytes=fixture["retained_raw"],
            required_manifest_pubkeys=fixture["required_manifest_pubkeys"],
            context=fixture["context"],
            plan=fixture["plan"],
            witness_policy_set=fixture["policy_set"],
            tree=fixture["tree"],
            participant_secret=fixture["participant_secret"],
            ledger=fixture["ledger"],
            rollback_witnesses=(substituted,),
            bitcoin_core=core,
            minimum_confirmations=6,
        )
    assert fixture["ledger"].remaining == 2
