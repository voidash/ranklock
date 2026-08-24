from __future__ import annotations

"""Generate the full-size v0.25 split-scalar safety qualification.

This deterministic conformance fixture combines two independently generated
RankLock artifacts under scalar shares r_0 and r_1.  Participant 0 reuses the
full-size public v0.25 committee fixture; participant 1 is generated here with
DFB nonce namespaces 2 and 3.  The aggregate outputs are checked against
[r_0+r_1]A for A_1 and for an A_2 selected after the aggregate first output.

All seeds and secrets in this fixture are public.  It is never safe to fund.
"""

from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile

from ranklock.adaptive_sealing import parse_sealed_retained_object, seal_fused_slot
from ranklock.authorization_transaction_plan import build_authorization_transaction_plan
from ranklock.authorized_labels import (
    EvaluationContext,
    LabelCommitmentTree,
    execute_authorized_fused_slot,
    issue_label_release,
)
from ranklock.babe_positive_lock import deterministic_fixture, setup_positive_lock
from ranklock.bip340 import N, lift_x, public_key, tagged_hash, tapleaf_hash
from ranklock.bitcoin_authorization import BitcoinAuthorizationBinding, parse_bitcoin_transaction
from ranklock.bitcoin_witness_selection import (
    SignedBitcoinWitnessPolicy,
    WitnessItemRule,
    UnsignedBitcoinWitnessPolicy,
    selector_validation_tapscript,
    sign_authorization_witness,
    verify_request_matches_witness,
    witness_control_hash,
    witness_script_hash,
)
from ranklock.predicate_locked_hashlock import NUMS_INTERNAL_KEY

# Split-scalar keeps label *release* N-of-N: every participant must contribute
# a scalar share before any label is reconstructed.  Authorizing the Bitcoin
# carrier transaction is a separate concern, and the ACK leaf's
# OP_CHECKSIGVERIFY takes exactly one key, so this deterministic fixture uses a
# single designated carrier authorizer.  Like every other secret in this
# conformance fixture it is public by construction and must never be funded.
CARRIER_AUTHORIZER_SECRET = 0x251000
from ranklock.bn254_real import CURVE_ORDER, affine, compress_g1, decompress_g1, eq_points, multiply
from ranklock.bounded_mpc_embryo import (
    BoundedSlotLedger,
    UnsignedBoundedEmbryoManifest,
    sign_manifest_fixture,
    slot_descriptor_from_artifact,
)
from ranklock.dfb_real import DfbProfile
from ranklock.durable_slot_ledger import DurableSlotLedger
from ranklock.rollback_witness import SqliteRollbackWitness
from ranklock.real_secp import G as SECP_G, add as secp_add, multiply as secp_multiply
from ranklock.embryo_mask_fusion import (
    CURRENT_MANIFEST_BYTES,
    FIRST_91_PRIMES,
    FusedRetainedObject,
    build_mask_fused_template,
    serialize_fused_slot,
)
from ranklock.split_scalar_authorization import (
    SignedSplitScalarWitnessPolicy,
    SplitScalarParticipantReleaseSidecar,
    SplitScalarWitnessPolicySet,
)
from ranklock.split_scalar_lock import (
    SignedSplitScalarBundle,
    SplitScalarBundleSignature,
    SplitScalarContribution,
    SplitScalarHashlockConnector,
    UnsignedSplitScalarBundle,
    aggregate_projective_outputs,
    assemble_signed_split_scalar_bundle,
    unlock_split_scalar_bundle,
)

from generate_v025_committee_qualification import (
    DEPOSIT_INPUT_VALUE_SAT,
    Entropy,
    SEED as PARTICIPANT_ZERO_SEED,
    SLOT_OUTPUT_VALUES_SAT,
    _adaptive_valid_proof,
    _counterproof_transaction,
    _sha,
)


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "v025-split-scalar-conformance"
RESULT = ROOT / "results" / "v025_split_scalar_qualification.json"
P0_SEED = b"ranklock-v025-split-scalar-participant-0-public-seed"
P1_SEED = b"ranklock-v025-split-scalar-participant-1-public-seed"


def _generator_code_hash(profile: DfbProfile, *, namespace_base: int) -> bytes:
    h = sha256(b"ranklock/v025/split-scalar-full-generator/v1\x00")
    for relative in (
        "src/ranklock/dfb_real.py",
        "src/ranklock/embryo_real.py",
        "src/ranklock/embryo_mask_fusion.py",
        "src/ranklock/adaptive_sealing.py",
        "src/ranklock/authorized_labels.py",
        "src/ranklock/split_scalar_lock.py",
        "scripts/generate_v025_split_scalar_qualification.py",
    ):
        h.update(relative.encode())
        h.update((ROOT / relative).read_bytes())
    h.update(namespace_base.to_bytes(2, "big"))
    h.update(json.dumps(profile.document((1834, 1243)), sort_keys=True).encode())
    return h.digest()


def _taproot_script_output(script: bytes) -> tuple[bytes, bytes]:
    """Commit ``script`` under the shared unspendable NUMS internal key."""

    internal_key = NUMS_INTERNAL_KEY
    merkle_root = tapleaf_hash(script)
    internal_point = lift_x(int.from_bytes(internal_key, "big"))
    tweak = int.from_bytes(tagged_hash("TapTweak", internal_key + merkle_root), "big")
    if tweak >= N:
        raise RuntimeError("Taproot tweak exceeds secp256k1 order")
    output = secp_add(internal_point, secp_multiply(SECP_G, tweak))
    if output is None:
        raise RuntimeError("Taproot tweak produced infinity")
    parity = output[1] & 1
    output_key = output[0].to_bytes(32, "big")
    return b"\x51\x20" + output_key, bytes((0xC0 | parity,)) + internal_key


def _selector_template(*, slot_id: int, input_bits: int) -> tuple[
    tuple[WitnessItemRule, ...], tuple[tuple[bytes, bytes], ...], bytes, bytes, bytes
]:
    """Build one public 512-bit selector policy shared by all scalar holders."""

    rules: list[WitnessItemRule] = []
    alternatives: list[tuple[bytes, bytes]] = []
    for coordinate in (0, 1):
        for bit in range(input_bits):
            tag = slot_id.to_bytes(4, "big") + bytes((coordinate,)) + bit.to_bytes(2, "big")
            zero = b"RLW0" + tag + _sha(b"ranklock/v025/witness-zero/v1\x00", tag) + bytes(21)
            one = b"RLW1" + tag + _sha(b"ranklock/v025/witness-one/v1\x00", tag) + bytes(21)
            alternatives.append((zero, one))
            rules.append(
                WitnessItemRule.selector(
                    coordinate=coordinate,
                    bit=bit,
                    zero_item=zero,
                    one_item=one,
                )
            )
    tapscript = selector_validation_tapscript(
        rules, authorizer_pubkey=public_key(CARRIER_AUTHORIZER_SECRET)
    )
    output_script, control = _taproot_script_output(tapscript)
    return tuple(rules), tuple(alternatives), tapscript, control, output_script


def _select_witness_items(
    point: object,
    *,
    alternatives: tuple[tuple[bytes, bytes], ...],
    input_bits: int,
) -> tuple[bytes, ...]:
    coordinates = affine(point)  # type: ignore[arg-type]
    if coordinates is None:
        raise RuntimeError("authorization point is infinity")
    values = (int(coordinates[0].n), int(coordinates[1].n))
    return tuple(
        alternatives[coordinate * input_bits + bit][
            (values[coordinate] >> bit) & 1
        ]
        for coordinate in (0, 1)
        for bit in range(input_bits)
    )


def _common_fixture():
    fixture_context = b"ranklock-v025-full-committee-conformance"
    vk, public_inputs, proof0 = deterministic_fixture(context=fixture_context)
    profile = DfbProfile(primes=FIRST_91_PRIMES)
    chain_genesis = _sha(b"ranklock/v025/chain/v1\x00", b"bitcoin-regtest")
    selector_templates = tuple(
        _selector_template(slot_id=slot_id, input_bits=profile.input_bits)
        for slot_id in range(2)
    )
    deposit_txid = _sha(b"ranklock/v025/deposit-txid/v1\x00", b"contest-deposit")
    placeholder0 = _counterproof_transaction(
        previous_txid=deposit_txid,
        previous_vout=0,
        output_script=selector_templates[1][4],
        output_value_sat=SLOT_OUTPUT_VALUES_SAT[0],
        witness_items=tuple(pair[0] for pair in selector_templates[0][1]),
        tapscript=selector_templates[0][2],
        control=selector_templates[0][3],
    )
    planned_txid0 = parse_bitcoin_transaction(placeholder0).txid
    final_output_script = b"\x51\x20" + _sha(
        b"ranklock/v025/final-output-key/v1\x00", b"positive-lock"
    )
    placeholder1 = _counterproof_transaction(
        previous_txid=planned_txid0,
        previous_vout=0,
        output_script=final_output_script,
        output_value_sat=SLOT_OUTPUT_VALUES_SAT[1],
        witness_items=tuple(pair[0] for pair in selector_templates[1][1]),
        tapscript=selector_templates[1][2],
        control=selector_templates[1][3],
    )
    planned_txids = (
        parse_bitcoin_transaction(placeholder0).txid,
        parse_bitcoin_transaction(placeholder1).txid,
    )
    authorization_plan_digest = _sha(
        b"ranklock/v025/split-scalar/authorization-plan/v1\x00",
        chain_genesis,
        deposit_txid,
        *planned_txids,
    )
    # Keep the exact context used by the participant-0 conformance object.
    # Its counterproof_txid is the canonical plan digest generated by the
    # original script, so read it from the activated manifest context below.
    return (
        fixture_context,
        vk,
        tuple(public_inputs),
        proof0,
        profile,
        chain_genesis,
        selector_templates,
        deposit_txid,
        planned_txids,
        final_output_script,
        authorization_plan_digest,
    )


class _FixtureBitcoinCore:
    """Deterministic active-chain oracle for the conformance qualification.

    This is not reported as Bitcoin Core execution.  The real release gate
    remains ``run_v025_bitcoin_core_regtest.py`` against a pinned daemon.
    """

    def __init__(
        self,
        raw_transaction: bytes,
        *,
        chain_genesis_hash: bytes,
        block_hash: str,
        confirmations: int = 6,
        height: int = 2_500,
    ) -> None:
        self.raw_transaction = bytes(raw_transaction)
        self.chain_genesis_hash = bytes(chain_genesis_hash)
        self.block_hash = str(block_hash)
        self.confirmations = int(confirmations)
        self.height = int(height)

    def call(self, method: str, *params: object) -> object:
        parsed = parse_bitcoin_transaction(self.raw_transaction)
        if method == "getblockhash":
            if params != (0,):
                raise RuntimeError("fixture Core received a non-genesis getblockhash")
            return self.chain_genesis_hash.hex()
        if method == "getrawtransaction":
            return {
                "hex": self.raw_transaction.hex(),
                "txid": parsed.txid.hex(),
                "hash": parsed.wtxid.hex(),
                "blockhash": self.block_hash,
                "confirmations": self.confirmations,
            }
        if method == "getblockheader":
            return {"height": self.height, "confirmations": self.confirmations}
        raise RuntimeError(f"unsupported fixture Bitcoin RPC method: {method}")


def _split_scalar_policy_set(
    *,
    slot_id: int,
    bundle: SignedSplitScalarBundle,
    plan,
    context: EvaluationContext,
    selector_template,
    participant_secrets: tuple[int, ...],
    rollback_witness_pubkeys: tuple[bytes, ...],
    input_bits: int,
) -> SplitScalarWitnessPolicySet:
    rules, _alternatives, tapscript, control, _output_script = selector_template
    unsigned = UnsignedBitcoinWitnessPolicy(
        context_digest=context.digest,
        activation_digest=bundle.digest,
        slot_id=slot_id,
        authorization_input_index=plan.templates[slot_id].authorization_input_index,
        input_bits=input_bits,
        tapscript_hash=witness_script_hash(tapscript),
        control_block_hash=witness_control_hash(control),
        authorizer_pubkey=public_key(CARRIER_AUTHORIZER_SECRET),
        rules=rules,
    )
    messages = tuple(
        SignedSplitScalarWitnessPolicy.create(
            unsigned,
            bundle=bundle,
            plan=plan,
            participant_index=index,
            participant_secret=secret,
            rollback_witness_pubkeys=rollback_witness_pubkeys,
        )
        for index, secret in enumerate(participant_secrets)
    )
    result = SplitScalarWitnessPolicySet.assemble(
        tuple(reversed(messages)), bundle=bundle, plan=plan
    )
    if SplitScalarWitnessPolicySet.parse_compact(result.compact_bytes) != result:
        raise RuntimeError("split-scalar policy set failed canonical roundtrip")
    return result


def _generate_participant(
    *,
    participant_index: int,
    seed: bytes,
    namespace_base: int,
    context: EvaluationContext,
    fixture_context: bytes,
    vk,
    public_inputs: tuple[int, ...],
    profile: DfbProfile,
):
    """Generate one complete scalar-share object without another participant's secrets."""

    participant_index = int(participant_index)
    entropy = Entropy(seed)
    scalar = entropy.scalar(b"scalar-share")
    bundle_secret = entropy.scalar(b"bundle-signing")
    contributor_secrets = (
        entropy.scalar(b"manifest-contributor-0"),
        entropy.scalar(b"manifest-contributor-1"),
    )
    payload = entropy.bytes(b"positive-lock-preimage")
    lock = setup_positive_lock(
        vk,
        public_inputs,
        payload,
        scale=scalar,
        session_context=context.digest,
    )
    ciphertexts: list[bytes] = []
    trees: list[LabelCommitmentTree] = []
    descriptors = []
    setup_rows = []
    for slot_id in range(2):
        slot_profile = profile.with_nonce_namespace(namespace_base + slot_id)
        _garbling, template, mask_state, metadata = build_mask_fused_template(
            hidden_scalar=scalar,
            profile=slot_profile,
            dfb_seed=entropy.bytes(f"slot-{slot_id}/dfb".encode()),
            garbling_seed=entropy.bytes(f"slot-{slot_id}/embryo".encode()),
        )
        plaintext = serialize_fused_slot(template.program, mask_state)
        program_seed = entropy.bytes(f"slot-{slot_id}/program-seed".encode())
        ciphertext = seal_fused_slot(
            plaintext,
            context_digest=context.digest,
            slot_id=slot_id,
            program_seed=program_seed,
        )
        tree = LabelCommitmentTree.from_input_encodings(
            template.input_encodings,
            context_digest=context.digest,
            slot_id=slot_id,
            input_bits=profile.input_bits,
            program_seed=program_seed,
        )
        descriptor = slot_descriptor_from_artifact(
            slot_id,
            ciphertext,
            input_label_commitment=tree.root,
            independence_nonce=(
                f"ranklock-v025-split-p{participant_index}-slot-{slot_id}".encode()
            ),
        )
        ciphertexts.append(ciphertext)
        trees.append(tree)
        descriptors.append(descriptor)
        setup_rows.append(
            {
                "participant_index": participant_index,
                "slot_id": slot_id,
                "nonce_namespace": namespace_base + slot_id,
                "plaintext_bytes": len(plaintext),
                "ciphertext_bytes": len(ciphertext),
                "artifact_root": descriptor.artifact_root.hex(),
                "input_label_root": tree.root.hex(),
                "no_wrap_limit": metadata.no_wrap_limit,
            }
        )
    contributor_pubkeys = tuple(sorted(public_key(value) for value in contributor_secrets))
    unsigned = UnsignedBoundedEmbryoManifest(
        context_digest=context.digest,
        generator_code_hash=_generator_code_hash(profile, namespace_base=namespace_base),
        transcript_digest=_sha(
            b"ranklock/v025/split-scalar-participant-transcript/v1\x00",
            participant_index.to_bytes(2, "big"),
            context.digest,
            *(descriptor.artifact_root for descriptor in descriptors),
            *(tree.root for tree in trees),
        ),
        positive_lock=lock,
        slots=tuple(descriptors),
        contributor_pubkeys=contributor_pubkeys,
    )
    manifest = sign_manifest_fixture(unsigned, contributor_secrets)
    if manifest.encoded_bytes != CURRENT_MANIFEST_BYTES:
        raise RuntimeError(f"participant-{participant_index} manifest size drift")
    retained = FusedRetainedObject(manifest=manifest, slots=tuple(ciphertexts))
    parsed = parse_sealed_retained_object(retained.encoded)
    if parsed.encoded != retained.encoded:
        raise RuntimeError(
            f"participant-{participant_index} retained object failed canonical roundtrip"
        )
    return {
        "participant_index": participant_index,
        "scalar": scalar,
        "bundle_secret": bundle_secret,
        "payload": payload,
        "retained": retained,
        "trees": tuple(trees),
        "setup_rows": setup_rows,
        "namespace_base": namespace_base,
        "contributor_pubkeys": contributor_pubkeys,
    }


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    RESULT.parent.mkdir(exist_ok=True)

    (
        fixture_context,
        vk,
        public_inputs,
        proof0,
        profile,
        chain_genesis,
        selector_templates,
        deposit_txid,
        planned_txids,
        final_output_script,
        _authorization_plan_digest,
    ) = _common_fixture()

    placeholder_transactions = (
        _counterproof_transaction(
            previous_txid=deposit_txid,
            previous_vout=0,
            output_script=selector_templates[1][4],
            output_value_sat=SLOT_OUTPUT_VALUES_SAT[0],
            witness_items=tuple(pair[0] for pair in selector_templates[0][1]),
            tapscript=selector_templates[0][2],
            control=selector_templates[0][3],
        ),
        _counterproof_transaction(
            previous_txid=planned_txids[0],
            previous_vout=0,
            output_script=final_output_script,
            output_value_sat=SLOT_OUTPUT_VALUES_SAT[1],
            witness_items=tuple(pair[0] for pair in selector_templates[1][1]),
            tapscript=selector_templates[1][2],
            control=selector_templates[1][3],
        ),
    )
    plan = build_authorization_transaction_plan(
        chain_genesis_hash=chain_genesis,
        deposit_outpoint=deposit_txid + (0).to_bytes(4, "little"),
        raw_transactions=placeholder_transactions,
        authorization_input_index=0,
        continuation_output_index=0,
    )
    authorization_graph_id = _sha(
        b"ranklock/v025/authorization-graph-id/v1\x00",
        chain_genesis,
        deposit_txid,
        fixture_context,
    )
    context = EvaluationContext(
        chain_genesis_hash=chain_genesis,
        program_id=_sha(b"ranklock/v025/program/v1\x00", b"strata-counterproof"),
        verifier_key_digest=vk.digest,
        deposit_outpoint=deposit_txid + (0).to_bytes(4, "little"),
        game_index=7,
        operator_index=2,
        counterproof_txid=authorization_graph_id,
        epoch=12,
        deadline_height=900_144,
    )

    participants = (
        _generate_participant(
            participant_index=0,
            seed=P0_SEED,
            namespace_base=0,
            context=context,
            fixture_context=fixture_context,
            vk=vk,
            public_inputs=public_inputs,
            profile=profile,
        ),
        _generate_participant(
            participant_index=1,
            seed=P1_SEED,
            namespace_base=2,
            context=context,
            fixture_context=fixture_context,
            vk=vk,
            public_inputs=public_inputs,
            profile=profile,
        ),
    )
    p0, p1 = participants
    retained0: FusedRetainedObject = p0["retained"]
    retained1: FusedRetainedObject = p1["retained"]
    r0 = p0["scalar"]
    payload0 = p0["payload"]
    bundle_secrets = (p0["bundle_secret"], p1["bundle_secret"])
    contributions = (
        SplitScalarContribution.create(
            participant_index=0,
            participant_secret=bundle_secrets[0],
            retained_object_digest=sha256(retained0.encoded).digest(),
            retained_object_bytes=len(retained0.encoded),
            positive_lock=retained0.manifest.unsigned.positive_lock,
            preimage_hash=sha256(payload0).digest(),
            scale=r0,
            vk=vk,
            nonce_namespace_base=0,
        ),
        SplitScalarContribution.create(
            participant_index=1,
            participant_secret=bundle_secrets[1],
            retained_object_digest=sha256(retained1.encoded).digest(),
            retained_object_bytes=len(retained1.encoded),
            positive_lock=retained1.manifest.unsigned.positive_lock,
            preimage_hash=sha256(p1["payload"]).digest(),
            scale=p1["scalar"],
            vk=vk,
            nonce_namespace_base=p1["namespace_base"],
        ),
    )
    unsigned_bundle = UnsignedSplitScalarBundle(context.digest, contributions)
    bundle_signature_messages = tuple(
        SplitScalarBundleSignature.create(
            unsigned_bundle,
            participant_index=index,
            participant_secret=secret,
        )
        for index, secret in enumerate(bundle_secrets)
    )
    # Assemble from reversed, independently produced messages to prove the
    # coordinator does not need signing secrets or a trusted message order.
    bundle = assemble_signed_split_scalar_bundle(
        unsigned_bundle, tuple(reversed(bundle_signature_messages))
    )
    if SignedSplitScalarBundle.parse(bundle.encoded) != bundle:
        raise RuntimeError("split-scalar bundle failed canonical roundtrip")
    if not bundle.verify_for_statement(
        vk=vk,
        public_inputs=public_inputs,
        expected_context_digest=context.digest,
    ):
        raise RuntimeError("split-scalar bundle failed statement verification")

    n_of_n_secret = Entropy(b"ranklock-v025-split-ack-signing-seed").scalar(b"ack-key")
    connector = SplitScalarHashlockConnector(
        n_of_n_pubkey=public_key(n_of_n_secret),
        preimage_hashes=tuple(item.preimage_hash for item in contributions),
        relative_delay=144,
        value_sat=100_000,
    )
    rollback_witness_secrets = tuple(
        Entropy(b"ranklock-v025-split-rollback-witness-seed").scalar(
            f"participant-{index}".encode()
        )
        for index in range(2)
    )
    rollback_witness_pubkeys = tuple(
        sorted(public_key(secret) for secret in rollback_witness_secrets)
    )

    policy_sets = tuple(
        _split_scalar_policy_set(
            slot_id=slot_id,
            bundle=bundle,
            plan=plan,
            context=context,
            selector_template=selector_templates[slot_id],
            participant_secrets=bundle_secrets,
            rollback_witness_pubkeys=rollback_witness_pubkeys,
            input_bits=profile.input_bits,
        )
        for slot_id in range(2)
    )

    retained_objects = (retained0, retained1)
    trees_by_participant = (p0["trees"], p1["trees"])
    manifest_pubkeys = (p0["contributor_pubkeys"], p1["contributor_pubkeys"])
    namespace_bases = (0, p1["namespace_base"])
    evaluator_ledgers = (
        BoundedSlotLedger(context.digest, 2),
        BoundedSlotLedger(context.digest, 2),
    )

    points = [decompress_g1(proof0.a_g1)]
    proofs = [proof0]
    aggregate_outputs: list[bytes] = []
    participant_outputs_by_slot: list[tuple[bytes, bytes]] = []
    unlocks = []
    raw_transactions: list[bytes] = []
    participant_releases: list[list[object]] = [[], []]
    participant_receipt_counts = [0, 0]
    participant_created_counts = [0, 0]
    confirmed_wtxids: list[str] = []
    durable_states: list[list[str]] = [[], []]
    rollback_receipts_verified = True

    with tempfile.TemporaryDirectory(prefix="ranklock-v025-split-ledger-") as temporary:
        temporary_path = Path(temporary)
        durable_ledgers = tuple(
            DurableSlotLedger(
                temporary_path / f"participant-{index}.sqlite",
                context_digest=context.digest,
                slot_count=2,
            )
            for index in range(2)
        )
        rollback_witnesses = tuple(
            SqliteRollbackWitness(
                temporary_path / f"rollback-participant-{index}.sqlite",
                witness_secret=rollback_witness_secrets[index],
            )
            for index in range(2)
        )

        for slot_id in range(2):
            point = points[slot_id]
            selected = _select_witness_items(
                point,
                alternatives=selector_templates[slot_id][1],
                input_bits=profile.input_bits,
            )
            transaction_fields = {
                "previous_txid": deposit_txid if slot_id == 0 else planned_txids[0],
                "previous_vout": 0,
                "output_script": (
                    selector_templates[1][4] if slot_id == 0 else final_output_script
                ),
                "output_value_sat": SLOT_OUTPUT_VALUES_SAT[slot_id],
                "witness_items": selected,
                "tapscript": selector_templates[slot_id][2],
                "control": selector_templates[slot_id][3],
            }
            unsigned_tx = _counterproof_transaction(**transaction_fields)
            carrier_signature = sign_authorization_witness(
                unsigned_tx,
                authorization_input_index=0,
                spent_values_sat=(
                    (DEPOSIT_INPUT_VALUE_SAT, SLOT_OUTPUT_VALUES_SAT[0])[slot_id],
                ),
                spent_scripts=(selector_templates[slot_id][4],),
                tapscript=selector_templates[slot_id][2],
                request_authorizer_secret=CARRIER_AUTHORIZER_SECRET,
            )
            raw_tx = _counterproof_transaction(
                **transaction_fields, authorizer_signature=carrier_signature
            )
            parsed_tx = parse_bitcoin_transaction(raw_tx)
            if parsed_tx.txid != planned_txids[slot_id]:
                raise RuntimeError("adaptive witness changed a precommitted txid")
            if not plan.verify_raw_transaction(slot_id, raw_tx):
                raise RuntimeError("raw transaction differs from authorization plan")

            block_hash = _sha(
                b"ranklock/v025/split-conformance-block/v1\x00",
                slot_id.to_bytes(2, "big"),
                parsed_tx.wtxid,
            ).hex()
            core = _FixtureBitcoinCore(
                raw_tx,
                chain_genesis_hash=chain_genesis,
                block_hash=block_hash,
                confirmations=6,
                height=2_500 + slot_id,
            )

            outputs: list[bytes] = []
            for participant_index in range(2):
                output_path = OUT / (
                    f"participant-{participant_index}-slot-{slot_id}-authorized-release.bin"
                )
                sidecar = SplitScalarParticipantReleaseSidecar(
                    bundle=bundle,
                    participant_index=participant_index,
                    retained_object_bytes=retained_objects[participant_index].encoded,
                    required_manifest_pubkeys=manifest_pubkeys[participant_index],
                    context=context,
                    verifying_key=vk,
                    public_inputs=public_inputs,
                    plan=plan,
                    witness_policy_set=policy_sets[slot_id],
                    tree=trees_by_participant[participant_index][slot_id],
                    participant_secret=bundle_secrets[participant_index],
                    ledger=durable_ledgers[participant_index],
                    rollback_witnesses=rollback_witnesses,
                    bitcoin_core=core,
                    minimum_confirmations=6,
                )
                release, observation, receipts, created = sidecar.issue(
                    raw_transaction=raw_tx,
                    block_hash=block_hash,
                    output_path=output_path,
                )
                if observation.wtxid != parsed_tx.wtxid.hex():
                    raise RuntimeError("participant sidecar bound another Bitcoin witness")
                if not created:
                    raise RuntimeError("fresh conformance release was not written")
                if not receipts or not all(receipt.verify() for receipt in receipts):
                    rollback_receipts_verified = False
                    raise RuntimeError("participant rollback receipt failed verification")
                participant_receipt_counts[participant_index] += len(receipts)
                participant_created_counts[participant_index] += int(created)
                participant_releases[participant_index].append(release)

                execution = execute_authorized_fused_slot(
                    manifest=retained_objects[participant_index].manifest,
                    required_manifest_pubkeys=manifest_pubkeys[participant_index],
                    context=context,
                    expected_authorizer_pubkey=public_key(
                        bundle_secrets[participant_index]
                    ),
                    ledger=evaluator_ledgers[participant_index],
                    slot_artifact=retained_objects[participant_index].slots[slot_id],
                    profile=profile,
                    release=release,
                    nonce_namespace_base=namespace_bases[participant_index],
                )
                outputs.append(compress_g1(execution.replay.result.output_point))
                state = durable_ledgers[participant_index].use(slot_id)
                if state.state != "success" or not state.terminal:
                    raise RuntimeError("participant durable slot did not terminate successfully")
                durable_states[participant_index].append(state.state)

            participant_output_tuple = tuple(outputs)
            aggregate = aggregate_projective_outputs(participant_output_tuple)
            expected = multiply(
                point,
                (r0 + p1["scalar"]) % CURVE_ORDER,
                group="g1",
            )
            if not eq_points(decompress_g1(aggregate), expected):
                raise RuntimeError(f"slot {slot_id} aggregate output is not [r0+r1]A")
            unlocked = unlock_split_scalar_bundle(
                bundle,
                vk=vk,
                public_inputs=public_inputs,
                proof=proofs[slot_id],
                participant_outputs_g1=participant_output_tuple,
                expected_context_digest=context.digest,
            )
            if unlocked.preimages != (payload0, p1["payload"]):
                raise RuntimeError("split-scalar positive locks recovered wrong preimages")
            if not connector.verify_preimages(unlocked.preimages):
                raise RuntimeError("aggregate ACK connector rejected all valid preimages")
            raw_transactions.append(raw_tx)
            confirmed_wtxids.append(parsed_tx.wtxid.hex())
            participant_outputs_by_slot.append(participant_output_tuple)
            aggregate_outputs.append(aggregate)
            unlocks.append(unlocked)
            if slot_id == 0:
                proof1 = _adaptive_valid_proof(vk, public_inputs, aggregate)
                proofs.append(proof1)
                points.append(decompress_g1(proof1.a_g1))

        if any(ledger.remaining != 0 for ledger in durable_ledgers):
            raise RuntimeError("a participant durable ledger retained an unused slot")
        if any(not ledger.verify_audit_chain() for ledger in durable_ledgers):
            raise RuntimeError("participant durable ledger audit chain failed verification")

    # A participant output from the wrong slot must not unlock the corresponding lock.
    crosswire_rejected = False
    try:
        unlock_split_scalar_bundle(
            bundle,
            vk=vk,
            public_inputs=public_inputs,
            proof=proofs[0],
            participant_outputs_g1=(
                participant_outputs_by_slot[1][0],
                participant_outputs_by_slot[0][1],
            ),
            expected_context_digest=context.digest,
        )
    except Exception:
        crosswire_rejected = True
    if not crosswire_rejected:
        raise RuntimeError("cross-slot participant output was accepted")

    OUT.joinpath("participant-0-retained-object.bin").write_bytes(retained0.encoded)
    OUT.joinpath("participant-1-retained-object.bin").write_bytes(retained1.encoded)
    OUT.joinpath("ranklock-v025-split-scalar-unsigned-bundle.bin").write_bytes(
        unsigned_bundle.encoded
    )
    OUT.joinpath("ranklock-v025-split-scalar-bundle.bin").write_bytes(bundle.encoded)
    OUT.joinpath("ranklock-v025-split-ack-script.bin").write_bytes(connector.ack_script)
    for participant_index, message in enumerate(bundle_signature_messages):
        OUT.joinpath(
            f"participant-{participant_index}-bundle-signature-message.bin"
        ).write_bytes(message.encoded)
    for slot_id, policy_set in enumerate(policy_sets):
        OUT.joinpath(f"slot-{slot_id}-common-witness-policy-set.bin").write_bytes(
            policy_set.compact_bytes
        )
        OUT.joinpath(f"slot-{slot_id}-counterproof-transaction.bin").write_bytes(
            raw_transactions[slot_id]
        )
        OUT.joinpath(f"slot-{slot_id}-aggregate-output-g1.bin").write_bytes(
            aggregate_outputs[slot_id]
        )

    release_bytes = [
        [len(release.compact_bytes) for release in releases]
        for releases in participant_releases
    ]
    report = {
        "schema": "ranklock-v025-split-scalar-qualification-v2",
        "decision": (
            "FULL_SIZE_SPLIT_SCALAR_PARTICIPANT_LOCAL_RELEASE_PASS_"
            "REAL_CORE_NATIVE_AUDIT_GATES_OPEN"
        ),
        "public_fixture_warning": (
            "all deterministic setup secrets are public; never fund these artifacts"
        ),
        "setup_model": {
            "mode": "split-scalar-n-of-n",
            "participants": 2,
            "one_honest_participant_conditionally_protects_ack_safety": True,
            "corrupt_participant_can_abort": True,
            "dealer_knowing_aggregate_scalar_required": False,
            "active_mpc_required_for_this_mode": False,
            "per_participant_artifact_generated_independently": True,
            "participant_0_tree_migrated_from_public_committee_fixture": False,
            "production_tree_reconstruction_across_participants": False,
            "scale_knowledge_proofs_verified": True,
            "independent_bundle_signature_messages": len(bundle_signature_messages),
            "bundle_assembled_from_reversed_messages": True,
            "all_participants_signed_exact_bundle": bundle.verify_signatures(),
            "nonce_namespace_ranges": [[0, 2], [2, 4]],
            "namespace_ranges_disjoint": True,
        },
        "retained_material": {
            "participant_0_bytes": len(retained0.encoded),
            "participant_1_bytes": len(retained1.encoded),
            "participant_0_sha256": sha256(retained0.encoded).hexdigest(),
            "participant_1_sha256": sha256(retained1.encoded).hexdigest(),
            "artifact_bytes_sum": len(retained0.encoded) + len(retained1.encoded),
            "unsigned_bundle_bytes": len(unsigned_bundle.encoded),
            "signed_bundle_bytes": len(bundle.encoded),
            "complete_split_scalar_retained_bytes": (
                len(retained0.encoded) + len(retained1.encoded) + len(bundle.encoded)
            ),
            "below_one_mib": False,
            "size_tradeoff": (
                "approximately linear in independently generated scalar-share artifacts"
            ),
        },
        "bitcoin_bound_participant_release": {
            "common_selector_policy_sets": len(policy_sets),
            "participant_policy_signatures": sum(
                len(policy_set.policies) for policy_set in policy_sets
            ),
            "selector_items_per_transaction": profile.input_bits * 2,
            "witness_items_including_tapscript_and_control": profile.input_bits * 2 + 2,
            "rejected_architecture_items_for_two_private_vectors": profile.input_bits * 4,
            "single_common_selector_avoids_bip342_1000_item_limit": True,
            "participant_local_label_trees": True,
            "participant_local_release_sidecars": 2,
            "durable_participant_ledgers": 2,
            "independent_rollback_witnesses_in_fixture": 2,
            "rollback_receipts_verified": rollback_receipts_verified,
            "rollback_receipt_counts": participant_receipt_counts,
            "durable_final_states": durable_states,
            "release_files_created": participant_created_counts,
            "authorized_release_bytes": release_bytes,
            "confirmed_wtxids": confirmed_wtxids,
            "minimum_confirmations": 6,
            "bitcoin_core_rpc_semantics_exercised_with_deterministic_oracle": True,
            "real_bitcoin_core_process_executed": False,
        },
        "adaptive_evaluation": {
            "slot_count": 2,
            "full_91_prime_artifacts": 2,
            "full_91_prime_slots": 4,
            "a2_derived_after_aggregate_y1": True,
            "participant_output_checks": 4,
            "aggregate_direct_scalar_checks": 2,
            "aggregate_output_sha256": [
                sha256(item).hexdigest() for item in aggregate_outputs
            ],
            "positive_lock_preimages_unlocked_per_slot": 2,
            "all_preimages_required_by_ack_script": True,
            "cross_slot_output_rejected": crosswire_rejected,
            "participant_maps_per_slot": [[256, 256], [256, 256]],
        },
        "bitcoin_ack": {
            "script_bytes": len(connector.ack_script),
            "script_sha256": sha256(connector.ack_script).hexdigest(),
            "preimage_count": len(connector.preimage_hashes),
            "n_of_n": True,
            "bitcoin_core_regtest_executed": False,
        },
        "participant_setup_rows": [p0["setup_rows"], p1["setup_rows"]],
        "closed_by_this_qualification": [
            "dealer-free one-honest conditional safety mode for the hidden scalar",
            "independent full retained object per scalar share",
            "independent N-of-N bundle signature messages",
            "cross-participant DFB nonce namespace separation",
            "one common 512-bit Bitcoin selector policy signed by every participant",
            "participant-local durable burn and rollback-witness anchoring",
            "participant-local labels released only after exact wtxid confirmation checks",
            "adaptive aggregate A2 selected only after aggregate [r]A1",
            "N-of-N Bitcoin ACK script requiring every independently locked preimage",
        ],
        "remaining_safe_for_funds_gates": [
            "execute ACK/NACK, release, reorg and fee flow against a pinned Bitcoin Core 31.1 regtest daemon",
            "compile and run the exact current strata-bridge integration",
            "replace Python variable-time secret setup/evaluation paths with audited native constant-time code",
            "deploy independently administered sidecars and rollback witnesses with hardware-backed keys",
            "complete crash/restart/reorg/CPFP tests under real Core and filesystem fault injection",
            "obtain independent cryptographic, implementation and Bitcoin audits",
        ],
        "safe_for_funds": False,
    }
    RESULT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
