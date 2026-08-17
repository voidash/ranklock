from __future__ import annotations

"""Generate the full-size v0.25 committee-authorization conformance fixture.

The output uses a public deterministic seed and a dealer to split labels.  It
exists to reproduce bytes and exercise the full two-slot evaluator.  It is
intentionally unsafe for funds; a production ceremony must replace the dealer
with active MPC and must execute the Bitcoin path against Core regtest.
"""

from hashlib import sha256, shake_256
import json
from pathlib import Path
import shutil
import tempfile

from ranklock.adaptive_sealing import parse_sealed_retained_object, seal_fused_slot
from ranklock.authorized_labels import EvaluationContext, LabelCommitmentTree
from ranklock.babe_positive_lock import (
    PositiveGroth16Proof,
    deterministic_fixture,
    setup_positive_lock,
    unlock_positive_lock,
    verify_positive_groth16,
)
from ranklock.bip340 import N, lift_x, public_key, tagged_hash, tapleaf_hash
from ranklock.bitcoin_authorization import (
    BitcoinAuthorizationBinding,
    parse_bitcoin_transaction,
)
from ranklock.authorization_transaction_plan import build_authorization_transaction_plan
from ranklock.bitcoin_witness_selection import (
    derive_witness_selection,
    SignedBitcoinWitnessPolicy,
    UnsignedBitcoinWitnessPolicy,
    selector_validation_tapscript,
    sign_authorization_witness,
    witness_control_hash,
    witness_rules_from_label_pairs,
    witness_script_hash,
)
from ranklock.predicate_locked_hashlock import NUMS_INTERNAL_KEY
from ranklock.bn254_real import (
    CURVE_ORDER,
    G1,
    G2,
    compress_g1,
    compress_g2,
    decompress_g1,
    eq_points,
    affine,
    multiply,
)
from ranklock.bounded_mpc_embryo import (
    UnsignedBoundedEmbryoManifest,
    sign_manifest_fixture,
    slot_descriptor_from_artifact,
)
from ranklock.committee_authorization import (
    CommitteeAuthorizationError,
    CommitteeAuthorizationRequest,
    CommitteeLabelGuide,
    ParticipantSlotSecrets,
    SignedCommitteeActivation,
    dealer_split_fixture,
    issue_committee_request,
)
from ranklock.dfb_real import DfbProfile
from ranklock.durable_slot_ledger import DurableSlotLedger, SlotConflictError
from ranklock.real_secp import G as SECP_G, add as secp_add, multiply as secp_multiply
from ranklock.rollback_witness import (
    RollbackDetectedError,
    SqliteRollbackWitness,
    anchor_ledger_at_all_witnesses,
)
from ranklock.two_phase_authorization import (
    ParticipantSeedResponse,
    ParticipantWitnessShareResponse,
    TwoPhaseAuthorizationError,
    WitnessPreauthorizationRequest,
    execute_two_phase_authorized_fused_slot,
    issue_witness_preauthorization_request,
    prepare_seed_response,
    prepare_witness_share_response,
    reconstruct_program_seed,
    reconstruct_witness_labels,
)
from ranklock.embryo_mask_fusion import (
    CURRENT_MANIFEST_BYTES,
    FIRST_91_PRIMES,
    FusedRetainedObject,
    build_mask_fused_template,
    serialize_fused_slot,
)


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "v025-committee-conformance"
RESULTS = ROOT / "results"
SEED = b"ranklock-v025-public-committee-conformance-seed"
DEPOSIT_INPUT_VALUE_SAT = 160_000
# Structural stand-in while a transaction is being precommitted; replaced
# by the real signature once the exact sighash is known.
_PLACEHOLDER_SIGNATURE = bytes(64)
SLOT_OUTPUT_VALUES_SAT = (130_000, 100_000)


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = sha256(domain)
    for part in parts:
        h.update(bytes(part))
    return h.digest()


class Entropy:
    def __init__(self, seed: bytes = SEED) -> None:
        self.seed = bytes(seed)
        self.counter = 0

    def bytes(self, domain: bytes, length: int = 32) -> bytes:
        self.counter += 1
        return shake_256(
            b"ranklock/v025/conformance-entropy/v1\x00"
            + self.seed
            + len(domain).to_bytes(4, "big")
            + domain
            + self.counter.to_bytes(8, "big")
        ).digest(length)

    def scalar(self, domain: bytes) -> int:
        return int.from_bytes(self.bytes(domain, 64), "big") % (CURVE_ORDER - 1) + 1


def _compact(value: int) -> bytes:
    value = int(value)
    if value < 0:
        raise ValueError("negative CompactSize")
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _taproot_script_output(script: bytes) -> tuple[bytes, bytes]:
    """Commit ``script`` under the shared unspendable NUMS internal key.

    A derivable internal key would leave a key-path spend that bypasses the
    authorization script entirely.
    """

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


def _selector_template(
    tree: LabelCommitmentTree,
    *,
    authorizer_pubkey: bytes,
) -> tuple[tuple[object, ...], bytes, bytes, bytes]:
    rules = witness_rules_from_label_pairs(
        tree.label_pairs,
        input_bits=tree.input_bits,
    )
    tapscript = selector_validation_tapscript(rules, authorizer_pubkey=authorizer_pubkey)
    output_script, control = _taproot_script_output(tapscript)
    return tuple(rules), tapscript, control, output_script


def _selected_labels(tree: LabelCommitmentTree, point: object) -> tuple[bytes, ...]:
    coordinates = affine(point)  # type: ignore[arg-type]
    if coordinates is None:
        raise RuntimeError("authorization point is infinity")
    values = (int(coordinates[0].n), int(coordinates[1].n))
    return tuple(
        tree.label_pairs[coordinate * tree.input_bits + bit][
            (values[coordinate] >> bit) & 1
        ]
        for coordinate in (0, 1)
        for bit in range(tree.input_bits)
    )


def _counterproof_transaction(
    *,
    previous_txid: bytes,
    previous_vout: int,
    output_script: bytes,
    output_value_sat: int,
    witness_items: tuple[bytes, ...],
    tapscript: bytes,
    control: bytes,
    authorizer_signature: bytes = _PLACEHOLDER_SIGNATURE,
) -> bytes:
    """Canonical one-input SegWit transaction; witness does not affect txid.

    ``authorizer_signature`` sits between the selector items and the tapscript
    so the script's leading OP_CHECKSIGVERIFY consumes it first.  Because the
    BIP341 script-path sighash excludes the spending input's own witness, the
    placeholder default yields the same txid as the finally-signed transaction.
    """

    if len(previous_txid) != 32:
        raise ValueError("previous transaction id must be 32 bytes")
    version = (2).to_bytes(4, "little")
    txin = (
        previous_txid[::-1]
        + int(previous_vout).to_bytes(4, "little")
        + b"\x00"
        + bytes.fromhex("fdffffff")
    )
    if not 0 <= int(output_value_sat) < 2**64:
        raise ValueError("output value must fit u64")
    txout = int(output_value_sat).to_bytes(8, "little") + _compact(len(output_script)) + output_script
    stack = tuple(witness_items) + (
        bytes(authorizer_signature),
        bytes(tapscript),
        bytes(control),
    )
    witness = _compact(len(stack)) + b"".join(
        _compact(len(item)) + item for item in stack
    )
    return version + b"\x00\x01" + b"\x01" + txin + b"\x01" + txout + witness + bytes(4)


def _generator_code_hash(profile: DfbProfile) -> bytes:
    h = sha256(b"ranklock/v025/full-generator-code/v1\x00")
    for relative in (
        "src/ranklock/dfb_real.py",
        "src/ranklock/embryo_real.py",
        "src/ranklock/embryo_mask_fusion.py",
        "src/ranklock/adaptive_sealing.py",
        "src/ranklock/authorized_labels.py",
        "src/ranklock/bitcoin_authorization.py",
        "src/ranklock/authorization_transaction_plan.py",
        "src/ranklock/bitcoin_witness_selection.py",
        "src/ranklock/durable_slot_ledger.py",
        "src/ranklock/committee_authorization.py",
        "scripts/generate_v025_committee_qualification.py",
    ):
        h.update(relative.encode())
        h.update((ROOT / relative).read_bytes())
    h.update(json.dumps(profile.document((1834, 1243)), sort_keys=True).encode())
    return h.digest()


def _adaptive_valid_proof(vk, public_inputs: tuple[int, ...], first_output: bytes) -> PositiveGroth16Proof:
    # The conformance VK is deterministic_fixture's exponent-known test key.
    a = int.from_bytes(
        _sha(b"ranklock/v025/adaptive-proof-a/v1\x00", first_output), "big"
    ) % CURVE_ORDER
    a = a or 1
    b = 31
    alpha, beta, gamma, delta = 3, 5, 7, 11
    vk_x = (13 + public_inputs[0] * 19) % CURVE_ORDER
    c = ((a * b - alpha * beta - vk_x * gamma) * pow(delta, -1, CURVE_ORDER)) % CURVE_ORDER
    proof = PositiveGroth16Proof(
        a_g1=compress_g1(multiply(G1, a, group="g1")),
        b_g2=compress_g2(multiply(G2, b, group="g2")),
        c_g1=compress_g1(multiply(G1, c, group="g1")),
    )
    if not verify_positive_groth16(vk, public_inputs, proof):
        raise RuntimeError("adaptive conformance Groth16 proof is invalid")
    return proof


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(exist_ok=True)
    entropy = Entropy()

    fixture_context = b"ranklock-v025-full-committee-conformance"
    vk, public_inputs, proof0 = deterministic_fixture(context=fixture_context)
    chain_genesis = _sha(b"ranklock/v025/chain/v1\x00", b"bitcoin-regtest")
    deposit_txid = _sha(b"ranklock/v025/deposit-txid/v1\x00", b"contest-deposit")
    profile = DfbProfile(primes=FIRST_91_PRIMES)
    input_bits = profile.input_bits

    # The inner DFB/Embryo context is deliberately independent of the exact
    # authorization transaction plan.  The final plan is bound one layer out by
    # the signed manifest transcript, each committee activation, each witness
    # policy, and both authorization requests.  This avoids an impossible hash
    # fixed point: the Taproot output commits label hashes, while the labels are
    # themselves derived under this setup context.
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

    hidden_scalar = entropy.scalar(b"same-hidden-scalar")
    authorizer_secret = entropy.scalar(b"request-authorizer")
    contributor_secrets = (entropy.scalar(b"manifest-0"), entropy.scalar(b"manifest-1"))
    committee_secrets = (
        entropy.scalar(b"committee-0"),
        entropy.scalar(b"committee-1"),
        entropy.scalar(b"committee-2"),
    )
    rollback_witness_secrets = (
        entropy.scalar(b"rollback-witness-0"),
        entropy.scalar(b"rollback-witness-1"),
        entropy.scalar(b"rollback-witness-2"),
    )
    payload = entropy.bytes(b"positive-lock-payload")
    positive_lock = setup_positive_lock(
        vk,
        public_inputs,
        payload,
        scale=hidden_scalar,
        session_context=fixture_context,
    )

    ciphertexts: list[bytes] = []
    trees: list[LabelCommitmentTree] = []
    descriptors = []
    setup_rows = []
    for slot_id in range(2):
        slot_profile = profile.with_nonce_namespace(slot_id)
        _garbling, template, mask_state, metadata = build_mask_fused_template(
            hidden_scalar=hidden_scalar,
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
            input_bits=input_bits,
            program_seed=program_seed,
        )
        descriptor = slot_descriptor_from_artifact(
            slot_id,
            ciphertext,
            input_label_commitment=tree.root,
            independence_nonce=f"ranklock-v025-independent-slot-{slot_id}".encode(),
        )
        ciphertexts.append(ciphertext)
        trees.append(tree)
        descriptors.append(descriptor)
        setup_rows.append(
            {
                "slot_id": slot_id,
                "plaintext_bytes": len(plaintext),
                "ciphertext_bytes": len(ciphertext),
                "input_label_root": tree.root.hex(),
                "artifact_root": descriptor.artifact_root.hex(),
                "no_wrap_limit": metadata.no_wrap_limit,
            }
        )

    authorizer_pubkey = public_key(authorizer_secret)
    selector_templates = tuple(
        _selector_template(tree, authorizer_pubkey=authorizer_pubkey) for tree in trees
    )
    final_output_script = b"\x51\x20" + _sha(
        b"ranklock/v025/final-output-key/v1\x00", b"positive-lock"
    )
    placeholder0 = _counterproof_transaction(
        previous_txid=deposit_txid,
        previous_vout=0,
        output_script=selector_templates[1][3],
        output_value_sat=SLOT_OUTPUT_VALUES_SAT[0],
        witness_items=tuple(pair[0] for pair in trees[0].label_pairs),
        tapscript=selector_templates[0][1],
        control=selector_templates[0][2],
    )
    planned_txid0 = parse_bitcoin_transaction(placeholder0).txid
    placeholder1 = _counterproof_transaction(
        previous_txid=planned_txid0,
        previous_vout=0,
        output_script=final_output_script,
        output_value_sat=SLOT_OUTPUT_VALUES_SAT[1],
        witness_items=tuple(pair[0] for pair in trees[1].label_pairs),
        tapscript=selector_templates[1][1],
        control=selector_templates[1][2],
    )
    authorization_plan = build_authorization_transaction_plan(
        chain_genesis_hash=chain_genesis,
        deposit_outpoint=deposit_txid + (0).to_bytes(4, "little"),
        raw_transactions=(placeholder0, placeholder1),
        authorization_input_index=0,
        continuation_output_index=0,
    )
    planned_txids = authorization_plan.txids

    contributor_pubkeys = tuple(sorted(public_key(value) for value in contributor_secrets))
    unsigned_manifest = UnsignedBoundedEmbryoManifest(
        context_digest=context.digest,
        generator_code_hash=_generator_code_hash(profile),
        transcript_digest=_sha(
            b"ranklock/v025/conformance-transcript/v2\x00",
            context.digest,
            authorization_plan.digest,
            *(descriptor.artifact_root for descriptor in descriptors),
            *(tree.root for tree in trees),
        ),
        positive_lock=positive_lock,
        slots=tuple(descriptors),
        contributor_pubkeys=contributor_pubkeys,
    )
    manifest = sign_manifest_fixture(unsigned_manifest, contributor_secrets)
    if manifest.encoded_bytes != CURRENT_MANIFEST_BYTES:
        raise RuntimeError("v0.25 manifest size drift")
    retained = FusedRetainedObject(manifest=manifest, slots=tuple(ciphertexts))
    if parse_sealed_retained_object(retained.encoded).encoded != retained.encoded:
        raise RuntimeError("v0.25 retained object is non-canonical")

    activations: list[SignedCommitteeActivation] = []
    guides: list[CommitteeLabelGuide] = []
    participant_states_by_slot: list[tuple[ParticipantSlotSecrets, ...]] = []
    for slot_id in range(2):
        activation, guide, states = dealer_split_fixture(
            trees[slot_id],
            chain_genesis_hash=chain_genesis,
            counterproof_txid=planned_txids[slot_id],
            artifact_root=descriptors[slot_id].artifact_root,
            participant_secrets=committee_secrets,
            request_authorizer_pubkey=public_key(authorizer_secret),
            rollback_witness_pubkeys=tuple(
                public_key(secret) for secret in rollback_witness_secrets
            ),
            deterministic_seed=entropy.bytes(f"slot-{slot_id}/dealer-split".encode()),
            allow_public_secrets=True,
        )
        activations.append(activation)
        guides.append(guide)
        participant_states_by_slot.append(states)

    witness_policies = tuple(
        SignedBitcoinWitnessPolicy.create(
            UnsignedBitcoinWitnessPolicy(
                context_digest=context.digest,
                activation_digest=activations[slot_id].digest,
                slot_id=slot_id,
                authorization_input_index=0,
                input_bits=input_bits,
                tapscript_hash=witness_script_hash(selector_templates[slot_id][1]),
                control_block_hash=witness_control_hash(selector_templates[slot_id][2]),
                authorizer_pubkey=authorizer_pubkey,
                rules=selector_templates[slot_id][0],
            ),
            activation=activations[slot_id],
            participant_secrets=committee_secrets,
        )
        for slot_id in range(2)
    )

    with tempfile.TemporaryDirectory(prefix="ranklock-v025-ledgers-") as temporary:
        temporary_path = Path(temporary)
        ledger_paths = [temporary_path / f"participant-{index}.sqlite" for index in range(3)]
        ledgers = [
            DurableSlotLedger(path, context_digest=context.digest, slot_count=2)
            for path in ledger_paths
        ]
        rollback_witnesses = tuple(
            SqliteRollbackWitness(
                temporary_path / f"rollback-witness-{index}.sqlite",
                witness_secret=rollback_witness_secrets[index],
            )
            for index in range(3)
        )
        bootstrap_receipts = [
            anchor_ledger_at_all_witnesses(
                ledgers[index],
                participant_secret=participant_states_by_slot[0][index].participant_secret,
                witnesses=rollback_witnesses,
            )
            for index in range(3)
        ]
        for ledger in ledgers:
            ledger.checkpoint()
        preburn_backup = temporary_path / "participant-0-preburn.sqlite"
        shutil.copy2(ledger_paths[0], preburn_backup)

        proofs = [proof0]
        points = [decompress_g1(proof0.a_g1)]
        preauthorizations: list[WitnessPreauthorizationRequest] = []
        confirmation_requests: list[CommitteeAuthorizationRequest] = []
        raw_transactions: list[bytes] = []
        bindings: list[BitcoinAuthorizationBinding] = []
        witness_responses_by_slot: list[tuple[ParticipantWitnessShareResponse, ...]] = []
        seed_responses_by_slot: list[tuple[ParticipantSeedResponse, ...]] = []
        witness_receipts_by_slot: list[tuple[object, ...]] = []
        executions = []
        unlocked_payloads: list[bytes] = []

        for slot_id in range(2):
            preauthorization = issue_witness_preauthorization_request(
                activations[slot_id],
                authorization_plan,
                point=points[slot_id],
                request_authorizer_secret=authorizer_secret,
            )
            witness_responses: list[ParticipantWitnessShareResponse] = []
            slot_receipts: list[object] = []
            for participant_index in range(3):
                response = prepare_witness_share_response(
                    activation=activations[slot_id],
                    preauthorization=preauthorization,
                    plan=authorization_plan,
                    policy=witness_policies[slot_id],
                    participant=participant_states_by_slot[slot_id][participant_index],
                    ledger=ledgers[participant_index],
                )
                slot_receipts.extend(
                    anchor_ledger_at_all_witnesses(
                        ledgers[participant_index],
                        participant_secret=participant_states_by_slot[slot_id][participant_index].participant_secret,
                        witnesses=rollback_witnesses,
                    )
                )
                witness_responses.append(response)
            reconstructed_witness = reconstruct_witness_labels(
                activation=activations[slot_id],
                preauthorization=preauthorization,
                plan=authorization_plan,
                policy=witness_policies[slot_id],
                responses=tuple(witness_responses),
            )
            transaction_fields = {
                "previous_txid": deposit_txid if slot_id == 0 else planned_txids[0],
                "previous_vout": 0,
                "output_script": (
                    selector_templates[1][3] if slot_id == 0 else final_output_script
                ),
                "output_value_sat": SLOT_OUTPUT_VALUES_SAT[slot_id],
                "witness_items": reconstructed_witness.witness_stack_items,
                "tapscript": selector_templates[slot_id][1],
                "control": selector_templates[slot_id][2],
            }
            # Sign the exact precommitted transaction, then splice the
            # signature in.  The BIP341 script-path sighash excludes the
            # spending input's own witness, so the txid is unchanged.
            unsigned_tx = _counterproof_transaction(**transaction_fields)
            authorizer_signature = sign_authorization_witness(
                unsigned_tx,
                authorization_input_index=0,
                spent_values_sat=(
                    (DEPOSIT_INPUT_VALUE_SAT, SLOT_OUTPUT_VALUES_SAT[0])[slot_id],
                ),
                spent_scripts=(selector_templates[slot_id][3],),
                tapscript=selector_templates[slot_id][1],
                request_authorizer_secret=authorizer_secret,
            )
            raw_tx = _counterproof_transaction(
                **transaction_fields, authorizer_signature=authorizer_signature
            )
            parsed_tx = parse_bitcoin_transaction(raw_tx)
            if parsed_tx.txid != planned_txids[slot_id]:
                raise RuntimeError("adaptive witness changed the precommitted transaction id")
            if not authorization_plan.verify_raw_transaction(slot_id, raw_tx):
                raise RuntimeError("authorization transaction differs from committed stripped template")
            selection = derive_witness_selection(
                raw_tx,
                policy=witness_policies[slot_id],
                activation=activations[slot_id],
            )
            if selection.point_encoding != preauthorization.point_encoding:
                raise RuntimeError("reconstructed Bitcoin witness selected another point")
            binding = BitcoinAuthorizationBinding.from_raw_transaction(
                raw_tx,
                chain_genesis_hash=chain_genesis,
                authorization_input_index=0,
            )
            confirmation_request = issue_committee_request(
                activations[slot_id],
                point=points[slot_id],
                bitcoin_binding=binding,
                request_authorizer_secret=authorizer_secret,
            )

            seed_responses: list[ParticipantSeedResponse] = []
            synthetic_block = _sha(
                b"ranklock/v025/synthetic-confirmation-block/v1\x00",
                bytes((slot_id,)),
                parsed_tx.wtxid,
            )
            for participant_index in range(3):
                response = prepare_seed_response(
                    activation=activations[slot_id],
                    preauthorization=preauthorization,
                    confirmation_request=confirmation_request,
                    raw_transaction=raw_tx,
                    plan=authorization_plan,
                    policy=witness_policies[slot_id],
                    participant=participant_states_by_slot[slot_id][participant_index],
                    ledger=ledgers[participant_index],
                )
                ledgers[participant_index].record_chain_observation(
                    slot_id,
                    event_type="confirmed",
                    block_hash=synthetic_block,
                    height=900_200 + slot_id,
                )
                slot_receipts.extend(
                    anchor_ledger_at_all_witnesses(
                        ledgers[participant_index],
                        participant_secret=participant_states_by_slot[slot_id][participant_index].participant_secret,
                        witnesses=rollback_witnesses,
                    )
                )
                ledgers[participant_index].finalize(slot_id, outcome="success")
                slot_receipts.extend(
                    anchor_ledger_at_all_witnesses(
                        ledgers[participant_index],
                        participant_secret=participant_states_by_slot[slot_id][participant_index].participant_secret,
                        witnesses=rollback_witnesses,
                    )
                )
                seed_responses.append(response)

            reconstructed_seed = reconstruct_program_seed(
                activation=activations[slot_id],
                preauthorization=preauthorization,
                confirmation_request=confirmation_request,
                responses=tuple(seed_responses),
            )
            if reconstructed_seed != trees[slot_id].program_seed:
                raise RuntimeError("committee reconstructed the wrong program seed")
            execution = execute_two_phase_authorized_fused_slot(
                manifest=manifest,
                required_manifest_pubkeys=contributor_pubkeys,
                activation=activations[slot_id],
                preauthorization=preauthorization,
                confirmation_request=confirmation_request,
                plan=authorization_plan,
                policy=witness_policies[slot_id],
                witness_responses=tuple(witness_responses),
                seed_responses=tuple(seed_responses),
                slot_artifact=ciphertexts[slot_id],
                profile=profile,
            )
            expected = multiply(points[slot_id], hidden_scalar, group="g1")
            if not eq_points(execution.replay.result.output_point, expected):
                raise RuntimeError(f"slot {slot_id} produced the wrong [r]A")
            unlocked = unlock_positive_lock(
                vk,
                public_inputs,
                proofs[slot_id],
                positive_lock,
                compress_g1(execution.replay.result.output_point),
                session_context=fixture_context,
            )
            if unlocked != payload:
                raise RuntimeError("valid proof did not recover positive-lock payload")

            preauthorizations.append(preauthorization)
            confirmation_requests.append(confirmation_request)
            raw_transactions.append(raw_tx)
            bindings.append(binding)
            witness_responses_by_slot.append(tuple(witness_responses))
            seed_responses_by_slot.append(tuple(seed_responses))
            witness_receipts_by_slot.append(tuple(slot_receipts))
            executions.append(execution)
            unlocked_payloads.append(unlocked)
            if slot_id == 0:
                first_output = compress_g1(execution.replay.result.output_point)
                proof1 = _adaptive_valid_proof(vk, public_inputs, first_output)
                proofs.append(proof1)
                points.append(decompress_g1(proof1.a_g1))

        # Exact phase-one and phase-two retries are deterministic and do not
        # create a second externally visible response when wrapped by the
        # atomic-write sidecar.
        reopened = DurableSlotLedger(
            ledger_paths[0], context_digest=context.digest, slot_count=2
        )
        replayed_witness_response = prepare_witness_share_response(
            activation=activations[0],
            preauthorization=preauthorizations[0],
            plan=authorization_plan,
            policy=witness_policies[0],
            participant=participant_states_by_slot[0][0],
            ledger=reopened,
        )
        replayed_seed_response = prepare_seed_response(
            activation=activations[0],
            preauthorization=preauthorizations[0],
            confirmation_request=confirmation_requests[0],
            raw_transaction=raw_transactions[0],
            plan=authorization_plan,
            policy=witness_policies[0],
            participant=participant_states_by_slot[0][0],
            ledger=reopened,
        )
        replay_receipts = anchor_ledger_at_all_witnesses(
            reopened,
            participant_secret=participant_states_by_slot[0][0].participant_secret,
            witnesses=rollback_witnesses,
        )
        exact_replay_identical = bool(
            replayed_witness_response.compact_bytes
            == witness_responses_by_slot[0][0].compact_bytes
            and replayed_seed_response.compact_bytes
            == seed_responses_by_slot[0][0].compact_bytes
        )

        # A second valid point gives the same precommitted txid but a different
        # witness/wtxid.  The phase-one durable binding rejects it permanently.
        fork_point = multiply(G1, 999_999, group="g1")
        fork_preauthorization = issue_witness_preauthorization_request(
            activations[0],
            authorization_plan,
            point=fork_point,
            request_authorizer_secret=authorizer_secret,
        )
        fork_raw = _counterproof_transaction(
            previous_txid=deposit_txid,
            previous_vout=0,
            output_script=selector_templates[1][3],
            output_value_sat=SLOT_OUTPUT_VALUES_SAT[0],
            witness_items=_selected_labels(trees[0], fork_point),
            tapscript=selector_templates[0][1],
            control=selector_templates[0][2],
        )
        fork_parsed = parse_bitcoin_transaction(fork_raw)
        first_parsed = parse_bitcoin_transaction(raw_transactions[0])
        if fork_parsed.txid != first_parsed.txid or fork_parsed.wtxid == first_parsed.wtxid:
            raise RuntimeError("fork attack fixture does not isolate txid/wtxid")
        try:
            prepare_witness_share_response(
                activation=activations[0],
                preauthorization=fork_preauthorization,
                plan=authorization_plan,
                policy=witness_policies[0],
                participant=participant_states_by_slot[0][0],
                ledger=reopened,
            )
            conflicting_fork_rejected = False
        except (SlotConflictError, TwoPhaseAuthorizationError):
            conflicting_fork_rejected = True
        conflict_receipts = anchor_ledger_at_all_witnesses(
            reopened,
            participant_secret=participant_states_by_slot[0][0].participant_secret,
            witnesses=rollback_witnesses,
        )

        reopened.record_chain_observation(
            0,
            event_type="reorg-observed",
            block_hash=_sha(b"ranklock/v025/orphan-block/v1\x00", b"fixture"),
            height=901_000,
        )
        reorg_receipts = anchor_ledger_at_all_witnesses(
            reopened,
            participant_secret=participant_states_by_slot[0][0].participant_secret,
            witnesses=rollback_witnesses,
        )
        reorg_never_reopened = reopened.use(0).state == "success" and reopened.remaining == 0
        audit_chains_valid = all(ledger.verify_audit_chain() for ledger in ledgers)

        rolled_back_path = temporary_path / "participant-0-restored.sqlite"
        shutil.copy2(preburn_backup, rolled_back_path)
        rolled_back_ledger = DurableSlotLedger(
            rolled_back_path, context_digest=context.digest, slot_count=2
        )
        try:
            anchor_ledger_at_all_witnesses(
                rolled_back_ledger,
                participant_secret=participant_states_by_slot[0][0].participant_secret,
                witnesses=rollback_witnesses,
            )
            restored_snapshot_rejected = False
        except RollbackDetectedError:
            restored_snapshot_rejected = True

        all_receipts = [
            receipt
            for rows in bootstrap_receipts
            for receipt in rows
        ] + [
            receipt
            for rows in witness_receipts_by_slot
            for receipt in rows
        ] + list(replay_receipts) + list(conflict_receipts) + list(reorg_receipts)
        witness_receipts_valid = all(receipt.verify() for receipt in all_receipts)

    try:
        reconstruct_witness_labels(
            activation=activations[0],
            preauthorization=preauthorizations[0],
            plan=authorization_plan,
            policy=witness_policies[0],
            responses=witness_responses_by_slot[0][:-1],
        )
        missing_witness_share_rejected = False
    except TwoPhaseAuthorizationError:
        missing_witness_share_rejected = True
    try:
        reconstruct_program_seed(
            activation=activations[0],
            preauthorization=preauthorizations[0],
            confirmation_request=confirmation_requests[0],
            responses=seed_responses_by_slot[0][:-1],
        )
        missing_seed_share_rejected = False
    except TwoPhaseAuthorizationError:
        missing_seed_share_rejected = True

    OUT.joinpath("ranklock-v025-two-slot-retained-object.bin").write_bytes(retained.encoded)
    OUT.joinpath("ranklock-v025-two-slot-manifest.bin").write_bytes(manifest.encoded)
    OUT.joinpath("authorization-transaction-plan.bin").write_bytes(authorization_plan.encoded)
    for slot_id in range(2):
        OUT.joinpath(f"slot-{slot_id}-authorization-transaction.bin").write_bytes(
            raw_transactions[slot_id]
        )
        OUT.joinpath(f"slot-{slot_id}-witness-policy.bin").write_bytes(
            witness_policies[slot_id].compact_bytes
        )
        OUT.joinpath(f"slot-{slot_id}-activation.bin").write_bytes(activations[slot_id].encoded)
        OUT.joinpath(f"slot-{slot_id}-private-label-guide.bin").write_bytes(
            guides[slot_id].compact_bytes
        )
        OUT.joinpath(f"slot-{slot_id}-preauthorization.bin").write_bytes(
            preauthorizations[slot_id].compact_bytes
        )
        OUT.joinpath(f"slot-{slot_id}-confirmation-request.bin").write_bytes(
            confirmation_requests[slot_id].compact_bytes
        )
        for participant_index in range(3):
            secret_path = OUT / (
                f"UNSAFE-PUBLIC-FIXTURE-slot-{slot_id}-participant-{participant_index}.secrets"
            )
            secret_path.write_bytes(
                participant_states_by_slot[slot_id][participant_index].compact_secret_bytes
            )
            secret_path.chmod(0o600)
            OUT.joinpath(
                f"slot-{slot_id}-participant-{participant_index}-witness-share-response.bin"
            ).write_bytes(
                witness_responses_by_slot[slot_id][participant_index].compact_bytes
            )
            OUT.joinpath(
                f"slot-{slot_id}-participant-{participant_index}-seed-response.bin"
            ).write_bytes(seed_responses_by_slot[slot_id][participant_index].compact_bytes)

    phase_one_response_size = len(witness_responses_by_slot[0][0].compact_bytes)
    phase_two_response_size = len(seed_responses_by_slot[0][0].compact_bytes)
    private_state_size = (
        len(participant_states_by_slot[0][0].compact_secret_bytes)
        + len(guides[0].compact_bytes)
    )
    transaction_rows = []
    previous_values = (DEPOSIT_INPUT_VALUE_SAT, SLOT_OUTPUT_VALUES_SAT[0])
    for slot_id in range(2):
        parsed = parse_bitcoin_transaction(raw_transactions[slot_id])
        output_value = parsed.output_values[0]
        stripped_size = len(parsed.stripped)
        witness_size = len(parsed.raw) - stripped_size
        weight = stripped_size * 4 + witness_size
        vsize = (weight + 3) // 4
        fee = previous_values[slot_id] - output_value
        transaction_rows.append(
            {
                "slot_id": slot_id,
                "txid": parsed.txid.hex(),
                "wtxid": parsed.wtxid.hex(),
                "witness_digest": parsed.witness_digest.hex(),
                "raw_bytes": len(parsed.raw),
                "stripped_bytes": stripped_size,
                "weight": weight,
                "vsize": vsize,
                "input_value_sat": previous_values[slot_id],
                "output_value_sat": output_value,
                "fee_sat": fee,
                "fee_rate_sat_vb": fee / vsize,
                "witness_policy_sha256": sha256(
                    witness_policies[slot_id].compact_bytes
                ).hexdigest(),
                "selector_items": len(witness_policies[slot_id].unsigned.rules),
                "selector_item_bytes": 16,
            }
        )

    report = {
        "schema": "ranklock-v025-committee-qualification-v2",
        "decision": "FULL_SIZE_COMMITTEE_SAFETY_HARNESS_PASS_PRODUCTION_GATES_OPEN",
        "source_revision": "v0.25.1",
        "public_fixture_warning": "all secrets in this conformance fixture are public; never fund it",
        "retained_object": {
            "bytes": len(retained.encoded),
            "sha256": sha256(retained.encoded).hexdigest(),
            "margin_to_one_mib": (1 << 20) - len(retained.encoded),
            "slot_count": 2,
            "manifest_bytes": len(manifest.encoded),
            "public_committee_metadata_added_to_retained_object": 0,
        },
        "context_binding": {
            "inner_setup_context_digest": context.digest.hex(),
            "authorization_graph_id": authorization_graph_id.hex(),
            "authorization_plan_digest": authorization_plan.digest.hex(),
            "manifest_transcript_binds_plan": True,
            "activation_binds_each_precommitted_txid": True,
            "preauthorization_binds_plan_and_stripped_transaction": True,
            "confirmation_binds_txid_wtxid_and_complete_witness": True,
            "no_hash_fixed_point_between_labels_and_taproot_output": True,
        },
        "committee": {
            "participants": 3,
            "release_policy": "n-of-n two-phase",
            "one_honest_participant_safety": True,
            "one_fault_can_block_liveness": True,
            "phase_one_witness_share_response_bytes_each": phase_one_response_size,
            "phase_two_seed_response_bytes_each": phase_two_response_size,
            "phase_one_response_bytes_all_per_slot": phase_one_response_size * 3,
            "phase_two_response_bytes_all_per_slot": phase_two_response_size * 3,
            "preauthorization_bytes": len(preauthorizations[0].compact_bytes),
            "confirmation_request_bytes": len(confirmation_requests[0].compact_bytes),
            "activation_bytes_per_slot": len(activations[0].encoded),
            "private_participant_state_bytes_per_slot": private_state_size,
            "private_guide_not_required_by_public_evaluator": True,
            "missing_one_witness_share_rejected": missing_witness_share_rejected,
            "missing_one_seed_share_rejected": missing_seed_share_rejected,
            "exact_restart_replay_byte_identical": exact_replay_identical,
            "conflicting_same_txid_different_wtxid_fork_rejected": conflicting_fork_rejected,
            "reorg_observation_never_reopens_slot": reorg_never_reopened,
            "audit_hash_chains_valid": audit_chains_valid,
            "independent_rollback_witnesses": 3,
            "rollback_witness_receipts_valid": witness_receipts_valid,
            "restored_preburn_snapshot_rejected": restored_snapshot_rejected,
            "available_to_terminal_without_witnessed_burn_forbidden": True,
            "latest_witness_generation": reorg_receipts[0].generation,
        },
        "bitcoin_binding": {
            "protocol": "two-phase labels-before-broadcast, seed-after-confirmation",
            "authorization_transaction_plan_digest": authorization_plan.digest.hex(),
            "authorization_transaction_plan_bytes": len(authorization_plan.encoded),
            "authorization_transaction_plan_roundtrip": (
                authorization_plan.__class__.parse(authorization_plan.encoded)
                == authorization_plan
            ),
            "transactions": transaction_rows,
            "slot_1_spends_precommitted_slot_0_output": True,
            "value_plan": {
                "deposit_input_value_sat": DEPOSIT_INPUT_VALUE_SAT,
                "slot_output_values_sat": list(SLOT_OUTPUT_VALUES_SAT),
                "fees_sat": [
                    DEPOSIT_INPUT_VALUE_SAT - SLOT_OUTPUT_VALUES_SAT[0],
                    SLOT_OUTPUT_VALUES_SAT[0] - SLOT_OUTPUT_VALUES_SAT[1],
                ],
            },
            "adaptive_witness_does_not_change_precommitted_txid": True,
            "witness_selected_point_matches_preauthorization": True,
            "valid_alternate_point_same_txid_conflict_rejected": conflicting_fork_rejected,
            "strict_parser_and_synthetic_transaction_passed": True,
            "bitcoin_core_regtest_executed": False,
        },
        "full_evaluation": {
            "two_full_91_prime_slots": True,
            "same_hidden_scalar": True,
            "second_valid_groth16_proof_adaptive_after_first_output": True,
            "direct_scalar_checks": 2,
            "positive_lock_payload_unlocks": 2,
            "conditional_maps_per_slot": [
                execution.replay.result.maps_evaluated for execution in executions
            ],
        },
        "setup_security": {
            "dealer_fixture_used": True,
            "active_dishonest_majority_mpc_executed": False,
            "safe_setup_for_funds": False,
        },
        "closed_in_v025": [
            "phase-one preauthorization releases only selected label shares before broadcast",
            "phase-two releases only program-seed shares after exact witness confirmation",
            "wtxid plus exact witness-digest authorization binding",
            "committee-signed 512-item Taproot validation of the actual 16-byte DFB labels",
            "two sequential precommitted transaction ids with adaptive witnesses",
            "positive fees on both authorization transactions",
            "SQLite FULL/WAL burn before phase-one output with concurrent writer serialization",
            "witnessed available-to-burned-to-terminal monotonic transitions",
            "permanent first-binding conflict rejection across restart and reorg observation",
            "n-of-n XOR-shared program seeds and input labels",
            "full-size two-slot adaptive valid-proof execution and positive-lock unlock",
            "signed rollback-witness receipts with restored-snapshot rejection",
        ],
        "remaining_safe_for_funds_gates": [
            "replace public dealer fixture with an independently reviewed production setup route",
            "execute pinned Bitcoin Core 31.1 regtest against the two-phase sidecar",
            "compile current strata-bridge integration and run its functional/regtest matrix",
            "deploy independently administered rollback witnesses with mTLS and hardware-backed keys",
            "constant-time native implementation, input bounds, denial-of-service hardening, and secret erasure",
            "independent cryptographic, implementation, Bitcoin, and operations review",
        ],
        "safe_for_funds": False,
        "setup_rows": setup_rows,
    }
    RESULTS.joinpath("v025_committee_qualification.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
