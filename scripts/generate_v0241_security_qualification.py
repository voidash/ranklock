from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ranklock.adaptive_sealing import (
    parse_sealed_retained_object,
    program_seed_commitment,
    seal_fused_slot,
)
from ranklock.authorized_labels import (
    AuthorizedLabelRelease,
    EvaluationContext,
    LabelAuthorizationError,
    LabelCommitmentTree,
    execute_authorized_fused_slot,
    issue_label_release,
)
from ranklock.babe_positive_lock import deterministic_fixture, setup_positive_lock
from ranklock.bip340 import public_key, sign
from ranklock.bn254_real import CURVE_ORDER, G1, add, compress_g1, eq_points, multiply
from ranklock.bounded_mpc_embryo import (
    ActiveMpcProfile,
    BoundedEmbryoError,
    BoundedSlotLedger,
    UnsignedBoundedEmbryoManifest,
    sign_manifest_fixture,
    slot_descriptor_from_artifact,
)
from ranklock.dfb_real import DfbProfile
from ranklock.embryo_mask_fusion import (
    CURRENT_MANIFEST_BYTES,
    FIRST_91_PRIMES,
    FusedRetainedObject,
    build_mask_fused_template,
    serialize_fused_slot,
)
from ranklock.embryo_real import EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION
from ranklock.security_qualification import (
    qualify_exceptional_inputs,
    qualify_input_commitments,
    qualify_mask_fusion,
    qualify_rom_adaptive_wrapper,
)


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
RESULTS = ROOT / "results"
PACKAGE_VERSION = "0.24.1"
PROTOCOL_REVISION = "ranklock-v0.24.1"


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha256(domain)
    for part in parts:
        h.update(bytes(part))
    return h.digest()


def _context() -> EvaluationContext:
    return EvaluationContext(
        chain_genesis_hash=_sha(b"ranklock/v0241/chain/v1\x00", b"bitcoin-regtest"),
        program_id=_sha(b"ranklock/v0241/program/v1\x00", b"strata-bridge-counterproof"),
        verifier_key_digest=_sha(b"ranklock/v0241/vk/v1\x00", b"sp1-groth16-bridge-vk"),
        deposit_outpoint=_sha(b"ranklock/v0241/deposit/v1\x00", b"fixture")
        + (3).to_bytes(4, "little"),
        game_index=7,
        operator_index=2,
        counterproof_txid=_sha(b"ranklock/v0241/counterproof-tx/v1\x00", b"fixture"),
        epoch=11,
        deadline_height=900_000,
    )


def _generator_code_hash(base_profile: DfbProfile) -> bytes:
    h = hashlib.sha256(b"ranklock/v0241/security-qualified-generator-code/v2\x00")
    for relative in (
        "src/ranklock/dfb_real.py",
        "src/ranklock/embryo_real.py",
        "src/ranklock/embryo_mask_fusion.py",
        "src/ranklock/adaptive_sealing.py",
        "src/ranklock/security_qualification.py",
        "src/ranklock/authorized_labels.py",
        "scripts/generate_v0241_security_qualification.py",
    ):
        h.update(relative.encode())
        h.update((ROOT / relative).read_bytes())
    for slot_id in range(2):
        h.update(
            json.dumps(
                base_profile.with_nonce_namespace(slot_id).document(
                    (EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION)
                ),
                sort_keys=True,
            ).encode()
        )
    return h.digest()


def _adaptive_second_scalar(first_output: bytes) -> int:
    scalar = int.from_bytes(
        _sha(b"ranklock/v0241/adaptive-second-input/v1\x00", first_output), "big"
    ) % CURVE_ORDER
    return scalar or 1


class _EntropySource:
    """OS entropy by default; an explicit environment seed is test-only."""

    def __init__(self) -> None:
        configured = os.environ.get("RANKLOCK_V0241_INSECURE_REPRO_SEED")
        if configured is None:
            # Compatibility with the incomplete v0.24 checkpoint.  New
            # reproduction instructions use only the v0.24.1 name.
            configured = os.environ.get("RANKLOCK_V024_INSECURE_REPRO_SEED")
        self._master = None if configured is None else configured.encode()
        self.mode = (
            "os-random-unfunded-evidence"
            if self._master is None
            else "INSECURE-public-deterministic-conformance"
        )
        self._counter = 0

    @property
    def deterministic(self) -> bool:
        return self._master is not None

    @property
    def seed_fingerprint(self) -> str | None:
        if self._master is None:
            return None
        return hashlib.sha256(
            b"ranklock/v0241/reproduction-seed-fingerprint/v1\x00" + self._master
        ).hexdigest()

    def bytes(self, domain: bytes, length: int = 32) -> bytes:
        if self._master is None:
            return secrets.token_bytes(length)
        self._counter += 1
        transcript = (
            b"ranklock/v0241/insecure-repro-entropy/v1\x00"
            + self._master
            + len(domain).to_bytes(4, "big")
            + domain
            + self._counter.to_bytes(8, "big")
        )
        return hashlib.shake_256(transcript).digest(length)

    def scalar(self, domain: bytes) -> int:
        if self._master is None:
            return secrets.randbelow(CURVE_ORDER - 1) + 1
        return int.from_bytes(self.bytes(domain, 64), "big") % (CURVE_ORDER - 1) + 1


def _negative_authorization_tests(
    *,
    context: EvaluationContext,
    manifest,
    contributor_pubkeys: tuple[bytes, ...],
    base_profile: DfbProfile,
    ciphertexts: list[bytes],
    releases: list[AuthorizedLabelRelease],
    authorizer_secret: int,
) -> dict[str, bool]:
    authorizer_pubkey = public_key(authorizer_secret)

    forged = replace(releases[0], authorizer_signature=bytes(64))
    forged_ledger = BoundedSlotLedger(context.digest, 2)
    try:
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=authorizer_pubkey,
            ledger=forged_ledger,
            slot_artifact=ciphertexts[0],
            profile=base_profile,
            release=forged,
        )
        forged_rejected = False
    except LabelAuthorizationError:
        forged_rejected = forged_ledger.remaining == 2

    crosswired_unsigned = replace(
        releases[0], slot_id=1, authorizer_signature=bytes(64)
    )
    crosswired = replace(
        crosswired_unsigned,
        authorizer_signature=sign(crosswired_unsigned.signing_message, authorizer_secret),
    )
    crosswire_ledger = BoundedSlotLedger(context.digest, 2)
    try:
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=authorizer_pubkey,
            ledger=crosswire_ledger,
            slot_artifact=ciphertexts[1],
            profile=base_profile,
            release=crosswired,
        )
        crosswire_rejected = False
    except LabelAuthorizationError:
        crosswire_rejected = crosswire_ledger.remaining == 2

    first = releases[0].openings[0]
    tampered = replace(
        releases[0],
        openings=(replace(first, label=bytes(16)),) + releases[0].openings[1:],
    )
    tamper_ledger = BoundedSlotLedger(context.digest, 2)
    try:
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=authorizer_pubkey,
            ledger=tamper_ledger,
            slot_artifact=ciphertexts[0],
            profile=base_profile,
            release=tampered,
        )
        tampered_opening_rejected_without_burn = False
    except LabelAuthorizationError:
        tampered_opening_rejected_without_burn = tamper_ledger.remaining == 2

    malformed_unsigned = replace(tampered, authorizer_signature=bytes(64))
    malformed = replace(
        malformed_unsigned,
        authorizer_signature=sign(
            malformed_unsigned.signing_message, authorizer_secret
        ),
    )
    malformed_ledger = BoundedSlotLedger(context.digest, 2)
    try:
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=authorizer_pubkey,
            ledger=malformed_ledger,
            slot_artifact=ciphertexts[0],
            profile=base_profile,
            release=malformed,
        )
        malformed_rejected_and_burned = False
    except LabelAuthorizationError:
        malformed_rejected_and_burned = (
            malformed_ledger.use(0).outcome == "malformed"
            and malformed_ledger.remaining == 1
        )

    outsider_seed_substitution = replace(
        releases[0],
        program_seed=_sha(b"ranklock/v0241/substituted-seed/v1\x00", b"outsider"),
    )
    seed_ledger = BoundedSlotLedger(context.digest, 2)
    try:
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=authorizer_pubkey,
            ledger=seed_ledger,
            slot_artifact=ciphertexts[0],
            profile=base_profile,
            release=outsider_seed_substitution,
        )
        outsider_seed_rejected = False
    except LabelAuthorizationError:
        outsider_seed_rejected = seed_ledger.remaining == 2

    signed_bad_seed_unsigned = replace(
        releases[0],
        program_seed=_sha(b"ranklock/v0241/substituted-seed/v1\x00", b"signed"),
        authorizer_signature=bytes(64),
    )
    signed_bad_seed = replace(
        signed_bad_seed_unsigned,
        authorizer_signature=sign(
            signed_bad_seed_unsigned.signing_message, authorizer_secret
        ),
    )
    signed_seed_ledger = BoundedSlotLedger(context.digest, 2)
    try:
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=authorizer_pubkey,
            ledger=signed_seed_ledger,
            slot_artifact=ciphertexts[0],
            profile=base_profile,
            release=signed_bad_seed,
        )
        signed_bad_seed_rejected_and_burned = False
    except LabelAuthorizationError:
        signed_bad_seed_rejected_and_burned = (
            signed_seed_ledger.use(0).outcome == "malformed"
            and signed_seed_ledger.remaining == 1
        )

    return {
        "forged_signature_rejected_without_burn": forged_rejected,
        "validly_resigned_cross_slot_release_rejected_without_burn": crosswire_rejected,
        "outsider_opening_tamper_rejected_without_burn": tampered_opening_rejected_without_burn,
        "valid_authorization_with_bad_opening_rejected_and_burned": malformed_rejected_and_burned,
        "outsider_program_seed_substitution_rejected_without_burn": outsider_seed_rejected,
        "validly_signed_wrong_program_seed_rejected_and_burned": signed_bad_seed_rejected_and_burned,
    }


def main() -> None:
    ARTIFACTS.mkdir(exist_ok=True)
    RESULTS.mkdir(exist_ok=True)
    for stale in ARTIFACTS.glob("embryo-v0241-slot-*-compact-program.bin"):
        stale.unlink()
    for stale in ARTIFACTS.glob("embryo-v0241-slot-*-fused-masks.bin"):
        stale.unlink()

    entropy = _EntropySource()
    hidden_scalar = entropy.scalar(b"same-hidden-scalar")
    authorizer_secret = entropy.scalar(b"authorization-signing-key")
    contributor_secrets = (
        entropy.scalar(b"manifest-contributor-0"),
        entropy.scalar(b"manifest-contributor-1"),
    )

    base_profile = DfbProfile(primes=FIRST_91_PRIMES)
    context = _context()
    fusion_qualification = qualify_mask_fusion(profile=base_profile, slots=2)
    input_qualification = qualify_input_commitments(slots=2)
    if not fusion_qualification.composition_preconditions_machine_checked:
        raise RuntimeError("v0.24.1 machine-checkable fusion preconditions failed")
    if not input_qualification.gate_passed:
        raise RuntimeError("v0.24.1 authenticated-input qualification failed")

    # SETUP PHASE. Both complete selectively-secure plaintext slots are generated,
    # sealed, committed and published before either future point is selected.
    templates = []
    mask_states = []
    plaintexts: list[bytes] = []
    ciphertexts: list[bytes] = []
    trees: list[LabelCommitmentTree] = []
    program_seeds: list[bytes] = []
    setup_rows = []
    for slot_id in range(2):
        slot_profile = base_profile.with_nonce_namespace(slot_id)
        garbling, template, mask_state, metadata = build_mask_fused_template(
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
            input_bits=base_profile.input_bits,
            program_seed=program_seed,
        )
        templates.append((garbling, template, metadata))
        mask_states.append(mask_state)
        plaintexts.append(plaintext)
        ciphertexts.append(ciphertext)
        trees.append(tree)
        program_seeds.append(program_seed)
        setup_rows.append(
            {
                "slot_id": slot_id,
                "nonce_namespace": slot_profile.nonce_namespace,
                "plaintext_bytes": len(plaintext),
                "ciphertext_bytes": len(ciphertext),
                "length_preserved": len(plaintext) == len(ciphertext),
                "sealed_artifact_sha256": hashlib.sha256(ciphertext).hexdigest(),
                "program_seed_commitment": program_seed_commitment(program_seed).hex(),
                "input_label_root": tree.root.hex(),
                "no_wrap_limit": metadata.no_wrap_limit,
            }
        )
        (ARTIFACTS / f"embryo-v0241-slot-{slot_id}.bin").write_bytes(ciphertext)

    if ciphertexts[0] == ciphertexts[1] or trees[0].root == trees[1].root:
        raise RuntimeError("independent slots did not separate ciphertext/root state")

    adaptive_qualification = qualify_rom_adaptive_wrapper(
        program_seeds=program_seeds,
        label_roots=[tree.root for tree in trees],
        plaintext_lengths=[len(value) for value in plaintexts],
        ciphertext_lengths=[len(value) for value in ciphertexts],
        pre_release_query_budget_per_slot=1 << 64,
    )
    exceptional_qualification = qualify_exceptional_inputs(
        slots=2, one_shot_burn_enforced=True
    )
    if not adaptive_qualification.gate_passed:
        raise RuntimeError("whole-slot ROM adaptive-input qualification failed")
    if not exceptional_qualification.gate_passed:
        raise RuntimeError("exceptional-input one-shot qualification failed")

    fixture_context = b"ranklock-v0241-security-qualified-two-slot" + context.digest
    vk, public_inputs, _proof = deterministic_fixture(context=fixture_context)
    lock = setup_positive_lock(
        vk,
        public_inputs,
        entropy.bytes(b"positive-lock-payload"),
        scale=hidden_scalar,
        session_context=fixture_context,
    )
    descriptors = tuple(
        slot_descriptor_from_artifact(
            slot_id,
            ciphertexts[slot_id],
            input_label_commitment=trees[slot_id].root,
            independence_nonce=(
                f"ranklock/v0241/slot-{slot_id}/independent-random-tape-rom-seed-and-nonce-domain"
            ).encode(),
        )
        for slot_id in range(2)
    )
    contributor_pubkeys = tuple(sorted(public_key(s) for s in contributor_secrets))
    mpc_profile = ActiveMpcProfile(parties=len(contributor_secrets))
    transcript_digest = _sha(
        b"ranklock/v0241/ceremony-transcript/v2\x00",
        mpc_profile.digest,
        context.digest,
        *(descriptor.artifact_root for descriptor in descriptors),
        *(descriptor.input_label_root for descriptor in descriptors),
        *(program_seed_commitment(seed) for seed in program_seeds),
    )
    unsigned = UnsignedBoundedEmbryoManifest(
        context_digest=context.digest,
        generator_code_hash=_generator_code_hash(base_profile),
        transcript_digest=transcript_digest,
        positive_lock=lock,
        slots=descriptors,
        contributor_pubkeys=contributor_pubkeys,
    )
    manifest = sign_manifest_fixture(unsigned, contributor_secrets)
    if manifest.encoded_bytes != CURRENT_MANIFEST_BYTES:
        raise RuntimeError(f"manifest size drift: {manifest.encoded_bytes}")
    if not manifest.verify(
        required_pubkeys=contributor_pubkeys,
        expected_context_digest=context.digest,
        expected_generator_code_hash=unsigned.generator_code_hash,
    ):
        raise RuntimeError("v0.24.1 manifest verification failed")

    retained = FusedRetainedObject(manifest=manifest, slots=tuple(ciphertexts))
    parsed = parse_sealed_retained_object(retained.encoded)
    if parsed.encoded != retained.encoded:
        raise RuntimeError("v0.24.1 sealed retained object changed under canonical parsing")
    retained_path = ARTIFACTS / "ranklock-v0241-two-slot-retained-object.bin"
    manifest_path = ARTIFACTS / "ranklock-v0241-two-slot-manifest.bin"
    retained_path.write_bytes(retained.encoded)
    manifest_path.write_bytes(manifest.encoded)

    # ONLINE PHASE. A1 is fixed after both ciphertexts are public. Its seed and
    # labels are released atomically. Only after obtaining Y1 is A2 derived.
    ledger = BoundedSlotLedger(context.digest, 2)
    releases: list[AuthorizedLabelRelease] = []
    authorized_replays = []
    points = [multiply(G1, 1_234_567, group="g1")]

    release0 = issue_label_release(
        trees[0],
        point=points[0],
        authorization_txid=_sha(
            b"ranklock/v0241/authorization-tx/v1\x00", context.digest, b"slot-0"
        ),
        authorizer_secret=authorizer_secret,
    )
    replay0 = execute_authorized_fused_slot(
        manifest=manifest,
        required_manifest_pubkeys=contributor_pubkeys,
        context=context,
        expected_authorizer_pubkey=public_key(authorizer_secret),
        ledger=ledger,
        slot_artifact=ciphertexts[0],
        profile=base_profile,
        release=release0,
    )
    expected0 = multiply(points[0], hidden_scalar, group="g1")
    if not eq_points(replay0.replay.result.output_point, expected0):
        raise RuntimeError("authorized replay 0 produced wrong [r]A1")
    releases.append(release0)
    authorized_replays.append(replay0)

    first_output_encoding = compress_g1(replay0.replay.result.output_point)
    a2_scalar = _adaptive_second_scalar(first_output_encoding)
    points.append(multiply(G1, a2_scalar, group="g1"))
    release1 = issue_label_release(
        trees[1],
        point=points[1],
        authorization_txid=_sha(
            b"ranklock/v0241/authorization-tx/v1\x00",
            context.digest,
            b"slot-1",
            first_output_encoding,
        ),
        authorizer_secret=authorizer_secret,
    )
    replay1 = execute_authorized_fused_slot(
        manifest=manifest,
        required_manifest_pubkeys=contributor_pubkeys,
        context=context,
        expected_authorizer_pubkey=public_key(authorizer_secret),
        ledger=ledger,
        slot_artifact=ciphertexts[1],
        profile=base_profile,
        release=release1,
    )
    expected1 = multiply(points[1], hidden_scalar, group="g1")
    if not eq_points(replay1.replay.result.output_point, expected1):
        raise RuntimeError("authorized replay 1 produced wrong [r]A2")
    releases.append(release1)
    authorized_replays.append(replay1)

    for slot_id, release in enumerate(releases):
        if release.compact_size != 24_836:
            raise RuntimeError("authorized label witness size drift")
        path = ARTIFACTS / f"ranklock-v0241-slot-{slot_id}-authorized-label-release.bin"
        path.write_bytes(release.compact_bytes)
        if AuthorizedLabelRelease.parse_compact(path.read_bytes()) != release:
            raise RuntimeError("authorized release failed canonical roundtrip")

    if ledger.remaining != 0:
        raise RuntimeError("both one-shot slots were not consumed")
    try:
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=public_key(authorizer_secret),
            ledger=ledger,
            slot_artifact=ciphertexts[0],
            profile=base_profile,
            release=releases[0],
        )
        replay_rejected = False
    except BoundedEmbryoError:
        replay_rejected = True
    if not replay_rejected:
        raise RuntimeError("consumed slot accepted a replay")

    attack_results = _negative_authorization_tests(
        context=context,
        manifest=manifest,
        contributor_pubkeys=contributor_pubkeys,
        base_profile=base_profile,
        ciphertexts=ciphertexts,
        releases=releases,
        authorizer_secret=authorizer_secret,
    )
    if not all(attack_results.values()):
        raise RuntimeError(f"authorization attack regression: {attack_results}")

    # Corrected third-point boundary: raw linear derivation is unavoidable,
    # while an accepted third protocol evaluation is impossible with two slots.
    a3 = add(points[0], points[1], group="g1")
    y3_from_outputs = add(
        authorized_replays[0].replay.result.output_point,
        authorized_replays[1].replay.result.output_point,
        group="g1",
    )
    y3_direct = multiply(a3, hidden_scalar, group="g1")
    if not eq_points(y3_from_outputs, y3_direct):
        raise RuntimeError("group-linearity regression")

    slot_rows = []
    for slot_id in range(2):
        output = authorized_replays[slot_id].replay.result.output_point
        slot_rows.append(
            {
                **setup_rows[slot_id],
                "input_selection": (
                    "fixed only after both sealed slots were published"
                    if slot_id == 0
                    else "SHA256([r]A1)-adaptive while slot-1 seed remained hidden"
                ),
                "input_scalar": 1_234_567 if slot_id == 0 else a2_scalar,
                "input_point": compress_g1(points[slot_id]).hex(),
                "output_point": compress_g1(output).hex(),
                "output_matches_direct_scalar_multiplication": True,
                "authorized_release_bytes": releases[slot_id].compact_size,
                "authorized_release_sha256": hashlib.sha256(
                    releases[slot_id].compact_bytes
                ).hexdigest(),
                "slot_outcome": authorized_replays[slot_id].slot_use.outcome,
                "conditional_maps_verified": authorized_replays[
                    slot_id
                ].replay.result.maps_evaluated,
            }
        )

    storage_bytes = retained.encoded_bytes
    report = {
        "schema": "ranklock-v0241-security-qualification-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "package_version": PACKAGE_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "decision": "REPRODUCIBLE_CONDITIONAL_SECURITY_HARNESS_COMPLETE_NOT_PRODUCTION_QUALIFIED",
        "generation_entropy": {
            "mode": entropy.mode,
            "uses_os_entropy": not entropy.deterministic,
            "public_deterministic_conformance_mode": entropy.deterministic,
            "reproduction_seed_fingerprint": entropy.seed_fingerprint,
            "hidden_scalar_sampled_from_os_entropy": not entropy.deterministic,
            "dfb_and_embryo_tapes_independent_per_slot": True,
            "program_seeds_independent_per_slot": True,
            "signing_keys_derived_from_selected_entropy_source": True,
            "deterministic_mode_is_explicitly_insecure": True,
            "fixture_must_never_hold_funds": True,
        },
        "retained_object": {
            "path": str(retained_path.relative_to(ROOT)),
            "bytes": storage_bytes,
            "sha256": hashlib.sha256(retained.encoded).hexdigest(),
            "margin_to_one_mib": (1 << 20) - storage_bytes,
            "canonical_opaque_roundtrip": True,
            "manifest_bytes": manifest.encoded_bytes,
            "slot_count": 2,
            "whole_slot_sealing_retained_byte_overhead": 0,
        },
        "protocol_chronology": {
            "both_plaintext_slots_generated_before_A1": True,
            "both_complete_slots_sealed_before_A1": True,
            "manifest_and_both_ciphertexts_published_before_A1": True,
            "A1_fixed_before_slot0_seed_release": True,
            "A2_derived_only_after_Y1": True,
            "slot1_seed_hidden_until_after_A2_fixed": True,
            "seed_and_selected_labels_released_atomically": True,
        },
        "corrected_two_instance_game": {
            "same_hidden_scalar_used_by_both_slots": True,
            "hidden_scalar_not_serialized_in_report": True,
            "A2_adaptive_after_Y1": True,
            "authorized_outputs_correct": True,
            "accepted_evaluations": 2,
            "third_accepted_evaluation_rejected": replay_rejected,
            "raw_linear_third_output_derivable": True,
            "raw_linear_example": "[r](A1+A2)=[r]A1+[r]A2",
            "fresh_independent_A3_security": (
                "reduction to the post-challenge two-query one-more scalar-multiplication assumption"
            ),
        },
        "security_qualification": {
            "fusion": fusion_qualification.document(),
            "rom_adaptive_wrapper": adaptive_qualification.document(),
            "input_commitments": input_qualification.document(),
            "exceptional_inputs": exceptional_qualification.document(),
        },
        "authorization": {
            "context_digest": context.digest.hex(),
            "context": {
                "chain_genesis_hash": context.chain_genesis_hash.hex(),
                "program_id": context.program_id.hex(),
                "verifier_key_digest": context.verifier_key_digest.hex(),
                "deposit_outpoint": context.deposit_outpoint.hex(),
                "game_index": context.game_index,
                "operator_index": context.operator_index,
                "counterproof_txid": context.counterproof_txid.hex(),
                "epoch": context.epoch,
                "deadline_height": context.deadline_height,
            },
            "authorizer_pubkey": public_key(authorizer_secret).hex(),
            "exactly_one_label_per_bit": True,
            "labels_per_release": 512,
            "release_bytes_each": releases[0].compact_size,
            "release_bytes_two_slots": sum(r.compact_size for r in releases),
            "release_bytes_retained": False,
            "evidence_archive_contains_post_use_release_transcripts": True,
            "whole_slot_program_seed_released_atomically": True,
            "slot_burn_before_point_label_or_program_parsing": True,
            "replay_rejected": replay_rejected,
            "cross_slot_context_point_root_seed_and_tx_binding": True,
            "attack_regressions": attack_results,
        },
        "positive_lock_side_information": {
            "included_in_public_view": True,
            "claim_boundary": (
                "sealed DFB/Embryo slots add no leakage beyond authorized outputs; "
                "the BABE positive lock is separate public side information covered by its own assumption"
            ),
        },
        "slots": slot_rows,
        "closed_gates": [
            "exact uniform CRT body-pad sampling",
            "machine-checked triangular mask-fusion algebra",
            "disjoint per-slot CCRH nonce namespaces",
            "whole-program-plus-decoder ROM sealing with zero retained-byte overhead",
            "correct two-artifact-before-input adaptive chronology",
            "canonical context-bound exactly-one-label-per-bit authorization",
            "program-seed, point, slot, transaction and label-root binding",
            "burn-before-evaluate replay and selective-failure control",
            "one-shot hidden-phi exceptional-input bound above 243 bits",
            "corrected raw-linearity versus accepted-third-evaluation boundary",
        ],
        "formal_assumptions": [
            "selective privacy of the exact fused DFB/Embryo slot under CCRH",
            "Bellare-Hoang-Rogaway whole-garbled-function coarse-adaptive transform in the random-oracle model",
            "SHA-256 commitment/collision/preimage resistance and BIP340 EUF-CMA",
            "BN254 discrete logarithm and post-challenge two-query one-more scalar multiplication",
            "BABE positive-lock security for the explicit public lock side information",
        ],
        "remaining_production_gates": [
            "actively secure dishonest-majority MPC execution of this exact fused and sealed generator",
            "Bitcoin witness extraction plus Bitcoin Core regtest for atomic seed/label release and burn semantics",
            "constant-time implementation, denial-of-service hardening and independent cryptographic audit",
        ],
        "reproducibility_boundary": {
            "complete_source_required": True,
            "deterministic_fixture_is_public_and_insecure": entropy.deterministic,
            "report_is_evidence_not_an_independent_audit": True,
        },
        "safe_for_funds": False,
    }
    report_path = RESULTS / "v0241_security_qualification.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
