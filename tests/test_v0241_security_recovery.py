from __future__ import annotations

from dataclasses import replace
import hashlib

import numpy as np
import pytest

from ranklock.adaptive_sealing import (
    open_fused_slot,
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
from ranklock.bn254_real import G1, multiply
from ranklock.bounded_mpc_embryo import (
    BoundedSlotLedger,
    UnsignedBoundedEmbryoManifest,
    sign_manifest_fixture,
    slot_descriptor_from_artifact,
)
from ranklock.dfb_real import CoordinateInputEncoding, DfbProfile
from ranklock.embryo_mask_fusion import FusedRetainedObject, FIRST_91_PRIMES
from ranklock.security_qualification import (
    qualify_exceptional_inputs,
    qualify_input_commitments,
    qualify_mask_fusion,
    qualify_rom_adaptive_wrapper,
)


def _sha(tag: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(tag + payload).digest()


def _context() -> EvaluationContext:
    return EvaluationContext(
        chain_genesis_hash=_sha(b"chain", b"regtest"),
        program_id=_sha(b"program", b"bridge"),
        verifier_key_digest=_sha(b"vk", b"fixture"),
        deposit_outpoint=_sha(b"deposit", b"fixture") + (1).to_bytes(4, "little"),
        game_index=9,
        operator_index=2,
        counterproof_txid=_sha(b"counterproof", b"fixture"),
        epoch=4,
        deadline_height=777,
    )


def _encoding(input_bits: int, offset: int) -> CoordinateInputEncoding:
    words = (np.arange(input_bits * 2, dtype=np.uint64) + np.uint64(offset)).reshape(
        input_bits, 2
    )
    return CoordinateInputEncoding(
        masks=words.copy(),
        labels=words.copy(),
        delta=0xD6E8FEB86659FD93A5A3564E27F88691 ^ offset,
    )


def _tree(input_bits: int = 256, slot_id: int = 0) -> LabelCommitmentTree:
    return LabelCommitmentTree.from_input_encodings(
        (_encoding(input_bits, 100 + slot_id), _encoding(input_bits, 1000 + slot_id)),
        context_digest=_context().digest,
        slot_id=slot_id,
        input_bits=input_bits,
        program_seed=_sha(b"seed", bytes([slot_id])),
    )


def _manifest_for_artifacts(
    context: EvaluationContext, artifacts: tuple[bytes, ...], trees: tuple[LabelCommitmentTree, ...]
):
    fixture_context = b"ranklock-v0241-test" + context.digest
    vk, public_inputs, _proof = deterministic_fixture(context=fixture_context)
    lock = setup_positive_lock(
        vk,
        public_inputs,
        b"payload".ljust(32, b"\0"),
        scale=17,
        session_context=fixture_context,
    )
    descriptors = tuple(
        slot_descriptor_from_artifact(
            slot_id,
            artifact,
            input_label_commitment=trees[slot_id].root,
            independence_nonce=f"ranklock-v0241-independent-slot-{slot_id}".encode(),
        )
        for slot_id, artifact in enumerate(artifacts)
    )
    secrets = (7, 11)
    pubkeys = tuple(sorted(public_key(secret) for secret in secrets))
    unsigned = UnsignedBoundedEmbryoManifest(
        context_digest=context.digest,
        generator_code_hash=_sha(b"generator", b"test"),
        transcript_digest=_sha(b"transcript", b"test"),
        positive_lock=lock,
        slots=descriptors,
        contributor_pubkeys=pubkeys,
    )
    return sign_manifest_fixture(unsigned, secrets), pubkeys


def test_whole_slot_sealing_is_equal_length_and_domain_separated():
    plaintext = bytes(range(251)) * 3
    context = _context().digest
    seed = bytes(range(32))
    first = seal_fused_slot(
        plaintext, context_digest=context, slot_id=0, program_seed=seed
    )
    second = seal_fused_slot(
        plaintext, context_digest=context, slot_id=1, program_seed=seed
    )
    assert len(first) == len(plaintext)
    assert first != plaintext
    assert first != second
    assert open_fused_slot(
        first, context_digest=context, slot_id=0, program_seed=seed
    ) == plaintext
    assert program_seed_commitment(seed) != program_seed_commitment(bytes(reversed(seed)))


def test_opaque_retained_object_parses_without_opening_slot_ciphertexts():
    context = _context()
    trees = (_tree(8, 0), _tree(8, 1))
    artifacts = (bytes([0xA5]) * 333, bytes([0x5A]) * 444)
    manifest, _pubkeys = _manifest_for_artifacts(context, artifacts, trees)
    retained = FusedRetainedObject(manifest=manifest, slots=artifacts)
    parsed = parse_sealed_retained_object(retained.encoded)
    assert parsed.encoded == retained.encoded
    assert parsed.slots == artifacts


def test_release_is_exact_size_canonical_signed_and_root_bound():
    tree = _tree(256, 0)
    secret = 19
    release = issue_label_release(
        tree,
        point=multiply(G1, 1234567, group="g1"),
        authorization_txid=_sha(b"auth", b"slot0"),
        authorizer_secret=secret,
    )
    assert release.compact_size == 24_836
    assert len(release.openings) == 512
    assert release.verify_signature(public_key(secret))
    assert release.reconstruct_root() == tree.root
    assert AuthorizedLabelRelease.parse_compact(release.compact_bytes) == release


def test_outsider_failures_do_not_burn_but_authorized_bad_opening_does():
    context = _context()
    trees = (_tree(8, 0), _tree(8, 1))
    artifacts = (bytes([0x11]) * 400, bytes([0x22]) * 400)
    manifest, pubkeys = _manifest_for_artifacts(context, artifacts, trees)
    authorizer_secret = 23
    release = issue_label_release(
        trees[0],
        point=multiply(G1, 99, group="g1"),
        authorization_txid=_sha(b"auth", b"slot0"),
        authorizer_secret=authorizer_secret,
    )
    profile = DfbProfile(input_bits=8, primes=(2, 3, 5, 7), batch_size=4)

    forged = replace(release, authorizer_signature=bytes(64))
    outsider_ledger = BoundedSlotLedger(context.digest, 2)
    with pytest.raises(LabelAuthorizationError, match="signature"):
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=pubkeys,
            context=context,
            expected_authorizer_pubkey=public_key(authorizer_secret),
            ledger=outsider_ledger,
            slot_artifact=artifacts[0],
            profile=profile,
            release=forged,
        )
    assert outsider_ledger.remaining == 2

    first = release.openings[0]
    tampered = replace(
        release,
        openings=(replace(first, label=bytes(16)),) + release.openings[1:],
    )
    tamper_ledger = BoundedSlotLedger(context.digest, 2)
    with pytest.raises(LabelAuthorizationError, match="signature"):
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=pubkeys,
            context=context,
            expected_authorizer_pubkey=public_key(authorizer_secret),
            ledger=tamper_ledger,
            slot_artifact=artifacts[0],
            profile=profile,
            release=tampered,
        )
    assert tamper_ledger.remaining == 2

    malformed_unsigned = replace(tampered, authorizer_signature=bytes(64))
    malformed = replace(
        malformed_unsigned,
        authorizer_signature=sign(
            malformed_unsigned.signing_message, authorizer_secret
        ),
    )
    malformed_ledger = BoundedSlotLedger(context.digest, 2)
    with pytest.raises(LabelAuthorizationError, match="openings"):
        execute_authorized_fused_slot(
            manifest=manifest,
            required_manifest_pubkeys=pubkeys,
            context=context,
            expected_authorizer_pubkey=public_key(authorizer_secret),
            ledger=malformed_ledger,
            slot_artifact=artifacts[0],
            profile=profile,
            release=malformed,
        )
    assert malformed_ledger.remaining == 1
    assert malformed_ledger.use(0).outcome == "malformed"


def test_security_qualification_recomputes_load_bearing_numbers():
    profile = DfbProfile(primes=FIRST_91_PRIMES)
    fusion = qualify_mask_fusion(profile=profile, slots=2)
    assert fusion.lane_count == 3077
    assert fusion.chain_count == 2050
    assert fusion.dependency_edges == 1027
    assert fusion.maximum_indegree == fusion.maximum_outdegree == 1
    assert fusion.no_wrap_union_bound_bits_two_slots > 129
    assert fusion.composition_preconditions_machine_checked

    seeds = (bytes(32), bytes([1]) * 32)
    adaptive = qualify_rom_adaptive_wrapper(
        program_seeds=seeds,
        label_roots=(bytes([2]) * 32, bytes([3]) * 32),
        plaintext_lengths=(522102, 522102),
        ciphertext_lengths=(522102, 522102),
        pre_release_query_budget_per_slot=1 << 64,
    )
    assert adaptive.pre_release_seed_query_bound_bits == 191.0
    assert adaptive.gate_passed
    assert qualify_input_commitments(slots=2).gate_passed
    exceptional = qualify_exceptional_inputs(slots=2, one_shot_burn_enforced=True)
    assert exceptional.exceptional_hit_union_bound_bits > 243
    assert exceptional.gate_passed
