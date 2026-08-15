from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from math import ceil, log2
from pathlib import Path

from ranklock.babe_positive_lock import deterministic_fixture, setup_positive_lock
from ranklock.bip340 import public_key
from ranklock.bn254_real import CURVE_ORDER, FIELD_MODULUS, compress_g1, eq_points
from ranklock.bounded_mpc_embryo import (
    ActiveMpcProfile,
    UnsignedBoundedEmbryoManifest,
    sign_manifest_fixture,
    slot_descriptor_from_artifact,
)
from ranklock.dfb_real import DfbProfile, FIRST_90_PRIMES, serialize_program
from ranklock.embryo_mask_fusion import (
    CURRENT_MANIFEST_BYTES,
    FIRST_91_PRIMES,
    FUSED_FIELD_BITS,
    FUSED_MAP_MASKS,
    FusedRetainedObject,
    execute_mask_fused_embryo,
    parse_fused_retained_object,
    parse_fused_slot,
    replay_fused_slot,
)
from ranklock.embryo_real import EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
RESULTS = ROOT / "results"
HIDDEN_SCALAR = 37


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha256(domain)
    for part in parts:
        h.update(bytes(part))
    return h.digest()


def _generator_code_hash(profile: DfbProfile) -> bytes:
    h = hashlib.sha256(b"ranklock/v023/mask-fusion-generator-code/v1\x00")
    for relative in (
        "src/ranklock/dfb_real.py",
        "src/ranklock/embryo_real.py",
        "src/ranklock/embryo_mask_fusion.py",
    ):
        h.update(relative.encode())
        h.update((ROOT / relative).read_bytes())
    h.update(json.dumps(profile.document((EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION)), sort_keys=True).encode())
    return h.digest()


def _input_label_commitment(execution) -> bytes:
    return _sha(
        b"ranklock/v023/two-coordinate-input-label-root/v1\x00",
        execution.generation.input_encodings[0].root,
        execution.generation.input_encodings[1].root,
    )


def _committee_frontier(*, slot_bytes: int, lock_bytes: int, slot_count: int = 2) -> dict[str, object]:
    """Exact signed-manifest scaling for the current all-signatures format.

    The manifest has a 556-byte fixed portion for two slot descriptors and the
    current 32-byte positive-lock payload. Every contributor adds one 32-byte
    x-only BIP340 public key and one 64-byte BIP340 signature.
    """

    fixed_without_contributors = (
        16  # magic/version/flags/cardinalities
        + 96  # context, generator and transcript digests
        + lock_bytes
        + slot_count * 108
        + 32  # manifest checksum
    )
    per_contributor = 32 + 64
    available = (1 << 20) - slot_count * slot_bytes - fixed_without_contributors
    maximum = available // per_contributor
    rows = []
    for contributors in sorted({2, 3, 5, 10, 16, 32, maximum, maximum + 1}):
        if contributors < 2:
            continue
        manifest_bytes = fixed_without_contributors + per_contributor * contributors
        total = slot_count * slot_bytes + manifest_bytes
        rows.append(
            {
                "contributors": contributors,
                "manifest_bytes": manifest_bytes,
                "complete_retained_bytes": total,
                "margin_to_one_mib": (1 << 20) - total,
                "fits_one_mib": total <= (1 << 20),
            }
        )
    return {
        "fixed_manifest_bytes_without_contributors": fixed_without_contributors,
        "bytes_per_contributor": per_contributor,
        "maximum_contributors_below_one_mib": maximum,
        "margin_at_maximum_contributors": (1 << 20)
        - (slot_count * slot_bytes + fixed_without_contributors + per_contributor * maximum),
        "first_failing_contributor_count": maximum + 1,
        "rows": rows,
    }


def _frontier() -> list[dict[str, object]]:
    rows = []
    prime_sets = {
        88: FIRST_90_PRIMES[:88],
        89: FIRST_90_PRIMES[:89],
        90: FIRST_90_PRIMES,
        91: FIRST_91_PRIMES,
    }
    components = 2 * (EMBRYO_X_DIMENSION + EMBRYO_Y_DIMENSION)
    mask_bytes = ceil(FUSED_MAP_MASKS * FUSED_FIELD_BITS / 8)
    for count, primes in prime_sets.items():
        profile = DfbProfile(primes=primes)
        standard = profile.document((EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION))["program_bytes"]
        fixed_bits = sum(
            profile.coordinate_program_bits(dimension) - dimension * profile.crt_bits
            for dimension in (EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION)
        )
        compact_bits = fixed_bits + (EMBRYO_X_DIMENSION + EMBRYO_Y_DIMENSION) * profile.primorial.bit_length()
        compact = ceil(compact_bits / 8)
        total = 2 * (compact + mask_bytes) + CURRENT_MANIFEST_BYTES
        rho = profile.statistical_smudging_bits(FIELD_MODULUS)
        rows.append(
            {
                "prime_count": count,
                "largest_prime": primes[-1],
                "crt_residue_width_bits": profile.crt_bits,
                "primorial_width_bits": profile.primorial.bit_length(),
                "per_component_smudging_bits": rho,
                "conservative_two_slot_vector_bits": rho - log2(components),
                "standard_program_bytes": standard,
                "compact_program_bytes": compact,
                "fused_mask_bytes": mask_bytes,
                "two_slot_plus_manifest_bytes": total,
                "margin_to_one_mib": (1 << 20) - total,
                "fits_one_mib": total <= (1 << 20),
            }
        )
    return rows


def main() -> None:
    ARTIFACTS.mkdir(exist_ok=True)
    RESULTS.mkdir(exist_ok=True)
    profile = DfbProfile(primes=FIRST_91_PRIMES)
    executions = []
    slot_artifacts = []
    public_replays = []
    input_label_fixtures = []
    for slot_id in range(2):
        execution = execute_mask_fused_embryo(
            hidden_scalar=HIDDEN_SCALAR,
            profile=profile,
            dfb_seed=f"ranklock/v023/release/slot-{slot_id}/dfb".encode(),
            garbling_seed=f"ranklock/v023/release/slot-{slot_id}/embryo".encode(),
            input_scalar_start=1_234_567 + slot_id,
        )
        if not execution.result.output_matches:
            raise RuntimeError(f"slot {slot_id} failed [r]A execution")
        artifact = execution.retained_slot_bytes
        parsed_program, parsed_masks = parse_fused_slot(artifact, profile=profile)
        if parsed_program.encoded != execution.generation.program.encoded:
            raise RuntimeError("compact program changed under slot parsing")
        if parsed_masks != execution.mask_state:
            raise RuntimeError("fused mask state changed under slot parsing")

        x_labels = execution.generation.input_encodings[0].encoded_labels
        y_labels = execution.generation.input_encodings[1].encoded_labels
        replay = replay_fused_slot(
            program=parsed_program,
            mask_state=parsed_masks,
            input_point=execution.result.input_point,
            x_input_labels=x_labels,
            y_input_labels=y_labels,
        )
        if not replay.result.curve_check_valid:
            raise RuntimeError(f"slot {slot_id} public replay failed curve validation")
        if replay.result.recovered_curve_secret != execution.garbling.curve_secret:
            raise RuntimeError(f"slot {slot_id} public replay recovered the wrong key")
        if replay.result.maps_evaluated != 256:
            raise RuntimeError(f"slot {slot_id} public replay evaluated the wrong map count")
        if not eq_points(replay.result.output_point, execution.result.expected_point):
            raise RuntimeError(f"slot {slot_id} public replay failed [r]A")

        executions.append(execution)
        public_replays.append(replay)
        input_label_fixtures.append((x_labels, y_labels))
        slot_artifacts.append(artifact)
        (ARTIFACTS / f"embryo-v023-slot-{slot_id}-compact-program.bin").write_bytes(
            execution.generation.program.encoded
        )
        (ARTIFACTS / f"embryo-v023-slot-{slot_id}-fused-masks.bin").write_bytes(
            execution.mask_state.encoded_bytes
        )
        (ARTIFACTS / f"embryo-v023-slot-{slot_id}.bin").write_bytes(artifact)
        (ARTIFACTS / f"embryo-v023-slot-{slot_id}-input-labels-x.bin").write_bytes(
            x_labels
        )
        (ARTIFACTS / f"embryo-v023-slot-{slot_id}-input-labels-y.bin").write_bytes(
            y_labels
        )

    if slot_artifacts[0] == slot_artifacts[1]:
        raise RuntimeError("two one-shot slots are not independent")

    context = b"ranklock-v0.23-mask-fused-two-slot-retained-object"
    context_digest = _sha(b"ranklock/v023/context/v1\x00", context)
    vk, public_inputs, proof = deterministic_fixture(context=context)
    lock = setup_positive_lock(
        vk,
        public_inputs,
        b"R" * 32,
        scale=HIDDEN_SCALAR,
        session_context=context,
    )
    slots = tuple(
        slot_descriptor_from_artifact(
            slot_id,
            artifact,
            input_label_commitment=_input_label_commitment(executions[slot_id]),
            independence_nonce=f"ranklock/v023/slot-{slot_id}/independent-random-tape".encode(),
        )
        for slot_id, artifact in enumerate(slot_artifacts)
    )
    contributor_secrets = (7, 11)
    pubkeys = tuple(sorted(public_key(secret) for secret in contributor_secrets))
    mpc_profile = ActiveMpcProfile(parties=len(contributor_secrets))
    transcript_digest = _sha(
        b"ranklock/v023/ceremony-transcript/v1\x00",
        mpc_profile.digest,
        *(descriptor.artifact_root for descriptor in slots),
    )
    unsigned = UnsignedBoundedEmbryoManifest(
        context_digest=context_digest,
        generator_code_hash=_generator_code_hash(profile),
        transcript_digest=transcript_digest,
        positive_lock=lock,
        slots=slots,
        contributor_pubkeys=pubkeys,
    )
    manifest = sign_manifest_fixture(unsigned, contributor_secrets)
    if manifest.encoded_bytes != CURRENT_MANIFEST_BYTES:
        raise RuntimeError(f"manifest size drift: {manifest.encoded_bytes}")
    if not manifest.verify(
        required_pubkeys=pubkeys,
        expected_context_digest=context_digest,
        expected_generator_code_hash=unsigned.generator_code_hash,
    ):
        raise RuntimeError("two-slot manifest failed verification")

    retained = FusedRetainedObject(manifest=manifest, slots=tuple(slot_artifacts))
    expected_total = executions[0].accounting.complete_retained_bytes
    if retained.encoded_bytes != expected_total:
        raise RuntimeError(
            f"retained-object size drift: {retained.encoded_bytes} != {expected_total}"
        )
    parsed_retained = parse_fused_retained_object(retained.encoded, profile=profile)
    if parsed_retained.encoded != retained.encoded:
        raise RuntimeError("retained object changed under canonical parsing")

    manifest_path = ARTIFACTS / "ranklock-v023-two-slot-manifest.bin"
    retained_path = ARTIFACTS / "ranklock-v023-two-slot-retained-object.bin"
    manifest_path.write_bytes(manifest.encoded)
    retained_path.write_bytes(retained.encoded)

    slot_rows = []
    for slot_id, execution in enumerate(executions):
        standard = serialize_program(
            execution.generation.program.coordinates,
            execution.generation.program.profile,
        )
        slot_rows.append(
            {
                "slot_id": slot_id,
                "hidden_scalar": HIDDEN_SCALAR,
                "program_bytes_compact": len(execution.generation.program.encoded),
                "program_bytes_standard_residue_encoding": len(standard.encoded),
                "compact_crt_savings_bytes": len(standard.encoded)
                - len(execution.generation.program.encoded),
                "fused_mask_bytes": len(execution.mask_state.encoded_bytes),
                "retained_slot_bytes": len(execution.retained_slot_bytes),
                "program_sha256": execution.generation.program.sha256,
                "fused_mask_sha256": execution.mask_state.sha256,
                "slot_sha256": hashlib.sha256(execution.retained_slot_bytes).hexdigest(),
                "artifact_root": slots[slot_id].artifact_root.hex(),
                "input_label_root": slots[slot_id].input_label_root.hex(),
                "input_label_fixture_bytes": sum(
                    len(value) for value in input_label_fixtures[slot_id]
                ),
                "input_label_fixture_sha256_x": hashlib.sha256(
                    input_label_fixtures[slot_id][0]
                ).hexdigest(),
                "input_label_fixture_sha256_y": hashlib.sha256(
                    input_label_fixtures[slot_id][1]
                ).hexdigest(),
                "input_label_fixture_path_x": f"artifacts/embryo-v023-slot-{slot_id}-input-labels-x.bin",
                "input_label_fixture_path_y": f"artifacts/embryo-v023-slot-{slot_id}-input-labels-y.bin",
                "input_labels_are_runtime_not_retained": True,
                "input_point": compress_g1(execution.result.input_point).hex(),
                "public_replay_without_generator_state": True,
                "public_replay_output_point": compress_g1(
                    public_replays[slot_id].result.output_point
                ).hex(),
                "output_point": compress_g1(execution.result.output_point).hex(),
                "expected_point": compress_g1(execution.result.expected_point).hex(),
                "output_matches": execution.result.output_matches,
                "conditional_maps_verified": execution.result.map_points_verified,
                "individual_affine_masks": 3_077,
                "nonzero_terminal_affine_masks": execution.lift_metadata.nonzero_individual_masks,
                "retained_final_polynomial_masks": len(
                    execution.mask_state.map_coordinate_masks
                ),
                "timings_seconds": execution.timings,
            }
        )

    breakdown = {
        "manifest_header_bytes": 16,
        "context_generator_transcript_digests_bytes": 96,
        "positive_lock_bytes": lock.encoded_bytes,
        "two_slot_descriptors_bytes": 216,
        "two_contributor_pubkeys_bytes": 64,
        "two_bip340_signatures_bytes": 128,
        "manifest_checksum_bytes": 32,
    }
    if sum(breakdown.values()) != manifest.encoded_bytes:
        raise RuntimeError("manifest component accounting drift")

    report = {
        "schema": "ranklock-v023-mask-fusion-retained-object-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "decision": "EXECUTABLE_STORAGE_TARGET_MET_SECURITY_THEOREM_STILL_OPEN",
        "hard_answer": {
            "two_complete_instances_plus_current_lock_manifest_below_one_mib": True,
            "production_replacement_ready": False,
            "public_replay_without_generator_state": True,
            "reason_not_production_ready": [
                "readout-correlated intercept-lift security proof is not established",
                "DFB future-input adaptive two-instance privacy is not established",
                "uniform Z_p body-pad sampler is not implemented",
                "active n-1-corrupt MPC execution of this fused generator is not implemented",
                "Bitcoin authenticated one-label-per-bit release and regtest are not implemented",
            ],
        },
        "profile": {
            **profile.document((EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION)),
            "primorial_width_bits": profile.primorial.bit_length(),
            "whole_two_slot_conservative_smudging_bits": profile.statistical_smudging_bits(
                FIELD_MODULUS
            )
            - log2(2 * (EMBRYO_X_DIMENSION + EMBRYO_Y_DIMENSION)),
        },
        "storage": {
            **executions[0].accounting.document(),
            "standalone_decode_state_bytes_old_91_prime": ceil(
                (EMBRYO_X_DIMENSION + EMBRYO_Y_DIMENSION) * profile.crt_bits / 8
            ),
            "fused_output_mask_savings_bytes_per_slot": ceil(
                (EMBRYO_X_DIMENSION + EMBRYO_Y_DIMENSION) * profile.crt_bits / 8
            )
            - len(executions[0].mask_state.encoded_bytes),
            "compact_crt_join_savings_bytes_per_slot": 16_539,
            "margin_after_deleting_entire_manifest_bytes": (1 << 20)
            - 2 * len(executions[0].retained_slot_bytes),
        },
        "manifest": {
            "encoded_bytes": manifest.encoded_bytes,
            "encoded_sha256": hashlib.sha256(manifest.encoded).hexdigest(),
            "verified": True,
            "breakdown": breakdown,
            "positive_lock_payload_bytes": len(lock.masked_payload),
            "positive_lock_vk_binding": "32-byte digest; full fixed VK is treated as globally deployed bridge data",
            "committee_frontier": _committee_frontier(
                slot_bytes=len(executions[0].retained_slot_bytes),
                lock_bytes=lock.encoded_bytes,
            ),
        },
        "retained_object": {
            "path": str(retained_path.relative_to(ROOT)),
            "encoded_bytes": retained.encoded_bytes,
            "sha256": hashlib.sha256(retained.encoded).hexdigest(),
            "canonical_roundtrip": True,
            "manifest_first": True,
            "slot_count": 2,
        },
        "slots": slot_rows,
        "parameter_frontier": _frontier(),
        "construction": {
            "nonterminal_mask_rule": "transmitted affine intercept equals DFB readout modulo BN254",
            "terminal_mask_rule": "retain one aggregate BN254 mask per final X/Y/Z polynomial",
            "curve_mask_rule": "choose the random curve-check secret so the two terminal masks sum to zero",
            "no_wrap_rule": "every DFB readout R satisfies R + (q-1)^2 < CRT primorial",
            "body_join_encoding": "one 649-bit canonical CRT integer instead of 91 independently padded residues totaling 692 bits",
            "retained_map_masks": FUSED_MAP_MASKS,
            "retained_curve_masks": 0,
        },
        "claim_boundary": {
            "executable_correctness_and_byte_accounting": True,
            "public_replay_without_generator_state": True,
            "selective_privacy_proof_for_correlated_lifts": False,
            "adaptive_two_instance_proof": False,
            "safe_for_funds": False,
        },
    }
    (RESULTS / "v023_mask_fusion_retained_object.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
