#!/usr/bin/env python3
from __future__ import annotations

"""Regenerate the corrected v0.22.1 DFB/Embryo security-audit baseline.

This is a deterministic research fixture.  It applies the DFB statistical lift
at rho=128 per component, uses independent coordinate deltas/nonce namespaces, emits the
canonical join program plus standalone output-mask state, replays them from
bytes, and checks the final Embryo output against direct BN254 scalar
multiplication.  It does not prove adaptive privacy, active-MPC setup, Bitcoin
label authentication, q=2 composition, or output-mask fusion.
"""

import argparse
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path

from ranklock.bn254_real import affine, compress_g1
from ranklock.dfb_real import (
    DfbGeneration,
    DfbProfile,
    FIRST_90_PRIMES,
    body_pad_statistical_distance,
    NonceLayout,
    evaluate_program,
    parse_input_labels,
    parse_standalone_bundle,
    reconstruct_crt_columns,
    serialize_standalone_bundle,
    verify_affine_residues,
)
from ranklock.embryo_real import (
    FIELD_MODULUS,
    evaluate_embryo_outputs,
    execute_embryo,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
RESULTS = ROOT / "results"
HIDDEN_SCALAR = 0x123456789ABCDEF00112233445566778899AABBCCDDEEFF
RHO = 128
MANIFEST_BYTES = 748
ONE_MIB = 1 << 20


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write(path: Path, raw: bytes) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {
        "path": str(path.relative_to(ROOT)),
        "bytes": len(raw),
        "sha256": sha256(raw),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULTS / "v0221_security_audit_baseline.json",
    )
    args = parser.parse_args()

    profile = DfbProfile(primes=FIRST_90_PRIMES)
    execution = execute_embryo(
        hidden_scalar=HIDDEN_SCALAR,
        profile=profile,
        statistical_security_bits=RHO,
    )
    generation = execution.dfb_generation
    if generation.effective_coefficients is None:
        raise RuntimeError("smudged coefficient metadata is absent")

    program_raw = generation.program.encoded
    decode_raw = generation.decode_state.canonical_bytes(profile)
    bundle_raw = serialize_standalone_bundle(generation.program, generation.decode_state)
    program_info = write(ARTIFACTS / "embryo-v0221-dfb-program-128.bin", program_raw)
    decode_info = write(ARTIFACTS / "embryo-v0221-decode-state-128.bin", decode_raw)
    bundle_info = write(ARTIFACTS / "embryo-v0221-standalone-128.bin", bundle_raw)

    input_infos: list[dict[str, object]] = []
    input_raws: list[bytes] = []
    for name, encoding in zip(("x", "y"), generation.input_encodings, strict=True):
        raw = encoding.encoded_labels
        input_raws.append(raw)
        info = write(ARTIFACTS / f"embryo-v0221-input-labels-{name}.bin", raw)
        info["root"] = encoding.root.hex()
        input_infos.append(info)

    # Independent replay from the canonical standalone bytes and late-bound labels.
    program, decode_state = parse_standalone_bundle(
        bundle_raw,
        dimensions=generation.program.dimensions,
        profile=profile,
    )
    labels = tuple(parse_input_labels(raw, profile=profile) for raw in input_raws)
    replay = DfbGeneration(
        program=program,
        decode_state=decode_state,
        input_encodings=labels,
        garbler_hash_blocks=0,
        effective_coefficients=generation.effective_coefficients,
        field_modulus=FIELD_MODULUS,
        statistical_security_bits=RHO,
    )
    point = affine(execution.result.input_point)
    if point is None:
        raise RuntimeError("fixture input point is infinity")
    values = (point[0].n, point[1].n)
    replay_eval = evaluate_program(replay, values=values)
    verify_affine_residues(
        replay_eval,
        values=values,
        coefficients=generation.effective_coefficients,
        profile=profile,
    )
    x_encodings = [
        value % FIELD_MODULUS
        for value in reconstruct_crt_columns(replay_eval.decoded_residues[0], profile)
    ]
    y_encodings = [
        value % FIELD_MODULUS
        for value in reconstruct_crt_columns(replay_eval.decoded_residues[1], profile)
    ]
    replay_result = evaluate_embryo_outputs(
        execution.garbling,
        input_point=execution.result.input_point,
        x_encodings=x_encodings,
        y_encodings=y_encodings,
    )
    if not replay_result.curve_check_valid or not replay_result.output_matches:
        raise RuntimeError("standalone byte replay failed")

    deltas = tuple(encoding.delta for encoding in generation.input_encodings)
    delta_independent = all(value is not None for value in deltas) and len(set(deltas)) == len(deltas)
    layouts = tuple(
        NonceLayout.build(profile, dimension, coordinate_index=index)
        for index, dimension in enumerate(generation.program.dimensions)
    )
    nonce_independent = layouts[0].bulk_extract_base < layouts[1].solo_chunk_base

    document = profile.document(generation.program.dimensions)
    join_bytes = len(program_raw)
    standalone_bytes = len(bundle_raw)
    first_91 = DfbProfile(primes=FIRST_90_PRIMES + (467,))
    first_91_doc = first_91.document(generation.program.dimensions)
    worst_prime, worst_bias = profile.body_pad_bias_frontier
    report = {
        "schema": "ranklock-v0221-security-audit-baseline-v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "version": "0.22.1",
        "field_modulus": str(FIELD_MODULUS),
        "statistical_security_bits_requested": RHO,
        "statistical_security_bits_supported": profile.statistical_smudging_bits(FIELD_MODULUS),
        "smudging_applied": generation.field_modulus == FIELD_MODULUS and generation.statistical_security_bits == RHO,
        "coordinate_deltas_independent": delta_independent,
        "nonce_namespaces_independent": nonce_independent,
        "curve_check_valid": replay_result.curve_check_valid,
        "map_points_verified": replay_result.map_points_verified,
        "output_matches_hidden_scalar_multiplication": replay_result.output_matches,
        "input_point_compressed": compress_g1(replay_result.input_point).hex(),
        "output_point_compressed": compress_g1(replay_result.output_point).hex(),
        "expected_point_compressed": compress_g1(replay_result.expected_point).hex(),
        "garbler_aes_blocks": generation.garbler_hash_blocks,
        "evaluator_aes_blocks": replay_eval.evaluator_hash_blocks,
        "timings_seconds": execution.timings,
        "profile": document,
        "program_bytes": join_bytes,
        "program_sha256": program_info["sha256"],
        "decode_bytes": len(decode_raw),
        "decode_sha256": decode_info["sha256"],
        "bundle_bytes": standalone_bytes,
        "bundle_sha256": bundle_info["sha256"],
        "input_labels": input_infos,
        "q2_join_plus_748": 2 * join_bytes + MANIFEST_BYTES,
        "q2_join_margin_to_mib": ONE_MIB - (2 * join_bytes + MANIFEST_BYTES),
        "q2_standalone_plus_748": 2 * standalone_bytes + MANIFEST_BYTES,
        "body_pad_sampler": {
            "uniform": False,
            "construction": "nibble-width raw random slice, reduced modulo the CRT prime",
            "worst_prime": worst_prime,
            "max_total_variation_distance": worst_bias,
            "paper_uniform_group_requirement_met": False,
        },
        "whole_q2_smudging_accounting": {
            "affine_outputs_per_slot": sum(generation.program.dimensions),
            "components_across_two_slots": 2 * sum(generation.program.dimensions),
            "available_per_component_bits": profile.statistical_smudging_bits(FIELD_MODULUS),
            "conservative_joint_bits": profile.statistical_smudging_bits(FIELD_MODULUS)
            - math.log2(2 * sum(generation.program.dimensions)),
            "first_primes_for_conservative_128_bit_joint_target": 91,
            "first_91_largest_prime": 467,
            "first_91_supported_bits": first_91.statistical_smudging_bits(FIELD_MODULUS),
            "first_91_program_bytes": first_91_doc["program_bytes"],
            "first_91_q2_join_plus_748": 2 * first_91_doc["program_bytes"] + MANIFEST_BYTES,
            "first_91_q2_join_margin_to_mib": ONE_MIB
            - (2 * first_91_doc["program_bytes"] + MANIFEST_BYTES),
            "executed_91_prime_artifact": False,
        },
        "claim_boundary": {
            "selective_dfb_theorem_instantiated_more_faithfully": False,
            "uniform_body_pad_sampling_implemented": False,
            "conservative_whole_q2_128_bit_statistical_target_met": False,
            "slot_level_nonce_domain_separation_implemented": False,
            "adaptive_security_proved": False,
            "active_mpc_executed": False,
            "authenticated_bitcoin_label_release_implemented": False,
            "two_instance_same_scalar_theorem_proved": False,
            "output_mask_fusion_proved": False,
            "production_ready": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
