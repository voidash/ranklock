from __future__ import annotations

import argparse
import hashlib
import json
import platform
import resource
import sys
from time import perf_counter
from datetime import datetime, timezone
from pathlib import Path

from ranklock.bn254_real import affine, compress_g1
from ranklock.dfb_real import (
    DfbGeneration,
    DfbProfile,
    REFERENCE_REVISION,
    evaluate_program,
    parse_input_labels,
    parse_standalone_bundle,
    reconstruct_crt_columns,
    serialize_standalone_bundle,
    verify_affine_residues,
)
from ranklock.embryo_real import FIELD_MODULUS, evaluate_embryo_outputs, execute_embryo


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
RESULTS = ROOT / "results"
HIDDEN_SCALAR = 0x123456789ABCDEF00112233445566778899AABBCCDDEEFF
MANIFEST_BYTES = 748
ONE_MIB = 1 << 20


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_bytes(path: Path, raw: bytes) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {
        "path": str(path.relative_to(ROOT)),
        "bytes": len(raw),
        "sha256": sha256_bytes(raw),
    }


def max_rss_kib() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB; macOS reports bytes. The release runtime is Linux, but
    # keep the script portable for independent reruns.
    if sys.platform == "darwin":
        value //= 1024
    return int(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the deterministic v0.22 DFB/Embryo checkpoint")
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULTS / "v022_real_dfb_embryo_execution.json",
        help="machine-readable result path",
    )
    args = parser.parse_args()

    execution = execute_embryo(hidden_scalar=HIDDEN_SCALAR)
    generation = execution.dfb_generation
    profile: DfbProfile = generation.program.profile

    program_raw = generation.program.encoded
    decode_raw = generation.decode_state.canonical_bytes(profile)
    standalone_raw = serialize_standalone_bundle(generation.program, generation.decode_state)
    program_info = write_bytes(ARTIFACTS / "embryo-v022-dfb-program.bin", program_raw)
    decode_info = write_bytes(
        ARTIFACTS / "embryo-v022-standalone-decode-state.bin", decode_raw
    )
    standalone_info = write_bytes(
        ARTIFACTS / "embryo-v022-standalone-artifact.bin", standalone_raw
    )
    input_infos: list[dict[str, object]] = []
    input_raws: list[bytes] = []
    for index, encoding in enumerate(generation.input_encodings):
        raw = encoding.encoded_labels
        input_raws.append(raw)
        info = write_bytes(
            ARTIFACTS / f"embryo-v022-input-labels-{index}.bin",
            raw,
        )
        info["root"] = encoding.root.hex()
        info["retained_with_setup_artifact"] = False
        input_infos.append(info)

    # Replay from only the emitted public bytes plus future input labels. This
    # prevents an in-memory garbler object from silently satisfying evaluation.
    replay_start = perf_counter()
    replay_program, replay_state = parse_standalone_bundle(
        standalone_raw,
        dimensions=generation.program.dimensions,
        profile=profile,
    )
    replay_inputs = tuple(parse_input_labels(raw, profile=profile) for raw in input_raws)
    replay_generation = DfbGeneration(
        program=replay_program,
        decode_state=replay_state,
        input_encodings=replay_inputs,
        delta=0,
        garbler_hash_blocks=0,
    )
    point = affine(execution.result.input_point)
    if point is None:
        raise RuntimeError("fixture input point is infinity")
    x, y = point[0].n, point[1].n
    replay_evaluation = evaluate_program(replay_generation, values=(x, y))
    verify_affine_residues(
        replay_evaluation,
        values=(x, y),
        coefficients=(
            (execution.garbling.a_x, execution.garbling.b_x),
            (execution.garbling.a_y, execution.garbling.b_y),
        ),
        profile=profile,
    )
    replay_x = [
        value % FIELD_MODULUS
        for value in reconstruct_crt_columns(replay_evaluation.decoded_residues[0], profile)
    ]
    replay_y = [
        value % FIELD_MODULUS
        for value in reconstruct_crt_columns(replay_evaluation.decoded_residues[1], profile)
    ]
    replay_result = evaluate_embryo_outputs(
        execution.garbling,
        input_point=execution.result.input_point,
        x_encodings=replay_x,
        y_encodings=replay_y,
    )
    if not replay_result.output_matches:
        raise RuntimeError("serialized artifact replay failed hidden-scalar multiplication")
    replay_seconds = perf_counter() - replay_start

    profile_doc = profile.document(generation.program.dimensions)
    standalone_bytes = int(profile_doc["standalone_bundle_bytes"])
    join_bytes = int(profile_doc["program_bytes"])
    decode_bytes = int(profile_doc["standalone_decode_bytes"])
    q2_join = 2 * join_bytes + MANIFEST_BYTES
    q2_standalone = 2 * standalone_bytes + MANIFEST_BYTES

    test_report_path = RESULTS / "v022_test_files.json"
    test_evidence: dict[str, object]
    if test_report_path.exists():
        test_report = json.loads(test_report_path.read_text(encoding="utf-8"))
        test_evidence = {
            "test_files": int(test_report["test_files"]),
            "tests_passed": int(test_report["tests_passed"]),
            "tests_failed": int(test_report["tests_failed"]),
            "nonzero_test_files": int(test_report["nonzero_test_files"]),
            "report": str(test_report_path.relative_to(ROOT)),
        }
    else:
        test_evidence = {"status": "not run in this tree"}

    clean_report_path = RESULTS / "v022_clean_archive_verification.json"
    clean_archive_evidence: dict[str, object]
    if clean_report_path.exists():
        clean_report = json.loads(clean_report_path.read_text(encoding="utf-8"))
        clean_archive_evidence = {
            "test_files": int(clean_report["test_files"]),
            "tests_passed": int(clean_report["tests_passed"]),
            "tests_failed": int(clean_report["tests_failed"]),
            "manifest_verified": bool(clean_report["manifest_verified"]),
            "compileall": bool(clean_report["compileall"]),
            "report": str(clean_report_path.relative_to(ROOT)),
        }
    else:
        clean_archive_evidence = {"status": "not yet available"}

    report = {
        "schema": "ranklock-real-dfb-embryo-execution-v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "version": "0.22.0",
        "reference": {
            "repository": "alpenlabs/duty-free-bits",
            "revision": REFERENCE_REVISION,
            "port_scope": (
                "fixed-key AES CCRND/CCRH, 128-bit labels, nonce layout, fused "
                "[8,8,6] extraction, fold/body switch execution, canonical LSB packing"
            ),
        },
        "profile": profile_doc,
        "embryo": {
            "dimensions": list(execution.garbling.dimensions),
            "conditional_maps": 256,
            "curve_check_elements": 5,
            "hidden_scalar_hex": hex(HIDDEN_SCALAR),
            "curve_check_valid": execution.result.curve_check_valid,
            "curve_secret_recovered": (
                execution.result.recovered_curve_secret == execution.garbling.curve_secret
            ),
            "conditional_maps_verified": execution.result.map_points_verified,
            "output_matches_hidden_scalar_multiplication": execution.result.output_matches,
            "input_point_compressed": compress_g1(execution.result.input_point).hex(),
            "output_point_compressed": compress_g1(execution.result.output_point).hex(),
            "expected_point_compressed": compress_g1(execution.result.expected_point).hex(),
        },
        "execution": {
            "program_generated_before_input_binding": True,
            "program_reparsed_canonically_before_evaluation": True,
            "standalone_bundle_and_future_labels_replayed_from_bytes": True,
            "artifact_replay_seconds": replay_seconds,
            "artifact_replay_evaluator_aes_blocks": replay_evaluation.evaluator_hash_blocks,
            "garbler_aes_blocks": generation.garbler_hash_blocks,
            "evaluator_aes_blocks": execution.dfb_evaluation.evaluator_hash_blocks,
            "timings_seconds": execution.timings,
            "max_rss_kib": max_rss_kib(),
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "artifacts": {
            "join_program": program_info,
            "standalone_decode_state": decode_info,
            "standalone_artifact": standalone_info,
            "future_input_labels": input_infos,
        },
        "storage": {
            "one_mib_bytes": ONE_MIB,
            "manifest_bytes_v021_fixture": MANIFEST_BYTES,
            "one_slot_join_program_bytes": join_bytes,
            "one_slot_output_mask_bytes": decode_bytes,
            "one_slot_standalone_bytes": standalone_bytes,
            "q2_join_program_plus_manifest_bytes": q2_join,
            "q2_join_program_margin_to_one_mib": ONE_MIB - q2_join,
            "q2_standalone_plus_manifest_bytes": q2_standalone,
            "q2_standalone_over_one_mib": q2_standalone - ONE_MIB,
            "v021_paper_model_slot_bytes": 511_219,
            "join_program_delta_from_v021_paper_model": join_bytes - 511_219,
            "standalone_delta_from_v021_paper_model": standalone_bytes - 511_219,
            "boundary": (
                "The 449,779-byte object is the DFB join payload. Standalone public "
                "decoding also requires 228,083 bytes of final output masks unless an "
                "application-level label-flow fusion is constructed and proved."
            ),
        },
        "test_evidence": test_evidence,
        "clean_archive_evidence": clean_archive_evidence,
        "claim_boundary": {
            "real_dfb_join_program_generated_serialized_parsed_evaluated": True,
            "real_embryo_polynomial_and_group_evaluation": True,
            "standalone_output_masks_serialized": True,
            "application_level_output_mask_fusion_proved": False,
            "adaptive_security_proved": False,
            "active_mpc_executed": False,
            "authenticated_bitcoin_label_release_implemented": False,
            "bitcoin_core_regtest_complete": False,
            "breakthrough_target_met": False,
        },
        "next_gate": {
            "id": "P0-MASK-FUSION-1",
            "question": (
                "Can the DFB final output masks be consumed inside Embryo without "
                "serializing one CRT residue per affine output, under a complete "
                "selective/adaptive security proof?"
            ),
            "kill_condition": (
                "If the 228,083-byte output-mask state cannot be eliminated or "
                "compressed soundly, two standalone slots exceed one MiB by 307,896 bytes."
            ),
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
