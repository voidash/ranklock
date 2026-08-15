#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ranklock.bn254_real import compress_g1, decompress_g1, eq_points, multiply
from ranklock.dfb_real import DfbProfile
from ranklock.embryo_mask_fusion import (
    FIRST_91_PRIMES,
    parse_fused_retained_object,
    parse_fused_slot,
    replay_fused_slot,
)
from ranklock.embryo_real import EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "results" / "v023_mask_fusion_retained_object.json"
DEFAULT_OBJECT = ROOT / "artifacts" / "ranklock-v023-two-slot-retained-object.bin"
HIDDEN_SCALAR_FIXTURE = 37


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
    h.update(
        json.dumps(
            profile.document((EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION)),
            sort_keys=True,
        ).encode()
    )
    return h.digest()


def _coordinate_label_root(raw: bytes) -> bytes:
    return hashlib.sha256(b"ranklock/dfb-input-labels/v1\x00" + raw).digest()


def verify(report_path: Path, object_path: Path) -> dict[str, object]:
    profile = DfbProfile(primes=FIRST_91_PRIMES)
    report = json.loads(report_path.read_text())
    raw = object_path.read_bytes()
    expected_object = report["retained_object"]
    actual_hash = hashlib.sha256(raw).hexdigest()
    if len(raw) != int(expected_object["encoded_bytes"]):
        raise RuntimeError("retained-object byte length differs from report")
    if actual_hash != expected_object["sha256"]:
        raise RuntimeError("retained-object hash differs from report")

    retained = parse_fused_retained_object(raw, profile=profile)
    manifest = retained.manifest
    context = b"ranklock-v0.23-mask-fused-two-slot-retained-object"
    context_digest = _sha(b"ranklock/v023/context/v1\x00", context)
    generator_hash = _generator_code_hash(profile)
    pubkeys = manifest.unsigned.contributor_pubkeys
    if not manifest.verify(
        required_pubkeys=pubkeys,
        expected_context_digest=context_digest,
        expected_generator_code_hash=generator_hash,
    ):
        raise RuntimeError("signed retained-object manifest did not verify")

    slot_results: list[dict[str, object]] = []
    for descriptor, slot_bytes, row in zip(
        manifest.unsigned.slots, retained.slots, report["slots"], strict=True
    ):
        slot_id = int(row["slot_id"])
        if descriptor.slot_id != slot_id:
            raise RuntimeError("slot ordering differs between manifest and report")
        program, masks = parse_fused_slot(slot_bytes, profile=profile)
        x_labels = (ROOT / row["input_label_fixture_path_x"]).read_bytes()
        y_labels = (ROOT / row["input_label_fixture_path_y"]).read_bytes()
        if hashlib.sha256(x_labels).hexdigest() != row["input_label_fixture_sha256_x"]:
            raise RuntimeError(f"slot {slot_id} x-label fixture hash mismatch")
        if hashlib.sha256(y_labels).hexdigest() != row["input_label_fixture_sha256_y"]:
            raise RuntimeError(f"slot {slot_id} y-label fixture hash mismatch")
        input_root = _sha(
            b"ranklock/v023/two-coordinate-input-label-root/v1\x00",
            _coordinate_label_root(x_labels),
            _coordinate_label_root(y_labels),
        )
        if input_root != descriptor.input_label_root:
            raise RuntimeError(f"slot {slot_id} future-label commitment mismatch")

        input_point = decompress_g1(bytes.fromhex(row["input_point"]))
        replay = replay_fused_slot(
            program=program,
            mask_state=masks,
            input_point=input_point,
            x_input_labels=x_labels,
            y_input_labels=y_labels,
        )
        expected = multiply(input_point, HIDDEN_SCALAR_FIXTURE, group="g1")
        if not replay.result.curve_check_valid:
            raise RuntimeError(f"slot {slot_id} failed the public curve check")
        if replay.result.maps_evaluated != 256:
            raise RuntimeError(f"slot {slot_id} evaluated an unexpected map count")
        if not eq_points(replay.result.output_point, expected):
            raise RuntimeError(f"slot {slot_id} public replay differs from [37]A")
        if compress_g1(replay.result.output_point).hex() != row["expected_point"]:
            raise RuntimeError(f"slot {slot_id} public replay differs from report")
        slot_results.append(
            {
                "slot_id": slot_id,
                "slot_bytes": len(slot_bytes),
                "slot_sha256": hashlib.sha256(slot_bytes).hexdigest(),
                "input_label_bytes": len(x_labels) + len(y_labels),
                "input_label_root": input_root.hex(),
                "maps_evaluated": replay.result.maps_evaluated,
                "curve_check_valid": replay.result.curve_check_valid,
                "output_point": compress_g1(replay.result.output_point).hex(),
                "direct_hidden_scalar_check": True,
                "generator_state_supplied_to_replay": False,
            }
        )

    if retained.encoded != raw:
        raise RuntimeError("retained object failed canonical reserialization")
    return {
        "schema": "ranklock-v023-retained-object-verification-v1",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "verified": True,
        "profile_prime_count": len(profile.primes),
        "retained_object_bytes": len(raw),
        "retained_object_sha256": actual_hash,
        "margin_to_one_mib_bytes": (1 << 20) - len(raw),
        "manifest_bytes": manifest.encoded_bytes,
        "manifest_verified": True,
        "canonical_roundtrip": True,
        "public_replay_without_generator_state": True,
        "slots": slot_results,
        "claim_boundary": "Correctness, format and exact bytes only; this does not prove the open correlated-lift, uniform-pad, adaptive-q=2, active-MPC or Bitcoin-integration security gates.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--object", type=Path, default=DEFAULT_OBJECT)
    parser.add_argument(
        "--json",
        type=Path,
        default=ROOT / "results" / "v023_retained_object_verification.json",
    )
    args = parser.parse_args()
    result = verify(args.report.resolve(), args.object.resolve())
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
