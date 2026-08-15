from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ranklock.adaptive_sealing import parse_sealed_retained_object
from ranklock.authorized_labels import (
    AuthorizedLabelRelease,
    EvaluationContext,
    execute_authorized_fused_slot,
)
from ranklock.bn254_real import CURVE_ORDER, G1, add, compress_g1, decompress_g1, multiply
from ranklock.bounded_mpc_embryo import BoundedEmbryoError, BoundedSlotLedger
from ranklock.dfb_real import DfbProfile
from ranklock.embryo_mask_fusion import FIRST_91_PRIMES

# This import is deliberate: it binds the activated generator-code digest to
# the exact checked-out v0.24.1 source while never importing setup secrets.
from generate_v0241_security_qualification import _generator_code_hash


ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "results" / "v0241_security_qualification.json"
OUTPUT_PATH = ROOT / "results" / "v0241_independent_verification.json"


def _sha(domain: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha256(domain)
    for part in parts:
        h.update(bytes(part))
    return h.digest()


def _adaptive_second_scalar(first_output: bytes) -> int:
    scalar = int.from_bytes(
        _sha(b"ranklock/v0241/adaptive-second-input/v1\x00", first_output), "big"
    ) % CURVE_ORDER
    return scalar or 1


def _context(document: dict[str, object]) -> EvaluationContext:
    return EvaluationContext(
        chain_genesis_hash=bytes.fromhex(str(document["chain_genesis_hash"])),
        program_id=bytes.fromhex(str(document["program_id"])),
        verifier_key_digest=bytes.fromhex(str(document["verifier_key_digest"])),
        deposit_outpoint=bytes.fromhex(str(document["deposit_outpoint"])),
        game_index=int(document["game_index"]),
        operator_index=int(document["operator_index"]),
        counterproof_txid=bytes.fromhex(str(document["counterproof_txid"])),
        epoch=int(document["epoch"]),
        deadline_height=int(document["deadline_height"]),
    )


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    report = json.loads(REPORT_PATH.read_text())
    _check(
        report["schema"] == "ranklock-v0241-security-qualification-v1",
        "unexpected v0.24.1 report schema",
    )
    _check(report["package_version"] == "0.24.1", "unexpected package version")
    _check(report["safe_for_funds"] is False, "unsafe research fixture claims funds safety")
    retained_path = ROOT / report["retained_object"]["path"]
    retained_raw = retained_path.read_bytes()
    _check(
        len(retained_raw) == int(report["retained_object"]["bytes"]),
        "retained-object byte count differs from report",
    )
    _check(
        hashlib.sha256(retained_raw).hexdigest()
        == report["retained_object"]["sha256"],
        "retained-object hash differs from report",
    )
    retained = parse_sealed_retained_object(retained_raw)
    _check(retained.encoded == retained_raw, "sealed retained object is noncanonical")

    context = _context(report["authorization"]["context"])
    _check(
        context.digest.hex() == report["authorization"]["context_digest"],
        "evaluation context digest differs from report",
    )
    profile = DfbProfile(primes=FIRST_91_PRIMES)
    _check(
        retained.manifest.verify(
            required_pubkeys=retained.manifest.unsigned.contributor_pubkeys,
            expected_context_digest=context.digest,
            expected_generator_code_hash=_generator_code_hash(profile),
        ),
        "manifest signatures, context or generator-code binding failed",
    )

    authorizer_pubkey = bytes.fromhex(report["authorization"]["authorizer_pubkey"])
    releases: list[AuthorizedLabelRelease] = []
    for slot_id, row in enumerate(report["slots"]):
        artifact = retained.slots[slot_id]
        _check(
            hashlib.sha256(artifact).hexdigest() == row["sealed_artifact_sha256"],
            f"slot {slot_id} artifact hash differs from report",
        )
        release_path = (
            ROOT
            / "artifacts"
            / f"ranklock-v0241-slot-{slot_id}-authorized-label-release.bin"
        )
        release_raw = release_path.read_bytes()
        _check(
            len(release_raw) == int(row["authorized_release_bytes"]),
            f"slot {slot_id} release byte count differs from report",
        )
        _check(
            hashlib.sha256(release_raw).hexdigest()
            == row["authorized_release_sha256"],
            f"slot {slot_id} release hash differs from report",
        )
        release = AuthorizedLabelRelease.parse_compact(
            release_raw, input_bits=profile.input_bits
        )
        _check(release.slot_id == slot_id, f"release {slot_id} slot id mismatch")
        _check(
            release.verify_signature(authorizer_pubkey),
            f"release {slot_id} authorizer signature failed",
        )
        releases.append(release)

    ledger = BoundedSlotLedger(context.digest, 2)
    replay_rows = []
    outputs = []
    for slot_id, release in enumerate(releases):
        replay = execute_authorized_fused_slot(
            manifest=retained.manifest,
            required_manifest_pubkeys=retained.manifest.unsigned.contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=authorizer_pubkey,
            ledger=ledger,
            slot_artifact=retained.slots[slot_id],
            profile=profile,
            release=release,
        )
        output_encoding = compress_g1(replay.replay.result.output_point)
        _check(
            output_encoding.hex() == report["slots"][slot_id]["output_point"],
            f"slot {slot_id} public replay output differs from report",
        )
        _check(
            replay.replay.result.curve_check_valid,
            f"slot {slot_id} embedded curve check failed",
        )
        _check(
            replay.replay.result.maps_evaluated == 256,
            f"slot {slot_id} conditional-map count drifted",
        )
        outputs.append(replay.replay.result.output_point)
        replay_rows.append(
            {
                "slot_id": slot_id,
                "point": release.point_encoding.hex(),
                "output": output_encoding.hex(),
                "maps_evaluated": replay.replay.result.maps_evaluated,
                "outcome": replay.slot_use.outcome,
            }
        )

    _check(ledger.remaining == 0, "both one-shot slots were not consumed")
    expected_a2_scalar = _adaptive_second_scalar(compress_g1(outputs[0]))
    expected_a2 = multiply(G1, expected_a2_scalar, group="g1")
    _check(
        compress_g1(expected_a2) == releases[1].point_encoding,
        "A2 was not derived from the first authorized output",
    )

    # Public linearity is an unavoidable boundary, not a forgery: anyone can
    # derive A3 = A1 + A2 and Y3 = Y1 + Y2 from the two authorized
    # transcripts.  No hidden scalar is available or needed here.
    raw_a3 = add(
        decompress_g1(releases[0].point_encoding),
        decompress_g1(releases[1].point_encoding),
        group="g1",
    )
    raw_y3 = add(outputs[0], outputs[1], group="g1")
    raw_a3_encoding = compress_g1(raw_a3)
    raw_y3_encoding = compress_g1(raw_y3)

    try:
        execute_authorized_fused_slot(
            manifest=retained.manifest,
            required_manifest_pubkeys=retained.manifest.unsigned.contributor_pubkeys,
            context=context,
            expected_authorizer_pubkey=authorizer_pubkey,
            ledger=ledger,
            slot_artifact=retained.slots[0],
            profile=profile,
            release=releases[0],
        )
        replay_rejected = False
    except BoundedEmbryoError:
        replay_rejected = True
    _check(replay_rejected, "consumed slot accepted a third protocol evaluation")

    verification = {
        "schema": "ranklock-v0241-independent-verification-v1",
        "package_version": "0.24.1",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "retained_object_bytes": len(retained_raw),
        "retained_object_sha256": hashlib.sha256(retained_raw).hexdigest(),
        "manifest_verified_against_current_source": True,
        "public_replay_without_hidden_scalar": True,
        "adaptive_A2_binding_verified": True,
        "two_slots_consumed": True,
        "third_protocol_evaluation_rejected": True,
        "raw_linear_combination_boundary_acknowledged": True,
        "raw_linear_A3": raw_a3_encoding.hex(),
        "raw_linear_Y3": raw_y3_encoding.hex(),
        "replays": replay_rows,
        "all_checks_passed": True,
    }
    OUTPUT_PATH.write_text(json.dumps(verification, indent=2, sort_keys=True) + "\n")
    print(json.dumps(verification, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
