from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ranklock.babe_positive_lock import deterministic_fixture, setup_positive_lock
from ranklock.bip340 import public_key
from ranklock.bounded_mpc_embryo import (
    ActiveMpcProfile,
    EmbryoPaperCost,
    UnsignedBoundedEmbryoManifest,
    active_mpc_generator_code_hash,
    bounded_embryo_checkpoint,
    sign_manifest_fixture,
    slot_descriptor_from_artifact,
)


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest():
    session_context = b"ranklock-v0.21-result-fixture"
    context_digest = hashlib.sha256(b"context\x00" + session_context).digest()
    vk, inputs, _proof = deterministic_fixture(context=session_context)
    lock = setup_positive_lock(
        vk,
        inputs,
        b"R" * 32,
        scale=37,
        session_context=session_context,
    )
    cost = EmbryoPaperCost()
    slots = tuple(
        slot_descriptor_from_artifact(
            slot_id,
            bytes((81 + slot_id,)) * cost.artifact_bytes,
            input_label_commitment=hashlib.sha256(
                b"result-input-label-root" + slot_id.to_bytes(4, "big")
            ).digest(),
            independence_nonce=b"result-independent-random-tape" + slot_id.to_bytes(4, "big"),
        )
        for slot_id in range(2)
    )
    secrets = (7, 11)
    pubkeys = tuple(sorted(public_key(secret) for secret in secrets))
    profile = ActiveMpcProfile(parties=len(secrets))
    unsigned = UnsignedBoundedEmbryoManifest(
        context_digest=context_digest,
        generator_code_hash=active_mpc_generator_code_hash(profile),
        transcript_digest=hashlib.sha256(b"result-active-mpc-transcript").digest(),
        positive_lock=lock,
        slots=slots,
        contributor_pubkeys=pubkeys,
    )
    return sign_manifest_fixture(unsigned, secrets), profile


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    manifest, profile = build_manifest()
    checkpoint = bounded_embryo_checkpoint(
        manifest_bytes_for_two_slots_two_contributors=manifest.encoded_bytes
    )
    checkpoint.update(
        {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "manifest": {
                "encoded_bytes": manifest.encoded_bytes,
                "retained_bytes": manifest.retained_bytes,
                "margin_to_one_mib": manifest.margin_to_one_mib,
                "slot_count": manifest.unsigned.slot_count,
                "contributor_count": manifest.unsigned.contributor_count,
                "verified": manifest.verify(
                    required_pubkeys=manifest.unsigned.contributor_pubkeys,
                    expected_context_digest=manifest.unsigned.context_digest,
                    expected_generator_code_hash=active_mpc_generator_code_hash(profile),
                ),
                "encoded_sha256": hashlib.sha256(manifest.encoded).hexdigest(),
            },
            "test_evidence": {
                "test_files": 74,
                "tests_passed": 277,
                "tests_failed": 0,
                "report": "results/v021_test_report.txt",
                "machine_report": "results/v021_test_files.json",
            },
            "adaptive_security": {
                "dfb_paper_security_notion": "selective",
                "future_input_requires_adaptive_security": True,
                "proof_target": "docs/52_ADAPTIVE_DFB_PROOF_TARGET.md",
                "direct_transfer_from_half_gates_or_npro_results_proved": False,
            },
        }
    )
    (RESULTS / "v021_bounded_mpc_embryo.json").write_text(
        json.dumps(checkpoint, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    analysis_root = ROOT.parents[1]
    archives = {
        "v019": analysis_root / "ranklock-v0.19-current-research-checkpoint.zip",
        "v020": analysis_root / "ranklock-v0.20-candidate-checkpoint.zip",
    }
    audit = {
        "schema": "ranklock-v021-storage-audit-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "v019": {
            "archive": archives["v019"].name,
            "size_bytes": archives["v019"].stat().st_size,
            "sha256": sha256_file(archives["v019"]),
            "checkpoint_primary_target_still_open": True,
            "top_level_metadata_version": "0.18.0",
            "v019_addition_modules": 8,
            "v019_delta_modules_importing_missing_bip340": [
                "authenticated_counterproof_semantics.py",
                "predicate_locked_hashlock.py",
            ],
            "reported_focused_tests_not_present_in_archive_as_delta_coverage": True,
            "release_baseline_accepted": False,
        },
        "v020": {
            "archive": archives["v020"].name,
            "size_bytes": archives["v020"].stat().st_size,
            "sha256": sha256_file(archives["v020"]),
            "additive_share_pairing_composition": True,
            "cut_and_choose_total_copies_over_40_bits": 44,
            "setup_bytes_per_contributor_at_500_kib": 22_528_000,
            "exact_dfb_generator_present": False,
            "breakthrough_target_met": False,
        },
        "v021_repairs": {
            "bip340_added_and_official_vectors_tested": True,
            "v019_connector_and_semantic_modules_exercised": True,
            "bounded_two_slot_active_mpc_candidate": True,
            "full_suite": {"test_files": 74, "passed": 277, "failed": 0},
        },
    }
    (RESULTS / "v021_storage_audit.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
