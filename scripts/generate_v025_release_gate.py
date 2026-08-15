#!/usr/bin/env python3
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from ranklock.release_qualification import LocalReleaseFacts

ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise RuntimeError(f"required evidence is absent: {path}")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"evidence is not a JSON object: {path}")
    return value


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--clean-archive-report",
        type=Path,
        help="optional companion clean-archive report produced outside the source archive",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "v025_release_gate.json",
    )
    args = parser.parse_args()

    paths = {
        "committee": ROOT / "results/v025_committee_qualification.json",
        "split_scalar": ROOT / "results/v025_split_scalar_qualification.json",
        "bitcoin_policy": ROOT / "results/v025_bitcoin_policy_envelope.json",
        "bitcoin_core": ROOT / "results/v025_bitcoin_core_regtest.json",
        "tests": ROOT / "results/v025_test_files.json",
        "hardening": ROOT / "results/v0251_security_hardening.json",
    }
    evidence = {name: _load(path) for name, path in paths.items()}
    clean = _load(args.clean_archive_report.resolve()) if args.clean_archive_report else None

    committee = evidence["committee"]
    split_scalar = evidence["split_scalar"]
    bitcoin_policy = evidence["bitcoin_policy"]
    bitcoin_core = evidence["bitcoin_core"]
    tests = evidence["tests"]
    hardening = evidence["hardening"]
    if hardening.get("all_local_checks_passed") is not True:
        raise RuntimeError("v0.25.1 security hardening report did not pass")

    facts = LocalReleaseFacts(
        complete_source_archive_reproducible=bool(
            clean and clean.get("all_checks_passed") is True
        ),
        complete_test_suite_passed=bool(
            tests.get("complete") is True
            and tests.get("failed") == 0
            and tests.get("nonzero_files") == 0
        ),
        retained_object_below_one_mib=bool(
            committee.get("retained_object", {}).get("bytes", 1 << 60) < 1 << 20  # type: ignore[union-attr]
        ),
        committee_authorization_harness_passed=bool(
            committee.get("decision")
            == "FULL_SIZE_COMMITTEE_SAFETY_HARNESS_PASS_PRODUCTION_GATES_OPEN"
            and committee.get("safe_for_funds") is False
        ),
        split_scalar_one_honest_harness_passed=bool(
            split_scalar.get("decision")
            == "FULL_SIZE_SPLIT_SCALAR_PARTICIPANT_LOCAL_RELEASE_PASS_REAL_CORE_NATIVE_AUDIT_GATES_OPEN"
            and split_scalar.get("safe_for_funds") is False
        ),
        bitcoin_policy_envelope_passed=bitcoin_policy.get("passed") is True,
        bitcoin_core_regtest_executed=bitcoin_core.get("executed") is True,
        bitcoin_core_regtest_passed=bitcoin_core.get("passed") is True,
        current_bridge_compiled_and_tested=False,
        native_constant_time_implementation=False,
        production_rollback_witnesses_deployed=False,
        deterministic_fixture_secrets_absent=False,
        independent_cryptography_audit_passed=False,
        independent_implementation_audit_passed=False,
        split_scalar_production_setup_passed=False,
        setup_security_mode="split-scalar-n-of-n",
    )
    document = facts.document()
    document.update(
        {
            "schema": "ranklock-v025-release-gate-v1",
            "package_version": "0.25.1",
            "claim_boundary": (
                "reproducible safety and authorization harness; no authority to protect funds"
            ),
            "recommended_setup_path": (
                "split-scalar N-of-N removes an aggregate-scalar dealer at the cost of "
                "approximately linear retained material and N-of-N liveness"
            ),
            "evidence": {
                name: {
                    "path": str(path.relative_to(ROOT)),
                    "sha256": _digest(path),
                }
                for name, path in paths.items()
            },
            "clean_archive_report": (
                None
                if args.clean_archive_report is None
                else {
                    "path": str(args.clean_archive_report.resolve()),
                    "sha256": _digest(args.clean_archive_report.resolve()),
                    "all_checks_passed": bool(clean and clean.get("all_checks_passed") is True),
                }
            ),
            "local_security_hardening_passed": True,
            "external_attestations_must_be_verified_by": (
                "ranklock.deployment_policy.evaluate_deployment"
            ),
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))
    # This script succeeds when it has produced an honest fail-closed verdict.
    # Safe-for-funds is intentionally not the process success condition.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
