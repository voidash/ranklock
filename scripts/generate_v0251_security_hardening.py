#!/usr/bin/env python3
from __future__ import annotations

"""Emit a machine-readable summary of the v0.25.1 local security hardening.

The report records only properties established inside this source tree.  It
cannot mint external Core, Strata, production-ceremony, constant-time, operations,
or audit evidence, and therefore always keeps ``safe_for_funds`` false.
"""

from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
EXPECTED_BITCOIND_SHA256 = (
    "d55c12b0b02001cc16b1481c4075361dcba193100a8143924abda911174c09ec"
)
EXPECTED_BITCOIN_CORE_VERSION = 310100


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def core_evidence_is_fail_closed_or_pinned(core: dict[str, object]) -> bool:
    """Accept only an honest unavailable state or the qualified Core binary."""

    executed = core.get("executed") is True
    passed = core.get("passed") is True
    if not executed:
        return not passed and isinstance(core.get("error"), str)
    result = core.get("result")
    return bool(
        passed
        and isinstance(result, dict)
        and result.get("bitcoin_core_version_number")
        == EXPECTED_BITCOIN_CORE_VERSION
        and result.get("bitcoind_sha256") == EXPECTED_BITCOIND_SHA256
    )


def main() -> int:
    tests = load(RESULTS / "v025_test_files.json")
    committee = load(RESULTS / "v025_committee_qualification.json")
    split_scalar = load(RESULTS / "v025_split_scalar_qualification.json")
    policy = load(RESULTS / "v025_bitcoin_policy_envelope.json")
    core = load(RESULTS / "v025_bitcoin_core_regtest.json")
    evidence = load(RESULTS / "v025_evidence_verification.json")

    local_checks = {
        "complete_per_file_suite": bool(
            tests.get("complete") is True
            and tests.get("failed") == 0
            and tests.get("nonzero_files") == 0
        ),
        "durable_two_phase_committee_harness": committee.get("decision")
        == "FULL_SIZE_COMMITTEE_SAFETY_HARNESS_PASS_PRODUCTION_GATES_OPEN",
        "split_scalar_one_honest_harness": split_scalar.get("decision")
        == "FULL_SIZE_SPLIT_SCALAR_PARTICIPANT_LOCAL_RELEASE_PASS_REAL_CORE_NATIVE_AUDIT_GATES_OPEN",
        "static_bitcoin_policy_envelope": policy.get("passed") is True,
        "canonical_evidence_verifier": evidence.get("all_checks_passed") is True,
        "core_evidence_fail_closed_or_pinned": core_evidence_is_fail_closed_or_pinned(
            core
        ),
    }
    source_paths = {
        "mpc_qualification": ROOT / "src/ranklock/mpc_qualification.py",
        "ceremony_core_binding": ROOT / "src/ranklock/setup_ceremony_evidence.py",
        "durable_ledger": ROOT / "src/ranklock/durable_slot_ledger.py",
        "rollback_witness": ROOT / "src/ranklock/rollback_witness.py",
        "two_phase_sidecar": ROOT / "src/ranklock/two_phase_sidecar.py",
        "bitcoin_core_regtest": ROOT / "src/ranklock/bitcoin_core_regtest.py",
        "kill_safe_test_runner": ROOT / "scripts/run_test_files.py",
    }
    document = {
        "schema": "ranklock-v0251-security-hardening-v1",
        "package_version": "0.25.1",
        "tests": {
            "files": tests.get("files"),
            "passed": tests.get("passed"),
            "failed": tests.get("failed"),
        },
        "local_checks": local_checks,
        "all_local_checks_passed": all(local_checks.values()),
        "hardening_properties": {
            "mpc_statement_deployment_context_bound": True,
            "mpc_statement_chain_genesis_bound": True,
            "funding_attestation_exact_core_observation_bound": True,
            "funding_attestation_maximum_ttl_seconds": 3600,
            "ceremony_and_mpc_verifier_separation_required": True,
            "bitcoind_cli_hash_pin_required": True,
            "test_timeout_kills_process_group": True,
        },
        "source_digests": {
            name: {"path": str(path.relative_to(ROOT)), "sha256": digest(path)}
            for name, path in source_paths.items()
        },
        "external_gates": {
            "bitcoin_core_31_1_regtest": core.get("passed") is True,
            "current_strata_workspace_compile_and_tests": False,
            "production_active_mpc_or_split_scalar_ceremony": False,
            "native_constant_time_and_secret_erasure": False,
            "independently_administered_rollback_witnesses": False,
            "independent_cryptography_audit": False,
            "independent_implementation_audit": False,
            "independent_operations_audit": False,
        },
        "maximum_mode": "canary",
        "safe_for_funds": False,
    }
    output = RESULTS / "v0251_security_hardening.json"
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0 if document["all_local_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
