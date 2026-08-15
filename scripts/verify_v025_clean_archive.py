#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.25.1"
PREFIX = f"ranklock-v{VERSION}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log: Path,
    allowed: tuple[int, ...] = (0,),
) -> int:
    with log.open("w") as handle:
        process = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
    if process.returncode not in allowed:
        tail = "\n".join(log.read_text(errors="replace").splitlines()[-100:])
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(command)}\n{tail}"
        )
    return process.returncode


def expected_archive_hash(archive: Path) -> str | None:
    for name in (f"{PREFIX}-SHA256SUMS.txt", "SHA256SUMS"):
        path = archive.parent / name
        if not path.is_file():
            continue
        for raw in path.read_text().splitlines():
            if not raw.strip():
                continue
            expected, filename = raw.split("  ", 1)
            if filename == archive.name:
                return expected
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=420)
    parser.add_argument("--bitcoind", type=Path)
    parser.add_argument("--bitcoind-sha256")
    args = parser.parse_args()

    archive = args.archive.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    expected = expected_archive_hash(archive)

    with tempfile.TemporaryDirectory(prefix="ranklock-v025-clean-") as temp_name:
        temp = Path(temp_name)
        shutil.unpack_archive(str(archive), str(temp))
        root = temp / PREFIX
        if not root.is_dir():
            raise RuntimeError(f"archive did not contain {PREFIX} root")
        logs = temp / "logs"
        logs.mkdir()
        py = Path(sys.executable)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

        run(
            [str(py), "-m", "pip", "install", "--no-index", "--dry-run", "-r", "requirements.lock"],
            cwd=root,
            env=env,
            log=logs / "dependencies.log",
        )
        install_target = temp / "installed-package"
        run(
            [
                str(py), "-m", "pip", "install", "--no-deps", "--no-build-isolation",
                "--target", str(install_target), ".",
            ],
            cwd=root,
            env=env,
            log=logs / "install.log",
        )
        installed_env = env.copy()
        installed_env["PYTHONPATH"] = str(install_target)
        run(
            [str(py), "-c", f"import ranklock; assert ranklock.__version__ == '{VERSION}'"],
            cwd=temp,
            env=installed_env,
            log=logs / "installed-import.log",
        )
        run([str(py), "scripts/verify_manifest.py"], cwd=root, env=env, log=logs / "manifest.log")
        run([str(py), "scripts/check_locked_environment.py"], cwd=root, env=env, log=logs / "environment.log")
        run(
            [str(py), "-m", "compileall", "-q", "src", "tests", "scripts"],
            cwd=root,
            env=env,
            log=logs / "compileall.log",
        )
        run(
            [
                str(py), "scripts/run_test_files.py", "--workers", str(args.workers),
                "--timeout", str(args.timeout), "--json", "results/v025_clean_test_files_raw.json",
            ],
            cwd=root,
            env=env,
            log=logs / "tests.log",
        )
        tests_raw = json.loads((root / "results/v025_clean_test_files_raw.json").read_text())

        evidence_names = [
            "artifacts/v025-committee-conformance/ranklock-v025-two-slot-retained-object.bin",
            "artifacts/v025-committee-conformance/ranklock-v025-two-slot-manifest.bin",
            "artifacts/v025-committee-conformance/authorization-transaction-plan.bin",
            "artifacts/v025-committee-conformance/slot-0-authorization-transaction.bin",
            "artifacts/v025-committee-conformance/slot-1-authorization-transaction.bin",
            "artifacts/v025-committee-conformance/slot-0-witness-policy.bin",
            "artifacts/v025-committee-conformance/slot-1-witness-policy.bin",
            "artifacts/v025-split-scalar-conformance/participant-0-retained-object.bin",
            "artifacts/v025-split-scalar-conformance/participant-1-retained-object.bin",
            "artifacts/v025-split-scalar-conformance/ranklock-v025-split-scalar-bundle.bin",
            "artifacts/v025-split-scalar-conformance/ranklock-v025-split-ack-script.bin",
        ]
        packaged_hashes = {name: sha256(root / name) for name in evidence_names}

        run(
            [str(py), "scripts/generate_v025_committee_qualification.py"],
            cwd=root,
            env=env,
            log=logs / "committee-generation.log",
        )
        run(
            [str(py), "scripts/audit_v025_bitcoin_policy.py"],
            cwd=root,
            env=env,
            log=logs / "bitcoin-policy.log",
        )
        run(
            [str(py), "scripts/generate_v025_split_scalar_qualification.py"],
            cwd=root,
            env=env,
            log=logs / "split-scalar-generation.log",
        )
        regenerated_hashes = {name: sha256(root / name) for name in evidence_names}

        run(
            [str(py), "scripts/verify_v025_evidence.py"],
            cwd=root,
            env=env,
            log=logs / "evidence-verifier.log",
        )
        evidence_verification = json.loads(
            (root / "results/v025_evidence_verification.json").read_text()
        )
        run(
            [str(py), "scripts/generate_v0251_security_hardening.py"],
            cwd=root,
            env=env,
            log=logs / "security-hardening.log",
        )
        hardening = json.loads(
            (root / "results/v0251_security_hardening.json").read_text()
        )
        run(
            ["bash", "run_bundle_checks.sh"],
            cwd=root / "integration/alpen-validity-first-f94c-v025",
            env=env,
            log=logs / "strata-handoff.log",
        )

        core_output = root / "results/v025_clean_bitcoin_core_regtest.json"
        bitcoind = str(args.bitcoind.resolve()) if args.bitcoind else "bitcoind"
        core_command = [
            str(py), "scripts/run_v025_bitcoin_core_regtest.py", "--bitcoind", bitcoind,
            "--output", str(core_output),
        ]
        if args.bitcoind is not None:
            if not args.bitcoind_sha256:
                raise RuntimeError(
                    "--bitcoind-sha256 is mandatory when --bitcoind is supplied"
                )
            core_command.extend(
                ["--expected-bitcoind-sha256", args.bitcoind_sha256]
            )
        core_rc = run(
            core_command,
            cwd=root,
            env=env,
            log=logs / "bitcoin-core.log",
            allowed=(0, 2),
        )
        core = json.loads(core_output.read_text())
        committee = json.loads((root / "results/v025_committee_qualification.json").read_text())
        split_scalar = json.loads((root / "results/v025_split_scalar_qualification.json").read_text())
        policy = json.loads((root / "results/v025_bitcoin_policy_envelope.json").read_text())

        reproducibility_checks = {
            "release_checksum_verified": expected is not None and sha256(archive) == expected,
            "source_manifest_verified": True,
            "locked_dependencies_available": True,
            "clean_target_package_install": True,
            "compileall": True,
            "complete_test_suite": (
                tests_raw["nonzero_files"] == 0
                and tests_raw["files"] == tests_raw["total_discovered_files"]
            ),
            "packaged_fixtures_match_clean_generation": packaged_hashes == regenerated_hashes,
            "committee_harness_passed": committee["decision"]
            == "FULL_SIZE_COMMITTEE_SAFETY_HARNESS_PASS_PRODUCTION_GATES_OPEN",
            "split_scalar_harness_passed": split_scalar["decision"]
            == "FULL_SIZE_SPLIT_SCALAR_PARTICIPANT_LOCAL_RELEASE_PASS_REAL_CORE_NATIVE_AUDIT_GATES_OPEN",
            "bitcoin_policy_envelope_passed": policy["passed"] is True,
            "evidence_verifier_passed": evidence_verification["all_checks_passed"] is True,
            "security_hardening_report_passed": hardening["all_local_checks_passed"] is True,
            "strata_handoff_static_checks_passed": True,
            "retained_object_below_one_mib": committee["retained_object"]["bytes"] < 1 << 20,
            "release_claims_safe_for_funds_false": (
                committee["safe_for_funds"] is False
                and split_scalar["safe_for_funds"] is False
            ),
        }
        report = {
            "schema": "ranklock-v0251-clean-archive-verification-v1",
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
            "package_version": VERSION,
            "archive": str(archive),
            "archive_bytes": archive.stat().st_size,
            "archive_sha256": sha256(archive),
            "python": subprocess.check_output([str(py), "--version"], text=True).strip(),
            "tests": {
                "files": tests_raw["files"],
                "passed": tests_raw["passed"],
                "failed": tests_raw["failed"],
                "nonzero_files": tests_raw["nonzero_files"],
            },
            "packaged_artifact_hashes": packaged_hashes,
            "clean_generation_hashes": regenerated_hashes,
            "reproducibility_checks": reproducibility_checks,
            "all_checks_passed": all(reproducibility_checks.values()),
            "bitcoin_core": {
                "supplied": args.bitcoind is not None,
                "runner_exit_code": core_rc,
                "executed": core.get("executed") is True,
                "passed": core.get("passed") is True,
                "evidence": core,
            },
            "safe_for_funds": False,
            "maximum_mode": "canary",
            "remaining_external_gates": [
                "pinned Bitcoin Core 31.1 regtest" if core.get("passed") is not True else None,
                "current strata-bridge compilation and functional/regtest matrix",
                "production split-scalar or active-MPC ceremony",
                "native constant-time implementation and secret erasure",
                "independently administered rollback witnesses",
                "independent cryptography and implementation audits",
            ],
        }
        report["remaining_external_gates"] = [
            item for item in report["remaining_external_gates"] if item is not None
        ]
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        log_dir = output.parent / f"{PREFIX}-clean-logs"
        if log_dir.exists():
            shutil.rmtree(log_dir)
        shutil.copytree(logs, log_dir)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
