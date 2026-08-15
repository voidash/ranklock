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


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], *, cwd: Path, env: dict[str, str], log: Path) -> None:
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
    if process.returncode != 0:
        tail = "\n".join(log.read_text(errors="replace").splitlines()[-80:])
        raise RuntimeError(f"command failed ({process.returncode}): {' '.join(command)}\n{tail}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=420)
    args = parser.parse_args()
    archive = args.archive.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    checksum_path = archive.parent / "SHA256SUMS"
    expected_archive_hash: str | None = None
    if checksum_path.is_file():
        for raw in checksum_path.read_text().splitlines():
            if not raw.strip():
                continue
            expected, name = raw.split("  ", 1)
            if name == archive.name:
                expected_archive_hash = expected
                break

    with tempfile.TemporaryDirectory(prefix="ranklock-v0241-clean-") as temp_name:
        temp = Path(temp_name)
        shutil.unpack_archive(str(archive), str(temp))
        root = temp / "ranklock-v0.24.1"
        if not root.is_dir():
            raise RuntimeError("archive did not contain ranklock-v0.24.1 root")

        logs = temp / "logs"
        logs.mkdir()
        # The execution environment is already an isolated Python environment.
        # Creating a nested venv here can hide its pre-provisioned offline
        # wheels/site-packages, so verify the exact lock against this interpreter
        # and separately install RankLock into a clean target directory.
        py = Path(sys.executable)
        install_target = temp / "installed-package"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(root / "src")
        env["RANKLOCK_V0241_INSECURE_REPRO_SEED"] = "ranklock-v0241-public-conformance-seed"
        env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"

        run(
            [
                str(py),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--dry-run",
                "-r",
                "requirements.lock",
            ],
            cwd=root,
            env=env,
            log=logs / "dependencies.log",
        )
        run(
            [
                str(py),
                "-m",
                "pip",
                "install",
                "--no-deps",
                "--no-build-isolation",
                "--target",
                str(install_target),
                ".",
            ],
            cwd=root,
            env=env,
            log=logs / "install.log",
        )
        installed_env = env.copy()
        installed_env["PYTHONPATH"] = str(install_target)
        run(
            [
                str(py),
                "-c",
                "import ranklock; assert ranklock.__version__ == '0.24.1'",
            ],
            cwd=temp,
            env=installed_env,
            log=logs / "installed_import.log",
        )
        run([str(py), "scripts/verify_manifest.py"], cwd=root, env=env, log=logs / "manifest.log")
        run([str(py), "scripts/check_locked_environment.py"], cwd=root, env=env, log=logs / "environment.log")
        run([str(py), "-m", "compileall", "-q", "src", "tests", "scripts"], cwd=root, env=env, log=logs / "compileall.log")
        run(
            [
                str(py),
                "scripts/run_test_files.py",
                "--workers",
                str(args.workers),
                "--timeout",
                str(args.timeout),
                "--json",
                "results/v0241_clean_test_files.json",
            ],
            cwd=root,
            env=env,
            log=logs / "tests.log",
        )

        evidence_names = [
            "ranklock-v0241-two-slot-retained-object.bin",
            "ranklock-v0241-two-slot-manifest.bin",
            "ranklock-v0241-slot-0-authorized-label-release.bin",
            "ranklock-v0241-slot-1-authorized-label-release.bin",
            "embryo-v0241-slot-0.bin",
            "embryo-v0241-slot-1.bin",
        ]
        packaged_hashes = {name: sha256(root / "artifacts" / name) for name in evidence_names}

        run([str(py), "scripts/generate_v0241_security_qualification.py"], cwd=root, env=env, log=logs / "generation1.log")
        run([str(py), "scripts/verify_v0241_security_qualification.py"], cwd=root, env=env, log=logs / "verification1.log")
        first_hashes = {name: sha256(root / "artifacts" / name) for name in evidence_names}
        first_reports = {
            name: json.loads((root / "results" / name).read_text())
            for name in ("v0241_security_qualification.json", "v0241_independent_verification.json")
        }

        run([str(py), "scripts/generate_v0241_security_qualification.py"], cwd=root, env=env, log=logs / "generation2.log")
        run([str(py), "scripts/verify_v0241_security_qualification.py"], cwd=root, env=env, log=logs / "verification2.log")
        second_hashes = {name: sha256(root / "artifacts" / name) for name in evidence_names}
        second_reports = {
            name: json.loads((root / "results" / name).read_text())
            for name in ("v0241_security_qualification.json", "v0241_independent_verification.json")
        }

        for report in (*first_reports.values(), *second_reports.values()):
            report.pop("generated_at_utc", None)
            report.pop("verified_at_utc", None)
        normalized_reports_equal = first_reports == second_reports
        tests = json.loads((root / "results/v0241_clean_test_files.json").read_text())
        qualification = json.loads((root / "results/v0241_security_qualification.json").read_text())
        verification = json.loads((root / "results/v0241_independent_verification.json").read_text())
        checks = {
            "release_checksum_verified": (
                expected_archive_hash is not None
                and sha256(archive) == expected_archive_hash
            ),
            "manifest_verified_before_generation": True,
            "locked_dependencies_available": True,
            "clean_target_package_install": True,
            "compileall": True,
            "full_suite_zero_nonzero_files": tests["nonzero_files"] == 0,
            "packaged_fixture_matches_clean_generation": packaged_hashes == first_hashes,
            "two_clean_generations_byte_identical": first_hashes == second_hashes,
            "normalized_reports_equal": normalized_reports_equal,
            "independent_public_replay": verification["all_checks_passed"] is True,
            "retained_object_exact_bytes": qualification["retained_object"]["bytes"] == 1_044_952,
            "retained_object_below_one_mib": qualification["retained_object"]["bytes"] < 1 << 20,
            "safe_for_funds_false": qualification["safe_for_funds"] is False,
        }
        report = {
            "schema": "ranklock-v0241-clean-archive-verification-v1",
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
            "archive": str(archive),
            "archive_bytes": archive.stat().st_size,
            "archive_sha256": sha256(archive),
            "python": subprocess.check_output([str(py), "--version"], text=True).strip(),
            "tests": {
                "files": tests["files"],
                "passed": tests["passed"],
                "failed": tests["failed"],
                "nonzero_files": tests["nonzero_files"],
            },
            "packaged_artifact_hashes": packaged_hashes,
            "clean_generation_hashes": first_hashes,
            "checks": checks,
            "all_checks_passed": all(checks.values()),
            "safe_for_funds": False,
            "remaining_production_gates": qualification["remaining_production_gates"],
        }
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        # Preserve compact command logs beside the report for independent diagnosis.
        log_dir = output.parent / "ranklock-v0.24.1-clean-logs"
        if log_dir.exists():
            shutil.rmtree(log_dir)
        shutil.copytree(logs, log_dir)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
