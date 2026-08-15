#!/usr/bin/env python3
from __future__ import annotations

"""Strict cross-report verifier for v0.25.2 qualification evidence.

Unlike ``scripts/verify_v025_evidence.py`` (which checks the v0.25.1
research/canary artifacts and treats an absent Bitcoin Core report as an
acceptable fail-closed state), this verifier is the gate for the new
CORE-*/STRATA-* matrix evidence introduced for v0.25.2.  It is deliberately
paranoid: every report is untrusted input, and the checks here are exactly
the ones ``06_EVIDENCE_REQUIREMENTS.md`` lists as things a verifier must
reject --

* mismatched Core hashes/versions or Strata commits between reports;
* a "passed" case whose backing commands do not actually show success;
* a raw log file that was edited after the case result was written
  (its recorded sha256 no longer matches the bytes on disk);
* a report missing a required case ID, or inventing one that is not part of
  the canonical matrix.

Any report file that is simply *absent* is not an error here -- it means
that phase has not been attempted yet, which is an honest state (the
resulting verification output records it as such).  What must never happen
is a present report that is internally inconsistent or has been tampered
with; those raise and exit non-zero.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from ranklock.acceptance_matrix_v0252 import (
    CORE_CASE_IDS,
    STRATA_BUILD_CASE_IDS,
    STRATA_E2E_CASE_IDS,
)
from ranklock.evidence_v0252 import EvidenceError, MatrixReport

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"

CORE_SCHEMA = "ranklock-v0252-core-matrix-v1"
STRATA_BUILD_SCHEMA = "ranklock-v0252-strata-build-matrix-v1"
STRATA_E2E_SCHEMA = "ranklock-v0252-strata-e2e-matrix-v1"


def _check(condition: bool, label: str, checks: dict[str, bool]) -> None:
    checks[label] = bool(condition)
    if not condition:
        raise RuntimeError(f"v0.25.2 evidence verification failed: {label}")


def _verify_command_integrity(report_name: str, report: MatrixReport, checks: dict[str, bool]) -> None:
    """Re-hash every referenced log file from disk; reject any mismatch."""

    for case in report.cases:
        for command in case.commands:
            for path_str, recorded_hash, stream in (
                (command.stdout_path, command.stdout_sha256, "stdout"),
                (command.stderr_path, command.stderr_sha256, "stderr"),
            ):
                path = Path(path_str)
                label = f"{report_name}/{case.case_id}: {stream} log at {path.name}"
                if not path.is_file():
                    _check(False, f"{label} exists on disk", checks)
                    continue
                actual_hash = sha256(path.read_bytes()).hexdigest()
                _check(actual_hash == recorded_hash, f"{label} matches recorded hash", checks)


def _verify_passed_cases_have_real_commands(
    report_name: str, report: MatrixReport, checks: dict[str, bool]
) -> None:
    """Re-derive the "passed requires a real, successful command" rule.

    ``CaseResult.__post_init__`` already enforces this at construction time,
    but ``MatrixReport.load`` reconstructs ``CaseResult`` objects from raw
    JSON through the same constructor, so a hand-edited report that flips a
    case's status to "passed" without backing commands is rejected here too,
    not just when the original writer ran.
    """

    for case in report.cases:
        if case.status != "passed":
            continue
        ok = bool(case.commands) and all(
            command.exit_code == 0 and not command.timed_out for command in case.commands
        )
        _check(ok, f"{report_name}/{case.case_id}: passed status is backed by real commands", checks)


def _load_optional(
    path: Path, *, required_case_ids: tuple[str, ...], schema_name: str
) -> MatrixReport | None:
    if not path.is_file():
        return None
    try:
        return MatrixReport.load(path, required_case_ids=required_case_ids, schema_name=schema_name)
    except EvidenceError as exc:
        raise RuntimeError(f"{path}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--core-matrix", type=Path, default=RESULTS / "v0252_bitcoin_core_matrix.json")
    parser.add_argument(
        "--strata-build-matrix", type=Path, default=RESULTS / "v0252_strata_build_matrix.json"
    )
    parser.add_argument("--strata-e2e-matrix", type=Path, default=RESULTS / "v0252_strata_e2e_matrix.json")
    parser.add_argument("--output", type=Path, default=RESULTS / "v0252_evidence_verification.json")
    args = parser.parse_args()

    checks: dict[str, bool] = {}

    core = _load_optional(args.core_matrix, required_case_ids=CORE_CASE_IDS, schema_name=CORE_SCHEMA)
    strata_build = _load_optional(
        args.strata_build_matrix, required_case_ids=STRATA_BUILD_CASE_IDS, schema_name=STRATA_BUILD_SCHEMA
    )
    strata_e2e = _load_optional(
        args.strata_e2e_matrix, required_case_ids=STRATA_E2E_CASE_IDS, schema_name=STRATA_E2E_SCHEMA
    )

    reports: dict[str, MatrixReport] = {}
    if core is not None:
        reports["core"] = core
    if strata_build is not None:
        reports["strata_build"] = strata_build
    if strata_e2e is not None:
        reports["strata_e2e"] = strata_e2e

    for name, report in reports.items():
        _verify_command_integrity(name, report, checks)
        _verify_passed_cases_have_real_commands(name, report, checks)

    # Cross-report identity: if both the Core matrix and the Strata E2E
    # matrix recorded a bitcoind executable hash, they must be the same
    # binary -- an E2E run against an unpinned or different Core than the
    # one qualified in the Core matrix is not qualifying evidence for either.
    if core is not None and strata_e2e is not None:
        core_hash = core.identity.get("bitcoind_sha256")
        e2e_hash = strata_e2e.identity.get("bitcoind_sha256")
        if core_hash is not None and e2e_hash is not None:
            _check(
                core_hash == e2e_hash,
                "Core matrix and Strata E2E matrix used the same pinned bitcoind executable",
                checks,
            )

    # Cross-report identity: the Strata commit qualified during the build
    # phase must be the exact commit exercised during the E2E phase.
    if strata_build is not None and strata_e2e is not None:
        build_commit = strata_build.identity.get("strata_commit")
        e2e_commit = strata_e2e.identity.get("strata_commit")
        if build_commit is not None and e2e_commit is not None:
            _check(
                build_commit == e2e_commit,
                "Strata build matrix and Strata E2E matrix used the same pinned commit",
                checks,
            )

    # The E2E phase is meaningless evidence if the build phase it depends on
    # did not fully pass -- an E2E "pass" against an unformatted/uncompiled/
    # untested patch is not qualifying evidence, regardless of what the E2E
    # report itself claims.
    if strata_e2e is not None:
        _check(
            strata_build is not None and strata_build.all_passed,
            "Strata E2E matrix is only meaningful once the Strata build matrix fully passed",
            checks,
        )

    document = {
        "schema": "ranklock-v0252-evidence-verification-v1",
        "all_checks_passed": all(checks.values()) if checks else True,
        "checks": checks,
        "reports_present": sorted(reports.keys()),
        "core_matrix": None if core is None else core.document(),
        "strata_build_matrix": None if strata_build is None else strata_build.document(),
        "strata_e2e_matrix": None if strata_e2e is None else strata_e2e.document(),
        "bitcoin_core_regtest_executed": bool(core is not None and core.status_counts.get("passed", 0) > 0),
        "bitcoin_core_regtest_all_passed": bool(core is not None and core.all_passed),
        "strata_build_all_passed": bool(strata_build is not None and strata_build.all_passed),
        "strata_e2e_all_passed": bool(strata_e2e is not None and strata_e2e.all_passed),
        "safe_for_funds": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
