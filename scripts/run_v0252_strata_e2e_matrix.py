#!/usr/bin/env python3
from __future__ import annotations

"""Run (or honestly decline to run) the STRATA-010..020 execution matrix.

The build matrix qualifies a tree that compiles and whose tests pass. These
eleven qualify *behaviour*: that a valid RankLock unlock yields an ACK the
existing slash path accepts, that its absence yields a CSV-gated NACK and a
contested payout, and that neither can be forced by a malformed, replayed,
mutated or concurrently-raced input.

Today none of them execute, because no bridge node is running. That is
recorded rather than hidden: every case reports ``not_executed`` with the
specific prerequisite that is absent, and the probe output that established
its absence. The point of writing this now is that the *absence* becomes
visible evidence -- previously STRATA-010..020 had no report at all, which
reads the same as a phase nobody thought about.

This script will never mark a case ``passed``. ``CaseResult`` cannot even be
constructed as passed without a recorded zero-exit command behind it, so
adding execution later means adding real commands, not editing a status.
"""

import argparse
from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

from ranklock.acceptance_matrix_v0252 import STRATA_E2E_CASE_IDS
from ranklock.evidence_v0252 import CaseResult, MatrixReport
from ranklock.strata_e2e_v0252 import (
    CASE_DEFINITIONS,
    blocked_by_text,
    prerequisites_for,
)

ROOT = Path(__file__).resolve().parents[1]
PINNED_COMMIT = "f94c06d08ff29eee746f3e20bd63078d2949b304"


def _probe_bridge_binary(checkout: Path | None) -> dict[str, object]:
    """Look for a built strata-bridge binary.

    Absence is the expected result today. It is reported with the path that
    was searched so the row says what was checked, not merely that something
    was missing.
    """

    if checkout is None:
        return {
            "searched": None,
            "present": False,
            "note": "no --bridge-checkout supplied",
        }
    candidate = checkout / "target" / "debug" / "strata-bridge"
    return {
        "searched": str(candidate),
        "present": candidate.is_file(),
    }


def _probe_fdb() -> dict[str, object]:
    """Report whether a FoundationDB cluster file is reachable."""

    cluster = Path("/usr/local/etc/foundationdb/fdb.cluster")
    probe: dict[str, object] = {
        "cluster_file": str(cluster),
        "present": cluster.exists(),
    }
    cli = shutil.which("fdbcli")
    if cli is None:
        probe["fdbcli"] = None
        return probe
    probe["fdbcli"] = cli
    try:
        status = subprocess.run(
            [cli, "--exec", "status minimal", "--timeout", "30"],
            text=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        probe["status_error"] = str(error)
    else:
        probe["status"] = status.stdout.strip()[:200]
    return probe


def _probe_bitcoind() -> dict[str, object]:
    resolved = shutil.which("bitcoind")
    probe: dict[str, object] = {"resolved": resolved, "present": resolved is not None}
    if resolved is None:
        return probe
    path = Path(resolved)
    try:
        probe["sha256"] = sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        probe["sha256_error"] = str(exc)
    try:
        version = subprocess.run(
            [resolved, "--version"],
            text=True,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        probe["version_error"] = str(exc)
    else:
        probe["version_exit_code"] = version.returncode
        probe["version"] = version.stdout.splitlines()[0] if version.stdout else ""
    return probe


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bridge-checkout",
        type=Path,
        default=None,
        help="patched strata-bridge checkout whose target/ may hold a built node",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "v0252_strata_e2e_matrix.json",
    )
    args = parser.parse_args()

    bitcoind = _probe_bitcoind()
    environment = {
        "bridge_binary": _probe_bridge_binary(args.bridge_checkout),
        "foundationdb": _probe_fdb(),
        "bitcoind": bitcoind,
    }

    cases: list[CaseResult] = []
    for case_id, scenario, expectation in CASE_DEFINITIONS:
        cases.append(
            CaseResult(
                case_id=case_id,
                status="not_executed",
                description=f"{scenario}: {expectation}",
                blocked_by=blocked_by_text(case_id),
                evidence={
                    "scenario": scenario,
                    "expectation": expectation,
                    "wording_source": "03_ACCEPTANCE_MATRIX.md (verbatim)",
                    "prerequisites": [
                        {"name": item.name, "probe": item.probe}
                        for item in prerequisites_for(case_id)
                    ],
                    "environment_probe": environment,
                },
            )
        )

    report = MatrixReport(
        schema_name="ranklock-v0252-strata-e2e-matrix-v1",
        required_case_ids=STRATA_E2E_CASE_IDS,
        identity={
            "strata_commit": PINNED_COMMIT,
            "bridge_checkout": str(args.bridge_checkout) if args.bridge_checkout else None,
            "bitcoind_path": bitcoind.get("resolved"),
            "bitcoind_sha256": bitcoind.get("sha256"),
            "bitcoind_version": bitcoind.get("version"),
        },
        cases=tuple(cases),
    )
    report.write(args.output)

    counts = report.status_counts
    print(f"wrote {args.output}")
    for status in ("passed", "failed", "not_executed", "unavailable", "modeled_only"):
        print(f"  {status:<13} {counts.get(status, 0)}")
    print(
        "\nNo case executed. The execution phase needs a running bridge node;\n"
        "see V0252_PATH_TO_PRODUCTION.md for what that requires."
    )
    # Not a failure: declining to execute is the honest outcome, and the
    # release gate already treats a non-passed row as an open blocker.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
