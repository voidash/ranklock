#!/usr/bin/env python3
from __future__ import annotations

"""Run the CORE-001..030 acceptance matrix and write versioned evidence.

Qualification requires an independently verified, hash-pinned Bitcoin Core
31.1 release.  Supply it with ``--bitcoind`` and ``--expected-bitcoind-sha256``.

There is deliberately no ``--allow-unpinned-bitcoind`` flag.  A development
probe against some other build is still possible via ``--development-probe``,
but that path marks CORE-001 ``unavailable`` and stamps the report so it can
never be mistaken for qualification evidence.
"""

import argparse
from pathlib import Path
import sys
import tempfile

from ranklock.core_matrix_v0252 import run_core_matrix
from ranklock.evidence_v0252 import CommandRecord, run_recorded_command
from ranklock.regtest_node import binary_sha256, resolve_bitcoind

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoind", default="bitcoind")
    parser.add_argument(
        "--expected-bitcoind-sha256",
        help="SHA-256 of the independently verified bitcoind executable",
    )
    parser.add_argument(
        "--development-probe",
        action="store_true",
        help=(
            "run against an unpinned binary for development; CORE-001 is "
            "recorded as unavailable and the report is marked non-qualifying"
        ),
    )
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "v0252_bitcoin_core_matrix.json")
    parser.add_argument("--log-dir", type=Path, default=ROOT / "results" / "v0252_logs")
    parser.add_argument("--working-directory", type=Path)
    args = parser.parse_args()

    if args.expected_bitcoind_sha256 is None and not args.development_probe:
        parser.error(
            "qualification requires --expected-bitcoind-sha256 for an "
            "independently verified Bitcoin Core 31.1 release; use "
            "--development-probe to run against an unpinned binary without "
            "producing qualification evidence"
        )

    executable = resolve_bitcoind(args.bitcoind)

    # The matrix runs in-process, so record an explicit provenance command
    # rather than fabricating one: this captures the exact binary identity the
    # scenarios ran against, with its own raw log and hashes.
    provenance = run_recorded_command(
        [executable, "--version"],
        cwd=ROOT,
        log_dir=args.log_dir,
        label="core-matrix-bitcoind-version",
        timeout=60,
    )
    if provenance.exit_code != 0:
        print(f"bitcoind --version failed with exit {provenance.exit_code}", file=sys.stderr)
        return 1

    root = args.working_directory or Path(tempfile.mkdtemp(prefix="ranklock-v0252-core-matrix-"))
    root.mkdir(parents=True, exist_ok=True)

    report = run_core_matrix(
        bitcoind=executable,
        root=root,
        command_record=provenance,
        expected_bitcoind_sha256=args.expected_bitcoind_sha256,
        enforce_pinned_release=not args.development_probe,
    )
    report.write(args.output)

    counts = report.status_counts
    print(f"wrote {args.output}")
    print(f"observed bitcoind sha256: {binary_sha256(executable)}")
    for status in ("passed", "failed", "not_executed", "unavailable", "modeled_only"):
        print(f"  {status:<13} {counts.get(status, 0)}")
    if args.development_probe:
        print("DEVELOPMENT PROBE: this report is not qualification evidence.")
    # A failed case is a real defect and must break the build; not_executed and
    # unavailable are honest states that do not.
    return 1 if report.any_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
