#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ranklock.bitcoin_core_regtest import (
    EXPECTED_CORE_RELEASE,
    EXPECTED_CORE_VERSION,
    BitcoinCoreRegtestError,
    run_bitcoin_core_regtest,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the full RankLock v0.25.1 two-slot Bitcoin Core regtest"
    )
    parser.add_argument("--bitcoind", default="bitcoind")
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--expected-version",
        type=int,
        default=EXPECTED_CORE_VERSION,
        help=(
            f"Bitcoin Core numeric version (default: {EXPECTED_CORE_RELEASE}); "
            "use 0 only for deliberate local development"
        ),
    )
    parser.add_argument(
        "--expected-bitcoind-sha256",
        default=os.environ.get("RANKLOCK_BITCOIND_SHA256"),
        help=(
            "pinned SHA-256 of the supplied bitcoind executable; defaults to "
            "RANKLOCK_BITCOIND_SHA256"
        ),
    )
    parser.add_argument(
        "--allow-unpinned-bitcoind",
        action="store_true",
        help="development only: execute a bitcoind whose executable hash was not pinned",
    )
    args = parser.parse_args()
    expected_version = None if args.expected_version == 0 else args.expected_version
    try:
        if not args.expected_bitcoind_sha256 and not args.allow_unpinned_bitcoind:
            raise BitcoinCoreRegtestError(
                "a pinned bitcoind executable SHA-256 is required; "
                "set --expected-bitcoind-sha256 or RANKLOCK_BITCOIND_SHA256"
            )
        result = run_bitcoin_core_regtest(
            bitcoind=args.bitcoind,
            working_directory=args.workdir,
            expected_version=expected_version,
            expected_bitcoind_sha256=args.expected_bitcoind_sha256,
        )
        document = {
            "schema": "ranklock-v025-bitcoin-core-regtest-evidence-v3",
            "executed": True,
            "passed": True,
            "result": result.document(),
        }
        exit_code = 0
    except BitcoinCoreRegtestError as exc:
        document = {
            "schema": "ranklock-v025-bitcoin-core-regtest-evidence-v3",
            "executed": False,
            "passed": False,
            "error": str(exc),
        }
        exit_code = 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
