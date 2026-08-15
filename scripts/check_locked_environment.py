#!/usr/bin/env python3
from __future__ import annotations

import importlib.metadata
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements.lock"


def parse_lock() -> dict[str, str]:
    locked: dict[str, str] = {}
    for raw in LOCK.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "==" not in line:
            raise RuntimeError(f"unsupported lock entry: {line}")
        name, version = line.split("==", 1)
        locked[name.strip().lower()] = version.strip()
    return locked


def main() -> int:
    locked = parse_lock()
    installed: dict[str, str | None] = {}
    mismatches: list[dict[str, str | None]] = []
    for name, expected in locked.items():
        try:
            actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            actual = None
        installed[name] = actual
        if actual != expected:
            mismatches.append({"name": name, "expected": expected, "actual": actual})

    py_ok = sys.version_info[:2] >= (3, 11)
    report = {
        "schema": "ranklock-v0241-locked-environment-check-v1",
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_at_least_3_11": py_ok,
        "platform": platform.platform(),
        "locked": locked,
        "installed": installed,
        "mismatches": mismatches,
        "all_checks_passed": py_ok and not mismatches,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
