#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"


def main() -> int:
    checked = 0
    mismatches: list[dict[str, object]] = []
    for raw in MANIFEST.read_text().splitlines():
        if not raw.strip():
            continue
        expected, relative = raw.split("  ", 1)
        path = ROOT / relative
        if not path.is_file():
            mismatches.append({"path": relative, "error": "missing"})
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        checked += 1
        if actual != expected:
            mismatches.append(
                {"path": relative, "expected": expected, "actual": actual}
            )
    report = {
        "schema": "ranklock-v0241-manifest-verification-v1",
        "entries_checked": checked,
        "mismatches": mismatches,
        "all_checks_passed": not mismatches,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
