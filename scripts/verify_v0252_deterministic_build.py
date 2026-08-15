#!/usr/bin/env python3
from __future__ import annotations

"""EVID-007: prove the release archives are byte-reproducible.

``build_v025_release.py`` already sorts entries and pins timestamps,
permissions and compression level.  That makes determinism *plausible*; this
script makes it *evidence* by building twice into separate clean directories
and comparing every produced artifact byte for byte.

Two builds from the same tree is the check EVID-007 actually asks for.  It
does not establish that a different machine reproduces the same bytes -- that
additionally requires a hash-locked dependency set, which is recorded as a
separate open item rather than implied here.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import tempfile

from ranklock.evidence_v0252 import run_recorded_command

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_v025_release.py"


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "v0252_deterministic_build.json")
    parser.add_argument("--log-dir", type=Path, default=ROOT / "results" / "v0252_logs")
    args = parser.parse_args()

    workspace = Path(tempfile.mkdtemp(prefix="ranklock-v0252-determinism-"))
    try:
        first_dir = workspace / "build-a"
        second_dir = workspace / "build-b"
        commands = []
        for output_dir, label in ((first_dir, "build-a"), (second_dir, "build-b")):
            record = run_recorded_command(
                [sys.executable, str(BUILDER), "--output-dir", str(output_dir)],
                cwd=ROOT,
                log_dir=args.log_dir,
                label=f"deterministic-{label}",
                timeout=1800,
            )
            commands.append(record)
            if record.exit_code != 0:
                print(f"{label} failed with exit {record.exit_code}", file=sys.stderr)
                return 1

        first = {path.name: path for path in sorted(first_dir.iterdir()) if path.is_file()}
        second = {path.name: path for path in sorted(second_dir.iterdir()) if path.is_file()}

        artifacts = []
        identical = first.keys() == second.keys()
        for name in sorted(first.keys() | second.keys()):
            left, right = first.get(name), second.get(name)
            if left is None or right is None:
                identical = False
                artifacts.append({"name": name, "identical": False, "reason": "missing from one build"})
                continue
            left_digest, right_digest = _digest(left), _digest(right)
            match = left_digest == right_digest
            identical = identical and match
            artifacts.append(
                {
                    "name": name,
                    "identical": match,
                    "sha256": left_digest if match else None,
                    "first_sha256": left_digest,
                    "second_sha256": right_digest,
                    "bytes": left.stat().st_size,
                }
            )

        document = {
            "schema": "ranklock-v0252-deterministic-build-v1",
            "status": "passed" if identical else "failed",
            "byte_identical": identical,
            "artifact_count": len(artifacts),
            "artifacts": artifacts,
            "commands": [record.document() for record in commands],
            "scope_note": (
                "two builds from the same working tree on one machine; "
                "cross-machine reproducibility additionally requires a "
                "hash-locked dependency set and is not established here"
            ),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        print(json.dumps({k: document[k] for k in ("status", "byte_identical", "artifact_count")}, indent=2))
        for artifact in artifacts:
            flag = "IDENTICAL" if artifact["identical"] else "DIFFERS  "
            print(f"  {flag}  {artifact['name']}")
        return 0 if identical else 1
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
