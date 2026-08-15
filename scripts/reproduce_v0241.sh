#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="${PYTHONPATH:-src}"
export RANKLOCK_V0241_INSECURE_REPRO_SEED="${RANKLOCK_V0241_INSECURE_REPRO_SEED:-ranklock-v0241-public-conformance-seed}"
workers="${RANKLOCK_TEST_WORKERS:-2}"
timeout="${RANKLOCK_TEST_FILE_TIMEOUT:-420}"

mkdir -p artifacts results
python scripts/check_locked_environment.py > results/v0241_environment.json
python -m compileall -q src tests scripts
python scripts/run_test_files.py \
  --workers "$workers" \
  --timeout "$timeout" \
  --json results/v0241_test_files.json \
  | tee results/v0241_test_runner.log

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/run1/artifacts" "$scratch/run1/results"

python scripts/generate_v0241_security_qualification.py \
  > results/v0241_generation_run1.log
python scripts/verify_v0241_security_qualification.py \
  > results/v0241_verification_run1.log
cp artifacts/*v0241* "$scratch/run1/artifacts/"
cp results/v0241_security_qualification.json \
   results/v0241_independent_verification.json \
   "$scratch/run1/results/"

python scripts/generate_v0241_security_qualification.py \
  > results/v0241_generation_run2.log
python scripts/verify_v0241_security_qualification.py \
  > results/v0241_verification_run2.log

python - "$scratch/run1" <<'PY'
from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path.cwd()
run1 = Path(sys.argv[1])
artifact_names = sorted(path.name for path in (root / "artifacts").glob("*v0241*"))
if not artifact_names:
    raise SystemExit("no v0.24.1 artifacts were generated")

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

comparisons = []
for name in artifact_names:
    first = run1 / "artifacts" / name
    second = root / "artifacts" / name
    if not first.is_file() or not second.is_file():
        raise SystemExit(f"missing deterministic artifact: {name}")
    comparisons.append(
        {
            "path": f"artifacts/{name}",
            "bytes": second.stat().st_size,
            "run1_sha256": digest(first),
            "run2_sha256": digest(second),
            "byte_identical": first.read_bytes() == second.read_bytes(),
        }
    )

def normalized(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text())
    document.pop("generated_at_utc", None)
    document.pop("verified_at_utc", None)
    return document

report_pairs = []
for name in (
    "v0241_security_qualification.json",
    "v0241_independent_verification.json",
):
    first = normalized(run1 / "results" / name)
    second = normalized(root / "results" / name)
    report_pairs.append({"path": f"results/{name}", "normalized_equal": first == second})

qualification = json.loads((root / "results/v0241_security_qualification.json").read_text())
verification = json.loads((root / "results/v0241_independent_verification.json").read_text())
tests = json.loads((root / "results/v0241_test_files.json").read_text())
environment = json.loads((root / "results/v0241_environment.json").read_text())
all_identical = all(row["byte_identical"] for row in comparisons)
reports_equal = all(row["normalized_equal"] for row in report_pairs)
checks = {
    "locked_environment": bool(environment["all_checks_passed"]),
    "compileall": True,
    "full_test_suite": tests["nonzero_files"] == 0,
    "two_deterministic_generations_byte_identical": all_identical,
    "normalized_reports_equal": reports_equal,
    "independent_public_replay": bool(verification["all_checks_passed"]),
    "retained_object_below_one_mib": qualification["retained_object"]["bytes"] < 1 << 20,
    "safe_for_funds_remains_false": qualification["safe_for_funds"] is False,
}
summary = {
    "schema": "ranklock-v0241-reproducibility-run-v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "package_version": "0.24.1",
    "python": platform.python_version(),
    "public_conformance_seed_fingerprint": qualification["generation_entropy"]["reproduction_seed_fingerprint"],
    "tests": {
        "files": tests["files"],
        "passed": tests["passed"],
        "failed": tests["failed"],
        "nonzero_files": tests["nonzero_files"],
    },
    "artifact_comparisons": comparisons,
    "report_comparisons": report_pairs,
    "checks": checks,
    "all_checks_passed": all(checks.values()),
    "safe_for_funds": False,
    "remaining_production_gates": qualification["remaining_production_gates"],
}
(root / "results/v0241_reproducibility.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n"
)
if not summary["all_checks_passed"]:
    raise SystemExit(json.dumps(checks, sort_keys=True))
print(json.dumps(summary, indent=2, sort_keys=True))
PY

printf '%s\n' 'RankLock v0.24.1 reproducibility checks passed.'
