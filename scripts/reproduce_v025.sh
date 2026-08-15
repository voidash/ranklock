#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="${PYTHONPATH:-src}"
workers="${RANKLOCK_TEST_WORKERS:-4}"
timeout="${RANKLOCK_TEST_FILE_TIMEOUT:-420}"

mkdir -p artifacts results
python scripts/check_locked_environment.py > results/v025_environment.json
python -m compileall -q src tests scripts
python scripts/run_test_files.py \
  --workers "$workers" \
  --timeout "$timeout" \
  --json results/v025_test_files_raw.json \
  | tee results/v025_test_runner.log

python - <<'PY'
from pathlib import Path
import json
raw=json.loads(Path('results/v025_test_files_raw.json').read_text())
summary={
  'schema':'ranklock-v025-complete-test-suite-v1',
  'complete': raw['nonzero_files']==0 and raw['files']==raw['total_discovered_files'],
  'files':raw['files'], 'passed':raw['passed'], 'failed':raw['failed'],
  'nonzero_files':raw['nonzero_files'],
  'total_discovered_files':raw['total_discovered_files'],
  'workers':raw['workers'], 'timeout_per_file_seconds':raw['timeout_per_file_seconds'],
}
Path('results/v025_test_files.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
if not summary['complete']:
 raise SystemExit(json.dumps(summary,sort_keys=True))
PY

python scripts/generate_v025_committee_qualification.py \
  > results/v025_committee_qualification.log
python scripts/audit_v025_bitcoin_policy.py \
  > results/v025_bitcoin_policy_envelope.log
python scripts/generate_v025_split_scalar_qualification.py \
  > results/v025_split_scalar_qualification.log

( cd integration/alpen-validity-first-f94c-v025 && ./run_bundle_checks.sh ) \
  > results/v025_strata_handoff_checks.log

set +e
core_args=(
  --bitcoind "${RANKLOCK_BITCOIND:-bitcoind}"
  --output results/v025_bitcoin_core_regtest.json
)
if [[ -n "${RANKLOCK_BITCOIND_SHA256:-}" ]]; then
  core_args+=(--expected-bitcoind-sha256 "$RANKLOCK_BITCOIND_SHA256")
fi
python scripts/run_v025_bitcoin_core_regtest.py "${core_args[@]}" \
  > results/v025_bitcoin_core_regtest.log 2>&1
core_status=$?
set -e
if [[ "$core_status" -ne 0 && "$core_status" -ne 2 ]]; then
  cat results/v025_bitcoin_core_regtest.log >&2
  exit "$core_status"
fi

python scripts/verify_v025_evidence.py \
  > results/v025_evidence_verification.log

python scripts/generate_v0251_security_hardening.py \
  > results/v0251_security_hardening.log

python scripts/generate_v025_release_gate.py \
  --output results/v025_release_gate.json \
  > results/v025_release_gate.log

python - <<'PY'
import json
from pathlib import Path
checks={
 'environment': json.loads(Path('results/v025_environment.json').read_text())['all_checks_passed'],
 'tests': json.loads(Path('results/v025_test_files.json').read_text())['complete'],
 'committee_harness': json.loads(Path('results/v025_committee_qualification.json').read_text())['decision']=='FULL_SIZE_COMMITTEE_SAFETY_HARNESS_PASS_PRODUCTION_GATES_OPEN',
 'split_scalar_harness': json.loads(Path('results/v025_split_scalar_qualification.json').read_text())['decision']=='FULL_SIZE_SPLIT_SCALAR_PARTICIPANT_LOCAL_RELEASE_PASS_REAL_CORE_NATIVE_AUDIT_GATES_OPEN',
 'bitcoin_policy_envelope': json.loads(Path('results/v025_bitcoin_policy_envelope.json').read_text())['passed'],
 'evidence_verifier': json.loads(Path('results/v025_evidence_verification.json').read_text())['all_checks_passed'],
 'security_hardening': json.loads(Path('results/v0251_security_hardening.json').read_text())['all_local_checks_passed'],
 'strata_handoff_checks': '10 passed' in Path('results/v025_strata_handoff_checks.log').read_text(),
 'release_gate_is_fail_closed': json.loads(Path('results/v025_release_gate.json').read_text())['safe_for_funds'] is False,
}
report={
 'schema':'ranklock-v0251-reproducibility-v1',
 'package_version':'0.25.1',
 'checks':checks,
 'all_checks_passed':all(checks.values()),
 'safe_for_funds':False,
 'claim_boundary':'reproducible research/canary harness; external production gates remain open',
}
Path('results/v025_reproducibility.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
if not report['all_checks_passed']:
 raise SystemExit(json.dumps(checks,sort_keys=True))
print(json.dumps(report,indent=2,sort_keys=True))
PY
