#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
python -m py_compile "$ROOT"/*.py "$ROOT"/tests/*.py
cd "$ROOT"

# Verify the bundle manifest. Nothing checked this before, so MANIFEST.sha256
# had silently drifted from apply_validity_first.py -- a checksum ledger that
# nothing verifies records nothing. shasum exits nonzero on any mismatch or
# missing file, and set -e fails the whole bundle check with it.
shasum -a 256 -c MANIFEST.sha256 --quiet
echo "MANIFEST.sha256 verified ($(wc -l < MANIFEST.sha256 | tr -d ' ') entries)"

pytest -q tests
