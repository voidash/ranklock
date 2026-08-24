#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ -n "${PYTHON_BIN:-}" ]]; then
  if [[ ! -x "$PYTHON_BIN" ]]; then
    echo "error: PYTHON_BIN is not executable: $PYTHON_BIN" >&2
    exit 1
  fi
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
else
  echo "error: neither python nor python3 is available" >&2
  exit 1
fi

"$PYTHON_BIN" -m py_compile "$ROOT"/*.py "$ROOT"/tests/*.py
cd "$ROOT"

# Verify that the manifest covers every distributable bundle file. Hash checks
# alone do not detect an executable patch omitted from the ledger.
actual_files="$(mktemp)"
manifest_files="$(mktemp)"
cleanup() {
  rm -f "$actual_files" "$manifest_files"
}
trap cleanup EXIT

find . -type f \
  ! -name MANIFEST.sha256 \
  ! -name '*.pyc' \
  ! -path '*/__pycache__/*' \
  ! -path '*/.pytest_cache/*' \
  -print | LC_ALL=C sort > "$actual_files"
awk '{print $2}' MANIFEST.sha256 | LC_ALL=C sort > "$manifest_files"
if ! diff -u "$manifest_files" "$actual_files"; then
  echo "error: MANIFEST.sha256 does not cover the complete bundle" >&2
  exit 1
fi

# shasum exits nonzero on any mismatch or missing file, and set -e fails the
# whole bundle check with it.
shasum -a 256 -c MANIFEST.sha256 --quiet
echo "MANIFEST.sha256 verified ($(wc -l < MANIFEST.sha256 | tr -d ' ') entries)"

"$PYTHON_BIN" -m pytest -q tests
