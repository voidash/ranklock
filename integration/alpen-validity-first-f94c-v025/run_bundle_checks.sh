#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
python -m py_compile "$ROOT"/*.py "$ROOT"/tests/*.py
cd "$ROOT"
pytest -q tests
