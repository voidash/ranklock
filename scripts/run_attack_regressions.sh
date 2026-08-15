#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=src pytest -q \
  tests/test_phased_air.py::test_legacy_helper_has_a_real_late_binding_attack \
  tests/test_phased_permutation.py::test_legacy_tuple_permutation_has_late_binding_forgery \
  tests/test_phased_memory.py::test_legacy_memory_bundle_accepts_unrelated_permutation_and_air_tables \
  tests/test_batched_opening.py::test_known_batching_scalar_allows_false_values_to_cancel \
  tests/test_crt_field.py::test_unbound_dual_proofs_can_describe_two_unrelated_multiplications
