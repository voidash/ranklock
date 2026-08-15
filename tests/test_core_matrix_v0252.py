from __future__ import annotations

"""Regression tests for the CORE-001..030 matrix runner.

The Core-backed run is skipped when no ``bitcoind`` is available.  When one is
present these assert the honest-reporting properties that matter most: the
report covers exactly the canonical case set, an unpinned binary can never
close CORE-001, and a partially-executed matrix never reports as passed.
"""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from ranklock.acceptance_matrix_v0252 import CORE_CASE_IDS
from ranklock.core_matrix_v0252 import run_core_matrix
from ranklock.evidence_v0252 import run_recorded_command


def _bitcoind_or_skip() -> str:
    candidate = os.environ.get("RANKLOCK_BITCOIND") or shutil.which("bitcoind")
    if candidate is None:
        pytest.skip("no bitcoind available for the CORE matrix runner tests")
    return candidate


@pytest.fixture(scope="module")
def probe_report():
    bitcoind = _bitcoind_or_skip()
    root = Path(tempfile.mkdtemp(prefix="ranklock-core-matrix-test-"))
    try:
        command = run_recorded_command(
            [bitcoind, "--version"],
            cwd=root,
            log_dir=root / "logs",
            label="version",
            timeout=60,
        )
        yield run_core_matrix(
            bitcoind=bitcoind,
            root=root,
            command_record=command,
            expected_bitcoind_sha256=None,
            enforce_pinned_release=False,
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_report_covers_exactly_the_canonical_case_set(probe_report):
    assert {case.case_id for case in probe_report.cases} == set(CORE_CASE_IDS)


def test_no_case_fails(probe_report):
    failures = [case.case_id for case in probe_report.cases if case.status == "failed"]
    assert not failures, f"CORE cases failed: {failures}"


def test_an_unpinned_binary_can_never_close_core_001(probe_report):
    identity = next(case for case in probe_report.cases if case.case_id == "CORE-001")
    assert identity.status == "unavailable"
    assert identity.blocked_by


def test_partial_execution_is_not_reported_as_passed(probe_report):
    """A matrix with unexecuted rows must not read as a passing matrix."""

    assert not probe_report.all_passed
    counts = probe_report.status_counts
    assert counts["not_executed"] > 0
    # Every unexecuted row must say what is blocking it rather than be blank.
    for case in probe_report.cases:
        if case.status in {"not_executed", "unavailable"}:
            assert case.blocked_by, f"{case.case_id} is {case.status} with no blocked_by"


def test_executed_negative_cases_pin_their_rejection_reason(probe_report):
    """A negative case must reject for the reason it claims to test.

    Without this, e.g. the fee-floor case could silently start passing
    because the signature was invalid instead.
    """

    expected = {
        "CORE-004": "OP_VERIFY",
        "CORE-006": "OP_VERIFY",
        "CORE-007": "OP_VERIFY",
        "CORE-012": "Witness program hash mismatch",
        "CORE-024": "min relay fee not met",
        "CORE-028": "Invalid Schnorr signature",
    }
    by_id = {case.case_id: case for case in probe_report.cases}
    for case_id, substring in expected.items():
        case = by_id[case_id]
        if case.status != "passed":
            continue
        reason = str(case.evidence["testmempoolaccept"].get("reject-reason"))  # type: ignore[union-attr]
        assert substring in reason, f"{case_id} rejected for the wrong reason: {reason}"
