from __future__ import annotations

from pathlib import Path

import pytest

from ranklock.acceptance_matrix_v0252 import CORE_CASE_IDS
from ranklock.evidence_v0252 import (
    CaseResult,
    CommandRecord,
    EvidenceError,
    MatrixReport,
    run_recorded_command,
)


def _ok_command(tmp_path: Path) -> CommandRecord:
    return run_recorded_command(
        ["python3", "-c", "print('hello')"],
        cwd=tmp_path,
        log_dir=tmp_path / "logs",
        label="ok",
        timeout=30,
    )


def test_run_recorded_command_captures_success(tmp_path: Path):
    record = _ok_command(tmp_path)
    assert record.exit_code == 0
    assert not record.timed_out
    assert Path(record.stdout_path).read_bytes() == b"hello\n"
    assert record.stdout_sha256 == __import__("hashlib").sha256(b"hello\n").hexdigest()


def test_run_recorded_command_captures_nonzero_exit(tmp_path: Path):
    record = run_recorded_command(
        ["python3", "-c", "import sys; sys.exit(3)"],
        cwd=tmp_path,
        log_dir=tmp_path / "logs",
        label="fail",
        timeout=30,
    )
    assert record.exit_code == 3
    assert not record.timed_out


def test_run_recorded_command_kills_process_group_on_timeout(tmp_path: Path):
    record = run_recorded_command(
        ["python3", "-c", "import time; time.sleep(30)"],
        cwd=tmp_path,
        log_dir=tmp_path / "logs",
        label="hang",
        timeout=1,
    )
    assert record.timed_out
    assert record.exit_code != 0


def test_case_result_rejects_unknown_status(tmp_path: Path):
    with pytest.raises(EvidenceError):
        CaseResult(case_id="CORE-001", status="ok", description="x")  # type: ignore[arg-type]


def test_case_result_passed_requires_a_successful_command(tmp_path: Path):
    with pytest.raises(EvidenceError):
        CaseResult(case_id="CORE-001", status="passed", description="x")


def test_case_result_passed_rejects_nonzero_command(tmp_path: Path):
    bad = run_recorded_command(
        ["python3", "-c", "import sys; sys.exit(1)"],
        cwd=tmp_path,
        log_dir=tmp_path / "logs",
        label="bad",
        timeout=30,
    )
    with pytest.raises(EvidenceError):
        CaseResult(case_id="CORE-001", status="passed", description="x", commands=(bad,))


def test_case_result_unavailable_must_explain_itself(tmp_path: Path):
    with pytest.raises(EvidenceError):
        CaseResult(case_id="CORE-001", status="unavailable", description="x")
    # A blocked_by or non-empty evidence dict satisfies the requirement.
    CaseResult(case_id="CORE-001", status="unavailable", description="x", blocked_by="no core binary")
    CaseResult(case_id="CORE-001", status="unavailable", description="x", evidence={"reason": "no core"})


def test_matrix_report_requires_exact_case_set(tmp_path: Path):
    one_case = (CaseResult(case_id=CORE_CASE_IDS[0], status="unavailable", description="x", blocked_by="none"),)
    with pytest.raises(EvidenceError):
        MatrixReport(
            schema_name="ranklock-v0252-core-matrix-v1",
            required_case_ids=CORE_CASE_IDS,
            identity={},
            cases=one_case,
        )


def test_matrix_report_round_trips_through_disk(tmp_path: Path):
    cases = tuple(
        CaseResult(case_id=case_id, status="unavailable", description="x", blocked_by="no core binary")
        for case_id in CORE_CASE_IDS
    )
    report = MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={"expected_release": "31.1"},
        cases=cases,
    )
    assert not report.all_passed
    path = tmp_path / "report.json"
    report.write(path)
    loaded = MatrixReport.load(
        path, required_case_ids=CORE_CASE_IDS, schema_name="ranklock-v0252-core-matrix-v1"
    )
    assert loaded.document() == report.document()


def test_matrix_report_rejects_wrong_schema(tmp_path: Path):
    cases = tuple(
        CaseResult(case_id=case_id, status="unavailable", description="x", blocked_by="none")
        for case_id in CORE_CASE_IDS
    )
    report = MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={},
        cases=cases,
    )
    path = tmp_path / "report.json"
    report.write(path)
    with pytest.raises(EvidenceError):
        MatrixReport.load(path, required_case_ids=CORE_CASE_IDS, schema_name="some-other-schema-v1")
