from __future__ import annotations

"""Regression tests for the strict v0.25.2 evidence verifier.

These exercise the verifier as an external process (matching how it is
actually invoked in ``reproduce_v025.sh``-style pipelines), not just its
importable helpers, and specifically prove the two tamper classes
``06_EVIDENCE_REQUIREMENTS.md`` calls out: a status flipped to "passed"
without a real backing command, and a raw log file edited after the report
that references it was written.
"""

import json
from pathlib import Path
import subprocess
import sys

from ranklock.acceptance_matrix_v0252 import CORE_CASE_IDS
from ranklock.evidence_v0252 import CaseResult, MatrixReport, run_recorded_command

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_v0252_evidence.py"
PINNED_BITCOIND_SHA256 = "d55c12b0b02001cc16b1481c4075361dcba193100a8143924abda911174c09ec"


def _run_verifier(core_matrix: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), "--core-matrix", str(core_matrix), "--output", str(output)],
        cwd=ROOT,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=60,
    )


def _all_unavailable_report(tmp_path: Path) -> Path:
    cases = tuple(
        CaseResult(
            case_id=cid,
            status="unavailable",
            description="no independently verified Core 31.1 binary",
            blocked_by="CORE-001",
        )
        for cid in CORE_CASE_IDS
    )
    report = MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={"expected_release": "31.1"},
        cases=cases,
    )
    path = tmp_path / "honest.json"
    report.write(path)
    return path


def test_verifier_accepts_honest_all_unavailable_report(tmp_path: Path):
    report_path = _all_unavailable_report(tmp_path)
    result = _run_verifier(report_path, tmp_path / "out.json")
    assert result.returncode == 0, result.stderr
    document = json.loads((tmp_path / "out.json").read_text())
    assert document["all_checks_passed"] is True
    assert document["bitcoin_core_regtest_all_passed"] is False
    assert document["safe_for_funds"] is False


def test_verifier_rejects_passing_core_report_without_binary_identity(tmp_path: Path):
    command = run_recorded_command(
        [sys.executable, "-c", "print('regtest ok')"],
        cwd=tmp_path,
        log_dir=tmp_path / "logs",
        label="core001-no-identity",
        timeout=30,
    )
    cases = tuple(
        CaseResult(
            case_id=case_id,
            status="passed" if case_id == "CORE-001" else "not_executed",
            description="identity omission regression",
            commands=(command,) if case_id == "CORE-001" else (),
            blocked_by=None if case_id == "CORE-001" else "CORE-001-followups",
        )
        for case_id in CORE_CASE_IDS
    )
    report = MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={"expected_release": "31.1"},
        cases=cases,
    )
    report_path = tmp_path / "missing-identity.json"
    report.write(report_path)

    result = _run_verifier(report_path, tmp_path / "out.json")
    assert result.returncode != 0
    assert "identifies the pinned Bitcoin Core executable" in result.stderr


def test_verifier_accepts_one_legitimately_passed_case(tmp_path: Path):
    command = run_recorded_command(
        [sys.executable, "-c", "print('regtest ok')"],
        cwd=tmp_path,
        log_dir=tmp_path / "logs",
        label="core001",
        timeout=30,
    )
    cases = [
        CaseResult(
            case_id="CORE-001",
            status="passed",
            description="pinned core identity verified",
            commands=(command,),
            evidence={"note": "test fixture"},
        )
    ]
    cases += [
        CaseResult(case_id=cid, status="not_executed", description="blocked", blocked_by="CORE-001-followups")
        for cid in CORE_CASE_IDS
        if cid != "CORE-001"
    ]
    report = MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={
            "expected_release": "31.1",
            "bitcoind_sha256": PINNED_BITCOIND_SHA256,
        },
        cases=tuple(cases),
    )
    report_path = tmp_path / "legit.json"
    report.write(report_path)

    result = _run_verifier(report_path, tmp_path / "out.json")
    assert result.returncode == 0, result.stderr
    document = json.loads((tmp_path / "out.json").read_text())
    assert document["all_checks_passed"] is True


def test_verifier_rejects_status_flip_without_real_command(tmp_path: Path):
    report_path = _all_unavailable_report(tmp_path)
    doc = json.loads(report_path.read_text())
    doc["cases"]["CORE-002"]["status"] = "passed"
    doc["cases"]["CORE-002"]["evidence"] = {"fabricated": True}
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(doc))

    result = _run_verifier(tampered_path, tmp_path / "out.json")
    assert result.returncode != 0
    assert "passed case has no recorded commands" in result.stderr


def test_verifier_rejects_log_file_edited_after_the_fact(tmp_path: Path):
    command = run_recorded_command(
        [sys.executable, "-c", "print('regtest ok')"],
        cwd=tmp_path,
        log_dir=tmp_path / "logs",
        label="core001",
        timeout=30,
    )
    cases = [
        CaseResult(
            case_id="CORE-001",
            status="passed",
            description="pinned core identity verified",
            commands=(command,),
            evidence={"note": "test fixture"},
        )
    ]
    cases += [
        CaseResult(case_id=cid, status="not_executed", description="blocked", blocked_by="CORE-001-followups")
        for cid in CORE_CASE_IDS
        if cid != "CORE-001"
    ]
    report = MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={
            "expected_release": "31.1",
            "bitcoind_sha256": PINNED_BITCOIND_SHA256,
        },
        cases=tuple(cases),
    )
    report_path = tmp_path / "legit.json"
    report.write(report_path)

    # Mutate the log file *after* the report referencing its hash was written.
    Path(command.stdout_path).write_text("TAMPERED CONTENT - NOT WHAT WAS ACTUALLY RUN\n")

    result = _run_verifier(report_path, tmp_path / "out.json")
    assert result.returncode != 0
    assert "matches recorded hash" in result.stderr


def test_verifier_rejects_missing_required_case(tmp_path: Path):
    cases = tuple(
        CaseResult(case_id=cid, status="unavailable", description="x", blocked_by="none")
        for cid in CORE_CASE_IDS[:-1]  # drop the last required case ID
    )
    doc = {
        "schema": "ranklock-v0252-core-matrix-v1",
        "identity": {},
        "cases": {case.case_id: case.document() for case in cases},
    }
    incomplete_path = tmp_path / "incomplete.json"
    incomplete_path.write_text(json.dumps(doc))

    result = _run_verifier(incomplete_path, tmp_path / "out.json")
    assert result.returncode != 0
    assert "missing required cases" in result.stderr
