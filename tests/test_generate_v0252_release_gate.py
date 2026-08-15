from __future__ import annotations

"""Regression tests for scripts/generate_v0252_release_gate.py.

These prove the gate generator's key invariant: it derives
bitcoin_core_regtest_passed / current_bridge_compiled_and_tested *only* from
the strict verifier's output, never from a raw matrix report, and it refuses
outright to run when the verifier itself flagged an inconsistency.
"""

import json
import os
from pathlib import Path
import subprocess
import sys

from ranklock.acceptance_matrix_v0252 import CORE_CASE_IDS
from ranklock.evidence_v0252 import CaseResult, MatrixReport

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate_v0252_release_gate.py"


def _run_generator(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GENERATOR), *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_gate_stays_fail_closed_with_no_v0252_evidence(tmp_path: Path):
    result = _run_generator(
        [
            "--evidence-verification",
            str(tmp_path / "does-not-exist.json"),
            "--output",
            str(tmp_path / "gate.json"),
        ]
    )
    assert result.returncode == 0, result.stderr
    document = json.loads((tmp_path / "gate.json").read_text())
    assert document["safe_for_funds"] is False
    assert document["facts"]["bitcoin_core_regtest_executed"] is False
    assert document["facts"]["bitcoin_core_regtest_passed"] is False
    assert document["facts"]["current_bridge_compiled_and_tested"] is False
    assert document["evidence_verification"] is None


def test_gate_refuses_to_run_when_verifier_flags_inconsistency(tmp_path: Path):
    tampered = {
        "schema": "ranklock-v0252-evidence-verification-v1",
        "all_checks_passed": False,
        "checks": {"some check": False},
        "reports_present": [],
        "core_matrix": None,
        "strata_build_matrix": None,
        "strata_e2e_matrix": None,
        "bitcoin_core_regtest_executed": False,
        "bitcoin_core_regtest_all_passed": False,
        "strata_build_all_passed": False,
        "strata_e2e_all_passed": False,
        "safe_for_funds": False,
    }
    verification_path = tmp_path / "verification.json"
    verification_path.write_text(json.dumps(tampered))

    result = _run_generator(
        [
            "--evidence-verification",
            str(verification_path),
            "--output",
            str(tmp_path / "gate.json"),
        ]
    )
    assert result.returncode != 0
    assert "internal inconsistencies" in result.stderr
    assert not (tmp_path / "gate.json").exists()


def test_gate_reflects_a_genuinely_passed_core_matrix_via_the_verifier_only(tmp_path: Path):
    """A raw matrix report claiming success is not enough on its own -- the
    gate must go through the verifier. This test drives the real pipeline
    (matrix -> verifier -> gate) end to end rather than hand-crafting the
    verifier's output, so it also proves the two scripts compose correctly.
    """

    from ranklock.evidence_v0252 import run_recorded_command

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
    matrix_path = tmp_path / "core_matrix.json"
    MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={"expected_release": "31.1"},
        cases=tuple(cases),
    ).write(matrix_path)

    verifier = ROOT / "scripts" / "verify_v0252_evidence.py"
    verification_path = tmp_path / "verification.json"
    verify_result = subprocess.run(
        [
            sys.executable,
            str(verifier),
            "--core-matrix",
            str(matrix_path),
            "--output",
            str(verification_path),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert verify_result.returncode == 0, verify_result.stderr

    gate_result = _run_generator(
        ["--evidence-verification", str(verification_path), "--output", str(tmp_path / "gate.json")]
    )
    assert gate_result.returncode == 0, gate_result.stderr
    document = json.loads((tmp_path / "gate.json").read_text())
    # Only one of thirty cases passed, the rest are not_executed -- the whole
    # matrix must not be reported as passed, and safe_for_funds must stay
    # false regardless.
    assert document["facts"]["bitcoin_core_regtest_executed"] is True
    assert document["facts"]["bitcoin_core_regtest_passed"] is False
    assert document["safe_for_funds"] is False
