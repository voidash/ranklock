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


# ---------------------------------------------------------------------------
# The clean-archive report closes complete_source_archive_reproducible, which
# is a funds blocker. It used to be consumed with no schema or version check
# at all -- only `all_checks_passed` was read -- so evidence from a different
# release could have closed a v0.25.2 funds blocker. These pin both
# directions of that guard.
#
# Note what is deliberately absent: no fixture here sets
# `all_checks_passed: true`. Writing one would manufacture the very
# reproduction the guard exists to protect. The accept-side test instead uses
# a well-formed report whose result is null, which proves the guard lets a
# correctly-versioned report through *without* asserting a passing run.
# ---------------------------------------------------------------------------

CLEAN_SCHEMA = "ranklock-v0251-clean-archive-verification-v1"
SOURCE_VERSION = "0.25.1"


def _clean_report(tmp_path: Path, **overrides: object) -> Path:
    document: dict[str, object] = {
        "schema": CLEAN_SCHEMA,
        "package_version": SOURCE_VERSION,
        "all_checks_passed": None,
    }
    document.update(overrides)
    path = tmp_path / "clean.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return path


def test_clean_archive_report_from_another_release_is_rejected(tmp_path: Path):
    """A stale report must not close a funds blocker for this release."""

    report = _clean_report(tmp_path, package_version="0.18.0")
    result = _run_generator(
        [
            "--clean-archive-report",
            str(report),
            "--output",
            str(tmp_path / "gate.json"),
        ]
    )
    assert result.returncode != 0
    assert "0.18.0" in result.stderr
    assert not (tmp_path / "gate.json").exists(), "a rejected run must write no gate"


def test_clean_archive_report_with_a_foreign_schema_is_rejected(tmp_path: Path):
    """The v0.18-era schema is rejected rather than accepted as a fallback."""

    report = _clean_report(tmp_path, schema="ranklock-clean-archive-verification-v1")
    result = _run_generator(
        [
            "--clean-archive-report",
            str(report),
            "--output",
            str(tmp_path / "gate.json"),
        ]
    )
    assert result.returncode != 0
    assert "schema" in result.stderr


def test_the_real_stale_report_in_results_is_rejected(tmp_path: Path):
    """The actual artifact sitting in results/ must not be accepted.

    It is a v0.18.0 document. It happens to fail closed on its own because
    its `all_checks_passed` is null, but the gate must reject it outright
    rather than depend on that.
    """

    stale = ROOT / "results" / "clean_archive_verification.json"
    if not stale.is_file():
        return
    result = _run_generator(
        [
            "--clean-archive-report",
            str(stale),
            "--output",
            str(tmp_path / "gate.json"),
        ]
    )
    assert result.returncode != 0


def test_a_correctly_versioned_clean_report_is_accepted(tmp_path: Path):
    """The guard must not be fail-closed-too-far.

    A report carrying this release's schema and source version has to get
    through, or the clean-extraction run that is supposed to close the funds
    blocker could never do so. Its result here is null, so the fact stays
    false -- acceptance is about the guard, not about the outcome.
    """

    report = _clean_report(tmp_path)
    result = _run_generator(
        [
            "--clean-archive-report",
            str(report),
            "--output",
            str(tmp_path / "gate.json"),
        ]
    )
    assert result.returncode == 0, result.stderr
    document = json.loads((tmp_path / "gate.json").read_text())
    assert document["facts"]["complete_source_archive_reproducible"] is False
    assert document["safe_for_funds"] is False


# ---------------------------------------------------------------------------
# Plan section 7.5: prove that even a *completely green* local matrix leaves
# production ceremony, native hardening, independent rollback operations and
# the external audits false, so safe_for_funds stays false.
#
# tests/test_release_qualification.py already pins this at the model layer,
# where the facts are constructor arguments. That leaves the question this
# test answers: can the *generator* be driven to emit those facts as true by
# any evidence a local run can produce? If it could, the fail-closed boundary
# would be a convention rather than a property, and the model-layer tests
# would be guarding a door with no wall attached.
# ---------------------------------------------------------------------------

EXTERNALLY_ATTESTED_FACTS = (
    "native_constant_time_implementation",
    "production_rollback_witnesses_deployed",
    "deterministic_fixture_secrets_absent",
    "independent_cryptography_audit_passed",
    "independent_implementation_audit_passed",
    "split_scalar_production_setup_passed",
)


def test_a_fully_passing_local_matrix_still_cannot_open_the_funds_gate(tmp_path: Path):
    from ranklock.acceptance_matrix_v0252 import STRATA_BUILD_CASE_IDS
    from ranklock.evidence_v0252 import run_recorded_command

    command = run_recorded_command(
        [sys.executable, "-c", "print('everything green')"],
        cwd=tmp_path,
        log_dir=tmp_path / "logs",
        label="all-green",
        timeout=30,
    )

    # Every CORE and every STRATA build case passing -- the best result any
    # amount of local engineering could ever produce.
    core_path = tmp_path / "core_matrix.json"
    MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={"expected_release": "31.1"},
        cases=tuple(
            CaseResult(
                case_id=cid,
                status="passed",
                description="green fixture",
                commands=(command,),
                evidence={"note": "test fixture"},
            )
            for cid in CORE_CASE_IDS
        ),
    ).write(core_path)

    strata_path = tmp_path / "strata_matrix.json"
    MatrixReport(
        schema_name="ranklock-v0252-strata-build-matrix-v1",
        required_case_ids=STRATA_BUILD_CASE_IDS,
        identity={"strata_commit": "f" * 40},
        cases=tuple(
            CaseResult(
                case_id=cid,
                status="passed",
                description="green fixture",
                commands=(command,),
                evidence={"note": "test fixture"},
            )
            for cid in STRATA_BUILD_CASE_IDS
        ),
    ).write(strata_path)

    verification_path = tmp_path / "verification.json"
    verify = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_v0252_evidence.py"),
            "--core-matrix",
            str(core_path),
            "--strata-build-matrix",
            str(strata_path),
            # Point the E2E report at a path that does not exist, so this test
            # is hermetic. Without it the verifier falls back to the real
            # results/ report and cross-checks its pinned commit against this
            # fixture's placeholder, which correctly fails -- a verifier
            # working as designed, but not what this test is about.
            "--strata-e2e-matrix",
            str(tmp_path / "no-e2e-report.json"),
            "--output",
            str(verification_path),
        ],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert verify.returncode == 0, verify.stderr

    verification = json.loads(verification_path.read_text())
    assert verification["bitcoin_core_regtest_all_passed"] is True
    assert verification["strata_build_all_passed"] is True

    gate = _run_generator(
        [
            "--evidence-verification",
            str(verification_path),
            "--output",
            str(tmp_path / "gate.json"),
        ]
    )
    assert gate.returncode == 0, gate.stderr
    document = json.loads((tmp_path / "gate.json").read_text())
    facts = document["facts"]

    # The local half really did close.
    assert facts["bitcoin_core_regtest_passed"] is True
    assert facts["current_bridge_compiled_and_tested"] is True

    # The external half cannot be reached from here, by construction.
    for name in EXTERNALLY_ATTESTED_FACTS:
        assert facts[name] is False, (
            f"{name} became true from purely local evidence; the funds gate "
            "must depend on attestations this machine cannot produce"
        )

    assert document["safe_for_funds"] is False
    assert document["maximum_mode"] != "enforce"
    for message in (
        "independent cryptography audit is absent",
        "independent implementation audit is absent",
        "production rollback witnesses are not deployed",
        "native constant-time implementation is absent",
    ):
        assert message in document["funds_blockers"]
