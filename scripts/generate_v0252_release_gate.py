#!/usr/bin/env python3
from __future__ import annotations

"""Generate the v0.25.2 release gate from verified evidence only.

This mirrors ``scripts/generate_v025_release_gate.py`` for the v0.25.1
research/canary facts (source reproducibility, package tests, committee and
split-scalar harnesses, static Bitcoin policy envelope, local hardening --
none of that changes for v0.25.2), but for the two facts v0.25.2 actually
extends -- ``bitcoin_core_regtest_passed`` and
``current_bridge_compiled_and_tested`` -- it reads *only*
``results/v0252_evidence_verification.json``, the output of the strict
verifier in ``scripts/verify_v0252_evidence.py``.  It never reads a raw
CORE-*/STRATA-* matrix report's own ``all_passed`` field directly: only the
verifier is trusted to have confirmed those reports are internally
consistent and untampered.

If the v0.25.2 evidence-verification report is absent, both facts default to
False -- the same honest, fail-closed state as before any Core/Strata work
was attempted.  This script always succeeds when it produces an honest
verdict; ``safe_for_funds`` is not its exit-status condition.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path

from ranklock.release_qualification import LocalReleaseFacts

# The release this gate qualifies. Companion evidence must be for the same
# version, so this is a constant rather than a literal repeated per use.
PACKAGE_VERSION = "0.25.2"

ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise RuntimeError(f"required evidence is absent: {path}")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"evidence is not a JSON object: {path}")
    return value


def _load_optional(path: Path) -> dict[str, object] | None:
    return _load(path) if path.is_file() else None


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--evidence-verification",
        type=Path,
        default=ROOT / "results" / "v0252_evidence_verification.json",
        help="output of scripts/verify_v0252_evidence.py",
    )
    parser.add_argument(
        "--clean-archive-report",
        type=Path,
        help="optional companion clean-archive report produced outside the source archive",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "v0252_release_gate.json")
    args = parser.parse_args()

    # The v0.25.1 local facts (source reproducibility, full test suite,
    # committee/split-scalar harnesses, static Bitcoin policy envelope, local
    # hardening) remain the foundation -- v0.25.2 only extends them, it does
    # not replace them.
    paths = {
        "committee": ROOT / "results/v025_committee_qualification.json",
        "split_scalar": ROOT / "results/v025_split_scalar_qualification.json",
        "bitcoin_policy": ROOT / "results/v025_bitcoin_policy_envelope.json",
        "tests": ROOT / "results/v025_test_files.json",
        "hardening": ROOT / "results/v0251_security_hardening.json",
    }
    evidence = {name: _load(path) for name, path in paths.items()}
    clean = _load_optional(args.clean_archive_report.resolve()) if args.clean_archive_report else None
    verification = _load_optional(args.evidence_verification)

    committee = evidence["committee"]
    split_scalar = evidence["split_scalar"]
    bitcoin_policy = evidence["bitcoin_policy"]
    tests = evidence["tests"]
    hardening = evidence["hardening"]
    if hardening.get("all_local_checks_passed") is not True:
        raise RuntimeError("v0.25.1 security hardening report did not pass")

    # The clean-archive report closes `complete_source_archive_reproducible`,
    # which is a funds blocker, yet it was consumed with no schema or version
    # check at all -- only `all_checks_passed` was read.  The report currently
    # sitting in results/ is a v0.18.0 artifact; it fails closed today only
    # because its `all_checks_passed` happens to be null.  A stale report that
    # said `true` would silently have closed a v0.25.2 release fact with
    # evidence from a different release.  Pin both the schema and the version.
    if clean is not None:
        clean_schema = clean.get("schema")
        if clean_schema != "ranklock-clean-archive-verification-v1":
            raise RuntimeError(
                f"{args.clean_archive_report}: unexpected schema {clean_schema!r}"
            )
        clean_version = str(clean.get("version", ""))
        if clean_version != PACKAGE_VERSION:
            raise RuntimeError(
                f"{args.clean_archive_report}: clean-archive evidence is for version "
                f"{clean_version!r}, but this gate qualifies {PACKAGE_VERSION!r}; "
                "regenerate the clean-archive reproduction against this release"
            )

    if verification is not None and verification.get("schema") != "ranklock-v0252-evidence-verification-v1":
        raise RuntimeError(
            f"{args.evidence_verification}: unexpected schema {verification.get('schema')!r}"
        )
    if verification is not None and verification.get("all_checks_passed") is not True:
        raise RuntimeError(
            f"{args.evidence_verification}: verifier reported internal inconsistencies "
            "(tampering or malformed evidence) -- fix or regenerate the underlying reports"
        )

    bitcoin_core_executed = bool(verification and verification.get("bitcoin_core_regtest_executed") is True)
    bitcoin_core_passed = bool(verification and verification.get("bitcoin_core_regtest_all_passed") is True)
    bridge_compiled_and_tested = bool(verification and verification.get("strata_build_all_passed") is True)

    facts = LocalReleaseFacts(
        complete_source_archive_reproducible=bool(clean and clean.get("all_checks_passed") is True),
        complete_test_suite_passed=bool(
            tests.get("complete") is True and tests.get("failed") == 0 and tests.get("nonzero_files") == 0
        ),
        retained_object_below_one_mib=bool(
            committee.get("retained_object", {}).get("bytes", 1 << 60) < 1 << 20  # type: ignore[union-attr]
        ),
        committee_authorization_harness_passed=bool(
            committee.get("decision") == "FULL_SIZE_COMMITTEE_SAFETY_HARNESS_PASS_PRODUCTION_GATES_OPEN"
            and committee.get("safe_for_funds") is False
        ),
        split_scalar_one_honest_harness_passed=bool(
            split_scalar.get("decision")
            == "FULL_SIZE_SPLIT_SCALAR_PARTICIPANT_LOCAL_RELEASE_PASS_REAL_CORE_NATIVE_AUDIT_GATES_OPEN"
            and split_scalar.get("safe_for_funds") is False
        ),
        bitcoin_policy_envelope_passed=bitcoin_policy.get("passed") is True,
        bitcoin_core_regtest_executed=bitcoin_core_executed,
        bitcoin_core_regtest_passed=bitcoin_core_passed,
        # External gates below remain False here regardless of local
        # evidence: they require independently administered parties this
        # script cannot become, per 04_EXTERNAL_GATES.md.
        current_bridge_compiled_and_tested=bridge_compiled_and_tested,
        native_constant_time_implementation=False,
        production_rollback_witnesses_deployed=False,
        deterministic_fixture_secrets_absent=False,
        independent_cryptography_audit_passed=False,
        independent_implementation_audit_passed=False,
        split_scalar_production_setup_passed=False,
        setup_security_mode="split-scalar-n-of-n",
    )
    document = facts.document()
    document.update(
        {
            "schema": "ranklock-v0252-release-gate-v1",
            "package_version": PACKAGE_VERSION,
            "claim_boundary": (
                "hash-pinned Bitcoin Core and the pinned Strata validity-first path were "
                "executed and passed the stated matrix, to the extent bitcoin_core_regtest_passed "
                "and current_bridge_compiled_and_tested are true above; this is not a statement "
                "that RankLock is safe for production funds -- production setup, native "
                "hardening, independent rollback operations, governance and external audits "
                "remain separate, externally-gated requirements"
            ),
            "evidence": {
                name: {"path": str(path.relative_to(ROOT)), "sha256": _digest(path)}
                for name, path in paths.items()
            },
            "evidence_verification": (
                None
                if verification is None
                else {
                    "path": str(args.evidence_verification),
                    "sha256": _digest(args.evidence_verification),
                    "all_checks_passed": verification.get("all_checks_passed"),
                    "reports_present": verification.get("reports_present"),
                }
            ),
            "clean_archive_report": (
                None
                if args.clean_archive_report is None
                else {
                    "path": str(args.clean_archive_report.resolve()),
                    "sha256": _digest(args.clean_archive_report.resolve()),
                    "all_checks_passed": bool(clean and clean.get("all_checks_passed") is True),
                }
            ),
            "local_security_hardening_passed": True,
            "external_attestations_must_be_verified_by": "ranklock.deployment_policy.evaluate_deployment",
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
