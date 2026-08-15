#!/usr/bin/env python3
from __future__ import annotations

"""Verify the retained v0.25 conformance evidence without generator secrets.

This verifier checks canonical parsers, artifact hashes, precommitted transaction
chains, exact witness txid/wtxid bindings, committee signatures, split-scalar
bundle framing, the static Bitcoin-policy report, and the Strata handoff manifest.
It deliberately does not turn the absent Bitcoin Core/Rust/audit gates into a
pass.
"""

from hashlib import sha256
import json
from pathlib import Path

from ranklock.authorization_transaction_plan import AuthorizationTransactionPlan
from ranklock.bitcoin_authorization import parse_bitcoin_transaction
from ranklock.bitcoin_witness_selection import SignedBitcoinWitnessPolicy
from ranklock.committee_authorization import SignedCommitteeActivation
from ranklock.split_scalar_lock import SignedSplitScalarBundle

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
COMMITTEE = ROOT / "artifacts/v025-committee-conformance"
SPLIT = ROOT / "artifacts/v025-split-scalar-conformance"
INTEGRATION = ROOT / "integration/alpen-validity-first-f94c-v025"


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _check(condition: bool, label: str, checks: dict[str, bool]) -> None:
    checks[label] = bool(condition)
    if not condition:
        raise RuntimeError(f"evidence verification failed: {label}")


def _verify_manifest(path: Path) -> bool:
    for line in path.read_text().splitlines():
        expected, relative = line.split("  ", 1)
        target = path.parent / relative.removeprefix("./")
        if not target.is_file() or _sha(target) != expected:
            return False
    return True


def main() -> int:
    checks: dict[str, bool] = {}
    committee_report = _load(RESULTS / "v025_committee_qualification.json")
    split_report = _load(RESULTS / "v025_split_scalar_qualification.json")
    policy_report = _load(RESULTS / "v025_bitcoin_policy_envelope.json")
    core_report = _load(RESULTS / "v025_bitcoin_core_regtest.json")

    retained = COMMITTEE / "ranklock-v025-two-slot-retained-object.bin"
    retained_row = committee_report["retained_object"]
    assert isinstance(retained_row, dict)
    _check(retained.stat().st_size == int(retained_row["bytes"]), "committee retained size", checks)
    _check(_sha(retained) == retained_row["sha256"], "committee retained hash", checks)
    _check(retained.stat().st_size < 1 << 20, "committee retained below one MiB", checks)

    manifest = COMMITTEE / "ranklock-v025-two-slot-manifest.bin"
    _check(manifest.stat().st_size == int(retained_row["manifest_bytes"]), "committee manifest size", checks)

    plan_path = COMMITTEE / "authorization-transaction-plan.bin"
    plan = AuthorizationTransactionPlan.parse(plan_path.read_bytes())
    binding = committee_report["bitcoin_binding"]
    assert isinstance(binding, dict)
    _check(plan.digest.hex() == binding["authorization_transaction_plan_digest"], "authorization plan digest", checks)
    tx_paths = tuple(COMMITTEE / f"slot-{slot}-authorization-transaction.bin" for slot in range(2))
    raw_transactions = tuple(path.read_bytes() for path in tx_paths)
    _check(plan.verify_transactions(raw_transactions), "authorization transaction chain", checks)

    report_transactions = binding["transactions"]
    assert isinstance(report_transactions, list)
    policy_transactions = policy_report["transactions"]
    assert isinstance(policy_transactions, list)
    for slot, raw in enumerate(raw_transactions):
        parsed = parse_bitcoin_transaction(raw)
        report_row = report_transactions[slot]
        policy_row = policy_transactions[slot]
        assert isinstance(report_row, dict) and isinstance(policy_row, dict)
        _check(parsed.txid.hex() == report_row["txid"], f"slot {slot} txid", checks)
        _check(parsed.wtxid.hex() == report_row["wtxid"], f"slot {slot} wtxid", checks)
        _check(parsed.witness_digest.hex() == report_row["witness_digest"], f"slot {slot} witness digest", checks)
        _check(parsed.txid.hex() == policy_row["txid"], f"slot {slot} policy txid", checks)
        _check(parsed.wtxid.hex() == policy_row["wtxid"], f"slot {slot} policy wtxid", checks)
        _check(policy_row["passed"] is True, f"slot {slot} policy envelope", checks)

        activation = SignedCommitteeActivation.parse_compact(
            (COMMITTEE / f"slot-{slot}-activation.bin").read_bytes()
        )
        witness_policy = SignedBitcoinWitnessPolicy.parse_compact(
            (COMMITTEE / f"slot-{slot}-witness-policy.bin").read_bytes()
        )
        _check(activation.verify(), f"slot {slot} activation signatures", checks)
        _check(witness_policy.verify(activation), f"slot {slot} witness-policy signatures", checks)
        _check(activation.unsigned.counterproof_txid == parsed.txid, f"slot {slot} activation txid", checks)

    _check(policy_report.get("passed") is True, "static Bitcoin policy report", checks)
    core_executed = core_report.get("executed") is True
    core_passed = core_report.get("passed") is True
    core_consistent = bool(
        (core_executed and core_passed and isinstance(core_report.get("result"), dict))
        or (not core_executed and not core_passed and isinstance(core_report.get("error"), str))
    )
    _check(core_consistent, "Bitcoin Core evidence is internally fail-closed", checks)

    split_retained = split_report["retained_material"]
    assert isinstance(split_retained, dict)
    for participant in (0, 1):
        path = SPLIT / f"participant-{participant}-retained-object.bin"
        _check(
            path.stat().st_size == int(split_retained[f"participant_{participant}_bytes"]),
            f"split participant {participant} size",
            checks,
        )
        _check(
            _sha(path) == split_retained[f"participant_{participant}_sha256"],
            f"split participant {participant} hash",
            checks,
        )
    bundle = SignedSplitScalarBundle.parse(
        (SPLIT / "ranklock-v025-split-scalar-bundle.bin").read_bytes()
    )
    _check(bundle.verify_signatures(), "split-scalar contribution bundle signatures", checks)
    _check(split_report.get("safe_for_funds") is False, "split-scalar gate fail closed", checks)

    _check(_verify_manifest(INTEGRATION / "MANIFEST.sha256"), "Strata handoff manifest", checks)

    document = {
        "schema": "ranklock-v025-evidence-verification-v1",
        "all_checks_passed": all(checks.values()),
        "checks": checks,
        "committee_retained_object": {
            "bytes": retained.stat().st_size,
            "sha256": _sha(retained),
        },
        "authorization_plan_digest": plan.digest.hex(),
        "split_scalar_bundle_digest": bundle.digest.hex(),
        "bitcoin_core_executed": core_executed,
        "bitcoin_core_passed": core_passed,
        "safe_for_funds": False,
    }
    output = RESULTS / "v025_evidence_verification.json"
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
