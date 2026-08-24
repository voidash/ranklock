"""Emit deterministic evidence for the abstract v0.26 timeout model."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import fields, is_dataclass
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any

from ranklock.v026.timeout_economics import (
    AbstractDeclaredPolicySatisfiedV1,
    DeclaredCoverageAdequateV2,
    OutpointRoleV1,
    TerminalWealthCoverageInfeasibleV2,
    TerminalWorldV1,
    analyze_terminal_wealth_v2,
    terminal_protection_policy_projection_v1,
    terminal_wealth_policy_projection_v2,
)
from ranklock.v026.timeout_economics_reference import (
    reference_bond_coverage_policy_v2,
    reference_shared_selection_plan_v1,
    reference_terminal_protection_policy_v1,
    reference_terminal_wealth_policy_v2,
)

_RESULT_PATH = Path("results/v026_timeout_economics.json")


def _sha256_file(path: Path) -> str:
    try:
        return sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise RuntimeError(f"failed to hash required evidence input {path}") from exc


def _canonical_value(value: object) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            field.name: _canonical_value(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, tuple):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise TypeError(f"unsupported canonical evidence value {type(value).__name__}")


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")


def build_result(repo_root: Path) -> dict[str, object]:
    root = repo_root.resolve(strict=True)
    plan = reference_shared_selection_plan_v1()
    assessment = plan.assess()
    terminal_policy = reference_terminal_protection_policy_v1(plan)
    terminal_result = plan.analyze_terminal_protection(terminal_policy)
    terminal_wealth_policy = reference_terminal_wealth_policy_v2()
    terminal_wealth_result = analyze_terminal_wealth_v2(
        plan,
        terminal_wealth_policy,
    )
    bond_policy = reference_bond_coverage_policy_v2()
    bond_result = analyze_terminal_wealth_v2(plan, bond_policy)
    plan_projection = _canonical_value(plan)
    plan_digest = sha256(_canonical_json_bytes(plan_projection)).hexdigest()
    terminal_policy_projection = terminal_protection_policy_projection_v1(
        terminal_policy
    )
    terminal_policy_digest = sha256(
        _canonical_json_bytes(terminal_policy_projection)
    ).hexdigest()
    if terminal_policy_digest != terminal_policy.policy_digest.hex():
        raise RuntimeError(
            "terminal policy digest does not match its canonical projection"
        )
    terminal_wealth_projection = terminal_wealth_policy_projection_v2(
        terminal_wealth_policy
    )
    terminal_wealth_policy_digest = sha256(
        _canonical_json_bytes(terminal_wealth_projection)
    ).hexdigest()
    if terminal_wealth_policy_digest != terminal_wealth_policy.policy_digest.hex():
        raise RuntimeError(
            "terminal wealth policy digest does not match its canonical projection"
        )
    bond_projection = terminal_wealth_policy_projection_v2(bond_policy)
    bond_policy_digest = sha256(_canonical_json_bytes(bond_projection)).hexdigest()
    if bond_policy_digest != bond_policy.policy_digest.hex():
        raise RuntimeError("bond policy digest does not match its canonical projection")
    if not isinstance(
        terminal_wealth_result,
        TerminalWealthCoverageInfeasibleV2,
    ):
        raise TypeError("no-bond reference must remain typed infeasible")
    if not isinstance(bond_result, DeclaredCoverageAdequateV2):
        raise TypeError("atomic bond candidate must satisfy declared coverage")
    counterproof_alternatives = sum(
        outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
        for outpoint in plan.funding_outpoints
    )
    world_trace_by_key = {
        (world.world, world.alternative_id): world.trace_id
        for world in terminal_result.world_traces
    }
    timeout_worlds_share_trace = all(
        world_trace_by_key.get((TerminalWorldV1.VALID_RELEASE_WITHHELD, alternative))
        == world_trace_by_key.get((TerminalWorldV1.INVALID_RELEASE_ABSENT, alternative))
        for alternative in range(counterproof_alternatives)
    )

    source_paths = {
        "model": root / "src/ranklock/v026/timeout_economics.py",
        "reference_fixture": (
            root / "src/ranklock/v026/timeout_economics_reference.py"
        ),
        "generator": root / "scripts/generate_v026_timeout_economics.py",
        "tests": root / "tests/test_v026_timeout_economics.py",
    }
    source_hashes = {label: _sha256_file(path) for label, path in source_paths.items()}
    return {
        "assessment": {
            "funding_blockers": [
                blocker.value for blocker in assessment.funding_blockers
            ],
            "funding_eligible": assessment.funding_eligible,
            "structural_blockers": [
                blocker.value for blocker in assessment.structural_blockers
            ],
            "counterproof_selection_allocates_exact_deposit": (
                assessment.counterproof_selection_allocates_exact_deposit
            ),
            "timeout_cpfp_anchor_value_sat": (assessment.timeout_cpfp_anchor_value_sat),
            "universal_funds_safety_established": (
                assessment.universal_funds_safety_established
            ),
            "worst_case_unused_counterproof_sat": (
                assessment.worst_case_unused_counterproof_sat
            ),
        },
        "claim_boundary": {
            "ack_created_slash_authorization_modeled": True,
            "all_counterproof_reserves_consumed_atomically": True,
            "bitcoin_consensus_execution": False,
            "counterproof_semantic_validity_established": False,
            "evidence_class": assessment.evidence_class,
            "evidence_scope": assessment.evidence_scope,
            "focused_test_execution_embedded": False,
            "cpfp_descriptor_control_verified": False,
            "recovery_descriptor_control_verified": False,
            "counterproof_reserve_returns_beneficiary_bound": True,
            "resolution_connector_policy_verified": False,
            "slash_authorization_policy_verified": False,
            "slash_distribution_plan_bound": True,
            "slash_header_policy_bound": True,
            "slash_beneficiary_scripts_disjoint_from_other_plan_scripts": True,
            "slash_beneficiary_control_verified": False,
            "deposit_alternate_signature_exclusion_verified": False,
            "stake_exclusivity_verified": False,
            "complete_graph_presign_erasure_verified": False,
            "atomic_roster_weight_and_confirmed_parent_policy_verified": False,
            "legacy_v1_graph_material_excluded": False,
            "terminal_principal_disposition_enumerated": False,
            "separate_terminal_policy_disposition_enumerated": True,
            "terminal_policy_control_verified": False,
            "terminal_declared_policy_satisfied": isinstance(
                terminal_result,
                AbstractDeclaredPolicySatisfiedV1,
            ),
            "terminal_protected_value_theorem_established": (
                terminal_result.protected_value_theorem_established
            ),
            "terminal_wealth_v2_no_bond_infeasible": True,
            "terminal_wealth_v2_bond_declared_coverage_adequate": True,
            "terminal_wealth_v2_protected_value_theorem_established": False,
            "terminal_wealth_v2_funding_eligible": False,
            "threshold_valid_withheld_retained_as_assumption_failure_world": True,
            "bond_overlay_serialized_in_v1_templates": False,
            "bond_fusion_with_existing_counterproof_input_authorized": False,
            "terminal_policy_qualification_blockers": [
                blocker.value for blocker in terminal_result.qualification_blockers
            ],
            "protected_baseline_authority_verified": False,
            "per_principal_allowance_authority_verified": False,
            "service_fee_schedule_and_baseline_authority_verified": False,
            "by_horizon_csv_reorg_and_fee_execution_verified": False,
            "timeout_depends_on_claim_payout": False,
            "valid_withheld_and_invalid_absent_share_timeout_trace": (
                timeout_worlds_share_trace
            ),
            "universal_all_party_funds_safety": False,
            "versioned_rust_graph_implemented": True,
            "rust_graph_projection_verified": False,
            "bitcoin_core_acceptance_executed": True,
            "bitcoin_core_acceptance_bound_to_model": False,
        },
        "plan_projection": {
            "canonical_protocol_wire": False,
            "counterproof_alternatives": counterproof_alternatives,
            "sha256": plan_digest,
        },
        "terminal_protection": {
            "policy_projection_sha256": terminal_policy_digest,
            "result": _canonical_value(terminal_result),
        },
        "terminal_wealth_v2": {
            "no_bond_reference": {
                "policy_projection_sha256": terminal_wealth_policy_digest,
                "result": _canonical_value(terminal_wealth_result),
            },
            "atomic_bond_candidate": {
                "policy_projection_sha256": bond_policy_digest,
                "result": _canonical_value(bond_result),
            },
        },
        "reproduction": {
            "command": (
                "PYTHONPATH=src:. uv run python "
                "scripts/generate_v026_timeout_economics.py"
            ),
            "focused_test_command": (
                "PYTHONPATH=src:. uv run --with pytest pytest -q "
                "tests/test_v026_timeout_economics.py"
            ),
            "source_sha256": source_hashes,
        },
        "schema": "ranklock-v026-timeout-economics-result-v6",
    }


def build_result_bytes(repo_root: Path) -> bytes:
    return _canonical_json_bytes(build_result(repo_root))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="emit deterministic v0.26 abstract timeout evidence"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help=f"compare generated bytes with {_RESULT_PATH}",
    )
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    generated = build_result_bytes(repo_root)
    if args.check:
        result_path = repo_root / _RESULT_PATH
        try:
            committed = result_path.read_bytes()
        except OSError as exc:
            raise RuntimeError(
                f"failed to read committed timeout evidence {result_path}"
            ) from exc
        if committed != generated:
            raise RuntimeError("committed timeout evidence is stale")
        return 0
    sys.stdout.buffer.write(generated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
