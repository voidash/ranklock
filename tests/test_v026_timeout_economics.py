from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from ranklock.v026.timeout_economics import (
    AbstractDeclaredPolicySatisfiedV1,
    CoveragePolicyErrorV2,
    CoveragePolicyWitnessV2,
    CoverageReserveDeficitWitnessV2,
    DeclaredCoverageAdequateV2,
    ExecutionScheduleV2,
    OutpointRoleV1,
    PlannedOutpointV1,
    PrincipalCoverageDeficitWitnessV2,
    PrincipalStatusV2,
    ProtectedValueDeficitWitnessV1,
    SharedSelectionTimeoutPlanV1,
    TerminalBranchV1,
    TerminalDispositionBeneficiaryMismatchWitnessV1,
    TerminalPolicyRosterWitnessV1,
    TerminalProtectionInfeasibleV1,
    TerminalProtectionPolicyV1,
    TerminalQualificationBlockerV1,
    TerminalWealthCoverageInfeasibleV2,
    TerminalWorldV1,
    ThresholdReleaseQualificationV2,
    TimeoutCoalitionExcessWitnessV1,
    TimeoutEconomicsError,
    TimeoutSafetyBlockerV1,
    TransactionRoleV1,
    analyze_terminal_wealth_v2,
    terminal_wealth_policy_projection_v2,
)
from ranklock.v026.timeout_economics_reference import (
    CONNECTOR_SCRIPT,
    OWNER,
    OWNER_SCRIPT,
    RECOVERY,
    RELEASE_PARTICIPANT,
    WATCHTOWER,
    WATCHTOWER_SCRIPT,
    reference_bond_coverage_policy_v2,
    reference_outpoint,
    reference_shared_selection_plan_v1,
    reference_terminal_protection_policy_v1,
    reference_terminal_wealth_policy_v2,
    symbolic_id,
)
from scripts.generate_v026_timeout_economics import build_result_bytes


def _plan() -> SharedSelectionTimeoutPlanV1:
    return reference_shared_selection_plan_v1()


def _spendable_terminal_policy() -> TerminalProtectionPolicyV1:
    policy = reference_terminal_protection_policy_v1(_plan())
    return replace(
        policy,
        funding_principals=tuple(
            replace(binding, residual_spendable_by_horizon=True)
            for binding in policy.funding_principals
        ),
    )


def _one_alternative_plan() -> SharedSelectionTimeoutPlanV1:
    plan = _plan()
    removed_counterproof = next(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
        and outpoint.alternative_id == 1
    )
    funding = tuple(
        outpoint
        for outpoint in plan.funding_outpoints
        if not (
            outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
            and outpoint.alternative_id == 1
        )
    )
    transactions = []
    for transaction in plan.transactions:
        if transaction.alternative_id == 1:
            continue
        candidate = transaction
        if transaction.role in {
            TransactionRoleV1.OWNER_PAYOUT,
            TransactionRoleV1.COUNTERPROOF,
        }:
            candidate = replace(
                candidate,
                input_ids=tuple(
                    input_id
                    for input_id in candidate.input_ids
                    if input_id != removed_counterproof.outpoint_id
                ),
                outputs=tuple(
                    output
                    for output in candidate.outputs
                    if not (
                        output.role is OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN
                        and output.alternative_id == 1
                    )
                ),
            )
        if (
            transaction.role is TransactionRoleV1.SLASH
            and transaction.alternative_id == 0
        ):
            candidate = replace(
                candidate,
                outputs=(
                    candidate.outputs[0],
                    replace(candidate.outputs[1], value_sat=49_999_330),
                ),
            )
        transactions.append(candidate)
    return replace(
        plan,
        funding_outpoints=funding,
        transactions=tuple(transactions),
        counterproof_ack_cpfp_beneficiaries=(
            plan.counterproof_ack_cpfp_beneficiaries[0],
        ),
        counterproof_reserve_beneficiaries=(
            plan.counterproof_reserve_beneficiaries[0],
        ),
        slash_beneficiaries=(plan.slash_beneficiaries[0],),
        slash_output_policies=(
            (
                replace(
                    plan.slash_output_policies[0][0],
                    value_sat=49_999_330,
                ),
            ),
        ),
        maximum_abandoned_counterproof_sat=0,
    )


def test_shared_selection_allocates_deposit_but_is_not_funding_evidence() -> None:
    assessment = _plan().assess()

    assert assessment.structural_blockers == ()
    assert assessment.counterproof_selection_allocates_exact_deposit
    assert assessment.worst_case_unused_counterproof_sat == 0
    assert assessment.timeout_cpfp_anchor_value_sat == 330
    assert not assessment.universal_funds_safety_established
    assert not assessment.funding_eligible
    assert assessment.funding_blockers == (
        TimeoutSafetyBlockerV1.RECOVERY_DESCRIPTOR_CONTROL_UNVERIFIED,
        TimeoutSafetyBlockerV1.CPFP_CONTROL_UNVERIFIED,
        TimeoutSafetyBlockerV1.RESOLUTION_CONNECTOR_POLICY_UNVERIFIED,
        TimeoutSafetyBlockerV1.SLASH_AUTHORIZATION_POLICY_UNVERIFIED,
        TimeoutSafetyBlockerV1.SLASH_BENEFICIARY_CONTROL_UNVERIFIED,
        TimeoutSafetyBlockerV1.DEPOSIT_ALTERNATE_SIGNATURE_EXCLUSION_UNVERIFIED,
        TimeoutSafetyBlockerV1.STAKE_EXCLUSIVITY_UNVERIFIED,
        TimeoutSafetyBlockerV1.COMPLETE_GRAPH_PRESIGN_ERASURE_UNVERIFIED,
        TimeoutSafetyBlockerV1.ATOMIC_ROSTER_WEIGHT_EVIDENCE_UNVERIFIED,
        TimeoutSafetyBlockerV1.TERMINAL_PRINCIPAL_DISPOSITION_UNMODELED,
        TimeoutSafetyBlockerV1.VALIDITY_WITHHOLDING_AMBIGUITY_UNRESOLVED,
        TimeoutSafetyBlockerV1.RUST_GRAPH_PROJECTION_UNVERIFIED,
        TimeoutSafetyBlockerV1.BITCOIN_CORE_ACCEPTANCE_NOT_BOUND_TO_MODEL,
    )


def test_every_counterproof_must_consume_the_shared_payout_gate() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    index = next(
        index
        for index, transaction in enumerate(transactions)
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 1
    )
    counterproof = transactions[index]
    counterproof_input = next(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
        and outpoint.alternative_id == 1
    )
    deposit = next(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.DEPOSIT
    )
    transactions[index] = replace(
        counterproof,
        input_ids=(counterproof_input.outpoint_id, deposit.outpoint_id),
        fee_sat=4_564,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.COUNTERPROOFS_NOT_MUTUALLY_EXCLUSIVE
        in assessment.structural_blockers
    )
    assert not assessment.counterproof_selection_allocates_exact_deposit


def test_owner_payout_must_conflict_with_every_counterproof() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    owner = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.OWNER_PAYOUT
    )
    contest_payout = next(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.CONTEST_PAYOUT
    )
    owner_output = replace(owner.outputs[0], value_sat=100_000_056)
    replacement = replace(
        owner,
        input_ids=tuple(
            input_id
            for input_id in owner.input_ids
            if input_id != contest_payout.outpoint_id
        ),
        outputs=(owner_output,),
    )
    transactions[transactions.index(owner)] = replacement

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.OWNER_PAYOUT_NOT_GATED_BY_SHARED_CONTEST_PAYOUT
        in assessment.structural_blockers
    )


def test_counterproof_must_return_exact_deposit_to_committed_beneficiary() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    index = next(
        index
        for index, transaction in enumerate(transactions)
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 0
    )
    counterproof = transactions[index]
    outputs = list(counterproof.outputs)
    recovery_index = next(
        index
        for index, output in enumerate(outputs)
        if output.role is OutpointRoleV1.PROTECTED_RECOVERY
    )
    outputs[recovery_index] = replace(
        outputs[recovery_index],
        value_sat=outputs[recovery_index].value_sat - 1,
    )
    transactions[index] = replace(
        counterproof,
        outputs=tuple(outputs),
        fee_sat=counterproof.fee_sat + 1,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.COUNTERPROOF_DOES_NOT_ALLOCATE_EXACT_DEPOSIT
        in assessment.structural_blockers
    )


def test_timeout_must_conflict_with_slash_on_the_contest_slash_outpoint() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    timeout = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
        and transaction.alternative_id == 0
    )
    contest_slash = next(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.CONTEST_SLASH
    )
    replacement = replace(
        timeout,
        input_ids=tuple(
            input_id
            for input_id in timeout.input_ids
            if input_id != contest_slash.outpoint_id
        ),
        fee_sat=570,
    )
    transactions[transactions.index(timeout)] = replacement

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.TIMEOUT_AND_SLASH_DO_NOT_CONFLICT
        in assessment.structural_blockers
    )


def test_counterproof_must_consume_deposit_to_kill_legacy_spenders() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    counterproof = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 0
    )
    deposit = next(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.DEPOSIT
    )
    outputs = tuple(
        output
        for output in counterproof.outputs
        if output.role is not OutpointRoleV1.PROTECTED_RECOVERY
    )
    transactions[transactions.index(counterproof)] = replace(
        counterproof,
        input_ids=tuple(
            input_id
            for input_id in counterproof.input_ids
            if input_id != deposit.outpoint_id
        ),
        outputs=outputs,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.COUNTERPROOFS_NOT_MUTUALLY_EXCLUSIVE
        in assessment.structural_blockers
    )
    assert (
        TimeoutSafetyBlockerV1.COUNTERPROOF_DOES_NOT_ALLOCATE_EXACT_DEPOSIT
        in assessment.structural_blockers
    )


def test_ack_must_create_the_only_slash_authorization() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    ack = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.ACK and transaction.alternative_id == 0
    )
    slash_authorization = next(
        output
        for output in ack.outputs
        if output.role is OutpointRoleV1.SLASH_AUTHORIZATION
    )
    transactions[transactions.index(ack)] = replace(
        ack,
        outputs=tuple(
            output for output in ack.outputs if output is not slash_authorization
        ),
        fee_sat=ack.fee_sat + slash_authorization.value_sat,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.ACK_DOES_NOT_CREATE_SLASH_AUTHORIZATION
        in assessment.structural_blockers
    )


def test_slash_cannot_exist_before_ack_authorization() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    slash = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.SLASH
        and transaction.alternative_id == 0
    )
    slash_authorization_ids = {
        output.outpoint_id
        for transaction in plan.transactions
        if transaction.role is TransactionRoleV1.ACK and transaction.alternative_id == 0
        for output in transaction.outputs
        if output.role is OutpointRoleV1.SLASH_AUTHORIZATION
    }
    transactions[transactions.index(slash)] = replace(
        slash,
        input_ids=tuple(
            input_id
            for input_id in slash.input_ids
            if input_id not in slash_authorization_ids
        ),
        fee_sat=1_000,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.SLASH_NOT_GATED_BY_ACK in assessment.structural_blockers
    )


def test_slash_cannot_redirect_the_committed_distribution() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    slash = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.SLASH
        and transaction.alternative_id == 0
    )
    beneficiary_index = next(
        index
        for index, output in enumerate(slash.outputs)
        if output.role is OutpointRoleV1.BENEFICIARY
    )
    redirected = replace(
        slash.outputs[beneficiary_index],
        beneficiary_id=OWNER,
        script_pubkey=OWNER_SCRIPT,
    )
    outputs = list(slash.outputs)
    outputs[beneficiary_index] = redirected
    transactions[transactions.index(slash)] = replace(
        slash,
        outputs=tuple(outputs),
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.SLASH_OUTPUT_ROSTER_MISMATCH
        in assessment.structural_blockers
    )


def test_slash_cannot_split_or_extend_the_committed_distribution() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    slash = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.SLASH
        and transaction.alternative_id == 0
    )
    beneficiary_index = next(
        index
        for index, output in enumerate(slash.outputs)
        if output.role is OutpointRoleV1.BENEFICIARY
    )
    split_output = replace(
        slash.outputs[beneficiary_index],
        value_sat=slash.outputs[beneficiary_index].value_sat - 1,
    )
    extra_output = reference_outpoint(
        "unexpected-slash-output",
        OutpointRoleV1.BENEFICIARY,
        1,
        alternative_id=0,
        beneficiary_id=WATCHTOWER,
        script_pubkey=WATCHTOWER_SCRIPT,
    )
    outputs = list(slash.outputs)
    outputs[beneficiary_index] = split_output
    transactions[transactions.index(slash)] = replace(
        slash,
        outputs=tuple(outputs) + (extra_output,),
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.SLASH_OUTPUT_ROSTER_MISMATCH
        in assessment.structural_blockers
    )


def test_slash_output_must_name_the_selected_alternative() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    slash = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.SLASH
        and transaction.alternative_id == 0
    )
    beneficiary_index = next(
        index
        for index, output in enumerate(slash.outputs)
        if output.role is OutpointRoleV1.BENEFICIARY
    )
    outputs = list(slash.outputs)
    outputs[beneficiary_index] = replace(
        outputs[beneficiary_index],
        alternative_id=1,
    )
    transactions[transactions.index(slash)] = replace(
        slash,
        outputs=tuple(outputs),
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.SLASH_OUTPUT_ROSTER_MISMATCH
        in assessment.structural_blockers
    )


def test_slash_cannot_burn_the_committed_distribution_as_fee() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    slash = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.SLASH
        and transaction.alternative_id == 0
    )
    transactions[transactions.index(slash)] = replace(
        slash,
        outputs=(
            slash.outputs[0],
            replace(slash.outputs[1], value_sat=1),
        ),
        fee_sat=50_000_659,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.SLASH_OUTPUT_ROSTER_MISMATCH
        in assessment.structural_blockers
    )


def test_slash_requires_the_exact_zero_value_protocol_header() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    slash = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.SLASH
        and transaction.alternative_id == 0
    )
    outputs = list(slash.outputs)
    outputs[0] = replace(outputs[0], script_pubkey=b"\x6a\x01x")
    transactions[transactions.index(slash)] = replace(
        slash,
        outputs=tuple(outputs),
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.SLASH_OUTPUT_ROSTER_MISMATCH
        in assessment.structural_blockers
    )


def test_slash_payout_descriptors_are_separate_from_cpfp_descriptors() -> None:
    plan = _plan()
    assert tuple(
        descriptor.principal_id for descriptor in plan.slash_beneficiaries
    ) == tuple(
        descriptor.principal_id
        for descriptor in plan.counterproof_ack_cpfp_beneficiaries
    )
    assert tuple(
        descriptor.script_pubkey for descriptor in plan.slash_beneficiaries
    ) != tuple(
        descriptor.script_pubkey
        for descriptor in plan.counterproof_ack_cpfp_beneficiaries
    )


@pytest.mark.parametrize("alias_source", ("owner", "counterproof-cpfp"))
def test_slash_payout_script_cannot_alias_nonslash_script(
    alias_source: str,
) -> None:
    plan = _plan()
    alias_script = (
        plan.graph_owner.script_pubkey
        if alias_source == "owner"
        else plan.counterproof_ack_cpfp_beneficiaries[0].script_pubkey
    )
    aliased_beneficiary = replace(
        plan.slash_beneficiaries[0],
        script_pubkey=alias_script,
    )
    aliased_roster = (aliased_beneficiary, *plan.slash_beneficiaries[1:])
    aliased_policies = tuple(
        (
            replace(roster[0], beneficiary=aliased_beneficiary),
            *roster[1:],
        )
        for roster in plan.slash_output_policies
    )

    with pytest.raises(
        TimeoutEconomicsError,
        match="distinct from other plan scripts",
    ):
        replace(
            plan,
            slash_beneficiaries=aliased_roster,
            slash_output_policies=aliased_policies,
        )


@pytest.mark.parametrize(
    "policy_name",
    ("resolution", "slash-authorization"),
)
def test_slash_payout_script_cannot_alias_connector_policy(
    policy_name: str,
) -> None:
    plan = _plan()
    slash_script = plan.slash_beneficiaries[0].script_pubkey
    changes: dict[str, object]
    if policy_name == "resolution":
        changes = {
            "resolution_connector_policy": replace(
                plan.resolution_connector_policy,
                script_pubkey=slash_script,
            )
        }
    else:
        changes = {
            "slash_authorization_policy": replace(
                plan.slash_authorization_policy,
                script_pubkey=slash_script,
            )
        }

    with pytest.raises(
        TimeoutEconomicsError,
        match="distinct from other plan scripts",
    ):
        replace(plan, **changes)


@pytest.mark.parametrize("control_source", ("owner", "recovery", "timeout-cpfp"))
def test_slash_payout_control_cannot_alias_prohibited_control(
    control_source: str,
) -> None:
    plan = _plan()
    source = {
        "owner": plan.graph_owner,
        "recovery": plan.recovery_beneficiary,
        "timeout-cpfp": plan.timeout_cpfp_beneficiary,
    }[control_source]
    aliased_beneficiary = replace(
        plan.slash_beneficiaries[0],
        control_domain_ids=source.control_domain_ids,
    )
    aliased_roster = (aliased_beneficiary, *plan.slash_beneficiaries[1:])
    aliased_policies = tuple(
        (
            replace(roster[0], beneficiary=aliased_beneficiary),
            *roster[1:],
        )
        for roster in plan.slash_output_policies
    )

    with pytest.raises(
        TimeoutEconomicsError,
        match="independent of owner, recovery, and timeout controls",
    ):
        replace(
            plan,
            slash_beneficiaries=aliased_roster,
            slash_output_policies=aliased_policies,
        )


def test_timeout_must_not_depend_on_burnable_claim_payout() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    timeout = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
        and transaction.alternative_id == 0
    )
    claim_payout = next(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.CLAIM_PAYOUT
    )
    transactions[transactions.index(timeout)] = replace(
        timeout,
        input_ids=timeout.input_ids + (claim_payout.outpoint_id,),
        fee_sat=timeout.fee_sat + claim_payout.value_sat,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.CLAIM_PAYOUT_BURN_CAN_BLOCK_TIMEOUT
        in assessment.structural_blockers
    )


def test_timeout_accepts_exact_recovery_change() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    timeout = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
        and transaction.alternative_id == 0
    )
    change = reference_outpoint(
        "timeout-recovery-change",
        OutpointRoleV1.PROTECTED_RECOVERY,
        1,
        alternative_id=0,
        beneficiary_id=plan.recovery_beneficiary.principal_id,
        script_pubkey=plan.recovery_beneficiary.script_pubkey,
    )
    transactions[transactions.index(timeout)] = replace(
        timeout,
        outputs=timeout.outputs + (change,),
        fee_sat=timeout.fee_sat - 1,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert assessment.structural_blockers == ()


def test_timeout_recovery_change_cannot_be_redirected() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    timeout = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
        and transaction.alternative_id == 0
    )
    change = reference_outpoint(
        "redirected-timeout-change",
        OutpointRoleV1.PROTECTED_RECOVERY,
        1,
        alternative_id=0,
        beneficiary_id=OWNER,
        script_pubkey=OWNER_SCRIPT,
    )
    transactions[transactions.index(timeout)] = replace(
        timeout,
        outputs=timeout.outputs + (change,),
        fee_sat=timeout.fee_sat - 1,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.TIMEOUT_OUTPUT_ROSTER_MISMATCH
        in assessment.structural_blockers
    )


def test_timeout_rejects_duplicate_recovery_change() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    timeout = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
        and transaction.alternative_id == 0
    )
    changes = tuple(
        reference_outpoint(
            f"duplicate-timeout-change-{index}",
            OutpointRoleV1.PROTECTED_RECOVERY,
            1,
            alternative_id=0,
            beneficiary_id=plan.recovery_beneficiary.principal_id,
            script_pubkey=plan.recovery_beneficiary.script_pubkey,
        )
        for index in range(2)
    )
    transactions[transactions.index(timeout)] = replace(
        timeout,
        outputs=timeout.outputs + changes,
        fee_sat=timeout.fee_sat - 2,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.TIMEOUT_OUTPUT_ROSTER_MISMATCH
        in assessment.structural_blockers
    )


def test_recovery_vault_cannot_be_substituted_at_runtime() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    index = next(
        index
        for index, transaction in enumerate(transactions)
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 1
    )
    counterproof = transactions[index]
    outputs = tuple(
        replace(
            output,
            beneficiary_id=WATCHTOWER,
            script_pubkey=WATCHTOWER_SCRIPT,
        )
        if output.role is OutpointRoleV1.PROTECTED_RECOVERY
        else output
        for output in counterproof.outputs
    )
    transactions[index] = replace(counterproof, outputs=outputs)

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.COUNTERPROOF_RECOVERY_BENEFICIARY_MISMATCH
        in assessment.structural_blockers
    )


def test_deposit_principal_must_match_the_recovery_descriptor() -> None:
    plan = _plan()
    funding = tuple(
        replace(outpoint, beneficiary_id=WATCHTOWER)
        if outpoint.role is OutpointRoleV1.DEPOSIT
        else outpoint
        for outpoint in plan.funding_outpoints
    )
    assessment = replace(plan, funding_outpoints=funding).assess()
    assert (
        TimeoutSafetyBlockerV1.COUNTERPROOF_RECOVERY_BENEFICIARY_MISMATCH
        in assessment.structural_blockers
    )


def test_missing_atomic_reserve_return_fails_closed() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    owner_index = next(
        index
        for index, transaction in enumerate(transactions)
        if transaction.role is TransactionRoleV1.OWNER_PAYOUT
    )
    owner = transactions[owner_index]
    transactions[owner_index] = replace(owner, outputs=owner.outputs[:-1])
    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert assessment.worst_case_unused_counterproof_sat == 11_588
    assert (
        TimeoutSafetyBlockerV1.UNUSED_COUNTERPROOF_RESERVE_EXCEEDS_POLICY
        in assessment.structural_blockers
    )
    assert (
        TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER
        in assessment.structural_blockers
    )


def test_every_selection_parent_consumes_all_reserves_in_canonical_order() -> None:
    plan = _plan()
    counterproof_ids = tuple(
        outpoint.outpoint_id
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
    )
    owner = next(
        transaction
        for transaction in plan.transactions
        if transaction.role is TransactionRoleV1.OWNER_PAYOUT
    )
    counterproofs = tuple(
        transaction
        for transaction in plan.transactions
        if transaction.role is TransactionRoleV1.COUNTERPROOF
    )

    assert owner.input_ids[-len(counterproof_ids) :] == counterproof_ids
    assert all(
        transaction.input_ids[: len(counterproof_ids)] == counterproof_ids
        for transaction in counterproofs
    )
    assert plan.assess().worst_case_unused_counterproof_sat == 0

    transactions = list(plan.transactions)
    counterproof_index = next(
        index
        for index, transaction in enumerate(transactions)
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 0
    )
    counterproof = transactions[counterproof_index]
    transactions[counterproof_index] = replace(
        counterproof,
        input_ids=(
            counterproof.input_ids[1],
            counterproof.input_ids[0],
            *counterproof.input_ids[2:],
        ),
    )
    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.COUNTERPROOFS_NOT_MUTUALLY_EXCLUSIVE
        in assessment.structural_blockers
    )
    assert assessment.worst_case_unused_counterproof_sat == 11_588


def test_reserve_returns_are_exact_and_cannot_be_relabelled() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    counterproof_index = next(
        index
        for index, transaction in enumerate(transactions)
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 0
    )
    counterproof = transactions[counterproof_index]
    reserve_index = next(
        index
        for index, output in enumerate(counterproof.outputs)
        if output.role is OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN
    )
    outputs = list(counterproof.outputs)
    outputs[reserve_index] = replace(
        outputs[reserve_index],
        beneficiary_id=OWNER,
        script_pubkey=OWNER_SCRIPT,
    )
    transactions[counterproof_index] = replace(
        counterproof,
        outputs=tuple(outputs),
    )
    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER
        in assessment.structural_blockers
    )
    assert assessment.worst_case_unused_counterproof_sat == 11_588


def test_reserve_descriptor_roster_is_principal_bound_and_script_separated() -> None:
    plan = _plan()
    with pytest.raises(TimeoutEconomicsError, match="funding principals"):
        replace(
            plan,
            counterproof_reserve_beneficiaries=tuple(
                reversed(plan.counterproof_reserve_beneficiaries)
            ),
        )
    with pytest.raises(TimeoutEconomicsError, match="unique and distinct"):
        replace(
            plan,
            counterproof_reserve_beneficiaries=(
                replace(
                    plan.counterproof_reserve_beneficiaries[0],
                    script_pubkey=plan.graph_owner.script_pubkey,
                ),
                plan.counterproof_reserve_beneficiaries[1],
            ),
        )


def test_value_conservation_is_checked_for_every_alternative_parent() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    transactions[0] = replace(transactions[0], fee_sat=603)
    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert TimeoutSafetyBlockerV1.VALUE_NOT_CONSERVED in assessment.structural_blockers


def test_unmodeled_funding_outpoint_role_fails_closed() -> None:
    plan = _plan()
    extra = reference_outpoint(
        "unmodeled-funding-output",
        OutpointRoleV1.BENEFICIARY,
        1,
        beneficiary_id=OWNER,
        script_pubkey=OWNER_SCRIPT,
    )
    assessment = replace(
        plan,
        funding_outpoints=plan.funding_outpoints + (extra,),
    ).assess()
    assert (
        TimeoutSafetyBlockerV1.MALFORMED_RESOURCE_ROSTER
        in assessment.structural_blockers
    )


def test_counterproof_roster_and_descriptor_roster_must_match() -> None:
    plan = _plan()
    funding = tuple(
        outpoint
        for outpoint in plan.funding_outpoints
        if not (
            outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
            and outpoint.alternative_id == 1
        )
    )
    transactions = tuple(
        transaction
        for transaction in plan.transactions
        if transaction.alternative_id != 1
    )
    assessment = replace(
        plan,
        funding_outpoints=funding,
        transactions=transactions,
    ).assess()
    assert (
        TimeoutSafetyBlockerV1.MALFORMED_RESOURCE_ROSTER
        in assessment.structural_blockers
    )


def test_watchtower_roster_is_not_confused_with_ranklock_query_slots() -> None:
    assessment = _one_alternative_plan().assess()
    assert assessment.structural_blockers == ()
    assert not assessment.funding_eligible


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("outpoint_id", bytearray(32), "immutable bytes"),
        ("outpoint_id", b"x" * 31, "exactly 32 bytes"),
        ("value_sat", True, "must be an integer"),
        ("script_pubkey", bytearray(b"x"), "immutable bytes"),
        ("alternative_id", 4_294_967_296, "0..4294967295"),
    ),
)
def test_malformed_outpoints_fail_closed(
    field: str,
    value: object,
    message: str,
) -> None:
    values: dict[str, object] = {
        "outpoint_id": symbolic_id("malformed"),
        "role": OutpointRoleV1.COUNTERPROOF_INPUT,
        "value_sat": 1,
        "script_pubkey": CONNECTOR_SCRIPT,
        "alternative_id": 0,
    }
    values[field] = value
    with pytest.raises(TimeoutEconomicsError, match=message):
        PlannedOutpointV1(**values)  # type: ignore[arg-type]


def test_graph_owner_cannot_be_the_recovery_principal() -> None:
    plan = _plan()
    with pytest.raises(TimeoutEconomicsError, match="principals must be distinct"):
        replace(plan, recovery_beneficiary=plan.graph_owner)


def test_recovery_script_cannot_alias_the_graph_owner_script() -> None:
    plan = _plan()
    aliased = replace(
        plan.recovery_beneficiary,
        script_pubkey=plan.graph_owner.script_pubkey,
    )
    with pytest.raises(TimeoutEconomicsError, match="scripts must be distinct"):
        replace(plan, recovery_beneficiary=aliased)


def test_recovery_controls_cannot_overlap_the_cpfp_actor() -> None:
    plan = _plan()
    overlapping = replace(
        plan.recovery_beneficiary,
        control_domain_ids=plan.timeout_cpfp_beneficiary.control_domain_ids,
    )
    with pytest.raises(
        TimeoutEconomicsError,
        match="recovery and CPFP controls must be independent",
    ):
        replace(plan, recovery_beneficiary=overlapping)


def test_timeout_cpfp_controls_cannot_overlap_the_counterproof_actor() -> None:
    plan = _plan()
    overlapping = replace(
        plan.timeout_cpfp_beneficiary,
        control_domain_ids=(
            plan.counterproof_ack_cpfp_beneficiaries[0].control_domain_ids
        ),
    )
    with pytest.raises(
        TimeoutEconomicsError,
        match="CPFP controls must be independent of timeout-capable controls",
    ):
        replace(plan, timeout_cpfp_beneficiary=overlapping)


def test_recovery_descriptor_rejects_provably_unspendable_script() -> None:
    descriptor = _plan().recovery_beneficiary
    with pytest.raises(TimeoutEconomicsError, match="canonical P2TR"):
        replace(descriptor, script_pubkey=b"\x6a")


def test_timeout_anchor_must_match_the_independent_cpfp_descriptor() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    timeout = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
        and transaction.alternative_id == 0
    )
    outputs = tuple(
        replace(
            output,
            beneficiary_id=RELEASE_PARTICIPANT,
            script_pubkey=OWNER_SCRIPT,
        )
        if output.role is OutpointRoleV1.CPFP_ANCHOR
        else output
        for output in timeout.outputs
    )
    transactions[transactions.index(timeout)] = replace(timeout, outputs=outputs)
    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.TIMEOUT_OUTPUT_ROSTER_MISMATCH
        in assessment.structural_blockers
    )
    assert (
        TimeoutSafetyBlockerV1.TIMEOUT_CPFP_DESCRIPTOR_MISMATCH
        in assessment.structural_blockers
    )


@pytest.mark.parametrize(
    ("role", "expected_blocker"),
    (
        (
            TransactionRoleV1.COUNTERPROOF,
            TimeoutSafetyBlockerV1.COUNTERPROOF_CPFP_DESCRIPTOR_MISMATCH,
        ),
        (
            TransactionRoleV1.ACK,
            TimeoutSafetyBlockerV1.ACK_CPFP_DESCRIPTOR_MISMATCH,
        ),
    ),
)
def test_counterproof_and_ack_anchors_cannot_use_timeout_broadcaster(
    role: TransactionRoleV1,
    expected_blocker: TimeoutSafetyBlockerV1,
) -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    transaction = next(
        transaction
        for transaction in transactions
        if transaction.role is role and transaction.alternative_id == 0
    )
    outputs = tuple(
        replace(
            output,
            beneficiary_id=plan.timeout_cpfp_beneficiary.principal_id,
            script_pubkey=plan.timeout_cpfp_beneficiary.script_pubkey,
        )
        if output.role is OutpointRoleV1.CPFP_ANCHOR
        else output
        for output in transaction.outputs
    )
    transactions[transactions.index(transaction)] = replace(
        transaction,
        outputs=outputs,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert expected_blocker in assessment.structural_blockers


def test_counterproof_cannot_hide_a_second_cross_alternative_resolution() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    counterproof = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 0
    )
    anchor = next(
        output
        for output in counterproof.outputs
        if output.role is OutpointRoleV1.CPFP_ANCHOR
    )
    extra_resolution = reference_outpoint(
        "extra-cross-alternative-resolution",
        OutpointRoleV1.RESOLUTION,
        1,
        alternative_id=1,
    )
    outputs = tuple(
        replace(output, value_sat=output.value_sat - 1) if output is anchor else output
        for output in counterproof.outputs
    ) + (extra_resolution,)
    transactions[transactions.index(counterproof)] = replace(
        counterproof,
        outputs=outputs,
    )
    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.COUNTERPROOF_DOES_NOT_CREATE_UNIQUE_RESOLUTION
        in assessment.structural_blockers
    )


def test_resolution_connector_cannot_be_substituted_per_alternative() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    counterproof = next(
        transaction
        for transaction in transactions
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 0
    )
    outputs = tuple(
        replace(
            output,
            beneficiary_id=OWNER,
            script_pubkey=OWNER_SCRIPT,
        )
        if output.role is OutpointRoleV1.RESOLUTION
        else output
        for output in counterproof.outputs
    )
    transactions[transactions.index(counterproof)] = replace(
        counterproof,
        outputs=outputs,
    )

    assessment = replace(plan, transactions=tuple(transactions)).assess()
    assert (
        TimeoutSafetyBlockerV1.RESOLUTION_CONNECTOR_MISMATCH
        in assessment.structural_blockers
    )
    assert not assessment.counterproof_selection_allocates_exact_deposit


def test_unknown_plan_schema_fails_closed() -> None:
    with pytest.raises(TimeoutEconomicsError, match="unknown timeout plan schema"):
        replace(_plan(), schema="attacker-schema")


def test_template_ids_must_be_unique() -> None:
    plan = _plan()
    transactions = list(plan.transactions)
    transactions[1] = replace(
        transactions[1],
        template_id=transactions[0].template_id,
    )
    with pytest.raises(TimeoutEconomicsError, match="template ids must be unique"):
        replace(plan, transactions=tuple(transactions))


def test_terminal_enumerator_finds_every_maximal_local_trace_and_world() -> None:
    plan = _plan()
    policy = reference_terminal_protection_policy_v1(plan)
    result = plan.analyze_terminal_protection(policy)

    assert isinstance(result, AbstractDeclaredPolicySatisfiedV1)
    alternatives = len(plan.counterproof_ack_cpfp_beneficiaries)
    assert len(result.traces) == 1 + 2 * alternatives == 5
    assert len(result.world_traces) == 1 + 3 * alternatives == 7
    assert result.semantic_world_count == len(result.world_traces)
    assert {(trace.branch, trace.alternative_id) for trace in result.traces} == {
        (TerminalBranchV1.OWNER_PAYOUT, None),
        (TerminalBranchV1.ACK_SLASH, 0),
        (TerminalBranchV1.TIMEOUT, 0),
        (TerminalBranchV1.ACK_SLASH, 1),
        (TerminalBranchV1.TIMEOUT, 1),
    }

    for alternative in range(alternatives):
        valid_withheld = next(
            world
            for world in result.world_traces
            if world.world is TerminalWorldV1.VALID_RELEASE_WITHHELD
            and world.alternative_id == alternative
        )
        invalid_absent = next(
            world
            for world in result.world_traces
            if world.world is TerminalWorldV1.INVALID_RELEASE_ABSENT
            and world.alternative_id == alternative
        )
        assert valid_withheld.trace_id == invalid_absent.trace_id


def test_terminal_trace_and_world_formula_scales_to_one_alternative() -> None:
    plan = _one_alternative_plan()
    result = plan.analyze_terminal_protection(
        reference_terminal_protection_policy_v1(plan)
    )

    assert len(result.traces) == 1 + 2 * 1 == 3
    assert len(result.world_traces) == 1 + 3 * 1 == 4
    assert result.semantic_world_count == 4


def test_terminal_traces_conserve_total_value_and_have_exact_role_sequences() -> None:
    plan = _plan()
    result = plan.analyze_terminal_protection(
        reference_terminal_protection_policy_v1(plan)
    )
    transactions_by_id = {
        transaction.template_id: transaction for transaction in plan.transactions
    }
    all_outpoints = {
        outpoint.outpoint_id: outpoint for outpoint in plan.funding_outpoints
    }
    for transaction in plan.transactions:
        all_outpoints.update(
            (output.outpoint_id, output) for output in transaction.outputs
        )
    initial_value = sum(outpoint.value_sat for outpoint in plan.funding_outpoints)

    expected_roles = {
        TerminalBranchV1.OWNER_PAYOUT: (TransactionRoleV1.OWNER_PAYOUT,),
        TerminalBranchV1.ACK_SLASH: (
            TransactionRoleV1.COUNTERPROOF,
            TransactionRoleV1.ACK,
            TransactionRoleV1.SLASH,
        ),
        TerminalBranchV1.TIMEOUT: (
            TransactionRoleV1.COUNTERPROOF,
            TransactionRoleV1.TIMEOUT_SETTLEMENT,
        ),
    }
    for trace in result.traces:
        assert (
            tuple(
                transactions_by_id[template_id].role
                for template_id in trace.transaction_ids
            )
            == expected_roles[trace.branch]
        )
        assert (
            sum(
                all_outpoints[outpoint_id].value_sat
                for outpoint_id in trace.terminal_outpoint_ids
            )
            + trace.cumulative_fee_sat
            == initial_value
        )


def test_reference_terminal_policy_has_no_locked_counterproof_reserves() -> None:
    plan = _plan()
    result = plan.analyze_terminal_protection(
        reference_terminal_protection_policy_v1(plan)
    )
    assert isinstance(result, AbstractDeclaredPolicySatisfiedV1)
    assert not result.funding_eligible
    assert result.protected_value_theorem_established is False
    for trace in result.traces:
        assert all(
            outpoint_id
            not in {
                outpoint.outpoint_id
                for outpoint in plan.funding_outpoints
                if outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
            }
            for outpoint_id in trace.terminal_outpoint_ids
        )


def test_terminal_policy_requires_every_funding_and_positive_terminal_output() -> None:
    plan = _plan()
    policy = reference_terminal_protection_policy_v1(plan)
    missing_funding = policy.funding_principals[0].outpoint_id
    missing_output = policy.output_dispositions[0].outpoint_id
    missing_world = policy.world_policies[0]
    incomplete = replace(
        policy,
        funding_principals=policy.funding_principals[1:],
        output_dispositions=policy.output_dispositions[1:],
        world_policies=policy.world_policies[1:],
    )

    result = plan.analyze_terminal_protection(incomplete)
    assert isinstance(result, TerminalProtectionInfeasibleV1)
    roster = next(
        witness
        for witness in result.witnesses
        if isinstance(witness, TerminalPolicyRosterWitnessV1)
    )
    assert roster.missing_funding_ids == (missing_funding,)
    assert roster.missing_output_ids == (missing_output,)
    assert roster.missing_world_keys == (
        f"{missing_world.world.value}:{missing_world.alternative_id}",
    )


def test_protected_value_shortfall_returns_exact_world_trace_witness() -> None:
    plan = _plan()
    policy = _spendable_terminal_policy()
    no_counterproof = next(
        world
        for world in policy.world_policies
        if world.world is TerminalWorldV1.NO_COUNTERPROOF
    )
    baseline = no_counterproof.protected_baselines[0]
    residual_stake_value = next(
        outpoint.value_sat
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.STAKE
    )
    changed_world = replace(
        no_counterproof,
        protected_baselines=(
            replace(
                baseline,
                preexisting_principal_sat=(
                    baseline.preexisting_principal_sat + residual_stake_value + 1
                ),
                wealth_sat=baseline.wealth_sat + residual_stake_value + 1,
            ),
        ),
    )
    changed_policy = replace(
        policy,
        world_policies=tuple(
            changed_world if world is no_counterproof else world
            for world in policy.world_policies
        ),
    )

    result = plan.analyze_terminal_protection(changed_policy)
    assert isinstance(result, TerminalProtectionInfeasibleV1)
    deficit = next(
        witness
        for witness in result.witnesses
        if isinstance(witness, ProtectedValueDeficitWitnessV1)
    )
    owner_trace = next(
        trace
        for trace in result.traces
        if trace.branch is TerminalBranchV1.OWNER_PAYOUT
    )
    assert deficit.world is TerminalWorldV1.NO_COUNTERPROOF
    assert deficit.trace_id == owner_trace.trace_id
    assert deficit.aggregate_loss_sat == 1
    assert deficit.allowed_loss_sat == 0


def test_timeout_coalition_excess_returns_exact_gain_witness() -> None:
    plan = _plan()
    policy = _spendable_terminal_policy()
    changed_worlds = tuple(
        replace(world, explicit_service_fee_sat=329)
        if world.world
        in {
            TerminalWorldV1.VALID_RELEASE_WITHHELD,
            TerminalWorldV1.INVALID_RELEASE_ABSENT,
        }
        else world
        for world in policy.world_policies
    )
    changed_policy = replace(
        policy,
        world_policies=changed_worlds,
    )

    result = plan.analyze_terminal_protection(changed_policy)
    assert isinstance(result, TerminalProtectionInfeasibleV1)
    excesses = tuple(
        witness
        for witness in result.witnesses
        if isinstance(witness, TimeoutCoalitionExcessWitnessV1)
    )
    assert len(excesses) == 4
    assert {witness.actual_gain_sat for witness in excesses} == {330}
    assert {witness.allowed_gain_sat for witness in excesses} == {329}


def test_terminal_dispositions_must_match_committed_beneficiaries() -> None:
    plan = _plan()
    policy = _spendable_terminal_policy()
    outputs_by_id = {
        output.outpoint_id: output
        for transaction in plan.transactions
        for output in transaction.outputs
    }
    assert all(
        outputs_by_id[disposition.outpoint_id].beneficiary_id
        == disposition.principal_id
        for disposition in policy.output_dispositions
    )

    relabeled = replace(
        policy,
        output_dispositions=tuple(
            replace(disposition, principal_id=OWNER)
            for disposition in policy.output_dispositions
        ),
    )
    assert relabeled.policy_digest != policy.policy_digest

    result = plan.analyze_terminal_protection(relabeled)
    assert isinstance(result, TerminalProtectionInfeasibleV1)
    mismatches = tuple(
        witness
        for witness in result.witnesses
        if isinstance(
            witness,
            TerminalDispositionBeneficiaryMismatchWitnessV1,
        )
    )
    expected_mismatched_ids = {
        disposition.outpoint_id
        for disposition in relabeled.output_dispositions
        if outputs_by_id[disposition.outpoint_id].beneficiary_id != OWNER
    }
    assert {witness.outpoint_id for witness in mismatches} == expected_mismatched_ids
    assert all(witness.declared_principal_id == OWNER for witness in mismatches)
    counterproof_recovery = next(
        output
        for transaction in plan.transactions
        if transaction.role is TransactionRoleV1.COUNTERPROOF
        and transaction.alternative_id == 0
        for output in transaction.outputs
        if output.role is OutpointRoleV1.PROTECTED_RECOVERY
    )
    recovery_mismatch = next(
        witness
        for witness in mismatches
        if witness.outpoint_id == counterproof_recovery.outpoint_id
    )
    assert recovery_mismatch.committed_beneficiary_id == RECOVERY


def test_terminal_policy_digest_is_derived_from_canonical_content() -> None:
    policy = _spendable_terminal_policy()
    changed = replace(
        policy,
        horizon_blocks=policy.horizon_blocks + 1,
    )

    assert changed.policy_digest != policy.policy_digest
    with pytest.raises(ValueError, match="init=False"):
        replace(
            changed,
            policy_digest=policy.policy_digest,
        )


def test_complete_synthetic_neutral_policy_only_satisfies_declared_engine() -> None:
    plan = _plan()
    result = plan.analyze_terminal_protection(_spendable_terminal_policy())

    assert isinstance(result, AbstractDeclaredPolicySatisfiedV1)
    assert len(result.traces) == 5
    assert len(result.world_traces) == 7
    assert result.semantic_world_count == 7
    assert result.evidence_scope == (
        "caller-declared terminal policy satisfiability only"
    )
    assert not result.protected_value_theorem_established
    assert result.qualification_blockers == (
        TerminalQualificationBlockerV1.PROTECTED_BASELINE_AUTHORITY_UNVERIFIED,
        TerminalQualificationBlockerV1.PER_PRINCIPAL_ALLOWANCE_AUTHORITY_UNVERIFIED,
        TerminalQualificationBlockerV1.SERVICE_FEE_SCHEDULE_AND_BASELINE_AUTHORITY_UNVERIFIED,
        TerminalQualificationBlockerV1.BY_HORIZON_CSV_REORG_AND_FEE_EXECUTION_UNVERIFIED,
    )
    assert not result.funding_eligible
    assert not plan.assess().universal_funds_safety_established
    assert not plan.assess().funding_eligible


def test_terminal_enumeration_is_invariant_to_template_roster_order() -> None:
    plan = _plan()
    policy = reference_terminal_protection_policy_v1(plan)
    expected = plan.analyze_terminal_protection(policy)
    reordered = replace(plan, transactions=tuple(reversed(plan.transactions)))
    actual = reordered.analyze_terminal_protection(policy)

    assert isinstance(expected, AbstractDeclaredPolicySatisfiedV1)
    assert isinstance(actual, AbstractDeclaredPolicySatisfiedV1)
    assert actual.traces == expected.traces
    assert actual.world_traces == expected.world_traces


def test_v2_no_bond_exposes_exact_operator_principal_deficit() -> None:
    policy = reference_terminal_wealth_policy_v2()
    result = analyze_terminal_wealth_v2(_plan(), policy)

    assert isinstance(result, TerminalWealthCoverageInfeasibleV2)
    principal_deficits = tuple(
        witness
        for witness in result.witnesses
        if isinstance(witness, PrincipalCoverageDeficitWitnessV2)
    )
    assert len(principal_deficits) == 2
    assert {witness.principal_deficit_sat for witness in principal_deficits} == {
        100_000_000
    }
    assert {witness.authorized_cost_sat for witness in principal_deficits} == {660}
    assert {witness.baseline_wealth_sat for witness in principal_deficits} == {
        150_000_990
    }
    assert {witness.terminal_wealth_sat for witness in principal_deficits} == {
        50_000_330
    }
    reserve_deficits = tuple(
        witness
        for witness in result.witnesses
        if isinstance(witness, CoverageReserveDeficitWitnessV2)
    )
    assert len(reserve_deficits) == 2
    assert {witness.required_reserve_sat for witness in reserve_deficits} == {
        100_000_660
    }
    assert {witness.available_reserve_sat for witness in reserve_deficits} == {0}
    assert result.assumption_failure_world_keys == (
        "valid-release-withheld:0",
        "valid-release-withheld:1",
    )
    assert len(result.world_keys) == 7
    assert not result.protected_value_theorem_established
    assert not result.funding_eligible


def test_v2_no_counterproof_uses_exact_deposit_settlement_not_adversarial_relabel() -> (
    None
):
    policy = reference_terminal_wealth_policy_v2()
    no_counterproof_liabilities = tuple(
        liability
        for liability in policy.liabilities
        if liability.world is TerminalWorldV1.NO_COUNTERPROOF
    )
    assert len(no_counterproof_liabilities) == 1
    assert no_counterproof_liabilities[0].debtor_principal_id == RECOVERY
    assert no_counterproof_liabilities[0].creditor_principal_id == OWNER
    assert no_counterproof_liabilities[0].principal_sat == 100_000_000
    protected_recovery = next(
        status
        for status in policy.world_statuses
        if status.world is TerminalWorldV1.NO_COUNTERPROOF
        and status.principal_id == RECOVERY
    )
    assert protected_recovery.status is PrincipalStatusV2.PROTECTED
    assert protected_recovery.baseline_wealth_sat == 0

    relabeled_status = replace(
        protected_recovery,
        status=PrincipalStatusV2.ADVERSARIAL_BY_WORLD_PREMISE,
    )
    relabeled = replace(
        policy,
        world_statuses=tuple(
            relabeled_status if status is protected_recovery else status
            for status in policy.world_statuses
        ),
    )
    result = analyze_terminal_wealth_v2(_plan(), relabeled)
    assert isinstance(result, TerminalWealthCoverageInfeasibleV2)
    assert CoveragePolicyErrorV2.WORLD_STATUS_ROSTER_MISMATCH in {
        witness.error
        for witness in result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
    }


def test_v2_atomic_bond_candidate_only_establishes_declared_coverage() -> None:
    policy = reference_bond_coverage_policy_v2()
    result = analyze_terminal_wealth_v2(_plan(), policy)

    assert isinstance(result, DeclaredCoverageAdequateV2)
    assert result.coverage_adequacy_established
    assert not result.protected_value_theorem_established
    assert not result.funding_eligible
    assert len(result.qualification_blockers) == 4
    assert len(policy.coverage_reserves) == 2
    for reserve in policy.coverage_reserves:
        assert reserve.amount_sat == 100_000_660
        assert reserve.owner_return_value_sat == reserve.amount_sat
        assert reserve.bonded_resolution_value_sat == (
            reserve.base_resolution_value_sat + reserve.amount_sat
        )
        assert reserve.ack_refund_value_sat == reserve.amount_sat
        assert reserve.timeout_compensation_value_sat == reserve.amount_sat
        assert all(
            binding.value_sat == reserve.amount_sat
            for binding in reserve.sibling_returns
        )
        assert not reserve.fusion_with_existing_counterproof_input_authorized
        assert tuple(
            binding.selecting_alternative_id for binding in reserve.sibling_returns
        ) == tuple(
            alternative
            for alternative in (0, 1)
            if alternative != reserve.alternative_id
        )


def test_v2_policy_digest_is_content_derived_and_cannot_go_stale() -> None:
    policy = reference_bond_coverage_policy_v2()
    changed_endowment = replace(
        policy.endowments[0],
        value_sat=policy.endowments[0].value_sat + 1,
    )
    changed = replace(
        policy,
        endowments=(changed_endowment, *policy.endowments[1:]),
    )

    assert changed.policy_digest != policy.policy_digest
    assert terminal_wealth_policy_projection_v2(changed) != (
        terminal_wealth_policy_projection_v2(policy)
    )
    with pytest.raises(ValueError, match="init=False"):
        replace(policy, policy_digest=policy.policy_digest)


def test_v2_rejects_endowment_relabeling_and_omitted_principal() -> None:
    policy = reference_terminal_wealth_policy_v2()
    relabeled = replace(
        policy,
        endowments=(
            replace(policy.endowments[0], principal_id=RECOVERY),
            *policy.endowments[1:],
        ),
    )
    relabeled_result = analyze_terminal_wealth_v2(_plan(), relabeled)
    assert isinstance(relabeled_result, TerminalWealthCoverageInfeasibleV2)
    assert CoveragePolicyErrorV2.ENDOWMENT_OWNER_OR_VALUE_MISMATCH in {
        witness.error
        for witness in relabeled_result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
    }

    omitted = replace(policy, principals=policy.principals[1:])
    omitted_result = analyze_terminal_wealth_v2(_plan(), omitted)
    assert isinstance(omitted_result, TerminalWealthCoverageInfeasibleV2)
    assert CoveragePolicyErrorV2.PRINCIPAL_ROSTER_MISMATCH in {
        witness.error
        for witness in omitted_result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
    }


def test_v2_rejects_world_deletion_and_cross_principal_allowance() -> None:
    policy = reference_terminal_wealth_policy_v2()
    deleted = replace(policy, world_statuses=policy.world_statuses[1:])
    deleted_result = analyze_terminal_wealth_v2(_plan(), deleted)
    assert isinstance(deleted_result, TerminalWealthCoverageInfeasibleV2)
    assert CoveragePolicyErrorV2.WORLD_STATUS_ROSTER_MISMATCH in {
        witness.error
        for witness in deleted_result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
    }

    cross_principal = replace(
        policy,
        allowances=(
            replace(policy.allowances[0], principal_id=RECOVERY),
            *policy.allowances[1:],
        ),
    )
    cross_result = analyze_terminal_wealth_v2(_plan(), cross_principal)
    assert isinstance(cross_result, TerminalWealthCoverageInfeasibleV2)
    assert CoveragePolicyErrorV2.ALLOWANCE_AUTHORITY_MISMATCH in {
        witness.error
        for witness in cross_result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
    }


def test_v2_rejects_aggregate_netting_and_fee_double_count() -> None:
    policy = reference_terminal_wealth_policy_v2()
    aggregate = replace(
        policy,
        allowances=(
            replace(
                policy.allowances[0],
                amount_sat=policy.allowances[0].amount_sat + 100_000_000,
            ),
            *policy.allowances[1:],
        ),
    )
    aggregate_result = analyze_terminal_wealth_v2(_plan(), aggregate)
    assert isinstance(aggregate_result, TerminalWealthCoverageInfeasibleV2)
    assert CoveragePolicyErrorV2.ALLOWANCE_AUTHORITY_MISMATCH in {
        witness.error
        for witness in aggregate_result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
    }

    charge_id = policy.allowances[0].charge_ids[0]
    with pytest.raises(TimeoutEconomicsError, match="must be unique"):
        replace(policy.allowances[0], charge_ids=(charge_id, charge_id))


def test_v2_threshold_never_deletes_valid_withheld_world() -> None:
    policy = reference_terminal_wealth_policy_v2()
    without_threshold = replace(
        policy,
        threshold_qualification=None,
        world_statuses=tuple(
            replace(status, status=PrincipalStatusV2.PROTECTED)
            if status.world is TerminalWorldV1.VALID_RELEASE_WITHHELD
            else status
            for status in policy.world_statuses
        ),
    )
    result = analyze_terminal_wealth_v2(_plan(), without_threshold)

    assert isinstance(result, TerminalWealthCoverageInfeasibleV2)
    assert result.assumption_failure_world_keys == ()
    assert len(result.world_keys) == 7
    assert "valid-release-withheld:0" in result.world_keys
    assert "valid-release-withheld:1" in result.world_keys
    assert any(
        isinstance(witness, PrincipalCoverageDeficitWitnessV2)
        and witness.world is TerminalWorldV1.VALID_RELEASE_WITHHELD
        for witness in result.witnesses
    )


def test_v2_rejects_underfunding_collateral_reuse_and_nonatomic_returns() -> None:
    policy = reference_bond_coverage_policy_v2()
    underfunded_value = 100_000_659
    underfunded_reserve = replace(
        policy.coverage_reserves[0],
        amount_sat=underfunded_value,
        owner_return_value_sat=underfunded_value,
        sibling_returns=tuple(
            replace(binding, value_sat=underfunded_value)
            for binding in policy.coverage_reserves[0].sibling_returns
        ),
        bonded_resolution_value_sat=(
            policy.coverage_reserves[0].base_resolution_value_sat + underfunded_value
        ),
        ack_refund_value_sat=underfunded_value,
        timeout_compensation_value_sat=underfunded_value,
    )
    underfunded = replace(
        policy,
        coverage_reserves=(
            underfunded_reserve,
            *policy.coverage_reserves[1:],
        ),
    )
    underfunded_result = analyze_terminal_wealth_v2(_plan(), underfunded)
    assert isinstance(underfunded_result, TerminalWealthCoverageInfeasibleV2)
    assert any(
        isinstance(witness, CoverageReserveDeficitWitnessV2)
        and witness.alternative_id == 0
        and witness.reserve_shortfall_sat == 1
        for witness in underfunded_result.witnesses
    )

    reused_reserve = replace(
        policy.coverage_reserves[1],
        funding_outpoint_id=policy.coverage_reserves[0].funding_outpoint_id,
    )
    reused = replace(
        policy,
        coverage_reserves=(policy.coverage_reserves[0], reused_reserve),
    )
    reused_result = analyze_terminal_wealth_v2(_plan(), reused)
    assert isinstance(reused_result, TerminalWealthCoverageInfeasibleV2)
    assert CoveragePolicyErrorV2.COLLATERAL_REUSE in {
        witness.error
        for witness in reused_result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
    }

    nonatomic_reserve = replace(
        policy.coverage_reserves[0],
        sibling_returns=(),
    )
    nonatomic = replace(
        policy,
        coverage_reserves=(nonatomic_reserve, *policy.coverage_reserves[1:]),
    )
    nonatomic_result = analyze_terminal_wealth_v2(_plan(), nonatomic)
    assert isinstance(nonatomic_result, TerminalWealthCoverageInfeasibleV2)
    assert CoveragePolicyErrorV2.ATOMIC_BOND_TOPOLOGY_MISMATCH in {
        witness.error
        for witness in nonatomic_result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
    }


@pytest.mark.parametrize(
    "transition_kind",
    (
        "owner-return",
        "ack-refund",
        "timeout-compensation",
        "counterproof-sibling-return",
    ),
)
def test_v2_rejects_atomic_transition_id_colliding_with_plan_output(
    transition_kind: str,
) -> None:
    plan = _plan()
    policy = reference_bond_coverage_policy_v2()
    existing_plan_output_id = next(
        output.outpoint_id
        for transaction in plan.transactions
        for output in transaction.outputs
    )
    reserve = policy.coverage_reserves[0]
    if transition_kind == "counterproof-sibling-return":
        changed_reserve = replace(
            reserve,
            sibling_returns=(
                replace(
                    reserve.sibling_returns[0],
                    outpoint_id=existing_plan_output_id,
                ),
            ),
        )
    else:
        attribute = {
            "owner-return": "owner_return_outpoint_id",
            "ack-refund": "ack_refund_outpoint_id",
            "timeout-compensation": "timeout_compensation_outpoint_id",
        }[transition_kind]
        changed_reserve = replace(
            reserve,
            **{attribute: existing_plan_output_id},
        )
    changed_policy = replace(
        policy,
        coverage_reserves=(changed_reserve, *policy.coverage_reserves[1:]),
    )

    result = analyze_terminal_wealth_v2(plan, changed_policy)

    assert isinstance(result, TerminalWealthCoverageInfeasibleV2)
    collision = next(
        witness
        for witness in result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
        and witness.error is CoveragePolicyErrorV2.COLLATERAL_REUSE
    )
    assert collision.detail_ids == (existing_plan_output_id,)


def test_v2_rejects_atomic_owner_and_counterproof_aggregate_money_range() -> None:
    plan = _plan()
    policy = reference_bond_coverage_policy_v2(
        bond_value_sat=1_050_000_000_000_001,
    )

    result = analyze_terminal_wealth_v2(plan, policy)

    assert isinstance(result, TerminalWealthCoverageInfeasibleV2)
    witness = next(
        witness
        for witness in result.witnesses
        if isinstance(witness, CoveragePolicyWitnessV2)
        and witness.error is CoveragePolicyErrorV2.ATOMIC_BOND_MONEY_RANGE
    )
    expected_template_ids = {
        transaction.template_id
        for transaction in plan.transactions
        if transaction.role
        in {TransactionRoleV1.OWNER_PAYOUT, TransactionRoleV1.COUNTERPROOF}
    }
    expected_bond_ids = {
        reserve.funding_outpoint_id for reserve in policy.coverage_reserves
    }
    assert set(witness.detail_ids) == expected_template_ids | expected_bond_ids
    assert not result.protected_value_theorem_established
    assert not result.funding_eligible


@pytest.mark.parametrize(
    ("n", "threshold", "maximum_corruptions"),
    ((3, 1, 1), (3, 3, 1), (2, 2, 1)),
)
def test_v2_rejects_invalid_threshold_bounds(
    n: int,
    threshold: int,
    maximum_corruptions: int,
) -> None:
    policy = reference_terminal_wealth_policy_v2()
    qualification = policy.threshold_qualification
    assert qualification is not None
    participants = qualification.participant_ids[:n]
    with pytest.raises(
        TimeoutEconomicsError,
        match="0 <= f < t <= n-f|participant roster length",
    ):
        ThresholdReleaseQualificationV2(
            participant_ids=participants,
            ack_template_ids=qualification.ack_template_ids,
            n=n,
            threshold=threshold,
            maximum_corruptions=maximum_corruptions,
            exact_ack_conditional_signature_digest=(
                qualification.exact_ack_conditional_signature_digest
            ),
            transcript_digest=qualification.transcript_digest,
            schedule_digest=qualification.schedule_digest,
        )


def test_v2_execution_schedule_rejects_boolean_horizon() -> None:
    with pytest.raises(TimeoutEconomicsError, match="never a boolean"):
        ExecutionScheduleV2(
            horizon_blocks=True,
            release_deadline_blocks=1,
            ack_inclusion_blocks=1,
            timeout_csv_blocks=1,
            reorg_depth_blocks=1,
            maximum_confirmation_blocks=1,
            authority_digest=symbolic_id("schedule"),
        )


def test_committed_result_is_deterministically_regenerated() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assert (repo_root / "results/v026_timeout_economics.json").read_bytes() == (
        build_result_bytes(repo_root)
    )
