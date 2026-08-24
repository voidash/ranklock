"""Deterministic reference fixture for the v0.26 timeout-economics model.

The fixture is evidence input for the abstract model only. Its symbolic ids
and templates are not Bitcoin transaction bytes and cannot authorize funds.
"""

from __future__ import annotations

from hashlib import sha256

from ranklock.bip340 import public_key
from ranklock.v026.timeout_economics import (
    AllowanceCategoryV2,
    AtomicBondReturnV2,
    BeneficiaryDescriptorV1,
    CoverageReserveV2,
    EconomicPrincipalBindingV2,
    EconomicPrincipalRoleV2,
    EndowmentSourceV2,
    ExecutionScheduleV2,
    FundingEndowmentBindingV2,
    OutpointRoleV1,
    PlannedOutpointV1,
    PrincipalStatusV2,
    PrincipalWorldAllowanceV2,
    ResolutionConnectorPolicyV1,
    ServiceFeeChargeV2,
    ServiceFeeScheduleV2,
    SharedSelectionTimeoutPlanV1,
    SlashAuthorizationPolicyV1,
    SlashHeaderPolicyV1,
    SlashOutputPolicyV1,
    TerminalFundingPrincipalV1,
    TerminalOutpointDispositionV1,
    TerminalPrincipalBaselineV1,
    TerminalProtectionPolicyV1,
    TerminalWealthPolicyV2,
    TerminalWorldPolicyV1,
    TerminalWorldV1,
    ThresholdReleaseQualificationV2,
    TimeoutEconomicsError,
    TransactionRoleV1,
    TransactionTemplateV1,
    WorldLiabilityV2,
    WorldPrincipalStatusV2,
    service_fee_charge_id_v2,
)

OWNER = sha256(b"graph-owner").digest()
RECOVERY = sha256(b"recovery-principal").digest()
WATCHTOWER = sha256(b"watchtower").digest()
WATCHTOWER_1 = sha256(b"watchtower-1").digest()
RECOVERY_BROADCASTER = sha256(b"recovery-broadcaster").digest()
RELEASE_PARTICIPANT = sha256(b"release-participant").digest()
OWNER_CONTROL = sha256(b"owner-control").digest()
RECOVERY_CONTROL = sha256(b"recovery-control").digest()
WATCHTOWER_CONTROL = sha256(b"watchtower-control").digest()
WATCHTOWER_1_CONTROL = sha256(b"watchtower-1-control").digest()
SLASH_WATCHTOWER_CONTROL = sha256(b"slash-watchtower-control").digest()
SLASH_WATCHTOWER_1_CONTROL = sha256(b"slash-watchtower-1-control").digest()
RECOVERY_BROADCASTER_CONTROL = sha256(b"recovery-broadcaster-control").digest()
RELEASE_CONTROL = sha256(b"release-control").digest()
ECONOMIC_AUTHORITY = sha256(b"economic-authority").digest()
SERVICE_FEE_AUTHORITY = sha256(b"service-fee-authority").digest()
EXECUTION_SCHEDULE_AUTHORITY = sha256(b"execution-schedule-authority").digest()
OWNER_SCRIPT = b"\x51\x20" + public_key(0x111)
RECOVERY_SCRIPT = b"\x51\x20" + public_key(0x222)
WATCHTOWER_SCRIPT = b"\x51\x20" + public_key(0x333)
WATCHTOWER_1_SCRIPT = b"\x51\x20" + public_key(0x334)
WATCHTOWER_RESERVE_SCRIPT = b"\x51\x20" + public_key(0x337)
WATCHTOWER_1_RESERVE_SCRIPT = b"\x51\x20" + public_key(0x338)
SLASH_WATCHTOWER_SCRIPT = b"\x51\x20" + public_key(0x335)
SLASH_WATCHTOWER_1_SCRIPT = b"\x51\x20" + public_key(0x336)
RECOVERY_BROADCASTER_SCRIPT = b"\x51\x20" + public_key(0x444)
CONNECTOR_SCRIPT = b"\x51"
SLASH_AUTHORIZATION_SCRIPT = b"\x52"
SLASH_HEADER_SCRIPT = b"\x6a\x06SPS-50"


def symbolic_id(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def reference_outpoint(
    label: str,
    role: OutpointRoleV1,
    value_sat: int,
    *,
    alternative_id: int | None = None,
    beneficiary_id: bytes | None = None,
    script_pubkey: bytes = CONNECTOR_SCRIPT,
) -> PlannedOutpointV1:
    return PlannedOutpointV1(
        outpoint_id=symbolic_id(label),
        role=role,
        value_sat=value_sat,
        script_pubkey=script_pubkey,
        alternative_id=alternative_id,
        beneficiary_id=beneficiary_id,
    )


def _descriptor(
    label: str,
    principal_id: bytes,
    script_pubkey: bytes,
    control_domain_id: bytes,
) -> BeneficiaryDescriptorV1:
    return BeneficiaryDescriptorV1(
        principal_id=principal_id,
        script_pubkey=script_pubkey,
        control_domain_ids=(control_domain_id,),
        threshold=1,
        policy_digest=symbolic_id(f"{label}-policy"),
    )


def _transaction(
    label: str,
    role: TransactionRoleV1,
    inputs: tuple[PlannedOutpointV1, ...],
    outputs: tuple[PlannedOutpointV1, ...],
    fee_sat: int,
    *,
    alternative_id: int | None = None,
) -> TransactionTemplateV1:
    return TransactionTemplateV1(
        template_id=symbolic_id(label),
        role=role,
        input_ids=tuple(outpoint.outpoint_id for outpoint in inputs),
        outputs=outputs,
        fee_sat=fee_sat,
        alternative_id=alternative_id,
    )


def reference_shared_selection_plan_v1() -> SharedSelectionTimeoutPlanV1:
    """Return the deterministic two-alternative abstract reference plan."""

    graph_owner = _descriptor(
        "owner",
        OWNER,
        OWNER_SCRIPT,
        OWNER_CONTROL,
    )
    recovery = _descriptor(
        "recovery",
        RECOVERY,
        RECOVERY_SCRIPT,
        RECOVERY_CONTROL,
    )
    counterproof_ack_cpfp = (
        _descriptor(
            "watchtower-0",
            WATCHTOWER,
            WATCHTOWER_SCRIPT,
            WATCHTOWER_CONTROL,
        ),
        _descriptor(
            "watchtower-1",
            WATCHTOWER_1,
            WATCHTOWER_1_SCRIPT,
            WATCHTOWER_1_CONTROL,
        ),
    )
    counterproof_reserve = (
        _descriptor(
            "watchtower-reserve-0",
            WATCHTOWER,
            WATCHTOWER_RESERVE_SCRIPT,
            WATCHTOWER_CONTROL,
        ),
        _descriptor(
            "watchtower-reserve-1",
            WATCHTOWER_1,
            WATCHTOWER_1_RESERVE_SCRIPT,
            WATCHTOWER_1_CONTROL,
        ),
    )
    slash_beneficiaries = (
        _descriptor(
            "slash-watchtower-0",
            WATCHTOWER,
            SLASH_WATCHTOWER_SCRIPT,
            SLASH_WATCHTOWER_CONTROL,
        ),
        _descriptor(
            "slash-watchtower-1",
            WATCHTOWER_1,
            SLASH_WATCHTOWER_1_SCRIPT,
            SLASH_WATCHTOWER_1_CONTROL,
        ),
    )
    timeout_cpfp = _descriptor(
        "recovery-broadcaster",
        RECOVERY_BROADCASTER,
        RECOVERY_BROADCASTER_SCRIPT,
        RECOVERY_BROADCASTER_CONTROL,
    )
    deposit = reference_outpoint(
        "deposit",
        OutpointRoleV1.DEPOSIT,
        100_000_000,
        beneficiary_id=RECOVERY,
    )
    claim_payout = reference_outpoint(
        "claim-payout",
        OutpointRoleV1.CLAIM_PAYOUT,
        330,
    )
    contest_payout = reference_outpoint(
        "contest-payout",
        OutpointRoleV1.CONTEST_PAYOUT,
        330,
    )
    contest_slash = reference_outpoint(
        "contest-slash",
        OutpointRoleV1.CONTEST_SLASH,
        330,
    )
    stake = reference_outpoint("stake", OutpointRoleV1.STAKE, 50_000_000)
    counterproof_inputs = tuple(
        reference_outpoint(
            f"counterproof-input-{alternative}",
            OutpointRoleV1.COUNTERPROOF_INPUT,
            5_794,
            alternative_id=alternative,
        )
        for alternative in (0, 1)
    )

    owner_payout = _transaction(
        "owner-payout",
        TransactionRoleV1.OWNER_PAYOUT,
        (
            deposit,
            claim_payout,
            contest_payout,
            contest_slash,
            *counterproof_inputs,
        ),
        (
            reference_outpoint(
                "owner-payout-output",
                OutpointRoleV1.BENEFICIARY,
                100_000_386,
                beneficiary_id=OWNER,
                script_pubkey=OWNER_SCRIPT,
            ),
        )
        + tuple(
            reference_outpoint(
                f"owner-reserve-return-{alternative}",
                OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN,
                counterproof_input.value_sat,
                alternative_id=alternative,
                beneficiary_id=counterproof_reserve[alternative].principal_id,
                script_pubkey=counterproof_reserve[alternative].script_pubkey,
            )
            for alternative, counterproof_input in enumerate(counterproof_inputs)
        ),
        604,
    )
    alternative_transactions: list[TransactionTemplateV1] = []
    for alternative, counterproof_input in enumerate(counterproof_inputs):
        counterproof_cpfp = counterproof_ack_cpfp[alternative]
        resolution = reference_outpoint(
            f"resolution-{alternative}",
            OutpointRoleV1.RESOLUTION,
            900,
            alternative_id=alternative,
        )
        counterproof = _transaction(
            f"counterproof-{alternative}",
            TransactionRoleV1.COUNTERPROOF,
            (*counterproof_inputs, contest_payout, deposit),
            (
                reference_outpoint(
                    f"counterproof-recovery-{alternative}",
                    OutpointRoleV1.PROTECTED_RECOVERY,
                    deposit.value_sat,
                    alternative_id=alternative,
                    beneficiary_id=RECOVERY,
                    script_pubkey=RECOVERY_SCRIPT,
                ),
                resolution,
                reference_outpoint(
                    f"counterproof-anchor-{alternative}",
                    OutpointRoleV1.CPFP_ANCHOR,
                    330,
                    alternative_id=alternative,
                    beneficiary_id=counterproof_cpfp.principal_id,
                    script_pubkey=counterproof_cpfp.script_pubkey,
                ),
            )
            + tuple(
                reference_outpoint(
                    f"counterproof-reserve-return-{alternative}-{candidate}",
                    OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN,
                    candidate_input.value_sat,
                    alternative_id=candidate,
                    beneficiary_id=counterproof_reserve[candidate].principal_id,
                    script_pubkey=counterproof_reserve[candidate].script_pubkey,
                )
                for candidate, candidate_input in enumerate(counterproof_inputs)
                if candidate != alternative
            ),
            4_894,
            alternative_id=alternative,
        )
        ack = _transaction(
            f"ack-{alternative}",
            TransactionRoleV1.ACK,
            (resolution,),
            (
                reference_outpoint(
                    f"slash-authorization-{alternative}",
                    OutpointRoleV1.SLASH_AUTHORIZATION,
                    330,
                    alternative_id=alternative,
                    script_pubkey=SLASH_AUTHORIZATION_SCRIPT,
                ),
                reference_outpoint(
                    f"ack-anchor-{alternative}",
                    OutpointRoleV1.CPFP_ANCHOR,
                    330,
                    alternative_id=alternative,
                    beneficiary_id=counterproof_cpfp.principal_id,
                    script_pubkey=counterproof_cpfp.script_pubkey,
                ),
            ),
            240,
            alternative_id=alternative,
        )
        slash_authorization = next(
            output
            for output in ack.outputs
            if output.role is OutpointRoleV1.SLASH_AUTHORIZATION
        )
        timeout = _transaction(
            f"timeout-{alternative}",
            TransactionRoleV1.TIMEOUT_SETTLEMENT,
            (resolution, contest_slash),
            (
                reference_outpoint(
                    f"timeout-anchor-{alternative}",
                    OutpointRoleV1.CPFP_ANCHOR,
                    330,
                    alternative_id=alternative,
                    beneficiary_id=RECOVERY_BROADCASTER,
                    script_pubkey=RECOVERY_BROADCASTER_SCRIPT,
                ),
            ),
            900,
            alternative_id=alternative,
        )
        slash = _transaction(
            f"slash-{alternative}",
            TransactionRoleV1.SLASH,
            (slash_authorization, contest_slash, stake),
            (
                reference_outpoint(
                    f"slash-header-{alternative}",
                    OutpointRoleV1.PROTOCOL_HEADER,
                    0,
                    alternative_id=alternative,
                    script_pubkey=SLASH_HEADER_SCRIPT,
                ),
            )
            + tuple(
                reference_outpoint(
                    f"slash-output-{alternative}-{beneficiary_index}",
                    OutpointRoleV1.BENEFICIARY,
                    24_999_665,
                    alternative_id=alternative,
                    beneficiary_id=beneficiary.principal_id,
                    script_pubkey=beneficiary.script_pubkey,
                )
                for beneficiary_index, beneficiary in enumerate(slash_beneficiaries)
            ),
            1_330,
            alternative_id=alternative,
        )
        alternative_transactions.extend((counterproof, ack, timeout, slash))

    return SharedSelectionTimeoutPlanV1(
        funding_outpoints=(
            deposit,
            claim_payout,
            contest_payout,
            contest_slash,
            stake,
            *counterproof_inputs,
        ),
        transactions=(owner_payout, *alternative_transactions),
        graph_owner=graph_owner,
        recovery_beneficiary=recovery,
        counterproof_ack_cpfp_beneficiaries=counterproof_ack_cpfp,
        counterproof_reserve_beneficiaries=counterproof_reserve,
        timeout_cpfp_beneficiary=timeout_cpfp,
        resolution_connector_policy=ResolutionConnectorPolicyV1(
            value_sat=900,
            script_pubkey=CONNECTOR_SCRIPT,
            policy_digest=symbolic_id("resolution-connector-policy"),
        ),
        slash_authorization_policy=SlashAuthorizationPolicyV1(
            value_sat=330,
            script_pubkey=SLASH_AUTHORIZATION_SCRIPT,
            policy_digest=symbolic_id("slash-authorization-policy"),
        ),
        slash_header_policy=SlashHeaderPolicyV1(
            script_pubkey=SLASH_HEADER_SCRIPT,
            policy_digest=symbolic_id("slash-header-policy"),
        ),
        slash_beneficiaries=slash_beneficiaries,
        slash_output_policies=tuple(
            tuple(
                SlashOutputPolicyV1(
                    beneficiary=beneficiary,
                    value_sat=24_999_665,
                )
                for beneficiary in slash_beneficiaries
            )
            for _alternative in range(len(counterproof_inputs))
        ),
        release_control_domain_ids=(RELEASE_CONTROL,),
        counterproof_ack_cpfp_anchor_value_sat=330,
        timeout_cpfp_anchor_value_sat=330,
        maximum_abandoned_counterproof_sat=0,
    )


def reference_terminal_protection_policy_v1(
    plan: SharedSelectionTimeoutPlanV1 | None = None,
) -> TerminalProtectionPolicyV1:
    """Return the complete but intentionally infeasible terminal policy.

    Every selecting parent consumes the complete counterproof-reserve roster
    atomically. Owner returns every reserve and `Counterproof_j` returns every
    unselected reserve to its setup-bound principal. The policy maps every
    initial and possible positive terminal outpoint. A satisfied result remains
    only declared-policy evidence, not a protected-value theorem, because the
    economic authorities and by-horizon execution assumptions are external.
    """

    candidate = reference_shared_selection_plan_v1() if plan is None else plan
    deposit = next(
        outpoint
        for outpoint in candidate.funding_outpoints
        if outpoint.role is OutpointRoleV1.DEPOSIT
    )
    counterproof_principals = tuple(
        descriptor.principal_id
        for descriptor in candidate.counterproof_ack_cpfp_beneficiaries
    )

    funding_principals: list[TerminalFundingPrincipalV1] = []
    for outpoint in candidate.funding_outpoints:
        if outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT:
            alternative = outpoint.alternative_id
            if alternative is None or alternative >= len(counterproof_principals):
                raise TimeoutEconomicsError(
                    "reference counterproof input has no matching principal"
                )
            principal_id = counterproof_principals[alternative]
            spendable = False
        else:
            principal_id = OWNER
            spendable = True
        funding_principals.append(
            TerminalFundingPrincipalV1(
                outpoint_id=outpoint.outpoint_id,
                principal_id=principal_id,
                residual_spendable_by_horizon=spendable,
            )
        )

    output_dispositions: list[TerminalOutpointDispositionV1] = []
    for transaction in candidate.transactions:
        for output in transaction.outputs:
            principal_id: bytes
            preexisting_sat: int
            if (
                output.role is OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN
                and output.beneficiary_id is not None
            ):
                principal_id = output.beneficiary_id
                preexisting_sat = output.value_sat
            elif transaction.role is TransactionRoleV1.OWNER_PAYOUT:
                principal_id = OWNER
                preexisting_sat = deposit.value_sat
            elif (
                transaction.role is TransactionRoleV1.COUNTERPROOF
                and output.role is OutpointRoleV1.PROTECTED_RECOVERY
            ):
                principal_id = RECOVERY
                preexisting_sat = deposit.value_sat
            elif (
                transaction.role
                in {TransactionRoleV1.COUNTERPROOF, TransactionRoleV1.ACK}
                and output.role is OutpointRoleV1.CPFP_ANCHOR
            ):
                alternative = transaction.alternative_id
                if alternative is None or alternative >= len(counterproof_principals):
                    raise TimeoutEconomicsError(
                        "reference CPFP output has no matching principal"
                    )
                principal_id = counterproof_principals[alternative]
                preexisting_sat = 0
            elif (
                transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
                and output.role is OutpointRoleV1.CPFP_ANCHOR
            ):
                principal_id = candidate.timeout_cpfp_beneficiary.principal_id
                preexisting_sat = 0
            elif (
                transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
                and output.role is OutpointRoleV1.PROTECTED_RECOVERY
            ):
                principal_id = RECOVERY
                preexisting_sat = output.value_sat
            elif (
                transaction.role is TransactionRoleV1.SLASH
                and output.role is OutpointRoleV1.BENEFICIARY
                and output.beneficiary_id is not None
            ):
                principal_id = output.beneficiary_id
                preexisting_sat = 0
            else:
                continue
            output_dispositions.append(
                TerminalOutpointDispositionV1(
                    outpoint_id=output.outpoint_id,
                    principal_id=principal_id,
                    preexisting_principal_sat=preexisting_sat,
                    spendable_by_horizon=True,
                )
            )

    owner_baseline = TerminalPrincipalBaselineV1(
        principal_id=OWNER,
        preexisting_principal_sat=deposit.value_sat,
        wealth_sat=deposit.value_sat,
    )
    recovery_baseline = TerminalPrincipalBaselineV1(
        principal_id=RECOVERY,
        preexisting_principal_sat=deposit.value_sat,
        wealth_sat=deposit.value_sat,
    )
    timeout_baselines = tuple(
        sorted(
            (
                recovery_baseline,
                TerminalPrincipalBaselineV1(
                    principal_id=candidate.timeout_cpfp_beneficiary.principal_id,
                    preexisting_principal_sat=0,
                    wealth_sat=0,
                ),
            ),
            key=lambda baseline: baseline.principal_id,
        )
    )
    world_policies = [
        TerminalWorldPolicyV1(
            world=TerminalWorldV1.NO_COUNTERPROOF,
            alternative_id=None,
            protected_baselines=(owner_baseline,),
            timeout_coalition_principal_ids=(),
            explicit_fee_and_delay_allowance_sat=0,
            explicit_service_fee_sat=0,
        )
    ]
    for alternative in range(len(counterproof_principals)):
        world_policies.extend(
            (
                TerminalWorldPolicyV1(
                    world=TerminalWorldV1.VALID_RELEASED,
                    alternative_id=alternative,
                    protected_baselines=(recovery_baseline,),
                    timeout_coalition_principal_ids=(),
                    explicit_fee_and_delay_allowance_sat=0,
                    explicit_service_fee_sat=0,
                ),
                TerminalWorldPolicyV1(
                    world=TerminalWorldV1.VALID_RELEASE_WITHHELD,
                    alternative_id=alternative,
                    protected_baselines=timeout_baselines,
                    timeout_coalition_principal_ids=(
                        candidate.timeout_cpfp_beneficiary.principal_id,
                    ),
                    explicit_fee_and_delay_allowance_sat=0,
                    explicit_service_fee_sat=(candidate.timeout_cpfp_anchor_value_sat),
                ),
                TerminalWorldPolicyV1(
                    world=TerminalWorldV1.INVALID_RELEASE_ABSENT,
                    alternative_id=alternative,
                    protected_baselines=timeout_baselines,
                    timeout_coalition_principal_ids=(
                        candidate.timeout_cpfp_beneficiary.principal_id,
                    ),
                    explicit_fee_and_delay_allowance_sat=0,
                    explicit_service_fee_sat=(candidate.timeout_cpfp_anchor_value_sat),
                ),
            )
        )

    return TerminalProtectionPolicyV1(
        horizon_blocks=2_016,
        funding_principals=tuple(
            sorted(funding_principals, key=lambda binding: binding.outpoint_id)
        ),
        output_dispositions=tuple(
            sorted(
                output_dispositions,
                key=lambda disposition: disposition.outpoint_id,
            )
        ),
        world_policies=tuple(
            sorted(
                world_policies,
                key=lambda world: (
                    world.world.value,
                    -1 if world.alternative_id is None else world.alternative_id,
                ),
            )
        ),
    )


def _reference_terminal_wealth_policy_v2(
    *,
    include_counterprover_bonds: bool,
    bond_value_sat: int = 100_000_660,
) -> TerminalWealthPolicyV2:
    plan = reference_shared_selection_plan_v1()
    alternatives = tuple(
        sorted(
            outpoint.alternative_id
            for outpoint in plan.funding_outpoints
            if outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
            and outpoint.alternative_id is not None
        )
    )
    principals = tuple(
        sorted(
            (
                EconomicPrincipalBindingV2(
                    principal_id=OWNER,
                    role=EconomicPrincipalRoleV2.FRONTING_OPERATOR,
                    authority_digest=symbolic_id("owner-economic-authority"),
                ),
                EconomicPrincipalBindingV2(
                    principal_id=RECOVERY,
                    role=EconomicPrincipalRoleV2.RECOVERY_DEPOSITOR,
                    authority_digest=symbolic_id("recovery-economic-authority"),
                ),
                EconomicPrincipalBindingV2(
                    principal_id=WATCHTOWER,
                    role=EconomicPrincipalRoleV2.COUNTERPROVER,
                    authority_digest=symbolic_id("watchtower-0-economic-authority"),
                ),
                EconomicPrincipalBindingV2(
                    principal_id=WATCHTOWER_1,
                    role=EconomicPrincipalRoleV2.COUNTERPROVER,
                    authority_digest=symbolic_id("watchtower-1-economic-authority"),
                ),
                EconomicPrincipalBindingV2(
                    principal_id=RECOVERY_BROADCASTER,
                    role=EconomicPrincipalRoleV2.TIMEOUT_BROADCASTER,
                    authority_digest=symbolic_id(
                        "recovery-broadcaster-economic-authority"
                    ),
                ),
            ),
            key=lambda principal: principal.principal_id,
        )
    )
    principals_by_id = {principal.principal_id: principal for principal in principals}
    endowments: list[FundingEndowmentBindingV2] = []
    for outpoint in plan.funding_outpoints:
        if outpoint.role is OutpointRoleV1.DEPOSIT:
            principal_id = RECOVERY
        elif outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT:
            alternative = outpoint.alternative_id
            if alternative is None:
                raise TimeoutEconomicsError(
                    "reference C outpoint must name an alternative"
                )
            principal_id = plan.counterproof_reserve_beneficiaries[
                alternative
            ].principal_id
        else:
            principal_id = OWNER
        endowments.append(
            FundingEndowmentBindingV2(
                outpoint_id=outpoint.outpoint_id,
                principal_id=principal_id,
                value_sat=outpoint.value_sat,
                source=EndowmentSourceV2.PROTOCOL_FUNDING,
            )
        )

    owner = next(
        transaction
        for transaction in plan.transactions
        if transaction.role is TransactionRoleV1.OWNER_PAYOUT
    )
    coverage_reserves: list[CoverageReserveV2] = []
    if include_counterprover_bonds:
        for alternative in alternatives:
            provider = plan.counterproof_reserve_beneficiaries[alternative].principal_id
            bond_outpoint_id = symbolic_id(f"counterprover-bond-{alternative}")
            endowments.append(
                FundingEndowmentBindingV2(
                    outpoint_id=bond_outpoint_id,
                    principal_id=provider,
                    value_sat=bond_value_sat,
                    source=EndowmentSourceV2.COUNTERPROOF_BOND,
                    alternative_id=alternative,
                )
            )
            counterproof = next(
                transaction
                for transaction in plan.transactions
                if transaction.role is TransactionRoleV1.COUNTERPROOF
                and transaction.alternative_id == alternative
            )
            ack = next(
                transaction
                for transaction in plan.transactions
                if transaction.role is TransactionRoleV1.ACK
                and transaction.alternative_id == alternative
            )
            timeout = next(
                transaction
                for transaction in plan.transactions
                if transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
                and transaction.alternative_id == alternative
            )
            resolution = next(
                output
                for output in counterproof.outputs
                if output.role is OutpointRoleV1.RESOLUTION
            )
            coverage_reserves.append(
                CoverageReserveV2(
                    alternative_id=alternative,
                    funding_outpoint_id=bond_outpoint_id,
                    provider_principal_id=provider,
                    amount_sat=bond_value_sat,
                    owner_template_id=owner.template_id,
                    owner_return_outpoint_id=symbolic_id(
                        f"owner-bond-return-{alternative}"
                    ),
                    owner_return_value_sat=bond_value_sat,
                    counterproof_template_id=counterproof.template_id,
                    sibling_returns=tuple(
                        AtomicBondReturnV2(
                            selecting_alternative_id=selected,
                            outpoint_id=symbolic_id(
                                f"counterproof-bond-return-{selected}-{alternative}"
                            ),
                            value_sat=bond_value_sat,
                        )
                        for selected in alternatives
                        if selected != alternative
                    ),
                    resolution_outpoint_id=resolution.outpoint_id,
                    base_resolution_value_sat=resolution.value_sat,
                    bonded_resolution_value_sat=(resolution.value_sat + bond_value_sat),
                    ack_template_id=ack.template_id,
                    ack_refund_outpoint_id=symbolic_id(
                        f"ack-bond-refund-{alternative}"
                    ),
                    ack_refund_value_sat=bond_value_sat,
                    timeout_template_id=timeout.template_id,
                    timeout_compensation_outpoint_id=symbolic_id(
                        f"timeout-operator-compensation-{alternative}"
                    ),
                    timeout_compensation_value_sat=bond_value_sat,
                    timeout_beneficiary_principal_id=OWNER,
                )
            )

    deposit = next(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role is OutpointRoleV1.DEPOSIT
    )
    liabilities = (
        WorldLiabilityV2(
            liability_id=symbolic_id("no-counterproof-deposit-settlement"),
            world=TerminalWorldV1.NO_COUNTERPROOF,
            alternative_id=None,
            debtor_principal_id=RECOVERY,
            creditor_principal_id=OWNER,
            principal_sat=deposit.value_sat,
        ),
        *(
            WorldLiabilityV2(
                liability_id=symbolic_id(
                    f"invalid-counterproof-liability-{alternative}"
                ),
                world=TerminalWorldV1.INVALID_RELEASE_ABSENT,
                alternative_id=alternative,
                debtor_principal_id=plan.counterproof_reserve_beneficiaries[
                    alternative
                ].principal_id,
                creditor_principal_id=OWNER,
                principal_sat=deposit.value_sat,
            )
            for alternative in alternatives
        ),
    )
    charge_outpoints = tuple(
        outpoint
        for outpoint in plan.funding_outpoints
        if outpoint.role
        in {OutpointRoleV1.CONTEST_PAYOUT, OutpointRoleV1.CONTEST_SLASH}
    )
    owner_authority = principals_by_id[OWNER].authority_digest
    charges = tuple(
        sorted(
            tuple(
                ServiceFeeChargeV2(
                    charge_id=service_fee_charge_id_v2(outpoint.outpoint_id),
                    principal_id=OWNER,
                    category=AllowanceCategoryV2.FRONTING_COST,
                    amount_sat=outpoint.value_sat,
                    authority_digest=owner_authority,
                )
                for outpoint in charge_outpoints
            )
            + (
                ServiceFeeChargeV2(
                    charge_id=service_fee_charge_id_v2(owner.template_id),
                    principal_id=OWNER,
                    category=AllowanceCategoryV2.MINER_FEE,
                    amount_sat=owner.fee_sat,
                    authority_digest=owner_authority,
                ),
            ),
            key=lambda charge: charge.charge_id,
        )
    )
    service_fee_schedule = ServiceFeeScheduleV2(
        charges=charges,
        authority_digest=SERVICE_FEE_AUTHORITY,
    )
    allowance_charge_ids = tuple(
        charge.charge_id
        for charge in charges
        if charge.category is AllowanceCategoryV2.FRONTING_COST
    )
    allowance_value = sum(
        charge.amount_sat
        for charge in charges
        if charge.category is AllowanceCategoryV2.FRONTING_COST
    )
    allowances = (
        PrincipalWorldAllowanceV2(
            world=TerminalWorldV1.NO_COUNTERPROOF,
            alternative_id=None,
            principal_id=OWNER,
            category=AllowanceCategoryV2.MINER_FEE,
            amount_sat=owner.fee_sat,
            charge_ids=(service_fee_charge_id_v2(owner.template_id),),
            authority_digest=owner_authority,
        ),
        *(
            PrincipalWorldAllowanceV2(
                world=TerminalWorldV1.INVALID_RELEASE_ABSENT,
                alternative_id=alternative,
                principal_id=OWNER,
                category=AllowanceCategoryV2.FRONTING_COST,
                amount_sat=allowance_value,
                charge_ids=allowance_charge_ids,
                authority_digest=owner_authority,
            )
            for alternative in alternatives
        ),
    )
    execution_schedule = ExecutionScheduleV2(
        horizon_blocks=2_016,
        release_deadline_blocks=144,
        ack_inclusion_blocks=12,
        timeout_csv_blocks=144,
        reorg_depth_blocks=12,
        maximum_confirmation_blocks=12,
        authority_digest=EXECUTION_SCHEDULE_AUTHORITY,
    )
    threshold = ThresholdReleaseQualificationV2(
        participant_ids=tuple(
            sorted(symbolic_id(f"threshold-participant-{index}") for index in range(3))
        ),
        ack_template_ids=tuple(
            sorted(
                transaction.template_id
                for transaction in plan.transactions
                if transaction.role is TransactionRoleV1.ACK
            )
        ),
        n=3,
        threshold=2,
        maximum_corruptions=1,
        exact_ack_conditional_signature_digest=symbolic_id(
            "exact-ack-conditional-signature-policy"
        ),
        transcript_digest=symbolic_id("threshold-release-transcript"),
        schedule_digest=execution_schedule.policy_digest,
    )

    endowment_totals = {principal.principal_id: 0 for principal in principals}
    for binding in endowments:
        endowment_totals[binding.principal_id] += binding.value_sat
    liabilities_by_world = {
        (liability.world, liability.alternative_id): liability
        for liability in liabilities
    }
    world_keys = {
        (TerminalWorldV1.NO_COUNTERPROOF, None),
        *(
            (world, alternative)
            for alternative in alternatives
            for world in (
                TerminalWorldV1.VALID_RELEASED,
                TerminalWorldV1.VALID_RELEASE_WITHHELD,
                TerminalWorldV1.INVALID_RELEASE_ABSENT,
            )
        ),
    }
    statuses: list[WorldPrincipalStatusV2] = []
    for world, alternative in world_keys:
        liability = liabilities_by_world.get((world, alternative))
        for principal in principals:
            baseline = endowment_totals[principal.principal_id]
            if liability is not None:
                if principal.principal_id == liability.creditor_principal_id:
                    baseline += liability.principal_sat
                if principal.principal_id == liability.debtor_principal_id:
                    baseline = max(0, baseline - liability.principal_sat)
            if world is TerminalWorldV1.VALID_RELEASE_WITHHELD:
                status = PrincipalStatusV2.ASSUMPTION_FAILURE_WORLD
            elif (
                world is TerminalWorldV1.VALID_RELEASED
                and principal.principal_id == OWNER
            ) or (
                world is TerminalWorldV1.INVALID_RELEASE_ABSENT
                and alternative is not None
                and principal.principal_id
                == plan.counterproof_reserve_beneficiaries[alternative].principal_id
            ):
                status = PrincipalStatusV2.ADVERSARIAL_BY_WORLD_PREMISE
            else:
                status = PrincipalStatusV2.PROTECTED
            statuses.append(
                WorldPrincipalStatusV2(
                    world=world,
                    alternative_id=alternative,
                    principal_id=principal.principal_id,
                    status=status,
                    baseline_wealth_sat=baseline,
                )
            )

    return TerminalWealthPolicyV2(
        principals=principals,
        endowments=tuple(sorted(endowments, key=lambda binding: binding.outpoint_id)),
        liabilities=tuple(
            sorted(liabilities, key=lambda liability: liability.liability_id)
        ),
        world_statuses=tuple(
            sorted(
                statuses,
                key=lambda status: (
                    status.world.value,
                    -1 if status.alternative_id is None else status.alternative_id,
                    status.principal_id,
                ),
            )
        ),
        allowances=tuple(
            sorted(
                allowances,
                key=lambda allowance: (
                    allowance.world.value,
                    -1
                    if allowance.alternative_id is None
                    else allowance.alternative_id,
                    allowance.principal_id,
                ),
            )
        ),
        service_fee_schedule=service_fee_schedule,
        execution_schedule=execution_schedule,
        coverage_reserves=tuple(
            sorted(
                coverage_reserves,
                key=lambda reserve: reserve.alternative_id,
            )
        ),
        threshold_qualification=threshold,
    )


def reference_terminal_wealth_policy_v2() -> TerminalWealthPolicyV2:
    """Natural no-bond policy; expected to expose the operator deficit."""

    return _reference_terminal_wealth_policy_v2(include_counterprover_bonds=False)


def reference_bond_coverage_policy_v2(
    *, bond_value_sat: int = 100_000_660
) -> TerminalWealthPolicyV2:
    """Fully specified atomic-bond candidate for declared coverage only."""

    return _reference_terminal_wealth_policy_v2(
        include_counterprover_bonds=True,
        bond_value_sat=bond_value_sat,
    )
