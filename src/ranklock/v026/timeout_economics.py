"""Exact abstract checks for the proposed v0.26 shared-selection graph.

The model checks UTXO conflicts and integer value conservation.  It does not
serialize Bitcoin transactions, execute Script, or establish counterproof
validity.  A passing result is therefore evidence for one narrow structural
invariant only: after a counterproof consumes the shared contest-payout
outpoint, that counterproof transaction also consumes the deposit and allocates
its exact amount to a distinct, caller-declared P2TR descriptor. The candidate
then requires ACK to create the only authorization outpoint from which a slash
can proceed.

The on-chain views ``valid counterproof + withheld release`` and ``invalid
counterproof + absent release`` remain indistinguishable to this graph.  This
module intentionally keeps every plan funding-ineligible until that ambiguity
and the missing Rust/Core implementation are closed by independent evidence.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from hashlib import sha256
from typing import Final, TypeAlias

from ranklock.bip340 import BIP340Error, lift_x

_ID_BYTES: Final = 32
_MAX_MONEY_SAT: Final = 2_100_000_000_000_000
_MAX_SCRIPT_PUBKEY_BYTES: Final = 10_000
_MAX_ALTERNATIVE_ID: Final = 4_294_967_295


class TimeoutEconomicsError(ValueError):
    """Raised when an abstract graph object is not canonically representable."""


class OutpointRoleV1(str, Enum):
    DEPOSIT = "deposit"
    CLAIM_PAYOUT = "claim-payout"
    CONTEST_PAYOUT = "contest-payout"
    CONTEST_SLASH = "contest-slash"
    STAKE = "stake"
    COUNTERPROOF_INPUT = "counterproof-input"
    COUNTERPROOF_RESERVE_RETURN = "counterproof-reserve-return"
    RESOLUTION = "resolution"
    SLASH_AUTHORIZATION = "slash-authorization"
    PROTECTED_RECOVERY = "protected-recovery"
    OWNER_CHANGE = "owner-change"
    CPFP_ANCHOR = "cpfp-anchor"
    BENEFICIARY = "beneficiary"
    PROTOCOL_HEADER = "protocol-header"


class TransactionRoleV1(str, Enum):
    OWNER_PAYOUT = "owner-payout"
    COUNTERPROOF = "counterproof-v2"
    ACK = "ack-v2"
    TIMEOUT_SETTLEMENT = "timeout-settlement-v2"
    SLASH = "slash"


class TerminalBranchV1(str, Enum):
    """One maximal branch in the local presigned-template graph."""

    OWNER_PAYOUT = "owner-payout"
    ACK_SLASH = "ack-slash"
    TIMEOUT = "timeout"
    UNEXPECTED = "unexpected"


class TerminalWorldV1(str, Enum):
    """Semantic worlds relevant to the release/timeout ambiguity."""

    NO_COUNTERPROOF = "no-counterproof"
    VALID_RELEASED = "valid-released"
    VALID_RELEASE_WITHHELD = "valid-release-withheld"
    INVALID_RELEASE_ABSENT = "invalid-release-absent"


class EconomicPrincipalRoleV2(str, Enum):
    RECOVERY_DEPOSITOR = "recovery-depositor"
    FRONTING_OPERATOR = "fronting-operator"
    COUNTERPROVER = "counterprover"
    TIMEOUT_BROADCASTER = "timeout-broadcaster"


class EndowmentSourceV2(str, Enum):
    PROTOCOL_FUNDING = "protocol-funding"
    COUNTERPROOF_BOND = "counterproof-bond"


class PrincipalStatusV2(str, Enum):
    PROTECTED = "protected"
    ADVERSARIAL_BY_WORLD_PREMISE = "adversarial-by-world-premise"
    ASSUMPTION_FAILURE_WORLD = "assumption-failure-world"


class AllowanceCategoryV2(str, Enum):
    FRONTING_COST = "fronting-cost"
    MINER_FEE = "miner-fee"
    AUTHORIZED_SERVICE_FEE = "authorized-service-fee"


class CoverageQualificationBlockerV2(str, Enum):
    CONTROL_AND_POSSESSION_AUTHORITY_UNVERIFIED = (
        "control-and-possession-authority-unverified"
    )
    EXECUTION_SCHEDULE_AUTHORITY_UNVERIFIED = "execution-schedule-authority-unverified"
    BITCOIN_CORE_GRAPH_BINDING_UNVERIFIED = "bitcoin-core-graph-binding-unverified"
    RUNTIME_ADMISSION_AND_BROADCAST_UNVERIFIED = (
        "runtime-admission-and-broadcast-unverified"
    )


class CoveragePolicyErrorV2(str, Enum):
    STRUCTURAL_PLAN_INVALID = "structural-plan-invalid"
    PRINCIPAL_ROSTER_MISMATCH = "principal-roster-mismatch"
    ENDOWMENT_ROSTER_MISMATCH = "endowment-roster-mismatch"
    ENDOWMENT_OWNER_OR_VALUE_MISMATCH = "endowment-owner-or-value-mismatch"
    WORLD_ROSTER_MISMATCH = "world-roster-mismatch"
    WORLD_STATUS_ROSTER_MISMATCH = "world-status-roster-mismatch"
    WORLD_BASELINE_MISMATCH = "world-baseline-mismatch"
    LIABILITY_ROSTER_MISMATCH = "liability-roster-mismatch"
    ALLOWANCE_AUTHORITY_MISMATCH = "allowance-authority-mismatch"
    ALLOWANCE_CHARGE_REUSE = "allowance-charge-reuse"
    SERVICE_FEE_ROSTER_MISMATCH = "service-fee-roster-mismatch"
    THRESHOLD_QUALIFICATION_MISMATCH = "threshold-qualification-mismatch"
    COVERAGE_ROSTER_MISMATCH = "coverage-roster-mismatch"
    COLLATERAL_REUSE = "collateral-reuse"
    ATOMIC_BOND_TOPOLOGY_MISMATCH = "atomic-bond-topology-mismatch"
    ATOMIC_BOND_MONEY_RANGE = "atomic-bond-money-range"


_COVERAGE_QUALIFICATION_BLOCKERS_V2: Final = (
    CoverageQualificationBlockerV2.CONTROL_AND_POSSESSION_AUTHORITY_UNVERIFIED,
    CoverageQualificationBlockerV2.EXECUTION_SCHEDULE_AUTHORITY_UNVERIFIED,
    CoverageQualificationBlockerV2.BITCOIN_CORE_GRAPH_BINDING_UNVERIFIED,
    CoverageQualificationBlockerV2.RUNTIME_ADMISSION_AND_BROADCAST_UNVERIFIED,
)


class TerminalQualificationBlockerV1(str, Enum):
    """External authorities absent from declared-policy satisfiability."""

    PROTECTED_BASELINE_AUTHORITY_UNVERIFIED = "protected-baseline-authority-unverified"
    PER_PRINCIPAL_ALLOWANCE_AUTHORITY_UNVERIFIED = (
        "per-principal-allowance-authority-unverified"
    )
    SERVICE_FEE_SCHEDULE_AND_BASELINE_AUTHORITY_UNVERIFIED = (
        "service-fee-schedule-and-baseline-authority-unverified"
    )
    BY_HORIZON_CSV_REORG_AND_FEE_EXECUTION_UNVERIFIED = (
        "by-horizon-csv-reorg-and-fee-execution-unverified"
    )


_TERMINAL_QUALIFICATION_BLOCKERS: Final = (
    TerminalQualificationBlockerV1.PROTECTED_BASELINE_AUTHORITY_UNVERIFIED,
    TerminalQualificationBlockerV1.PER_PRINCIPAL_ALLOWANCE_AUTHORITY_UNVERIFIED,
    TerminalQualificationBlockerV1.SERVICE_FEE_SCHEDULE_AND_BASELINE_AUTHORITY_UNVERIFIED,
    TerminalQualificationBlockerV1.BY_HORIZON_CSV_REORG_AND_FEE_EXECUTION_UNVERIFIED,
)


class TimeoutSafetyBlockerV1(str, Enum):
    MALFORMED_RESOURCE_ROSTER = "malformed-resource-roster"
    MALFORMED_TRANSACTION_ROSTER = "malformed-transaction-roster"
    UNKNOWN_OR_DUPLICATE_OUTPOINT = "unknown-or-duplicate-outpoint"
    VALUE_NOT_CONSERVED = "value-not-conserved"
    OWNER_PAYOUT_NOT_GATED_BY_SHARED_CONTEST_PAYOUT = (
        "owner-payout-not-gated-by-shared-contest-payout"
    )
    COUNTERPROOFS_NOT_MUTUALLY_EXCLUSIVE = "counterproofs-not-mutually-exclusive"
    COUNTERPROOF_DOES_NOT_CREATE_UNIQUE_RESOLUTION = (
        "counterproof-does-not-create-unique-resolution"
    )
    RESOLUTION_CONNECTOR_MISMATCH = "resolution-connector-mismatch"
    COUNTERPROOF_CPFP_DESCRIPTOR_MISMATCH = "counterproof-cpfp-descriptor-mismatch"
    ACK_AND_TIMEOUT_DO_NOT_CONFLICT = "ack-and-timeout-do-not-conflict"
    ACK_CPFP_DESCRIPTOR_MISMATCH = "ack-cpfp-descriptor-mismatch"
    COUNTERPROOF_DOES_NOT_ALLOCATE_EXACT_DEPOSIT = (
        "counterproof-does-not-allocate-exact-deposit"
    )
    COUNTERPROOF_RECOVERY_BENEFICIARY_MISMATCH = (
        "counterproof-recovery-beneficiary-mismatch"
    )
    ACK_DOES_NOT_CREATE_SLASH_AUTHORIZATION = "ack-does-not-create-slash-authorization"
    ACK_OUTPUT_ROSTER_MISMATCH = "ack-output-roster-mismatch"
    SLASH_NOT_GATED_BY_ACK = "slash-not-gated-by-ack"
    SLASH_OUTPUT_ROSTER_MISMATCH = "slash-output-roster-mismatch"
    TIMEOUT_AND_SLASH_DO_NOT_CONFLICT = "timeout-and-slash-do-not-conflict"
    CLAIM_PAYOUT_BURN_CAN_BLOCK_TIMEOUT = "claim-payout-burn-can-block-timeout"
    TIMEOUT_OUTPUT_ROSTER_MISMATCH = "timeout-output-roster-mismatch"
    TIMEOUT_CPFP_DESCRIPTOR_MISMATCH = "timeout-cpfp-descriptor-mismatch"
    RECOVERY_DESCRIPTOR_CONTROL_UNVERIFIED = "recovery-descriptor-control-unverified"
    CPFP_CONTROL_UNVERIFIED = "cpfp-control-unverified"
    RESOLUTION_CONNECTOR_POLICY_UNVERIFIED = "resolution-connector-policy-unverified"
    SLASH_AUTHORIZATION_POLICY_UNVERIFIED = "slash-authorization-policy-unverified"
    SLASH_BENEFICIARY_CONTROL_UNVERIFIED = "slash-beneficiary-control-unverified"
    DEPOSIT_ALTERNATE_SIGNATURE_EXCLUSION_UNVERIFIED = (
        "deposit-alternate-signature-exclusion-unverified"
    )
    STAKE_EXCLUSIVITY_UNVERIFIED = "stake-exclusivity-unverified"
    COMPLETE_GRAPH_PRESIGN_ERASURE_UNVERIFIED = (
        "complete-graph-presign-erasure-unverified"
    )
    ATOMIC_ROSTER_WEIGHT_EVIDENCE_UNVERIFIED = (
        "atomic-roster-weight-evidence-unverified"
    )
    UNUSED_COUNTERPROOF_RESERVE_EXCEEDS_POLICY = (
        "unused-counterproof-reserve-exceeds-policy"
    )
    TERMINAL_PRINCIPAL_DISPOSITION_UNMODELED = (
        "terminal-principal-disposition-unmodeled"
    )
    VALIDITY_WITHHOLDING_AMBIGUITY_UNRESOLVED = (
        "validity-withholding-ambiguity-unresolved"
    )
    RUST_GRAPH_PROJECTION_UNVERIFIED = "rust-graph-projection-unverified"
    BITCOIN_CORE_ACCEPTANCE_NOT_BOUND_TO_MODEL = (
        "bitcoin-core-acceptance-not-bound-to-model"
    )


def _exact_bytes(value: object, *, size: int, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise TimeoutEconomicsError(f"{label} must be immutable bytes")
    if len(value) != size:
        raise TimeoutEconomicsError(f"{label} must be exactly {size} bytes")
    return value


def _bounded_sat(value: object, *, label: str, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int):
        raise TimeoutEconomicsError(f"{label} must be an integer")
    if not minimum <= value <= _MAX_MONEY_SAT:
        qualifier = "nonnegative" if allow_zero else "positive"
        raise TimeoutEconomicsError(f"{label} must be a {qualifier} Bitcoin amount")
    return value


def _checked_money_range_total(values: tuple[int, ...]) -> int | None:
    """Return the exact aggregate, or ``None`` before exceeding MoneyRange."""

    total = 0
    for value in values:
        if value < 0 or value > _MAX_MONEY_SAT - total:
            return None
        total += value
    return total


def _alternative_id(value: object, *, required: bool, label: str) -> int | None:
    if value is None:
        if required:
            raise TimeoutEconomicsError(f"{label} requires an alternative id")
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TimeoutEconomicsError(f"{label} alternative id must be an integer")
    if not 0 <= value <= _MAX_ALTERNATIVE_ID:
        raise TimeoutEconomicsError(f"{label} alternative id must be in 0..4294967295")
    return value


@dataclass(frozen=True, slots=True)
class PlannedOutpointV1:
    """One symbolic outpoint in the exact abstract transaction graph."""

    outpoint_id: bytes
    role: OutpointRoleV1
    value_sat: int
    script_pubkey: bytes
    alternative_id: int | None = None
    beneficiary_id: bytes | None = None

    def __post_init__(self) -> None:
        outpoint_id = _exact_bytes(
            self.outpoint_id,
            size=_ID_BYTES,
            label="outpoint id",
        )
        if not isinstance(self.role, OutpointRoleV1):
            raise TimeoutEconomicsError("outpoint role must be OutpointRoleV1")
        value_sat = _bounded_sat(
            self.value_sat,
            label="outpoint value",
            allow_zero=self.role is OutpointRoleV1.PROTOCOL_HEADER,
        )
        if not isinstance(self.script_pubkey, bytes):
            raise TimeoutEconomicsError("scriptPubKey must be immutable bytes")
        if not 1 <= len(self.script_pubkey) <= _MAX_SCRIPT_PUBKEY_BYTES:
            raise TimeoutEconomicsError("scriptPubKey must contain 1..10000 bytes")
        alternative_required = self.role in {
            OutpointRoleV1.COUNTERPROOF_INPUT,
            OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN,
            OutpointRoleV1.RESOLUTION,
        }
        alternative_id = _alternative_id(
            self.alternative_id,
            required=alternative_required,
            label=self.role.value,
        )
        beneficiary_id = self.beneficiary_id
        if beneficiary_id is not None:
            beneficiary_id = _exact_bytes(
                beneficiary_id,
                size=_ID_BYTES,
                label="beneficiary id",
            )
        object.__setattr__(self, "outpoint_id", outpoint_id)
        object.__setattr__(self, "value_sat", value_sat)
        object.__setattr__(self, "alternative_id", alternative_id)
        object.__setattr__(self, "beneficiary_id", beneficiary_id)


@dataclass(frozen=True, slots=True)
class BeneficiaryDescriptorV1:
    """Setup-committed beneficiary metadata for the abstract model.

    The descriptor constrains identity, control-domain separation, and a
    canonical P2TR-looking scriptPubKey. It is not a proof that any party knows
    a satisfying key or script witness; that remains a funding blocker until
    the versioned Rust/Core implementation verifies it.
    """

    principal_id: bytes
    script_pubkey: bytes
    control_domain_ids: tuple[bytes, ...]
    threshold: int
    policy_digest: bytes
    schema: str = "ranklock-v026-beneficiary-descriptor-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-beneficiary-descriptor-v1":
            raise TimeoutEconomicsError("unknown beneficiary descriptor schema")
        principal_id = _exact_bytes(
            self.principal_id,
            size=_ID_BYTES,
            label="beneficiary principal id",
        )
        script_pubkey = self.script_pubkey
        if not isinstance(script_pubkey, bytes):
            raise TimeoutEconomicsError(
                "beneficiary scriptPubKey must be immutable bytes"
            )
        if len(script_pubkey) != 34 or script_pubkey[:2] != b"\x51\x20":
            raise TimeoutEconomicsError(
                "beneficiary scriptPubKey must be canonical P2TR"
            )
        try:
            lift_x(int.from_bytes(script_pubkey[2:], "big"))
        except BIP340Error as exc:
            raise TimeoutEconomicsError(
                "beneficiary P2TR output key is not a valid x-only point"
            ) from exc
        if not isinstance(self.control_domain_ids, tuple):
            raise TimeoutEconomicsError("control-domain ids must be an immutable tuple")
        control_domain_ids = tuple(
            _exact_bytes(
                value,
                size=_ID_BYTES,
                label="control-domain id",
            )
            for value in self.control_domain_ids
        )
        if not control_domain_ids:
            raise TimeoutEconomicsError("at least one control domain is required")
        if tuple(sorted(control_domain_ids)) != control_domain_ids:
            raise TimeoutEconomicsError("control-domain ids must be sorted")
        if len(set(control_domain_ids)) != len(control_domain_ids):
            raise TimeoutEconomicsError("control-domain ids must be unique")
        threshold = self.threshold
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or not 1 <= threshold <= len(control_domain_ids)
        ):
            raise TimeoutEconomicsError(
                "beneficiary threshold must be in 1..control-domain count"
            )
        policy_digest = _exact_bytes(
            self.policy_digest,
            size=_ID_BYTES,
            label="beneficiary policy digest",
        )
        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(self, "script_pubkey", script_pubkey)
        object.__setattr__(self, "control_domain_ids", control_domain_ids)
        object.__setattr__(self, "policy_digest", policy_digest)


@dataclass(frozen=True, slots=True)
class ResolutionConnectorPolicyV1:
    """Committed abstract identity for every selected resolution output.

    Exact Script semantics remain unverified until the Rust connector and Core
    acceptance evidence exist. This object only prevents per-alternative
    substitution inside the abstract plan.
    """

    value_sat: int
    script_pubkey: bytes
    policy_digest: bytes
    schema: str = "ranklock-v026-resolution-connector-policy-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-resolution-connector-policy-v1":
            raise TimeoutEconomicsError("unknown resolution connector policy schema")
        value_sat = _bounded_sat(self.value_sat, label="resolution connector value")
        if not isinstance(self.script_pubkey, bytes):
            raise TimeoutEconomicsError(
                "resolution connector scriptPubKey must be immutable bytes"
            )
        if not 1 <= len(self.script_pubkey) <= _MAX_SCRIPT_PUBKEY_BYTES:
            raise TimeoutEconomicsError(
                "resolution connector scriptPubKey must contain 1..10000 bytes"
            )
        policy_digest = _exact_bytes(
            self.policy_digest,
            size=_ID_BYTES,
            label="resolution connector policy digest",
        )
        object.__setattr__(self, "value_sat", value_sat)
        object.__setattr__(self, "policy_digest", policy_digest)


@dataclass(frozen=True, slots=True)
class SlashAuthorizationPolicyV1:
    """Committed abstract identity for ACK-created slash authorization."""

    value_sat: int
    script_pubkey: bytes
    policy_digest: bytes
    schema: str = "ranklock-v026-slash-authorization-policy-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-slash-authorization-policy-v1":
            raise TimeoutEconomicsError("unknown slash authorization policy schema")
        value_sat = _bounded_sat(self.value_sat, label="slash authorization value")
        if not isinstance(self.script_pubkey, bytes):
            raise TimeoutEconomicsError(
                "slash authorization scriptPubKey must be immutable bytes"
            )
        if not 1 <= len(self.script_pubkey) <= _MAX_SCRIPT_PUBKEY_BYTES:
            raise TimeoutEconomicsError(
                "slash authorization scriptPubKey must contain 1..10000 bytes"
            )
        policy_digest = _exact_bytes(
            self.policy_digest,
            size=_ID_BYTES,
            label="slash authorization policy digest",
        )
        object.__setattr__(self, "value_sat", value_sat)
        object.__setattr__(self, "policy_digest", policy_digest)


@dataclass(frozen=True, slots=True)
class SlashHeaderPolicyV1:
    """Exact zero-value protocol header required at Slash output index zero."""

    script_pubkey: bytes
    policy_digest: bytes
    schema: str = "ranklock-v026-slash-header-policy-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-slash-header-policy-v1":
            raise TimeoutEconomicsError("unknown slash header policy schema")
        if not isinstance(self.script_pubkey, bytes):
            raise TimeoutEconomicsError(
                "slash header scriptPubKey must be immutable bytes"
            )
        if not 1 <= len(self.script_pubkey) <= _MAX_SCRIPT_PUBKEY_BYTES:
            raise TimeoutEconomicsError(
                "slash header scriptPubKey must contain 1..10000 bytes"
            )
        policy_digest = _exact_bytes(
            self.policy_digest,
            size=_ID_BYTES,
            label="slash header policy digest",
        )
        object.__setattr__(self, "policy_digest", policy_digest)


@dataclass(frozen=True, slots=True)
class SlashOutputPolicyV1:
    """One exact beneficiary/value entry in a committed Slash output roster."""

    beneficiary: BeneficiaryDescriptorV1
    value_sat: int
    schema: str = "ranklock-v026-slash-output-policy-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-slash-output-policy-v1":
            raise TimeoutEconomicsError("unknown slash output policy schema")
        if not isinstance(self.beneficiary, BeneficiaryDescriptorV1):
            raise TimeoutEconomicsError(
                "slash output beneficiary must use BeneficiaryDescriptorV1"
            )
        value_sat = _bounded_sat(self.value_sat, label="slash output value")
        object.__setattr__(self, "value_sat", value_sat)


@dataclass(frozen=True, slots=True)
class TransactionTemplateV1:
    """A symbolic presigned parent; ``template_id`` is not a Bitcoin txid."""

    template_id: bytes
    role: TransactionRoleV1
    input_ids: tuple[bytes, ...]
    outputs: tuple[PlannedOutpointV1, ...]
    fee_sat: int
    alternative_id: int | None = None

    def __post_init__(self) -> None:
        template_id = _exact_bytes(
            self.template_id,
            size=_ID_BYTES,
            label="template id",
        )
        if not isinstance(self.role, TransactionRoleV1):
            raise TimeoutEconomicsError("transaction role must be TransactionRoleV1")
        if not isinstance(self.input_ids, tuple) or not self.input_ids:
            raise TimeoutEconomicsError(
                "transaction inputs must be a nonempty immutable tuple"
            )
        input_ids = tuple(
            _exact_bytes(value, size=_ID_BYTES, label="transaction input id")
            for value in self.input_ids
        )
        if len(set(input_ids)) != len(input_ids):
            raise TimeoutEconomicsError("transaction inputs must be unique")
        if not isinstance(self.outputs, tuple) or not self.outputs:
            raise TimeoutEconomicsError(
                "transaction outputs must be a nonempty immutable tuple"
            )
        if not all(isinstance(output, PlannedOutpointV1) for output in self.outputs):
            raise TimeoutEconomicsError(
                "transaction outputs must contain PlannedOutpointV1 values"
            )
        output_ids = tuple(output.outpoint_id for output in self.outputs)
        if len(set(output_ids)) != len(output_ids):
            raise TimeoutEconomicsError("transaction output ids must be unique")
        fee_sat = _bounded_sat(
            self.fee_sat,
            label="transaction fee",
            allow_zero=True,
        )
        alternative_required = self.role in {
            TransactionRoleV1.COUNTERPROOF,
            TransactionRoleV1.ACK,
            TransactionRoleV1.TIMEOUT_SETTLEMENT,
            TransactionRoleV1.SLASH,
        }
        alternative_id = _alternative_id(
            self.alternative_id,
            required=alternative_required,
            label=self.role.value,
        )
        object.__setattr__(self, "template_id", template_id)
        object.__setattr__(self, "input_ids", input_ids)
        object.__setattr__(self, "fee_sat", fee_sat)
        object.__setattr__(self, "alternative_id", alternative_id)


@dataclass(frozen=True, slots=True)
class TerminalFundingPrincipalV1:
    """Economic principal for one initial protocol UTXO.

    ``residual_spendable_by_horizon`` applies only when the funding outpoint is
    still live at a maximal local terminal. It is a signed-policy assertion,
    not evidence that the corresponding witness exists.
    """

    outpoint_id: bytes
    principal_id: bytes
    residual_spendable_by_horizon: bool
    schema: str = "ranklock-v026-terminal-funding-principal-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-terminal-funding-principal-v1":
            raise TimeoutEconomicsError("unknown terminal funding principal schema")
        outpoint_id = _exact_bytes(
            self.outpoint_id,
            size=_ID_BYTES,
            label="terminal funding outpoint id",
        )
        principal_id = _exact_bytes(
            self.principal_id,
            size=_ID_BYTES,
            label="terminal funding principal id",
        )
        if not isinstance(self.residual_spendable_by_horizon, bool):
            raise TimeoutEconomicsError(
                "residual spendability must be an exact boolean"
            )
        object.__setattr__(self, "outpoint_id", outpoint_id)
        object.__setattr__(self, "principal_id", principal_id)


@dataclass(frozen=True, slots=True)
class TerminalOutpointDispositionV1:
    """Economic disposition of one generated positive terminal output."""

    outpoint_id: bytes
    principal_id: bytes
    preexisting_principal_sat: int
    spendable_by_horizon: bool
    schema: str = "ranklock-v026-terminal-outpoint-disposition-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-terminal-outpoint-disposition-v1":
            raise TimeoutEconomicsError("unknown terminal outpoint disposition schema")
        outpoint_id = _exact_bytes(
            self.outpoint_id,
            size=_ID_BYTES,
            label="terminal output id",
        )
        principal_id = _exact_bytes(
            self.principal_id,
            size=_ID_BYTES,
            label="terminal output principal id",
        )
        preexisting = _bounded_sat(
            self.preexisting_principal_sat,
            label="terminal preexisting principal value",
            allow_zero=True,
        )
        if not isinstance(self.spendable_by_horizon, bool):
            raise TimeoutEconomicsError(
                "terminal output spendability must be an exact boolean"
            )
        object.__setattr__(self, "outpoint_id", outpoint_id)
        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(self, "preexisting_principal_sat", preexisting)


@dataclass(frozen=True, slots=True)
class TerminalPrincipalBaselineV1:
    """Committed baseline values for one protected economic principal."""

    principal_id: bytes
    preexisting_principal_sat: int
    wealth_sat: int
    schema: str = "ranklock-v026-terminal-principal-baseline-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-terminal-principal-baseline-v1":
            raise TimeoutEconomicsError("unknown terminal principal baseline schema")
        principal_id = _exact_bytes(
            self.principal_id,
            size=_ID_BYTES,
            label="terminal baseline principal id",
        )
        preexisting = _bounded_sat(
            self.preexisting_principal_sat,
            label="terminal baseline preexisting principal value",
            allow_zero=True,
        )
        wealth = _bounded_sat(
            self.wealth_sat,
            label="terminal baseline wealth",
            allow_zero=True,
        )
        if preexisting > wealth:
            raise TimeoutEconomicsError(
                "terminal baseline preexisting principal cannot exceed wealth"
            )
        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(self, "preexisting_principal_sat", preexisting)
        object.__setattr__(self, "wealth_sat", wealth)


@dataclass(frozen=True, slots=True)
class TerminalWorldPolicyV1:
    """Protected-value requirement for one semantic world."""

    world: TerminalWorldV1
    alternative_id: int | None
    protected_baselines: tuple[TerminalPrincipalBaselineV1, ...]
    timeout_coalition_principal_ids: tuple[bytes, ...]
    explicit_fee_and_delay_allowance_sat: int
    explicit_service_fee_sat: int
    schema: str = "ranklock-v026-terminal-world-policy-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-terminal-world-policy-v1":
            raise TimeoutEconomicsError("unknown terminal world policy schema")
        if not isinstance(self.world, TerminalWorldV1):
            raise TimeoutEconomicsError("terminal world must be TerminalWorldV1")
        alternative_required = self.world is not TerminalWorldV1.NO_COUNTERPROOF
        alternative_id = _alternative_id(
            self.alternative_id,
            required=alternative_required,
            label=self.world.value,
        )
        if not alternative_required and alternative_id is not None:
            raise TimeoutEconomicsError(
                "no-counterproof world cannot name an alternative"
            )
        if (
            not isinstance(self.protected_baselines, tuple)
            or not self.protected_baselines
            or not all(
                isinstance(baseline, TerminalPrincipalBaselineV1)
                for baseline in self.protected_baselines
            )
        ):
            raise TimeoutEconomicsError(
                "protected baselines must be a nonempty immutable tuple"
            )
        baseline_ids = tuple(
            baseline.principal_id for baseline in self.protected_baselines
        )
        if tuple(sorted(baseline_ids)) != baseline_ids:
            raise TimeoutEconomicsError("protected baselines must be sorted")
        if len(set(baseline_ids)) != len(baseline_ids):
            raise TimeoutEconomicsError("protected baseline principals must be unique")
        if not isinstance(self.timeout_coalition_principal_ids, tuple):
            raise TimeoutEconomicsError(
                "timeout coalition principals must be an immutable tuple"
            )
        coalition = tuple(
            _exact_bytes(
                principal_id,
                size=_ID_BYTES,
                label="timeout coalition principal id",
            )
            for principal_id in self.timeout_coalition_principal_ids
        )
        if tuple(sorted(coalition)) != coalition:
            raise TimeoutEconomicsError(
                "timeout coalition principal ids must be sorted"
            )
        if len(set(coalition)) != len(coalition):
            raise TimeoutEconomicsError(
                "timeout coalition principal ids must be unique"
            )
        baseline_id_set = set(baseline_ids)
        if not set(coalition).issubset(baseline_id_set):
            raise TimeoutEconomicsError(
                "timeout coalition principals require committed baselines"
            )
        allowance = _bounded_sat(
            self.explicit_fee_and_delay_allowance_sat,
            label="explicit fee and delay allowance",
            allow_zero=True,
        )
        service_fee = _bounded_sat(
            self.explicit_service_fee_sat,
            label="explicit service fee",
            allow_zero=True,
        )
        object.__setattr__(self, "alternative_id", alternative_id)
        object.__setattr__(self, "timeout_coalition_principal_ids", coalition)
        object.__setattr__(
            self,
            "explicit_fee_and_delay_allowance_sat",
            allowance,
        )
        object.__setattr__(self, "explicit_service_fee_sat", service_fee)


@dataclass(frozen=True, slots=True)
class TerminalProtectionPolicyV1:
    """Complete caller-declared economic policy for local terminal analysis."""

    horizon_blocks: int
    funding_principals: tuple[TerminalFundingPrincipalV1, ...]
    output_dispositions: tuple[TerminalOutpointDispositionV1, ...]
    world_policies: tuple[TerminalWorldPolicyV1, ...]
    policy_digest: bytes = field(init=False)
    schema: str = "ranklock-v026-terminal-protection-policy-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-terminal-protection-policy-v1":
            raise TimeoutEconomicsError("unknown terminal protection policy schema")
        if (
            isinstance(self.horizon_blocks, bool)
            or not isinstance(self.horizon_blocks, int)
            or not 1 <= self.horizon_blocks <= _MAX_ALTERNATIVE_ID
        ):
            raise TimeoutEconomicsError(
                "terminal protection horizon must be in 1..4294967295"
            )
        if not isinstance(self.funding_principals, tuple) or not all(
            isinstance(binding, TerminalFundingPrincipalV1)
            for binding in self.funding_principals
        ):
            raise TimeoutEconomicsError(
                "terminal funding principals must be an immutable tuple"
            )
        funding_ids = tuple(binding.outpoint_id for binding in self.funding_principals)
        if tuple(sorted(funding_ids)) != funding_ids:
            raise TimeoutEconomicsError("terminal funding principals must be sorted")
        if len(set(funding_ids)) != len(funding_ids):
            raise TimeoutEconomicsError("terminal funding outpoint ids must be unique")
        if not isinstance(self.output_dispositions, tuple) or not all(
            isinstance(disposition, TerminalOutpointDispositionV1)
            for disposition in self.output_dispositions
        ):
            raise TimeoutEconomicsError(
                "terminal output dispositions must be an immutable tuple"
            )
        disposition_ids = tuple(
            disposition.outpoint_id for disposition in self.output_dispositions
        )
        if tuple(sorted(disposition_ids)) != disposition_ids:
            raise TimeoutEconomicsError("terminal output dispositions must be sorted")
        if len(set(disposition_ids)) != len(disposition_ids):
            raise TimeoutEconomicsError(
                "terminal output disposition ids must be unique"
            )
        if not isinstance(self.world_policies, tuple) or not all(
            isinstance(world, TerminalWorldPolicyV1) for world in self.world_policies
        ):
            raise TimeoutEconomicsError(
                "terminal world policies must be an immutable tuple"
            )
        world_keys = tuple(
            (
                world.world.value,
                -1 if world.alternative_id is None else world.alternative_id,
            )
            for world in self.world_policies
        )
        if tuple(sorted(world_keys)) != world_keys:
            raise TimeoutEconomicsError("terminal world policies must be sorted")
        if len(set(world_keys)) != len(world_keys):
            raise TimeoutEconomicsError("terminal world policies must be unique")
        object.__setattr__(
            self,
            "policy_digest",
            _terminal_protection_policy_digest_v1(self),
        )


def terminal_protection_policy_projection_v1(
    policy: TerminalProtectionPolicyV1,
) -> dict[str, object]:
    """Return the canonical content projection committed by ``policy_digest``."""

    if not isinstance(policy, TerminalProtectionPolicyV1):
        raise TimeoutEconomicsError(
            "terminal policy projection requires TerminalProtectionPolicyV1"
        )
    return {
        "schema": policy.schema,
        "horizon_blocks": policy.horizon_blocks,
        "funding_principals": [
            {
                "schema": binding.schema,
                "outpoint_id": binding.outpoint_id.hex(),
                "principal_id": binding.principal_id.hex(),
                "residual_spendable_by_horizon": (
                    binding.residual_spendable_by_horizon
                ),
            }
            for binding in policy.funding_principals
        ],
        "output_dispositions": [
            {
                "schema": disposition.schema,
                "outpoint_id": disposition.outpoint_id.hex(),
                "principal_id": disposition.principal_id.hex(),
                "preexisting_principal_sat": (disposition.preexisting_principal_sat),
                "spendable_by_horizon": disposition.spendable_by_horizon,
            }
            for disposition in policy.output_dispositions
        ],
        "world_policies": [
            {
                "schema": world.schema,
                "world": world.world.value,
                "alternative_id": world.alternative_id,
                "protected_baselines": [
                    {
                        "schema": baseline.schema,
                        "principal_id": baseline.principal_id.hex(),
                        "preexisting_principal_sat": (
                            baseline.preexisting_principal_sat
                        ),
                        "wealth_sat": baseline.wealth_sat,
                    }
                    for baseline in world.protected_baselines
                ],
                "timeout_coalition_principal_ids": [
                    principal_id.hex()
                    for principal_id in world.timeout_coalition_principal_ids
                ],
                "explicit_fee_and_delay_allowance_sat": (
                    world.explicit_fee_and_delay_allowance_sat
                ),
                "explicit_service_fee_sat": world.explicit_service_fee_sat,
            }
            for world in policy.world_policies
        ],
    }


def _terminal_protection_policy_digest_v1(
    policy: TerminalProtectionPolicyV1,
) -> bytes:
    projection = terminal_protection_policy_projection_v1(policy)
    encoded = (
        json.dumps(
            projection,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")
    return sha256(encoded).digest()


@dataclass(frozen=True, slots=True)
class TerminalTraceV1:
    """One deterministic maximal local trace and its residual UTXO set."""

    trace_id: bytes
    branch: TerminalBranchV1
    alternative_id: int | None
    transaction_ids: tuple[bytes, ...]
    terminal_outpoint_ids: tuple[bytes, ...]
    cumulative_fee_sat: int
    schema: str = "ranklock-v026-terminal-trace-v1"


@dataclass(frozen=True, slots=True)
class TerminalWorldTraceV1:
    """Exact semantic-world to maximal local trace association."""

    world: TerminalWorldV1
    alternative_id: int | None
    trace_id: bytes
    schema: str = "ranklock-v026-terminal-world-trace-v1"


@dataclass(frozen=True, slots=True)
class PrincipalShortfallV1:
    """One protected principal's pre-existing-value shortfall."""

    principal_id: bytes
    baseline_sat: int
    actual_sat: int


@dataclass(frozen=True, slots=True)
class TerminalStructuralWitnessV1:
    blockers: tuple[TimeoutSafetyBlockerV1, ...]
    schema: str = "ranklock-v026-terminal-structural-witness-v1"


@dataclass(frozen=True, slots=True)
class TerminalTraceRosterWitnessV1:
    expected_trace_count: int
    actual_trace_count: int
    trace_ids: tuple[bytes, ...]
    schema: str = "ranklock-v026-terminal-trace-roster-witness-v1"


@dataclass(frozen=True, slots=True)
class TerminalPolicyRosterWitnessV1:
    missing_funding_ids: tuple[bytes, ...]
    extra_funding_ids: tuple[bytes, ...]
    missing_output_ids: tuple[bytes, ...]
    extra_output_ids: tuple[bytes, ...]
    missing_world_keys: tuple[str, ...]
    extra_world_keys: tuple[str, ...]
    schema: str = "ranklock-v026-terminal-policy-roster-witness-v1"


@dataclass(frozen=True, slots=True)
class LockedTerminalValueWitnessV1:
    trace_id: bytes
    outpoint_id: bytes
    principal_id: bytes
    value_sat: int
    schema: str = "ranklock-v026-locked-terminal-value-witness-v1"


@dataclass(frozen=True, slots=True)
class TerminalDispositionValueWitnessV1:
    outpoint_id: bytes
    outpoint_value_sat: int
    declared_preexisting_principal_sat: int
    schema: str = "ranklock-v026-terminal-disposition-value-witness-v1"


@dataclass(frozen=True, slots=True)
class TerminalDispositionBeneficiaryMismatchWitnessV1:
    outpoint_id: bytes
    committed_beneficiary_id: bytes
    declared_principal_id: bytes
    schema: str = "ranklock-v026-terminal-disposition-beneficiary-mismatch-witness-v1"


@dataclass(frozen=True, slots=True)
class ProtectedValueDeficitWitnessV1:
    world: TerminalWorldV1
    alternative_id: int | None
    trace_id: bytes
    shortfalls: tuple[PrincipalShortfallV1, ...]
    aggregate_loss_sat: int
    allowed_loss_sat: int
    schema: str = "ranklock-v026-protected-value-deficit-witness-v1"


@dataclass(frozen=True, slots=True)
class TimeoutCoalitionExcessWitnessV1:
    world: TerminalWorldV1
    alternative_id: int | None
    trace_id: bytes
    coalition_principal_ids: tuple[bytes, ...]
    actual_gain_sat: int
    allowed_gain_sat: int
    schema: str = "ranklock-v026-timeout-coalition-excess-witness-v1"


TerminalInfeasibilityWitnessV1: TypeAlias = (
    TerminalStructuralWitnessV1
    | TerminalTraceRosterWitnessV1
    | TerminalPolicyRosterWitnessV1
    | LockedTerminalValueWitnessV1
    | TerminalDispositionValueWitnessV1
    | TerminalDispositionBeneficiaryMismatchWitnessV1
    | ProtectedValueDeficitWitnessV1
    | TimeoutCoalitionExcessWitnessV1
)


@dataclass(frozen=True, slots=True)
class AbstractDeclaredPolicySatisfiedV1:
    """Finite satisfiability result over declarations, never a funds theorem."""

    traces: tuple[TerminalTraceV1, ...]
    world_traces: tuple[TerminalWorldTraceV1, ...]
    semantic_world_count: int
    policy_digest: bytes
    protected_value_theorem_established: bool = field(default=False, init=False)
    qualification_blockers: tuple[TerminalQualificationBlockerV1, ...] = field(
        default=_TERMINAL_QUALIFICATION_BLOCKERS,
        init=False,
    )
    funding_eligible: bool = field(default=False, init=False)
    evidence_class: str = "EXACT"
    evidence_scope: str = "caller-declared terminal policy satisfiability only"
    schema: str = "ranklock-v026-abstract-declared-policy-satisfied-v1"


@dataclass(frozen=True, slots=True)
class TerminalProtectionInfeasibleV1:
    """Canonical counterexamples to declared terminal-policy satisfaction."""

    traces: tuple[TerminalTraceV1, ...]
    world_traces: tuple[TerminalWorldTraceV1, ...]
    semantic_world_count: int
    policy_digest: bytes
    witnesses: tuple[TerminalInfeasibilityWitnessV1, ...]
    protected_value_theorem_established: bool = field(default=False, init=False)
    qualification_blockers: tuple[TerminalQualificationBlockerV1, ...] = field(
        default=_TERMINAL_QUALIFICATION_BLOCKERS,
        init=False,
    )
    funding_eligible: bool = field(default=False, init=False)
    evidence_class: str = "EXACT"
    evidence_scope: str = "caller-declared terminal policy satisfiability only"
    schema: str = "ranklock-v026-terminal-protection-infeasible-v1"


TerminalProtectionResultV1: TypeAlias = (
    AbstractDeclaredPolicySatisfiedV1 | TerminalProtectionInfeasibleV1
)


@dataclass(frozen=True, slots=True)
class TimeoutSafetyAssessmentV1:
    structural_blockers: tuple[TimeoutSafetyBlockerV1, ...]
    funding_blockers: tuple[TimeoutSafetyBlockerV1, ...]
    counterproof_selection_allocates_exact_deposit: bool
    universal_funds_safety_established: bool
    funding_eligible: bool
    worst_case_unused_counterproof_sat: int
    timeout_cpfp_anchor_value_sat: int
    evidence_class: str = "EXACT"
    evidence_scope: str = "caller-declared abstract symbols only"
    schema: str = "ranklock-v026-timeout-safety-assessment-v1"


@dataclass(frozen=True, slots=True)
class SharedSelectionTimeoutPlanV1:
    """Candidate topology and committed narrow economic policy."""

    funding_outpoints: tuple[PlannedOutpointV1, ...]
    transactions: tuple[TransactionTemplateV1, ...]
    graph_owner: BeneficiaryDescriptorV1
    recovery_beneficiary: BeneficiaryDescriptorV1
    counterproof_ack_cpfp_beneficiaries: tuple[BeneficiaryDescriptorV1, ...]
    counterproof_reserve_beneficiaries: tuple[BeneficiaryDescriptorV1, ...]
    timeout_cpfp_beneficiary: BeneficiaryDescriptorV1
    resolution_connector_policy: ResolutionConnectorPolicyV1
    slash_authorization_policy: SlashAuthorizationPolicyV1
    slash_header_policy: SlashHeaderPolicyV1
    slash_beneficiaries: tuple[BeneficiaryDescriptorV1, ...]
    slash_output_policies: tuple[tuple[SlashOutputPolicyV1, ...], ...]
    release_control_domain_ids: tuple[bytes, ...]
    counterproof_ack_cpfp_anchor_value_sat: int
    timeout_cpfp_anchor_value_sat: int
    maximum_abandoned_counterproof_sat: int
    schema: str = "ranklock-v026-shared-selection-timeout-plan-v1"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-shared-selection-timeout-plan-v1":
            raise TimeoutEconomicsError("unknown timeout plan schema")
        if not isinstance(self.funding_outpoints, tuple) or not self.funding_outpoints:
            raise TimeoutEconomicsError(
                "funding outpoints must be a nonempty immutable tuple"
            )
        if not all(
            isinstance(outpoint, PlannedOutpointV1)
            for outpoint in self.funding_outpoints
        ):
            raise TimeoutEconomicsError(
                "funding outpoints must contain PlannedOutpointV1 values"
            )
        if not isinstance(self.transactions, tuple) or not self.transactions:
            raise TimeoutEconomicsError(
                "transactions must be a nonempty immutable tuple"
            )
        if not all(
            isinstance(transaction, TransactionTemplateV1)
            for transaction in self.transactions
        ):
            raise TimeoutEconomicsError(
                "transactions must contain TransactionTemplateV1 values"
            )
        template_ids = tuple(
            transaction.template_id for transaction in self.transactions
        )
        if len(set(template_ids)) != len(template_ids):
            raise TimeoutEconomicsError("transaction template ids must be unique")
        if (
            not isinstance(self.counterproof_ack_cpfp_beneficiaries, tuple)
            or not self.counterproof_ack_cpfp_beneficiaries
        ):
            raise TimeoutEconomicsError(
                "counterproof/ACK CPFP beneficiaries must be a nonempty immutable tuple"
            )
        counterproof_descriptors = self.counterproof_ack_cpfp_beneficiaries
        reserve_descriptors = self.counterproof_reserve_beneficiaries
        if (
            not isinstance(reserve_descriptors, tuple)
            or len(reserve_descriptors) != len(counterproof_descriptors)
            or not all(
                isinstance(descriptor, BeneficiaryDescriptorV1)
                for descriptor in reserve_descriptors
            )
        ):
            raise TimeoutEconomicsError(
                "counterproof reserve beneficiaries must match the immutable alternative roster"
            )
        if any(
            reserve.principal_id != counterproof.principal_id
            for reserve, counterproof in zip(
                reserve_descriptors,
                counterproof_descriptors,
                strict=True,
            )
        ):
            raise TimeoutEconomicsError(
                "counterproof reserve beneficiaries must preserve ordered funding principals"
            )
        descriptors = (
            self.graph_owner,
            self.recovery_beneficiary,
            self.timeout_cpfp_beneficiary,
            *counterproof_descriptors,
        )
        if not all(
            isinstance(descriptor, BeneficiaryDescriptorV1)
            for descriptor in descriptors
        ):
            raise TimeoutEconomicsError(
                "beneficiaries must use BeneficiaryDescriptorV1"
            )
        if len({descriptor.principal_id for descriptor in descriptors}) != len(
            descriptors
        ):
            raise TimeoutEconomicsError(
                "owner, recovery, counterproof, and timeout principals must be distinct"
            )
        if len({descriptor.script_pubkey for descriptor in descriptors}) != len(
            descriptors
        ):
            raise TimeoutEconomicsError(
                "owner, recovery, counterproof, and timeout scripts must be distinct"
            )
        reserve_scripts = {
            descriptor.script_pubkey for descriptor in reserve_descriptors
        }
        if len(reserve_scripts) != len(
            reserve_descriptors
        ) or reserve_scripts.intersection(
            descriptor.script_pubkey for descriptor in descriptors
        ):
            raise TimeoutEconomicsError(
                "counterproof reserve scripts must be unique and distinct from other beneficiaries"
            )
        if not isinstance(
            self.resolution_connector_policy,
            ResolutionConnectorPolicyV1,
        ):
            raise TimeoutEconomicsError(
                "resolution connector policy must use ResolutionConnectorPolicyV1"
            )
        if not isinstance(
            self.slash_authorization_policy,
            SlashAuthorizationPolicyV1,
        ):
            raise TimeoutEconomicsError(
                "slash authorization policy must use SlashAuthorizationPolicyV1"
            )
        if not isinstance(self.slash_header_policy, SlashHeaderPolicyV1):
            raise TimeoutEconomicsError(
                "slash header policy must use SlashHeaderPolicyV1"
            )
        if (
            not isinstance(self.slash_beneficiaries, tuple)
            or not self.slash_beneficiaries
            or not all(
                isinstance(descriptor, BeneficiaryDescriptorV1)
                for descriptor in self.slash_beneficiaries
            )
        ):
            raise TimeoutEconomicsError(
                "slash beneficiaries must be a nonempty immutable descriptor tuple"
            )
        if len(self.slash_beneficiaries) != len(counterproof_descriptors) or any(
            slash.principal_id != counterproof.principal_id
            for slash, counterproof in zip(
                self.slash_beneficiaries,
                counterproof_descriptors,
                strict=True,
            )
        ):
            raise TimeoutEconomicsError(
                "slash beneficiaries must match the ordered watchtower principals"
            )
        if len(
            {descriptor.script_pubkey for descriptor in self.slash_beneficiaries}
        ) != len(self.slash_beneficiaries):
            raise TimeoutEconomicsError("slash beneficiary scripts must be unique")
        nonslash_scripts = (
            {descriptor.script_pubkey for descriptor in descriptors}
            | reserve_scripts
            | {outpoint.script_pubkey for outpoint in self.funding_outpoints}
            | {
                self.resolution_connector_policy.script_pubkey,
                self.slash_authorization_policy.script_pubkey,
                self.slash_header_policy.script_pubkey,
            }
        )
        if nonslash_scripts.intersection(
            descriptor.script_pubkey for descriptor in self.slash_beneficiaries
        ):
            raise TimeoutEconomicsError(
                "slash beneficiary scripts must be distinct from other plan scripts"
            )
        slash_prohibited_controls = (
            set(self.graph_owner.control_domain_ids)
            | set(self.recovery_beneficiary.control_domain_ids)
            | set(self.timeout_cpfp_beneficiary.control_domain_ids)
        )
        if any(
            slash_prohibited_controls.intersection(descriptor.control_domain_ids)
            for descriptor in self.slash_beneficiaries
        ):
            raise TimeoutEconomicsError(
                "slash beneficiary controls must be independent of owner, recovery, and timeout controls"
            )
        if (
            not isinstance(self.slash_output_policies, tuple)
            or not self.slash_output_policies
            or any(
                not isinstance(roster, tuple) or not roster
                for roster in self.slash_output_policies
            )
            or any(
                not isinstance(policy, SlashOutputPolicyV1)
                for roster in self.slash_output_policies
                for policy in roster
            )
        ):
            raise TimeoutEconomicsError(
                "slash output policies must be nonempty immutable rosters"
            )
        if any(
            tuple(policy.beneficiary for policy in roster) != self.slash_beneficiaries
            for roster in self.slash_output_policies
        ):
            raise TimeoutEconomicsError(
                "slash output beneficiaries must match the ordered watchtower roster"
            )
        if not isinstance(self.release_control_domain_ids, tuple):
            raise TimeoutEconomicsError(
                "release control-domain ids must be an immutable tuple"
            )
        release_control_domain_ids = tuple(
            _exact_bytes(
                value,
                size=_ID_BYTES,
                label="release control-domain id",
            )
            for value in self.release_control_domain_ids
        )
        if not release_control_domain_ids:
            raise TimeoutEconomicsError(
                "at least one release control domain is required"
            )
        if tuple(sorted(release_control_domain_ids)) != release_control_domain_ids:
            raise TimeoutEconomicsError("release control-domain ids must be sorted")
        if len(set(release_control_domain_ids)) != len(release_control_domain_ids):
            raise TimeoutEconomicsError("release control-domain ids must be unique")
        counterproof_controls = {
            control_domain_id
            for descriptor in counterproof_descriptors
            for control_domain_id in descriptor.control_domain_ids
        }
        prohibited_controls = (
            set(release_control_domain_ids)
            | set(self.graph_owner.control_domain_ids)
            | counterproof_controls
        )
        if prohibited_controls.intersection(
            self.recovery_beneficiary.control_domain_ids
        ):
            raise TimeoutEconomicsError(
                "recovery controls must be independent of timeout-capable controls"
            )
        if prohibited_controls.intersection(
            self.timeout_cpfp_beneficiary.control_domain_ids
        ):
            raise TimeoutEconomicsError(
                "CPFP controls must be independent of timeout-capable controls"
            )
        if set(self.recovery_beneficiary.control_domain_ids).intersection(
            self.timeout_cpfp_beneficiary.control_domain_ids
        ):
            raise TimeoutEconomicsError(
                "recovery and CPFP controls must be independent"
            )
        reserve_prohibited_controls = (
            set(release_control_domain_ids)
            | set(self.graph_owner.control_domain_ids)
            | set(self.recovery_beneficiary.control_domain_ids)
            | set(self.timeout_cpfp_beneficiary.control_domain_ids)
        )
        if any(
            reserve_prohibited_controls.intersection(descriptor.control_domain_ids)
            for descriptor in reserve_descriptors
        ):
            raise TimeoutEconomicsError(
                "counterproof reserve controls must be independent of release, owner, recovery, and timeout controls"
            )
        counterproof_anchor_value = _bounded_sat(
            self.counterproof_ack_cpfp_anchor_value_sat,
            label="counterproof/ACK CPFP anchor value",
        )
        anchor_value = _bounded_sat(
            self.timeout_cpfp_anchor_value_sat,
            label="timeout CPFP anchor value",
        )
        abandoned = _bounded_sat(
            self.maximum_abandoned_counterproof_sat,
            label="maximum abandoned counterproof reserve",
            allow_zero=True,
        )
        object.__setattr__(
            self,
            "release_control_domain_ids",
            release_control_domain_ids,
        )
        object.__setattr__(
            self,
            "counterproof_ack_cpfp_anchor_value_sat",
            counterproof_anchor_value,
        )
        object.__setattr__(
            self,
            "timeout_cpfp_anchor_value_sat",
            anchor_value,
        )
        object.__setattr__(
            self,
            "maximum_abandoned_counterproof_sat",
            abandoned,
        )

    def assess(self) -> TimeoutSafetyAssessmentV1:
        """Inspect the finite abstract graph and return a fail-closed result."""

        structural: list[TimeoutSafetyBlockerV1] = []

        def block(reason: TimeoutSafetyBlockerV1) -> None:
            if reason not in structural:
                structural.append(reason)

        funding_by_id: dict[bytes, PlannedOutpointV1] = {}
        for outpoint in self.funding_outpoints:
            if outpoint.outpoint_id in funding_by_id:
                block(TimeoutSafetyBlockerV1.UNKNOWN_OR_DUPLICATE_OUTPOINT)
            funding_by_id[outpoint.outpoint_id] = outpoint

        all_outpoints = dict(funding_by_id)
        for transaction in self.transactions:
            for output in transaction.outputs:
                if output.outpoint_id in all_outpoints:
                    block(TimeoutSafetyBlockerV1.UNKNOWN_OR_DUPLICATE_OUTPOINT)
                all_outpoints[output.outpoint_id] = output

        for transaction in self.transactions:
            try:
                inputs = tuple(
                    all_outpoints[input_id] for input_id in transaction.input_ids
                )
            except KeyError:
                block(TimeoutSafetyBlockerV1.UNKNOWN_OR_DUPLICATE_OUTPOINT)
                continue
            input_value = sum(outpoint.value_sat for outpoint in inputs)
            output_value = sum(output.value_sat for output in transaction.outputs)
            if (
                input_value > _MAX_MONEY_SAT
                or output_value > _MAX_MONEY_SAT
                or input_value != output_value + transaction.fee_sat
            ):
                block(TimeoutSafetyBlockerV1.VALUE_NOT_CONSERVED)

        resources_by_role: dict[OutpointRoleV1, list[PlannedOutpointV1]] = {}
        for outpoint in self.funding_outpoints:
            resources_by_role.setdefault(outpoint.role, []).append(outpoint)

        allowed_funding_roles = {
            OutpointRoleV1.DEPOSIT,
            OutpointRoleV1.CLAIM_PAYOUT,
            OutpointRoleV1.CONTEST_PAYOUT,
            OutpointRoleV1.CONTEST_SLASH,
            OutpointRoleV1.STAKE,
            OutpointRoleV1.COUNTERPROOF_INPUT,
        }
        if any(
            outpoint.role not in allowed_funding_roles
            for outpoint in self.funding_outpoints
        ):
            block(TimeoutSafetyBlockerV1.MALFORMED_RESOURCE_ROSTER)

        singleton_roles = (
            OutpointRoleV1.DEPOSIT,
            OutpointRoleV1.CLAIM_PAYOUT,
            OutpointRoleV1.CONTEST_PAYOUT,
            OutpointRoleV1.CONTEST_SLASH,
            OutpointRoleV1.STAKE,
        )
        if any(len(resources_by_role.get(role, ())) != 1 for role in singleton_roles):
            block(TimeoutSafetyBlockerV1.MALFORMED_RESOURCE_ROSTER)

        counterproof_inputs = resources_by_role.get(
            OutpointRoleV1.COUNTERPROOF_INPUT,
            [],
        )
        counterproof_inputs_ordered = tuple(
            sorted(
                counterproof_inputs,
                key=lambda outpoint: (
                    -1 if outpoint.alternative_id is None else outpoint.alternative_id
                ),
            )
        )
        alternatives = tuple(
            sorted(outpoint.alternative_id for outpoint in counterproof_inputs)
        )
        if (
            not alternatives
            or alternatives != tuple(range(len(alternatives)))
            or any(alternative is None for alternative in alternatives)
            or len(set(alternatives)) != len(alternatives)
            or len(self.counterproof_ack_cpfp_beneficiaries) != len(alternatives)
        ):
            block(TimeoutSafetyBlockerV1.MALFORMED_RESOURCE_ROSTER)

        transactions_by_role: dict[
            TransactionRoleV1,
            list[TransactionTemplateV1],
        ] = {}
        for transaction in self.transactions:
            transactions_by_role.setdefault(transaction.role, []).append(transaction)

        owner_transactions = transactions_by_role.get(
            TransactionRoleV1.OWNER_PAYOUT,
            [],
        )
        if len(owner_transactions) != 1:
            block(TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER)

        def singleton(role: OutpointRoleV1) -> PlannedOutpointV1 | None:
            values = resources_by_role.get(role, ())
            return values[0] if len(values) == 1 else None

        deposit = singleton(OutpointRoleV1.DEPOSIT)
        claim_payout = singleton(OutpointRoleV1.CLAIM_PAYOUT)
        contest_payout = singleton(OutpointRoleV1.CONTEST_PAYOUT)
        contest_slash = singleton(OutpointRoleV1.CONTEST_SLASH)
        stake = singleton(OutpointRoleV1.STAKE)
        atomic_reserve_recovery_valid = True

        if (
            deposit is not None
            and deposit.beneficiary_id != self.recovery_beneficiary.principal_id
        ):
            block(TimeoutSafetyBlockerV1.COUNTERPROOF_RECOVERY_BENEFICIARY_MISMATCH)

        if contest_payout is not None and len(owner_transactions) == 1:
            expected_owner_inputs = tuple(
                outpoint.outpoint_id
                for outpoint in (deposit, claim_payout, contest_payout, contest_slash)
                if outpoint is not None
            ) + tuple(outpoint.outpoint_id for outpoint in counterproof_inputs_ordered)
            if owner_transactions[0].input_ids != expected_owner_inputs:
                atomic_reserve_recovery_valid = False
                block(
                    TimeoutSafetyBlockerV1.OWNER_PAYOUT_NOT_GATED_BY_SHARED_CONTEST_PAYOUT
                )
            owner_outputs = owner_transactions[0].outputs
            expected_owner_reserve_outputs = tuple(
                (
                    OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN,
                    counterproof_input.value_sat,
                    alternative,
                    self.counterproof_reserve_beneficiaries[alternative].principal_id,
                    self.counterproof_reserve_beneficiaries[alternative].script_pubkey,
                )
                for alternative, counterproof_input in enumerate(
                    counterproof_inputs_ordered
                )
            )
            actual_owner_outputs = tuple(
                (
                    output.role,
                    output.value_sat,
                    output.alternative_id,
                    output.beneficiary_id,
                    output.script_pubkey,
                )
                for output in owner_outputs
            )
            owner_output_matches = (
                bool(owner_outputs)
                and owner_outputs[0].role is OutpointRoleV1.BENEFICIARY
                and owner_outputs[0].beneficiary_id == self.graph_owner.principal_id
                and owner_outputs[0].script_pubkey == self.graph_owner.script_pubkey
                and owner_outputs[0].alternative_id is None
            )
            if (
                not owner_output_matches
                or actual_owner_outputs[1:] != expected_owner_reserve_outputs
            ):
                atomic_reserve_recovery_valid = False
                block(TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER)

        counterproof_by_alternative = self._transactions_by_alternative(
            TransactionRoleV1.COUNTERPROOF,
            block,
        )
        ack_by_alternative = self._transactions_by_alternative(
            TransactionRoleV1.ACK,
            block,
        )
        timeout_by_alternative = self._transactions_by_alternative(
            TransactionRoleV1.TIMEOUT_SETTLEMENT,
            block,
        )
        slash_by_alternative = self._transactions_by_alternative(
            TransactionRoleV1.SLASH,
            block,
        )
        expected_alternatives = set(alternatives)
        if (
            set(counterproof_by_alternative) != expected_alternatives
            or set(ack_by_alternative) != expected_alternatives
            or set(timeout_by_alternative) != expected_alternatives
            or set(slash_by_alternative) != expected_alternatives
        ):
            block(TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER)

        counterproof_input_by_alternative = {
            outpoint.alternative_id: outpoint for outpoint in counterproof_inputs
        }
        resolution_by_alternative: dict[int, PlannedOutpointV1] = {}
        for alternative in expected_alternatives:
            counterproof = counterproof_by_alternative.get(alternative)
            counterproof_input = counterproof_input_by_alternative.get(alternative)
            if (
                counterproof is None
                or counterproof_input is None
                or contest_payout is None
                or deposit is None
            ):
                continue
            expected_counterproof_inputs = tuple(
                outpoint.outpoint_id for outpoint in counterproof_inputs_ordered
            ) + (
                contest_payout.outpoint_id,
                deposit.outpoint_id,
            )
            if counterproof.input_ids != expected_counterproof_inputs:
                atomic_reserve_recovery_valid = False
                block(TimeoutSafetyBlockerV1.COUNTERPROOFS_NOT_MUTUALLY_EXCLUSIVE)
            resolutions = tuple(
                output
                for output in counterproof.outputs
                if output.role is OutpointRoleV1.RESOLUTION
            )
            anchors = tuple(
                output
                for output in counterproof.outputs
                if output.role is OutpointRoleV1.CPFP_ANCHOR
            )
            recovery_outputs = tuple(
                output
                for output in counterproof.outputs
                if output.role is OutpointRoleV1.PROTECTED_RECOVERY
            )
            reserve_outputs = tuple(
                output
                for output in counterproof.outputs
                if output.role is OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN
            )
            counterproof_anchor_matches = (
                len(anchors) == 1
                and alternative < len(self.counterproof_ack_cpfp_beneficiaries)
                and self._matches_cpfp_descriptor(
                    anchors[0],
                    self.counterproof_ack_cpfp_beneficiaries[alternative],
                    self.counterproof_ack_cpfp_anchor_value_sat,
                )
            )
            if len(anchors) == 1 and not counterproof_anchor_matches:
                block(TimeoutSafetyBlockerV1.COUNTERPROOF_CPFP_DESCRIPTOR_MISMATCH)
            if (
                len(recovery_outputs) != 1
                or recovery_outputs[0].value_sat != deposit.value_sat
            ):
                block(
                    TimeoutSafetyBlockerV1.COUNTERPROOF_DOES_NOT_ALLOCATE_EXACT_DEPOSIT
                )
            elif (
                recovery_outputs[0].beneficiary_id
                != self.recovery_beneficiary.principal_id
                or recovery_outputs[0].script_pubkey
                != self.recovery_beneficiary.script_pubkey
            ):
                block(TimeoutSafetyBlockerV1.COUNTERPROOF_RECOVERY_BENEFICIARY_MISMATCH)
            expected_reserve_outputs = tuple(
                (
                    OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN,
                    candidate.value_sat,
                    candidate_alternative,
                    self.counterproof_reserve_beneficiaries[
                        candidate_alternative
                    ].principal_id,
                    self.counterproof_reserve_beneficiaries[
                        candidate_alternative
                    ].script_pubkey,
                )
                for candidate_alternative, candidate in enumerate(
                    counterproof_inputs_ordered
                )
                if candidate_alternative != alternative
            )
            actual_reserve_outputs = tuple(
                (
                    output.role,
                    output.value_sat,
                    output.alternative_id,
                    output.beneficiary_id,
                    output.script_pubkey,
                )
                for output in reserve_outputs
            )
            if actual_reserve_outputs != expected_reserve_outputs:
                atomic_reserve_recovery_valid = False
                block(TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER)
            expected_output_roles = (
                OutpointRoleV1.PROTECTED_RECOVERY,
                OutpointRoleV1.RESOLUTION,
                OutpointRoleV1.CPFP_ANCHOR,
            ) + tuple(
                OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN
                for _ in expected_reserve_outputs
            )
            if tuple(output.role for output in counterproof.outputs) != (
                expected_output_roles
            ):
                atomic_reserve_recovery_valid = False
                block(TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER)
            if (
                len(resolutions) != 1
                or resolutions[0].alternative_id != alternative
                or resolutions[0].value_sat
                != self.resolution_connector_policy.value_sat
                or resolutions[0].script_pubkey
                != self.resolution_connector_policy.script_pubkey
                or resolutions[0].beneficiary_id is not None
                or len(anchors) != 1
                or len(recovery_outputs) != 1
                or not counterproof_anchor_matches
                or any(
                    output.alternative_id != alternative
                    for output in (
                        *resolutions,
                        *anchors,
                        *recovery_outputs,
                    )
                )
                or any(
                    output.role
                    not in {
                        OutpointRoleV1.RESOLUTION,
                        OutpointRoleV1.PROTECTED_RECOVERY,
                        OutpointRoleV1.COUNTERPROOF_RESERVE_RETURN,
                        OutpointRoleV1.CPFP_ANCHOR,
                    }
                    for output in counterproof.outputs
                )
            ):
                block(
                    TimeoutSafetyBlockerV1.COUNTERPROOF_DOES_NOT_CREATE_UNIQUE_RESOLUTION
                )
                if len(resolutions) == 1 and (
                    resolutions[0].value_sat
                    != self.resolution_connector_policy.value_sat
                    or resolutions[0].script_pubkey
                    != self.resolution_connector_policy.script_pubkey
                    or resolutions[0].beneficiary_id is not None
                ):
                    block(TimeoutSafetyBlockerV1.RESOLUTION_CONNECTOR_MISMATCH)
                continue
            resolution_by_alternative[alternative] = resolutions[0]

        if contest_payout is not None and any(
            contest_payout.outpoint_id not in transaction.input_ids
            for transaction in counterproof_by_alternative.values()
        ):
            atomic_reserve_recovery_valid = False
            block(TimeoutSafetyBlockerV1.COUNTERPROOFS_NOT_MUTUALLY_EXCLUSIVE)

        for alternative in expected_alternatives:
            resolution = resolution_by_alternative.get(alternative)
            ack = ack_by_alternative.get(alternative)
            timeout = timeout_by_alternative.get(alternative)
            slash = slash_by_alternative.get(alternative)
            if resolution is None or ack is None or timeout is None or slash is None:
                continue
            if claim_payout is None or contest_slash is None or stake is None:
                continue
            if set(ack.input_ids) != {resolution.outpoint_id}:
                block(TimeoutSafetyBlockerV1.ACK_AND_TIMEOUT_DO_NOT_CONFLICT)

            slash_authorizations = tuple(
                output
                for output in ack.outputs
                if output.role is OutpointRoleV1.SLASH_AUTHORIZATION
            )
            ack_anchors = tuple(
                output
                for output in ack.outputs
                if output.role is OutpointRoleV1.CPFP_ANCHOR
            )
            ack_anchor_matches = (
                len(ack_anchors) == 1
                and alternative < len(self.counterproof_ack_cpfp_beneficiaries)
                and self._matches_cpfp_descriptor(
                    ack_anchors[0],
                    self.counterproof_ack_cpfp_beneficiaries[alternative],
                    self.counterproof_ack_cpfp_anchor_value_sat,
                )
            )
            if not ack_anchor_matches:
                block(TimeoutSafetyBlockerV1.ACK_CPFP_DESCRIPTOR_MISMATCH)
            slash_authorization_matches = (
                len(slash_authorizations) == 1
                and slash_authorizations[0].value_sat
                == self.slash_authorization_policy.value_sat
                and slash_authorizations[0].script_pubkey
                == self.slash_authorization_policy.script_pubkey
                and slash_authorizations[0].beneficiary_id is None
            )
            if not slash_authorization_matches:
                block(TimeoutSafetyBlockerV1.ACK_DOES_NOT_CREATE_SLASH_AUTHORIZATION)
            if (
                len(ack.outputs) != 2
                or len(slash_authorizations) != 1
                or len(ack_anchors) != 1
                or not ack_anchor_matches
                or not slash_authorization_matches
                or any(output.alternative_id != alternative for output in ack.outputs)
            ):
                block(TimeoutSafetyBlockerV1.ACK_OUTPUT_ROSTER_MISMATCH)

            expected_timeout_inputs = {
                resolution.outpoint_id,
                contest_slash.outpoint_id,
            }
            if claim_payout.outpoint_id in timeout.input_ids:
                block(TimeoutSafetyBlockerV1.CLAIM_PAYOUT_BURN_CAN_BLOCK_TIMEOUT)
            if set(timeout.input_ids) != expected_timeout_inputs:
                block(TimeoutSafetyBlockerV1.ACK_AND_TIMEOUT_DO_NOT_CONFLICT)
                block(TimeoutSafetyBlockerV1.TIMEOUT_AND_SLASH_DO_NOT_CONFLICT)

            cpfp_outputs = tuple(
                output
                for output in timeout.outputs
                if output.role is OutpointRoleV1.CPFP_ANCHOR
            )
            recovery_change_outputs = tuple(
                output
                for output in timeout.outputs
                if output.role is OutpointRoleV1.PROTECTED_RECOVERY
            )
            recovery_change_matches = len(recovery_change_outputs) <= 1 and all(
                output.beneficiary_id == self.recovery_beneficiary.principal_id
                and output.script_pubkey == self.recovery_beneficiary.script_pubkey
                for output in recovery_change_outputs
            )
            if (
                len(timeout.outputs) not in {1, 2}
                or len(cpfp_outputs) != 1
                or not recovery_change_matches
                or not self._matches_cpfp_descriptor(
                    cpfp_outputs[0],
                    self.timeout_cpfp_beneficiary,
                    self.timeout_cpfp_anchor_value_sat,
                )
                or any(
                    output.alternative_id != alternative for output in timeout.outputs
                )
                or any(
                    output.role
                    not in {
                        OutpointRoleV1.CPFP_ANCHOR,
                        OutpointRoleV1.PROTECTED_RECOVERY,
                    }
                    for output in timeout.outputs
                )
            ):
                block(TimeoutSafetyBlockerV1.TIMEOUT_OUTPUT_ROSTER_MISMATCH)
            if len(cpfp_outputs) == 1 and not self._matches_cpfp_descriptor(
                cpfp_outputs[0],
                self.timeout_cpfp_beneficiary,
                self.timeout_cpfp_anchor_value_sat,
            ):
                block(TimeoutSafetyBlockerV1.TIMEOUT_CPFP_DESCRIPTOR_MISMATCH)

            if slash_authorization_matches:
                expected_slash_inputs = {
                    slash_authorizations[0].outpoint_id,
                    contest_slash.outpoint_id,
                    stake.outpoint_id,
                }
                if set(slash.input_ids) != expected_slash_inputs:
                    block(TimeoutSafetyBlockerV1.SLASH_NOT_GATED_BY_ACK)
                    block(TimeoutSafetyBlockerV1.TIMEOUT_AND_SLASH_DO_NOT_CONFLICT)
                if alternative >= len(self.slash_output_policies):
                    block(TimeoutSafetyBlockerV1.SLASH_OUTPUT_ROSTER_MISMATCH)
                else:
                    expected_slash_outputs = (
                        (
                            OutpointRoleV1.PROTOCOL_HEADER,
                            0,
                            alternative,
                            None,
                            self.slash_header_policy.script_pubkey,
                        ),
                    ) + tuple(
                        (
                            OutpointRoleV1.BENEFICIARY,
                            policy.value_sat,
                            alternative,
                            policy.beneficiary.principal_id,
                            policy.beneficiary.script_pubkey,
                        )
                        for policy in self.slash_output_policies[alternative]
                    )
                    actual_slash_outputs = tuple(
                        (
                            output.role,
                            output.value_sat,
                            output.alternative_id,
                            output.beneficiary_id,
                            output.script_pubkey,
                        )
                        for output in slash.outputs
                    )
                    if actual_slash_outputs != expected_slash_outputs:
                        block(TimeoutSafetyBlockerV1.SLASH_OUTPUT_ROSTER_MISMATCH)

        if len(self.slash_output_policies) != len(expected_alternatives):
            block(TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER)

        counterproof_values = [outpoint.value_sat for outpoint in counterproof_inputs]
        worst_case_unused = (
            0 if atomic_reserve_recovery_valid else sum(counterproof_values)
        )
        if worst_case_unused > self.maximum_abandoned_counterproof_sat:
            block(TimeoutSafetyBlockerV1.UNUSED_COUNTERPROOF_RESERVE_EXCEEDS_POLICY)

        structural_blockers = tuple(structural)
        funding_only = (
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
        funding_blockers = structural_blockers + tuple(
            blocker for blocker in funding_only if blocker not in structural_blockers
        )
        return TimeoutSafetyAssessmentV1(
            structural_blockers=structural_blockers,
            funding_blockers=funding_blockers,
            counterproof_selection_allocates_exact_deposit=not structural_blockers,
            universal_funds_safety_established=False,
            funding_eligible=False,
            worst_case_unused_counterproof_sat=worst_case_unused,
            timeout_cpfp_anchor_value_sat=self.timeout_cpfp_anchor_value_sat,
        )

    def analyze_terminal_protection(
        self,
        policy: TerminalProtectionPolicyV1,
    ) -> TerminalProtectionResultV1:
        """Enumerate maximal local traces and evaluate a declared value policy.

        This method considers only the templates in this abstract plan. It does
        not model external conflicting transactions, miner policy, reorgs,
        descriptor possession, authoritative baselines or allowances, or
        Script execution. A satisfied declaration is only an engine result,
        never a protected-value theorem or funding authority.
        """

        if not isinstance(policy, TerminalProtectionPolicyV1):
            raise TimeoutEconomicsError(
                "terminal analysis requires TerminalProtectionPolicyV1"
            )

        assessment = self.assess()
        alternatives = tuple(
            sorted(
                outpoint.alternative_id
                for outpoint in self.funding_outpoints
                if outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
                and outpoint.alternative_id is not None
            )
        )
        semantic_world_count = 1 + 3 * len(alternatives)
        if assessment.structural_blockers:
            return TerminalProtectionInfeasibleV1(
                traces=(),
                world_traces=(),
                semantic_world_count=semantic_world_count,
                policy_digest=policy.policy_digest,
                witnesses=(
                    TerminalStructuralWitnessV1(
                        blockers=assessment.structural_blockers,
                    ),
                ),
            )

        traces = self._enumerate_terminal_traces()
        witnesses: list[TerminalInfeasibilityWitnessV1] = []
        expected_trace_keys = {
            (TerminalBranchV1.OWNER_PAYOUT, None),
            *(
                (branch, alternative)
                for alternative in alternatives
                for branch in (
                    TerminalBranchV1.ACK_SLASH,
                    TerminalBranchV1.TIMEOUT,
                )
            ),
        }
        actual_trace_keys = {(trace.branch, trace.alternative_id) for trace in traces}
        expected_trace_count = 1 + 2 * len(alternatives)
        if (
            len(traces) != expected_trace_count
            or actual_trace_keys != expected_trace_keys
        ):
            witnesses.append(
                TerminalTraceRosterWitnessV1(
                    expected_trace_count=expected_trace_count,
                    actual_trace_count=len(traces),
                    trace_ids=tuple(trace.trace_id for trace in traces),
                )
            )

        traces_by_key = {
            (trace.branch, trace.alternative_id): trace for trace in traces
        }
        expected_world_keys = {
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
        world_traces = ()
        if actual_trace_keys == expected_trace_keys:
            world_traces = tuple(
                TerminalWorldTraceV1(
                    world=world,
                    alternative_id=alternative,
                    trace_id=traces_by_key[
                        (self._terminal_branch_for_world(world), alternative)
                    ].trace_id,
                )
                for world, alternative in sorted(
                    expected_world_keys,
                    key=lambda key: self._terminal_world_key(*key),
                )
            )

        funding_by_id = {
            outpoint.outpoint_id: outpoint for outpoint in self.funding_outpoints
        }
        all_outpoints = dict(funding_by_id)
        for transaction in self.transactions:
            all_outpoints.update(
                (output.outpoint_id, output) for output in transaction.outputs
            )

        positive_terminal_ids = {
            outpoint_id
            for trace in traces
            for outpoint_id in trace.terminal_outpoint_ids
            if all_outpoints[outpoint_id].value_sat > 0
        }
        expected_generated_terminal_ids = positive_terminal_ids - set(funding_by_id)
        funding_bindings = {
            binding.outpoint_id: binding for binding in policy.funding_principals
        }
        output_dispositions = {
            disposition.outpoint_id: disposition
            for disposition in policy.output_dispositions
        }
        world_policies = {
            (world.world, world.alternative_id): world
            for world in policy.world_policies
        }
        missing_funding_ids = tuple(sorted(set(funding_by_id) - set(funding_bindings)))
        extra_funding_ids = tuple(sorted(set(funding_bindings) - set(funding_by_id)))
        missing_output_ids = tuple(
            sorted(expected_generated_terminal_ids - set(output_dispositions))
        )
        extra_output_ids = tuple(
            sorted(set(output_dispositions) - expected_generated_terminal_ids)
        )
        missing_world_keys = tuple(
            sorted(
                self._terminal_world_key(world, alternative)
                for world, alternative in expected_world_keys - set(world_policies)
            )
        )
        extra_world_keys = tuple(
            sorted(
                self._terminal_world_key(world, alternative)
                for world, alternative in set(world_policies) - expected_world_keys
            )
        )
        if any(
            (
                missing_funding_ids,
                extra_funding_ids,
                missing_output_ids,
                extra_output_ids,
                missing_world_keys,
                extra_world_keys,
            )
        ):
            witnesses.append(
                TerminalPolicyRosterWitnessV1(
                    missing_funding_ids=missing_funding_ids,
                    extra_funding_ids=extra_funding_ids,
                    missing_output_ids=missing_output_ids,
                    extra_output_ids=extra_output_ids,
                    missing_world_keys=missing_world_keys,
                    extra_world_keys=extra_world_keys,
                )
            )

        for outpoint_id in sorted(expected_generated_terminal_ids):
            disposition = output_dispositions.get(outpoint_id)
            if disposition is None:
                continue
            outpoint = all_outpoints[outpoint_id]
            if disposition.preexisting_principal_sat > outpoint.value_sat:
                witnesses.append(
                    TerminalDispositionValueWitnessV1(
                        outpoint_id=outpoint_id,
                        outpoint_value_sat=outpoint.value_sat,
                        declared_preexisting_principal_sat=(
                            disposition.preexisting_principal_sat
                        ),
                    )
                )
            if (
                outpoint.beneficiary_id is not None
                and disposition.principal_id != outpoint.beneficiary_id
            ):
                witnesses.append(
                    TerminalDispositionBeneficiaryMismatchWitnessV1(
                        outpoint_id=outpoint_id,
                        committed_beneficiary_id=outpoint.beneficiary_id,
                        declared_principal_id=disposition.principal_id,
                    )
                )

        roster_failure = any(
            isinstance(
                witness,
                (TerminalTraceRosterWitnessV1, TerminalPolicyRosterWitnessV1),
            )
            for witness in witnesses
        )
        disposition_failure = any(
            isinstance(
                witness,
                (
                    TerminalDispositionValueWitnessV1,
                    TerminalDispositionBeneficiaryMismatchWitnessV1,
                ),
            )
            for witness in witnesses
        )
        if not roster_failure and not disposition_failure:
            trace_balances: dict[
                bytes,
                tuple[dict[bytes, int], dict[bytes, int]],
            ] = {}
            for trace in traces:
                wealth_by_principal: dict[bytes, int] = {}
                principal_by_principal: dict[bytes, int] = {}
                for outpoint_id in trace.terminal_outpoint_ids:
                    outpoint = all_outpoints[outpoint_id]
                    if outpoint.value_sat == 0:
                        continue
                    if outpoint_id in funding_by_id:
                        binding = funding_bindings[outpoint_id]
                        principal_id = binding.principal_id
                        preexisting_sat = outpoint.value_sat
                        spendable = binding.residual_spendable_by_horizon
                    else:
                        disposition = output_dispositions[outpoint_id]
                        principal_id = disposition.principal_id
                        preexisting_sat = disposition.preexisting_principal_sat
                        spendable = disposition.spendable_by_horizon
                    if not spendable:
                        witnesses.append(
                            LockedTerminalValueWitnessV1(
                                trace_id=trace.trace_id,
                                outpoint_id=outpoint_id,
                                principal_id=principal_id,
                                value_sat=outpoint.value_sat,
                            )
                        )
                        continue
                    wealth_by_principal[principal_id] = (
                        wealth_by_principal.get(principal_id, 0) + outpoint.value_sat
                    )
                    principal_by_principal[principal_id] = (
                        principal_by_principal.get(principal_id, 0) + preexisting_sat
                    )
                trace_balances[trace.trace_id] = (
                    wealth_by_principal,
                    principal_by_principal,
                )

            for world_key in sorted(
                expected_world_keys,
                key=lambda key: self._terminal_world_key(*key),
            ):
                world, alternative = world_key
                world_policy = world_policies[world_key]
                branch = self._terminal_branch_for_world(world)
                trace = traces_by_key[(branch, alternative)]
                wealth_by_principal, principal_by_principal = trace_balances[
                    trace.trace_id
                ]
                shortfalls = tuple(
                    PrincipalShortfallV1(
                        principal_id=baseline.principal_id,
                        baseline_sat=baseline.preexisting_principal_sat,
                        actual_sat=principal_by_principal.get(
                            baseline.principal_id,
                            0,
                        ),
                    )
                    for baseline in world_policy.protected_baselines
                    if principal_by_principal.get(baseline.principal_id, 0)
                    < baseline.preexisting_principal_sat
                )
                aggregate_loss = sum(
                    shortfall.baseline_sat - shortfall.actual_sat
                    for shortfall in shortfalls
                )
                if aggregate_loss > world_policy.explicit_fee_and_delay_allowance_sat:
                    witnesses.append(
                        ProtectedValueDeficitWitnessV1(
                            world=world,
                            alternative_id=alternative,
                            trace_id=trace.trace_id,
                            shortfalls=shortfalls,
                            aggregate_loss_sat=aggregate_loss,
                            allowed_loss_sat=(
                                world_policy.explicit_fee_and_delay_allowance_sat
                            ),
                        )
                    )

                if world_policy.timeout_coalition_principal_ids:
                    baselines_by_principal = {
                        baseline.principal_id: baseline
                        for baseline in world_policy.protected_baselines
                    }
                    actual_coalition_wealth = sum(
                        wealth_by_principal.get(principal_id, 0)
                        for principal_id in (
                            world_policy.timeout_coalition_principal_ids
                        )
                    )
                    baseline_coalition_wealth = sum(
                        baselines_by_principal[principal_id].wealth_sat
                        for principal_id in (
                            world_policy.timeout_coalition_principal_ids
                        )
                    )
                    actual_gain = actual_coalition_wealth - baseline_coalition_wealth
                    if actual_gain > world_policy.explicit_service_fee_sat:
                        witnesses.append(
                            TimeoutCoalitionExcessWitnessV1(
                                world=world,
                                alternative_id=alternative,
                                trace_id=trace.trace_id,
                                coalition_principal_ids=(
                                    world_policy.timeout_coalition_principal_ids
                                ),
                                actual_gain_sat=actual_gain,
                                allowed_gain_sat=world_policy.explicit_service_fee_sat,
                            )
                        )

        if witnesses:
            return TerminalProtectionInfeasibleV1(
                traces=traces,
                world_traces=world_traces,
                semantic_world_count=semantic_world_count,
                policy_digest=policy.policy_digest,
                witnesses=tuple(witnesses),
            )
        return AbstractDeclaredPolicySatisfiedV1(
            traces=traces,
            world_traces=world_traces,
            semantic_world_count=semantic_world_count,
            policy_digest=policy.policy_digest,
        )

    def _enumerate_terminal_traces(self) -> tuple[TerminalTraceV1, ...]:
        transactions = tuple(
            sorted(
                self.transactions,
                key=lambda transaction: (
                    transaction.role.value,
                    -1
                    if transaction.alternative_id is None
                    else transaction.alternative_id,
                    transaction.template_id,
                ),
            )
        )
        initial_live = {
            outpoint.outpoint_id: outpoint for outpoint in self.funding_outpoints
        }
        visited: set[tuple[tuple[bytes, ...], tuple[bytes, ...]]] = set()
        terminal_states: dict[
            tuple[tuple[bytes, ...], tuple[bytes, ...]],
            tuple[tuple[TransactionTemplateV1, ...], dict[bytes, PlannedOutpointV1]],
        ] = {}

        def walk(
            confirmed: tuple[TransactionTemplateV1, ...],
            live: dict[bytes, PlannedOutpointV1],
        ) -> None:
            confirmed_ids = {transaction.template_id for transaction in confirmed}
            state_key = (
                tuple(sorted(confirmed_ids)),
                tuple(sorted(live)),
            )
            if state_key in visited:
                return
            visited.add(state_key)
            enabled = tuple(
                transaction
                for transaction in transactions
                if transaction.template_id not in confirmed_ids
                and all(input_id in live for input_id in transaction.input_ids)
            )
            if not enabled:
                terminal_states[state_key] = (confirmed, live)
                return
            for transaction in enabled:
                next_live = dict(live)
                for input_id in transaction.input_ids:
                    del next_live[input_id]
                for output in transaction.outputs:
                    next_live[output.outpoint_id] = output
                walk((*confirmed, transaction), next_live)

        walk((), initial_live)
        traces = tuple(
            self._terminal_trace_from_state(confirmed, live)
            for confirmed, live in terminal_states.values()
        )
        return tuple(
            sorted(
                traces,
                key=lambda trace: (
                    trace.branch.value,
                    -1 if trace.alternative_id is None else trace.alternative_id,
                    trace.trace_id,
                ),
            )
        )

    @staticmethod
    def _terminal_trace_from_state(
        confirmed: tuple[TransactionTemplateV1, ...],
        live: dict[bytes, PlannedOutpointV1],
    ) -> TerminalTraceV1:
        owner = tuple(
            transaction
            for transaction in confirmed
            if transaction.role is TransactionRoleV1.OWNER_PAYOUT
        )
        counterproof = tuple(
            transaction
            for transaction in confirmed
            if transaction.role is TransactionRoleV1.COUNTERPROOF
        )
        ack = tuple(
            transaction
            for transaction in confirmed
            if transaction.role is TransactionRoleV1.ACK
        )
        timeout = tuple(
            transaction
            for transaction in confirmed
            if transaction.role is TransactionRoleV1.TIMEOUT_SETTLEMENT
        )
        slash = tuple(
            transaction
            for transaction in confirmed
            if transaction.role is TransactionRoleV1.SLASH
        )
        alternative_id: int | None = None
        canonical: tuple[TransactionTemplateV1, ...]
        if len(confirmed) == 1 and len(owner) == 1:
            branch = TerminalBranchV1.OWNER_PAYOUT
            canonical = owner
        elif (
            len(confirmed) == 2
            and len(counterproof) == 1
            and len(timeout) == 1
            and counterproof[0].alternative_id == timeout[0].alternative_id
        ):
            branch = TerminalBranchV1.TIMEOUT
            alternative_id = counterproof[0].alternative_id
            canonical = (counterproof[0], timeout[0])
        elif (
            len(confirmed) == 3
            and len(counterproof) == 1
            and len(ack) == 1
            and len(slash) == 1
            and counterproof[0].alternative_id
            == ack[0].alternative_id
            == slash[0].alternative_id
        ):
            branch = TerminalBranchV1.ACK_SLASH
            alternative_id = counterproof[0].alternative_id
            canonical = (counterproof[0], ack[0], slash[0])
        else:
            branch = TerminalBranchV1.UNEXPECTED
            canonical = tuple(
                sorted(confirmed, key=lambda transaction: transaction.template_id)
            )
        transaction_ids = tuple(transaction.template_id for transaction in canonical)
        trace_id = sha256(
            b"RankLock/v026/TerminalTraceV1\x00" + b"".join(transaction_ids)
        ).digest()
        return TerminalTraceV1(
            trace_id=trace_id,
            branch=branch,
            alternative_id=alternative_id,
            transaction_ids=transaction_ids,
            terminal_outpoint_ids=tuple(sorted(live)),
            cumulative_fee_sat=sum(transaction.fee_sat for transaction in canonical),
        )

    @staticmethod
    def _terminal_branch_for_world(world: TerminalWorldV1) -> TerminalBranchV1:
        if world is TerminalWorldV1.NO_COUNTERPROOF:
            return TerminalBranchV1.OWNER_PAYOUT
        if world is TerminalWorldV1.VALID_RELEASED:
            return TerminalBranchV1.ACK_SLASH
        return TerminalBranchV1.TIMEOUT

    @staticmethod
    def _terminal_world_key(
        world: TerminalWorldV1,
        alternative_id: int | None,
    ) -> str:
        suffix = "none" if alternative_id is None else str(alternative_id)
        return f"{world.value}:{suffix}"

    @staticmethod
    def _matches_cpfp_descriptor(
        output: PlannedOutpointV1,
        descriptor: BeneficiaryDescriptorV1,
        expected_value_sat: int,
    ) -> bool:
        return (
            output.role is OutpointRoleV1.CPFP_ANCHOR
            and output.value_sat == expected_value_sat
            and output.beneficiary_id == descriptor.principal_id
            and output.script_pubkey == descriptor.script_pubkey
        )

    def _transactions_by_alternative(
        self,
        role: TransactionRoleV1,
        block: Callable[[TimeoutSafetyBlockerV1], None],
    ) -> dict[int, TransactionTemplateV1]:
        by_alternative: dict[int, TransactionTemplateV1] = {}
        for transaction in self.transactions:
            if transaction.role is not role or transaction.alternative_id is None:
                continue
            if transaction.alternative_id in by_alternative:
                block(TimeoutSafetyBlockerV1.MALFORMED_TRANSACTION_ROSTER)
                continue
            by_alternative[transaction.alternative_id] = transaction
        return by_alternative


@dataclass(frozen=True, slots=True)
class EconomicPrincipalBindingV2:
    """Authority-bound identity for one mandatory economic principal."""

    principal_id: bytes
    role: EconomicPrincipalRoleV2
    authority_digest: bytes
    schema: str = "ranklock-v026-economic-principal-binding-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-economic-principal-binding-v2":
            raise TimeoutEconomicsError("unknown economic principal schema")
        if not isinstance(self.role, EconomicPrincipalRoleV2):
            raise TimeoutEconomicsError(
                "economic principal role must be EconomicPrincipalRoleV2"
            )
        object.__setattr__(
            self,
            "principal_id",
            _exact_bytes(self.principal_id, size=_ID_BYTES, label="principal id"),
        )
        object.__setattr__(
            self,
            "authority_digest",
            _exact_bytes(
                self.authority_digest,
                size=_ID_BYTES,
                label="principal authority digest",
            ),
        )


@dataclass(frozen=True, slots=True)
class FundingEndowmentBindingV2:
    """Exact initial ownership and value of one protocol or bond outpoint."""

    outpoint_id: bytes
    principal_id: bytes
    value_sat: int
    source: EndowmentSourceV2
    alternative_id: int | None = None
    schema: str = "ranklock-v026-funding-endowment-binding-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-funding-endowment-binding-v2":
            raise TimeoutEconomicsError("unknown funding endowment schema")
        if not isinstance(self.source, EndowmentSourceV2):
            raise TimeoutEconomicsError("endowment source must be EndowmentSourceV2")
        alternative_required = self.source is EndowmentSourceV2.COUNTERPROOF_BOND
        alternative_id = _alternative_id(
            self.alternative_id,
            required=alternative_required,
            label="funding endowment",
        )
        if not alternative_required and alternative_id is not None:
            raise TimeoutEconomicsError(
                "protocol funding endowment cannot name an alternative"
            )
        object.__setattr__(
            self,
            "outpoint_id",
            _exact_bytes(
                self.outpoint_id,
                size=_ID_BYTES,
                label="endowment outpoint id",
            ),
        )
        object.__setattr__(
            self,
            "principal_id",
            _exact_bytes(
                self.principal_id,
                size=_ID_BYTES,
                label="endowment principal id",
            ),
        )
        object.__setattr__(
            self,
            "value_sat",
            _bounded_sat(self.value_sat, label="endowment value"),
        )
        object.__setattr__(self, "alternative_id", alternative_id)


@dataclass(frozen=True, slots=True)
class WorldLiabilityV2:
    """One exact principal claim that applies in one canonical world."""

    liability_id: bytes
    world: TerminalWorldV1
    alternative_id: int | None
    debtor_principal_id: bytes
    creditor_principal_id: bytes
    principal_sat: int
    schema: str = "ranklock-v026-world-liability-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-world-liability-v2":
            raise TimeoutEconomicsError("unknown world liability schema")
        if not isinstance(self.world, TerminalWorldV1):
            raise TimeoutEconomicsError("liability world must be TerminalWorldV1")
        alternative_id = _alternative_id(
            self.alternative_id,
            required=self.world is not TerminalWorldV1.NO_COUNTERPROOF,
            label="world liability",
        )
        if self.world is TerminalWorldV1.NO_COUNTERPROOF and alternative_id is not None:
            raise TimeoutEconomicsError(
                "no-counterproof liability cannot name an alternative"
            )
        debtor = _exact_bytes(
            self.debtor_principal_id,
            size=_ID_BYTES,
            label="liability debtor id",
        )
        creditor = _exact_bytes(
            self.creditor_principal_id,
            size=_ID_BYTES,
            label="liability creditor id",
        )
        if debtor == creditor:
            raise TimeoutEconomicsError("liability debtor and creditor must differ")
        object.__setattr__(
            self,
            "liability_id",
            _exact_bytes(
                self.liability_id,
                size=_ID_BYTES,
                label="liability id",
            ),
        )
        object.__setattr__(self, "debtor_principal_id", debtor)
        object.__setattr__(self, "creditor_principal_id", creditor)
        object.__setattr__(
            self,
            "principal_sat",
            _bounded_sat(self.principal_sat, label="liability principal"),
        )
        object.__setattr__(self, "alternative_id", alternative_id)


@dataclass(frozen=True, slots=True)
class WorldPrincipalStatusV2:
    """Non-optional status and derived wealth baseline for one world/principal."""

    world: TerminalWorldV1
    alternative_id: int | None
    principal_id: bytes
    status: PrincipalStatusV2
    baseline_wealth_sat: int
    schema: str = "ranklock-v026-world-principal-status-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-world-principal-status-v2":
            raise TimeoutEconomicsError("unknown world principal status schema")
        if not isinstance(self.world, TerminalWorldV1):
            raise TimeoutEconomicsError("status world must be TerminalWorldV1")
        if not isinstance(self.status, PrincipalStatusV2):
            raise TimeoutEconomicsError("status must be PrincipalStatusV2")
        alternative_id = _alternative_id(
            self.alternative_id,
            required=self.world is not TerminalWorldV1.NO_COUNTERPROOF,
            label="world principal status",
        )
        if self.world is TerminalWorldV1.NO_COUNTERPROOF and alternative_id is not None:
            raise TimeoutEconomicsError(
                "no-counterproof status cannot name an alternative"
            )
        object.__setattr__(
            self,
            "principal_id",
            _exact_bytes(
                self.principal_id,
                size=_ID_BYTES,
                label="world status principal id",
            ),
        )
        object.__setattr__(
            self,
            "baseline_wealth_sat",
            _bounded_sat(
                self.baseline_wealth_sat,
                label="world baseline wealth",
                allow_zero=True,
            ),
        )
        object.__setattr__(self, "alternative_id", alternative_id)


@dataclass(frozen=True, slots=True)
class ServiceFeeChargeV2:
    """Authority-bound categorized cost; charge ids prevent double counting."""

    charge_id: bytes
    principal_id: bytes
    category: AllowanceCategoryV2
    amount_sat: int
    authority_digest: bytes
    schema: str = "ranklock-v026-service-fee-charge-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-service-fee-charge-v2":
            raise TimeoutEconomicsError("unknown service fee charge schema")
        if not isinstance(self.category, AllowanceCategoryV2):
            raise TimeoutEconomicsError(
                "service fee category must be AllowanceCategoryV2"
            )
        for attribute, label in (
            ("charge_id", "service fee charge id"),
            ("principal_id", "service fee principal id"),
            ("authority_digest", "service fee authority digest"),
        ):
            object.__setattr__(
                self,
                attribute,
                _exact_bytes(
                    getattr(self, attribute),
                    size=_ID_BYTES,
                    label=label,
                ),
            )
        object.__setattr__(
            self,
            "amount_sat",
            _bounded_sat(self.amount_sat, label="service fee amount"),
        )


@dataclass(frozen=True, slots=True)
class ServiceFeeScheduleV2:
    charges: tuple[ServiceFeeChargeV2, ...]
    authority_digest: bytes
    policy_digest: bytes = field(init=False)
    schema: str = "ranklock-v026-service-fee-schedule-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-service-fee-schedule-v2":
            raise TimeoutEconomicsError("unknown service fee schedule schema")
        if not isinstance(self.charges, tuple) or not all(
            isinstance(charge, ServiceFeeChargeV2) for charge in self.charges
        ):
            raise TimeoutEconomicsError(
                "service fee charges must be an immutable typed tuple"
            )
        charge_ids = tuple(charge.charge_id for charge in self.charges)
        if charge_ids != tuple(sorted(charge_ids)):
            raise TimeoutEconomicsError("service fee charges must be sorted")
        if len(set(charge_ids)) != len(charge_ids):
            raise TimeoutEconomicsError("service fee charge ids must be unique")
        object.__setattr__(
            self,
            "authority_digest",
            _exact_bytes(
                self.authority_digest,
                size=_ID_BYTES,
                label="service fee schedule authority digest",
            ),
        )
        object.__setattr__(
            self,
            "policy_digest",
            _content_digest_v2(self, excluded_fields={"policy_digest"}),
        )


@dataclass(frozen=True, slots=True)
class PrincipalWorldAllowanceV2:
    world: TerminalWorldV1
    alternative_id: int | None
    principal_id: bytes
    category: AllowanceCategoryV2
    amount_sat: int
    charge_ids: tuple[bytes, ...]
    authority_digest: bytes
    schema: str = "ranklock-v026-principal-world-allowance-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-principal-world-allowance-v2":
            raise TimeoutEconomicsError("unknown principal allowance schema")
        if not isinstance(self.world, TerminalWorldV1):
            raise TimeoutEconomicsError("allowance world must be TerminalWorldV1")
        if not isinstance(self.category, AllowanceCategoryV2):
            raise TimeoutEconomicsError("allowance category must be typed")
        alternative_id = _alternative_id(
            self.alternative_id,
            required=self.world is not TerminalWorldV1.NO_COUNTERPROOF,
            label="principal allowance",
        )
        if self.world is TerminalWorldV1.NO_COUNTERPROOF and alternative_id is not None:
            raise TimeoutEconomicsError(
                "no-counterproof allowance cannot name an alternative"
            )
        if not isinstance(self.charge_ids, tuple) or not self.charge_ids:
            raise TimeoutEconomicsError(
                "allowance charge ids must be a nonempty immutable tuple"
            )
        charge_ids = tuple(
            _exact_bytes(value, size=_ID_BYTES, label="allowance charge id")
            for value in self.charge_ids
        )
        if charge_ids != tuple(sorted(charge_ids)):
            raise TimeoutEconomicsError("allowance charge ids must be sorted")
        if len(set(charge_ids)) != len(charge_ids):
            raise TimeoutEconomicsError("allowance charge ids must be unique")
        object.__setattr__(self, "charge_ids", charge_ids)
        object.__setattr__(
            self,
            "principal_id",
            _exact_bytes(
                self.principal_id,
                size=_ID_BYTES,
                label="allowance principal id",
            ),
        )
        object.__setattr__(
            self,
            "amount_sat",
            _bounded_sat(self.amount_sat, label="allowance amount"),
        )
        object.__setattr__(
            self,
            "authority_digest",
            _exact_bytes(
                self.authority_digest,
                size=_ID_BYTES,
                label="allowance authority digest",
            ),
        )
        object.__setattr__(self, "alternative_id", alternative_id)


@dataclass(frozen=True, slots=True)
class ExecutionScheduleV2:
    horizon_blocks: int
    release_deadline_blocks: int
    ack_inclusion_blocks: int
    timeout_csv_blocks: int
    reorg_depth_blocks: int
    maximum_confirmation_blocks: int
    authority_digest: bytes
    policy_digest: bytes = field(init=False)
    schema: str = "ranklock-v026-execution-schedule-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-execution-schedule-v2":
            raise TimeoutEconomicsError("unknown execution schedule schema")
        for attribute in (
            "horizon_blocks",
            "release_deadline_blocks",
            "ack_inclusion_blocks",
            "timeout_csv_blocks",
            "reorg_depth_blocks",
            "maximum_confirmation_blocks",
        ):
            value = getattr(self, attribute)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TimeoutEconomicsError(
                    f"{attribute} must be a nonnegative integer, never a boolean"
                )
            if value > _MAX_ALTERNATIVE_ID:
                raise TimeoutEconomicsError(f"{attribute} exceeds u32")
        if self.horizon_blocks == 0:
            raise TimeoutEconomicsError("execution horizon must be positive")
        required_horizon = (
            self.release_deadline_blocks
            + self.ack_inclusion_blocks
            + self.timeout_csv_blocks
            + self.reorg_depth_blocks
            + self.maximum_confirmation_blocks
        )
        if self.horizon_blocks < required_horizon:
            raise TimeoutEconomicsError(
                "execution horizon does not cover the declared schedule"
            )
        object.__setattr__(
            self,
            "authority_digest",
            _exact_bytes(
                self.authority_digest,
                size=_ID_BYTES,
                label="execution schedule authority digest",
            ),
        )
        object.__setattr__(
            self,
            "policy_digest",
            _content_digest_v2(self, excluded_fields={"policy_digest"}),
        )


@dataclass(frozen=True, slots=True)
class AtomicBondReturnV2:
    selecting_alternative_id: int
    outpoint_id: bytes
    value_sat: int
    schema: str = "ranklock-v026-atomic-bond-return-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-atomic-bond-return-v2":
            raise TimeoutEconomicsError("unknown atomic bond return schema")
        object.__setattr__(
            self,
            "selecting_alternative_id",
            _alternative_id(
                self.selecting_alternative_id,
                required=True,
                label="atomic bond return",
            ),
        )
        object.__setattr__(
            self,
            "outpoint_id",
            _exact_bytes(
                self.outpoint_id,
                size=_ID_BYTES,
                label="atomic bond return outpoint id",
            ),
        )
        object.__setattr__(
            self,
            "value_sat",
            _bounded_sat(self.value_sat, label="atomic bond return value"),
        )


@dataclass(frozen=True, slots=True)
class CoverageReserveV2:
    """Atomic all-bond overlay bound to the V1 template identities.

    The overlay is accounting evidence, not a claim that V1 transaction bytes
    already contain these inputs and outputs. A future implementation may fuse
    this value into a counterprover-funded C_i only with identical provenance,
    owner/sibling returns, ACK refund, and Timeout compensation bindings.
    """

    alternative_id: int
    funding_outpoint_id: bytes
    provider_principal_id: bytes
    amount_sat: int
    owner_template_id: bytes
    owner_return_outpoint_id: bytes
    owner_return_value_sat: int
    counterproof_template_id: bytes
    sibling_returns: tuple[AtomicBondReturnV2, ...]
    resolution_outpoint_id: bytes
    base_resolution_value_sat: int
    bonded_resolution_value_sat: int
    ack_template_id: bytes
    ack_refund_outpoint_id: bytes
    ack_refund_value_sat: int
    timeout_template_id: bytes
    timeout_compensation_outpoint_id: bytes
    timeout_compensation_value_sat: int
    timeout_beneficiary_principal_id: bytes
    fusion_with_existing_counterproof_input_authorized: bool = field(
        default=False,
        init=False,
    )
    schema: str = "ranklock-v026-coverage-reserve-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-coverage-reserve-v2":
            raise TimeoutEconomicsError("unknown coverage reserve schema")
        object.__setattr__(
            self,
            "alternative_id",
            _alternative_id(
                self.alternative_id,
                required=True,
                label="coverage reserve",
            ),
        )
        for attribute, label in (
            ("funding_outpoint_id", "bond funding outpoint id"),
            ("provider_principal_id", "bond provider principal id"),
            ("owner_template_id", "bond owner template id"),
            ("owner_return_outpoint_id", "bond owner return outpoint id"),
            ("counterproof_template_id", "bond counterproof template id"),
            ("resolution_outpoint_id", "bond resolution outpoint id"),
            ("ack_template_id", "bond ACK template id"),
            ("ack_refund_outpoint_id", "bond ACK refund outpoint id"),
            ("timeout_template_id", "bond Timeout template id"),
            (
                "timeout_compensation_outpoint_id",
                "bond Timeout compensation outpoint id",
            ),
            (
                "timeout_beneficiary_principal_id",
                "bond Timeout beneficiary principal id",
            ),
        ):
            object.__setattr__(
                self,
                attribute,
                _exact_bytes(
                    getattr(self, attribute),
                    size=_ID_BYTES,
                    label=label,
                ),
            )
        object.__setattr__(
            self,
            "amount_sat",
            _bounded_sat(self.amount_sat, label="coverage reserve amount"),
        )
        for attribute, label in (
            ("owner_return_value_sat", "owner bond return value"),
            ("base_resolution_value_sat", "base resolution value"),
            ("bonded_resolution_value_sat", "bonded resolution value"),
            ("ack_refund_value_sat", "ACK bond refund value"),
            (
                "timeout_compensation_value_sat",
                "Timeout operator compensation value",
            ),
        ):
            object.__setattr__(
                self,
                attribute,
                _bounded_sat(getattr(self, attribute), label=label),
            )
        bonded_resolution_value = self.base_resolution_value_sat + self.amount_sat
        if bonded_resolution_value > _MAX_MONEY_SAT:
            raise TimeoutEconomicsError("bonded resolution exceeds MoneyRange")
        if self.bonded_resolution_value_sat != bonded_resolution_value:
            raise TimeoutEconomicsError(
                "bonded resolution must equal base resolution plus selected bond"
            )
        if any(
            value != self.amount_sat
            for value in (
                self.owner_return_value_sat,
                self.ack_refund_value_sat,
                self.timeout_compensation_value_sat,
            )
        ):
            raise TimeoutEconomicsError(
                "owner, ACK, and Timeout bond dispositions must equal the bond"
            )
        if not isinstance(self.sibling_returns, tuple) or not all(
            isinstance(binding, AtomicBondReturnV2) for binding in self.sibling_returns
        ):
            raise TimeoutEconomicsError(
                "sibling bond returns must be an immutable typed tuple"
            )
        selecting_ids = tuple(
            binding.selecting_alternative_id for binding in self.sibling_returns
        )
        if selecting_ids != tuple(sorted(selecting_ids)):
            raise TimeoutEconomicsError("sibling bond returns must be sorted")
        if len(set(selecting_ids)) != len(selecting_ids):
            raise TimeoutEconomicsError(
                "sibling bond selecting alternatives must be unique"
            )
        if any(
            binding.value_sat != self.amount_sat for binding in self.sibling_returns
        ):
            raise TimeoutEconomicsError(
                "every unselected sibling bond return must equal the bond"
            )


@dataclass(frozen=True, slots=True)
class ThresholdReleaseQualificationV2:
    participant_ids: tuple[bytes, ...]
    ack_template_ids: tuple[bytes, ...]
    n: int
    threshold: int
    maximum_corruptions: int
    exact_ack_conditional_signature_digest: bytes
    transcript_digest: bytes
    schedule_digest: bytes
    schema: str = "ranklock-v026-threshold-release-qualification-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-threshold-release-qualification-v2":
            raise TimeoutEconomicsError("unknown threshold qualification schema")
        for attribute, label in (
            ("participant_ids", "threshold participant ids"),
            ("ack_template_ids", "threshold ACK template ids"),
        ):
            values = getattr(self, attribute)
            if not isinstance(values, tuple) or not values:
                raise TimeoutEconomicsError(
                    f"{label} must be a nonempty immutable tuple"
                )
            normalized = tuple(
                _exact_bytes(value, size=_ID_BYTES, label=label) for value in values
            )
            if normalized != tuple(sorted(normalized)):
                raise TimeoutEconomicsError(f"{label} must be sorted")
            if len(set(normalized)) != len(normalized):
                raise TimeoutEconomicsError(f"{label} must be unique")
            object.__setattr__(self, attribute, normalized)
        for attribute in ("n", "threshold", "maximum_corruptions"):
            value = getattr(self, attribute)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TimeoutEconomicsError(f"threshold {attribute} must be an integer")
        if self.n != len(self.participant_ids):
            raise TimeoutEconomicsError(
                "threshold n must equal the participant roster length"
            )
        if not (
            0
            <= self.maximum_corruptions
            < self.threshold
            <= self.n - self.maximum_corruptions
        ):
            raise TimeoutEconomicsError(
                "threshold parameters must satisfy 0 <= f < t <= n-f"
            )
        for attribute, label in (
            (
                "exact_ack_conditional_signature_digest",
                "conditional ACK signature digest",
            ),
            ("transcript_digest", "threshold transcript digest"),
            ("schedule_digest", "threshold schedule digest"),
        ):
            object.__setattr__(
                self,
                attribute,
                _exact_bytes(
                    getattr(self, attribute),
                    size=_ID_BYTES,
                    label=label,
                ),
            )

    @property
    def valid_withheld_is_assumption_failure(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class TerminalWealthPolicyV2:
    principals: tuple[EconomicPrincipalBindingV2, ...]
    endowments: tuple[FundingEndowmentBindingV2, ...]
    liabilities: tuple[WorldLiabilityV2, ...]
    world_statuses: tuple[WorldPrincipalStatusV2, ...]
    allowances: tuple[PrincipalWorldAllowanceV2, ...]
    service_fee_schedule: ServiceFeeScheduleV2
    execution_schedule: ExecutionScheduleV2
    coverage_reserves: tuple[CoverageReserveV2, ...]
    threshold_qualification: ThresholdReleaseQualificationV2 | None
    policy_digest: bytes = field(init=False)
    schema: str = "ranklock-v026-terminal-wealth-policy-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-v026-terminal-wealth-policy-v2":
            raise TimeoutEconomicsError("unknown terminal wealth policy schema")
        typed_rosters = (
            ("principals", EconomicPrincipalBindingV2),
            ("endowments", FundingEndowmentBindingV2),
            ("liabilities", WorldLiabilityV2),
            ("world_statuses", WorldPrincipalStatusV2),
            ("allowances", PrincipalWorldAllowanceV2),
            ("coverage_reserves", CoverageReserveV2),
        )
        for attribute, expected_type in typed_rosters:
            values = getattr(self, attribute)
            if not isinstance(values, tuple) or not all(
                isinstance(value, expected_type) for value in values
            ):
                raise TimeoutEconomicsError(
                    f"{attribute} must be an immutable typed tuple"
                )
        ordered_keys = (
            (
                "principals",
                tuple(value.principal_id for value in self.principals),
            ),
            (
                "endowments",
                tuple(value.outpoint_id for value in self.endowments),
            ),
            (
                "liabilities",
                tuple(value.liability_id for value in self.liabilities),
            ),
            (
                "world_statuses",
                tuple(
                    (
                        value.world.value,
                        -1 if value.alternative_id is None else value.alternative_id,
                        value.principal_id,
                    )
                    for value in self.world_statuses
                ),
            ),
            (
                "allowances",
                tuple(
                    (
                        value.world.value,
                        -1 if value.alternative_id is None else value.alternative_id,
                        value.principal_id,
                    )
                    for value in self.allowances
                ),
            ),
            (
                "coverage_reserves",
                tuple(value.alternative_id for value in self.coverage_reserves),
            ),
        )
        for label, keys in ordered_keys:
            if keys != tuple(sorted(keys)):
                raise TimeoutEconomicsError(f"{label} must be canonically sorted")
            if len(set(keys)) != len(keys):
                raise TimeoutEconomicsError(f"{label} must contain unique keys")
        if not isinstance(self.service_fee_schedule, ServiceFeeScheduleV2):
            raise TimeoutEconomicsError("service fee schedule must be typed")
        if not isinstance(self.execution_schedule, ExecutionScheduleV2):
            raise TimeoutEconomicsError("execution schedule must be typed")
        if self.threshold_qualification is not None and not isinstance(
            self.threshold_qualification,
            ThresholdReleaseQualificationV2,
        ):
            raise TimeoutEconomicsError("threshold qualification must be typed")
        if (
            self.threshold_qualification is not None
            and self.threshold_qualification.schedule_digest
            != self.execution_schedule.policy_digest
        ):
            raise TimeoutEconomicsError(
                "threshold qualification must bind the execution schedule"
            )
        object.__setattr__(
            self,
            "policy_digest",
            _content_digest_v2(self, excluded_fields={"policy_digest"}),
        )


@dataclass(frozen=True, slots=True)
class CoveragePolicyWitnessV2:
    error: CoveragePolicyErrorV2
    detail_ids: tuple[bytes, ...] = ()
    schema: str = "ranklock-v026-coverage-policy-witness-v2"


@dataclass(frozen=True, slots=True)
class PrincipalCoverageDeficitWitnessV2:
    world: TerminalWorldV1
    alternative_id: int
    principal_id: bytes
    baseline_wealth_sat: int
    terminal_wealth_sat: int
    authorized_cost_sat: int
    principal_deficit_sat: int
    schema: str = "ranklock-v026-principal-coverage-deficit-witness-v2"


@dataclass(frozen=True, slots=True)
class CoverageReserveDeficitWitnessV2:
    world: TerminalWorldV1
    alternative_id: int
    creditor_principal_id: bytes
    liability_principal_sat: int
    authorized_cost_sat: int
    required_reserve_sat: int
    available_reserve_sat: int
    reserve_shortfall_sat: int
    schema: str = "ranklock-v026-coverage-reserve-deficit-witness-v2"


CoverageWitnessV2: TypeAlias = (
    CoveragePolicyWitnessV2
    | PrincipalCoverageDeficitWitnessV2
    | CoverageReserveDeficitWitnessV2
)


@dataclass(frozen=True, slots=True)
class DeclaredCoverageAdequateV2:
    policy_digest: bytes
    mandatory_principal_ids: tuple[bytes, ...]
    world_keys: tuple[str, ...]
    assumption_failure_world_keys: tuple[str, ...]
    coverage_adequacy_established: bool = field(default=True, init=False)
    protected_value_theorem_established: bool = field(default=False, init=False)
    funding_eligible: bool = field(default=False, init=False)
    qualification_blockers: tuple[CoverageQualificationBlockerV2, ...] = field(
        default=_COVERAGE_QUALIFICATION_BLOCKERS_V2,
        init=False,
    )
    evidence_class: str = "EXACT"
    evidence_scope: str = (
        "typed declared terminal-wealth and atomic bond coverage accounting only"
    )
    schema: str = "ranklock-v026-declared-coverage-adequate-v2"


@dataclass(frozen=True, slots=True)
class TerminalWealthCoverageInfeasibleV2:
    policy_digest: bytes
    mandatory_principal_ids: tuple[bytes, ...]
    world_keys: tuple[str, ...]
    assumption_failure_world_keys: tuple[str, ...]
    witnesses: tuple[CoverageWitnessV2, ...]
    coverage_adequacy_established: bool = field(default=False, init=False)
    protected_value_theorem_established: bool = field(default=False, init=False)
    funding_eligible: bool = field(default=False, init=False)
    qualification_blockers: tuple[CoverageQualificationBlockerV2, ...] = field(
        default=_COVERAGE_QUALIFICATION_BLOCKERS_V2,
        init=False,
    )
    evidence_class: str = "EXACT"
    evidence_scope: str = (
        "typed declared terminal-wealth and atomic bond coverage accounting only"
    )
    schema: str = "ranklock-v026-terminal-wealth-coverage-infeasible-v2"


TerminalWealthResultV2: TypeAlias = (
    DeclaredCoverageAdequateV2 | TerminalWealthCoverageInfeasibleV2
)


def _canonical_value_v2(
    value: object,
    *,
    excluded_fields: set[str] | None = None,
) -> object:
    excluded = set() if excluded_fields is None else excluded_fields
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {
            item.name: _canonical_value_v2(getattr(value, item.name))
            for item in fields(value)
            if item.name not in excluded
        }
    if isinstance(value, tuple):
        return [_canonical_value_v2(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise TimeoutEconomicsError(
        f"unsupported canonical V2 policy value {type(value).__name__}"
    )


def _content_digest_v2(
    value: object,
    *,
    excluded_fields: set[str],
) -> bytes:
    projection = _canonical_value_v2(value, excluded_fields=excluded_fields)
    encoded = (
        json.dumps(
            projection,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode("ascii")
    return sha256(encoded).digest()


def terminal_wealth_policy_projection_v2(
    policy: TerminalWealthPolicyV2,
) -> dict[str, object]:
    if not isinstance(policy, TerminalWealthPolicyV2):
        raise TimeoutEconomicsError(
            "terminal wealth projection requires TerminalWealthPolicyV2"
        )
    projection = _canonical_value_v2(
        policy,
        excluded_fields={"policy_digest"},
    )
    if not isinstance(projection, dict):
        raise TimeoutEconomicsError("terminal wealth projection must be a mapping")
    return projection


def service_fee_charge_id_v2(outpoint_id: bytes) -> bytes:
    return sha256(b"RankLock/v026/ServiceFeeChargeV2\x00" + outpoint_id).digest()


def analyze_terminal_wealth_v2(
    plan: SharedSelectionTimeoutPlanV1,
    policy: TerminalWealthPolicyV2,
) -> TerminalWealthResultV2:
    """Check complete natural-principal wealth and atomic bond coverage.

    This is deliberately side-by-side with V1. ``CoverageReserveV2`` binds an
    exact proposed all-bond topology to the V1 template identities, but does
    not mutate or pretend to serialize those transactions. Consequently even
    an adequate declared result remains funding-ineligible.
    """

    if not isinstance(plan, SharedSelectionTimeoutPlanV1):
        raise TimeoutEconomicsError(
            "terminal wealth analysis requires SharedSelectionTimeoutPlanV1"
        )
    if not isinstance(policy, TerminalWealthPolicyV2):
        raise TimeoutEconomicsError(
            "terminal wealth analysis requires TerminalWealthPolicyV2"
        )

    alternatives = tuple(
        sorted(
            outpoint.alternative_id
            for outpoint in plan.funding_outpoints
            if outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT
            and outpoint.alternative_id is not None
        )
    )
    expected_world_keys = {
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
    ordered_world_keys = tuple(
        sorted(
            (
                f"{world.value}:{'none' if alternative is None else alternative}"
                for world, alternative in expected_world_keys
            )
        )
    )
    witnesses: list[CoverageWitnessV2] = []

    def policy_error(
        error: CoveragePolicyErrorV2,
        detail_ids: tuple[bytes, ...] = (),
    ) -> None:
        witness = CoveragePolicyWitnessV2(
            error=error,
            detail_ids=tuple(sorted(detail_ids)),
        )
        if witness not in witnesses:
            witnesses.append(witness)

    assessment = plan.assess()
    if assessment.structural_blockers:
        policy_error(CoveragePolicyErrorV2.STRUCTURAL_PLAN_INVALID)

    deposit = next(
        (
            outpoint
            for outpoint in plan.funding_outpoints
            if outpoint.role is OutpointRoleV1.DEPOSIT
        ),
        None,
    )
    claim_payout = next(
        (
            outpoint
            for outpoint in plan.funding_outpoints
            if outpoint.role is OutpointRoleV1.CLAIM_PAYOUT
        ),
        None,
    )
    contest_payout = next(
        (
            outpoint
            for outpoint in plan.funding_outpoints
            if outpoint.role is OutpointRoleV1.CONTEST_PAYOUT
        ),
        None,
    )
    contest_slash = next(
        (
            outpoint
            for outpoint in plan.funding_outpoints
            if outpoint.role is OutpointRoleV1.CONTEST_SLASH
        ),
        None,
    )
    stake = next(
        (
            outpoint
            for outpoint in plan.funding_outpoints
            if outpoint.role is OutpointRoleV1.STAKE
        ),
        None,
    )
    if any(
        value is None
        for value in (deposit, claim_payout, contest_payout, contest_slash, stake)
    ):
        policy_error(CoveragePolicyErrorV2.STRUCTURAL_PLAN_INVALID)
    if deposit is None or contest_payout is None or contest_slash is None:
        return TerminalWealthCoverageInfeasibleV2(
            policy_digest=policy.policy_digest,
            mandatory_principal_ids=(),
            world_keys=ordered_world_keys,
            assumption_failure_world_keys=(),
            witnesses=tuple(witnesses),
        )

    expected_endowments: dict[
        bytes,
        tuple[bytes, int, EndowmentSourceV2, int | None],
    ] = {}
    for outpoint in plan.funding_outpoints:
        if outpoint.role is OutpointRoleV1.DEPOSIT:
            principal_id = plan.recovery_beneficiary.principal_id
        elif outpoint.role is OutpointRoleV1.COUNTERPROOF_INPUT:
            alternative = outpoint.alternative_id
            if alternative is None or alternative >= len(
                plan.counterproof_reserve_beneficiaries
            ):
                policy_error(CoveragePolicyErrorV2.STRUCTURAL_PLAN_INVALID)
                continue
            principal_id = plan.counterproof_reserve_beneficiaries[
                alternative
            ].principal_id
        else:
            principal_id = plan.graph_owner.principal_id
        expected_endowments[outpoint.outpoint_id] = (
            principal_id,
            outpoint.value_sat,
            EndowmentSourceV2.PROTOCOL_FUNDING,
            None,
        )

    reserves_by_alternative: dict[int, CoverageReserveV2] = {}
    for reserve in policy.coverage_reserves:
        if reserve.alternative_id in reserves_by_alternative:
            policy_error(
                CoveragePolicyErrorV2.COLLATERAL_REUSE,
                (reserve.funding_outpoint_id,),
            )
            continue
        reserves_by_alternative[reserve.alternative_id] = reserve
        if reserve.funding_outpoint_id in expected_endowments:
            policy_error(
                CoveragePolicyErrorV2.COLLATERAL_REUSE,
                (reserve.funding_outpoint_id,),
            )
        expected_endowments[reserve.funding_outpoint_id] = (
            reserve.provider_principal_id,
            reserve.amount_sat,
            EndowmentSourceV2.COUNTERPROOF_BOND,
            reserve.alternative_id,
        )

    expected_principal_roles = {
        plan.graph_owner.principal_id: EconomicPrincipalRoleV2.FRONTING_OPERATOR,
        plan.recovery_beneficiary.principal_id: (
            EconomicPrincipalRoleV2.RECOVERY_DEPOSITOR
        ),
        plan.timeout_cpfp_beneficiary.principal_id: (
            EconomicPrincipalRoleV2.TIMEOUT_BROADCASTER
        ),
        **{
            descriptor.principal_id: EconomicPrincipalRoleV2.COUNTERPROVER
            for descriptor in plan.counterproof_reserve_beneficiaries
        },
    }
    mandatory_principal_ids = tuple(sorted(expected_principal_roles))
    principals_by_id = {
        principal.principal_id: principal for principal in policy.principals
    }
    principal_roles_match = set(principals_by_id) == set(
        expected_principal_roles
    ) and all(
        principals_by_id[principal_id].role is expected_role
        for principal_id, expected_role in expected_principal_roles.items()
    )
    if not principal_roles_match:
        policy_error(CoveragePolicyErrorV2.PRINCIPAL_ROSTER_MISMATCH)

    endowments_by_id = {binding.outpoint_id: binding for binding in policy.endowments}
    if len(endowments_by_id) != len(policy.endowments):
        policy_error(CoveragePolicyErrorV2.ENDOWMENT_ROSTER_MISMATCH)
    if set(endowments_by_id) != set(expected_endowments):
        policy_error(CoveragePolicyErrorV2.ENDOWMENT_ROSTER_MISMATCH)
    for outpoint_id, expected in expected_endowments.items():
        binding = endowments_by_id.get(outpoint_id)
        if binding is None:
            continue
        if (
            binding.principal_id,
            binding.value_sat,
            binding.source,
            binding.alternative_id,
        ) != expected:
            policy_error(
                CoveragePolicyErrorV2.ENDOWMENT_OWNER_OR_VALUE_MISMATCH,
                (outpoint_id,),
            )

    transactions_by_role_and_alternative = {
        (transaction.role, transaction.alternative_id): transaction
        for transaction in plan.transactions
    }
    owner = transactions_by_role_and_alternative.get(
        (TransactionRoleV1.OWNER_PAYOUT, None)
    )
    expected_ack_ids = tuple(
        sorted(
            transaction.template_id
            for transaction in plan.transactions
            if transaction.role is TransactionRoleV1.ACK
        )
    )
    threshold = policy.threshold_qualification
    threshold_qualified = (
        threshold is not None
        and threshold.schedule_digest == policy.execution_schedule.policy_digest
        and threshold.ack_template_ids == expected_ack_ids
    )
    if threshold is not None and not threshold_qualified:
        policy_error(CoveragePolicyErrorV2.THRESHOLD_QUALIFICATION_MISMATCH)
    assumption_failure_keys = (
        tuple(
            sorted(
                f"{TerminalWorldV1.VALID_RELEASE_WITHHELD.value}:{alternative}"
                for alternative in alternatives
            )
        )
        if threshold_qualified
        else ()
    )

    expected_liabilities = {
        (TerminalWorldV1.NO_COUNTERPROOF, None): (
            plan.recovery_beneficiary.principal_id,
            plan.graph_owner.principal_id,
            deposit.value_sat,
        ),
        **{
            (TerminalWorldV1.INVALID_RELEASE_ABSENT, alternative): (
                plan.counterproof_reserve_beneficiaries[alternative].principal_id,
                plan.graph_owner.principal_id,
                deposit.value_sat,
            )
            for alternative in alternatives
        },
    }
    liabilities_by_world: dict[
        tuple[TerminalWorldV1, int | None],
        list[WorldLiabilityV2],
    ] = {}
    liability_ids: set[bytes] = set()
    for liability in policy.liabilities:
        if liability.liability_id in liability_ids:
            policy_error(CoveragePolicyErrorV2.LIABILITY_ROSTER_MISMATCH)
        liability_ids.add(liability.liability_id)
        liabilities_by_world.setdefault(
            (liability.world, liability.alternative_id), []
        ).append(liability)
    if set(liabilities_by_world) != set(expected_liabilities):
        policy_error(CoveragePolicyErrorV2.LIABILITY_ROSTER_MISMATCH)
    for world_key, expected in expected_liabilities.items():
        values = liabilities_by_world.get(world_key, [])
        if len(values) != 1 or (
            values
            and (
                values[0].debtor_principal_id,
                values[0].creditor_principal_id,
                values[0].principal_sat,
            )
            != expected
        ):
            policy_error(CoveragePolicyErrorV2.LIABILITY_ROSTER_MISMATCH)

    endowment_totals = {principal_id: 0 for principal_id in mandatory_principal_ids}
    for outpoint_id, expected in expected_endowments.items():
        if outpoint_id not in endowments_by_id:
            continue
        principal_id, value_sat, _source, _alternative = expected
        endowment_totals[principal_id] = (
            endowment_totals.get(principal_id, 0) + value_sat
        )

    expected_statuses: dict[
        tuple[TerminalWorldV1, int | None, bytes],
        tuple[PrincipalStatusV2, int],
    ] = {}
    for world, alternative in expected_world_keys:
        incoming = {principal_id: 0 for principal_id in mandatory_principal_ids}
        outgoing = {principal_id: 0 for principal_id in mandatory_principal_ids}
        for liability in liabilities_by_world.get((world, alternative), []):
            incoming[liability.creditor_principal_id] += liability.principal_sat
            outgoing[liability.debtor_principal_id] += liability.principal_sat
        for principal_id in mandatory_principal_ids:
            baseline = (
                endowment_totals.get(principal_id, 0)
                + incoming.get(principal_id, 0)
                - outgoing.get(principal_id, 0)
            )
            baseline = max(baseline, 0)
            if world is TerminalWorldV1.VALID_RELEASE_WITHHELD and threshold_qualified:
                status = PrincipalStatusV2.ASSUMPTION_FAILURE_WORLD
            elif (
                world is TerminalWorldV1.VALID_RELEASED
                and principal_id == plan.graph_owner.principal_id
            ) or (
                world is TerminalWorldV1.INVALID_RELEASE_ABSENT
                and alternative is not None
                and principal_id
                == plan.counterproof_reserve_beneficiaries[alternative].principal_id
            ):
                status = PrincipalStatusV2.ADVERSARIAL_BY_WORLD_PREMISE
            else:
                status = PrincipalStatusV2.PROTECTED
            expected_statuses[(world, alternative, principal_id)] = (
                status,
                baseline,
            )
    statuses_by_key = {
        (status.world, status.alternative_id, status.principal_id): status
        for status in policy.world_statuses
    }
    if len(statuses_by_key) != len(policy.world_statuses) or set(
        statuses_by_key
    ) != set(expected_statuses):
        policy_error(CoveragePolicyErrorV2.WORLD_STATUS_ROSTER_MISMATCH)
    for key, expected in expected_statuses.items():
        status = statuses_by_key.get(key)
        if status is None:
            continue
        if status.status is not expected[0]:
            policy_error(CoveragePolicyErrorV2.WORLD_STATUS_ROSTER_MISMATCH)
        if status.baseline_wealth_sat != expected[1]:
            policy_error(CoveragePolicyErrorV2.WORLD_BASELINE_MISMATCH)

    fronting_outpoints = tuple(
        outpoint for outpoint in (contest_payout, contest_slash) if outpoint is not None
    )
    expected_charges = {
        service_fee_charge_id_v2(outpoint.outpoint_id): (
            plan.graph_owner.principal_id,
            AllowanceCategoryV2.FRONTING_COST,
            outpoint.value_sat,
        )
        for outpoint in fronting_outpoints
    }
    if owner is None:
        policy_error(CoveragePolicyErrorV2.STRUCTURAL_PLAN_INVALID)
    else:
        expected_charges[service_fee_charge_id_v2(owner.template_id)] = (
            plan.graph_owner.principal_id,
            AllowanceCategoryV2.MINER_FEE,
            owner.fee_sat,
        )
    charges_by_id = {
        charge.charge_id: charge for charge in policy.service_fee_schedule.charges
    }
    if set(charges_by_id) != set(expected_charges):
        policy_error(CoveragePolicyErrorV2.SERVICE_FEE_ROSTER_MISMATCH)
    for charge_id, expected in expected_charges.items():
        charge = charges_by_id.get(charge_id)
        principal = principals_by_id.get(expected[0])
        if charge is None:
            continue
        if (
            charge.principal_id,
            charge.category,
            charge.amount_sat,
        ) != expected or (
            principal is not None
            and charge.authority_digest != principal.authority_digest
        ):
            policy_error(CoveragePolicyErrorV2.SERVICE_FEE_ROSTER_MISMATCH)
    fronting_charge_ids = tuple(
        sorted(
            charge_id
            for charge_id, value in expected_charges.items()
            if value[1] is AllowanceCategoryV2.FRONTING_COST
        )
    )
    fronting_cost_sat = sum(
        value[2]
        for value in expected_charges.values()
        if value[1] is AllowanceCategoryV2.FRONTING_COST
    )
    expected_allowances = {
        (
            TerminalWorldV1.INVALID_RELEASE_ABSENT,
            alternative,
            plan.graph_owner.principal_id,
        ): (
            AllowanceCategoryV2.FRONTING_COST,
            fronting_cost_sat,
            fronting_charge_ids,
        )
        for alternative in alternatives
    }
    if owner is not None:
        expected_allowances[
            (TerminalWorldV1.NO_COUNTERPROOF, None, plan.graph_owner.principal_id)
        ] = (
            AllowanceCategoryV2.MINER_FEE,
            owner.fee_sat,
            (service_fee_charge_id_v2(owner.template_id),),
        )
    allowances_by_key = {
        (allowance.world, allowance.alternative_id, allowance.principal_id): allowance
        for allowance in policy.allowances
    }
    if len(allowances_by_key) != len(policy.allowances) or set(
        allowances_by_key
    ) != set(expected_allowances):
        policy_error(CoveragePolicyErrorV2.ALLOWANCE_AUTHORITY_MISMATCH)
    used_charges_by_world: dict[tuple[TerminalWorldV1, int | None], set[bytes]] = {}
    for key, expected in expected_allowances.items():
        allowance = allowances_by_key.get(key)
        principal = principals_by_id.get(key[2])
        if allowance is None:
            continue
        if (
            allowance.category,
            allowance.amount_sat,
            allowance.charge_ids,
        ) != expected or (
            principal is not None
            and allowance.authority_digest != principal.authority_digest
        ):
            policy_error(CoveragePolicyErrorV2.ALLOWANCE_AUTHORITY_MISMATCH)
        world_key = (allowance.world, allowance.alternative_id)
        used = used_charges_by_world.setdefault(world_key, set())
        if used.intersection(allowance.charge_ids):
            policy_error(CoveragePolicyErrorV2.ALLOWANCE_CHARGE_REUSE)
        used.update(allowance.charge_ids)
        for charge_id in allowance.charge_ids:
            charge = charges_by_id.get(charge_id)
            if charge is None or charge.principal_id != allowance.principal_id:
                policy_error(CoveragePolicyErrorV2.ALLOWANCE_AUTHORITY_MISMATCH)

    if policy.coverage_reserves and set(reserves_by_alternative) != set(alternatives):
        policy_error(CoveragePolicyErrorV2.COVERAGE_ROSTER_MISMATCH)
    transition_ids: list[bytes] = []
    for alternative, reserve in reserves_by_alternative.items():
        counterproof = transactions_by_role_and_alternative.get(
            (TransactionRoleV1.COUNTERPROOF, alternative)
        )
        ack = transactions_by_role_and_alternative.get(
            (TransactionRoleV1.ACK, alternative)
        )
        timeout = transactions_by_role_and_alternative.get(
            (TransactionRoleV1.TIMEOUT_SETTLEMENT, alternative)
        )
        resolution = None
        if counterproof is not None:
            resolution = next(
                (
                    output
                    for output in counterproof.outputs
                    if output.role is OutpointRoleV1.RESOLUTION
                ),
                None,
            )
        expected_sibling_ids = tuple(
            candidate for candidate in alternatives if candidate != alternative
        )
        actual_sibling_ids = tuple(
            binding.selecting_alternative_id for binding in reserve.sibling_returns
        )
        if (
            alternative not in alternatives
            or reserve.provider_principal_id
            != plan.counterproof_reserve_beneficiaries[alternative].principal_id
            or owner is None
            or reserve.owner_template_id != owner.template_id
            or counterproof is None
            or reserve.counterproof_template_id != counterproof.template_id
            or resolution is None
            or reserve.resolution_outpoint_id != resolution.outpoint_id
            or reserve.base_resolution_value_sat != resolution.value_sat
            or ack is None
            or reserve.ack_template_id != ack.template_id
            or timeout is None
            or reserve.timeout_template_id != timeout.template_id
            or reserve.timeout_beneficiary_principal_id != plan.graph_owner.principal_id
            or actual_sibling_ids != expected_sibling_ids
        ):
            policy_error(
                CoveragePolicyErrorV2.ATOMIC_BOND_TOPOLOGY_MISMATCH,
                (reserve.funding_outpoint_id,),
            )
        transition_ids.extend(
            (
                reserve.owner_return_outpoint_id,
                reserve.ack_refund_outpoint_id,
                reserve.timeout_compensation_outpoint_id,
                *(binding.outpoint_id for binding in reserve.sibling_returns),
            )
        )
    plan_output_ids = {
        output.outpoint_id
        for transaction in plan.transactions
        for output in transaction.outputs
    }
    transition_id_set = set(transition_ids)
    transition_collisions = transition_id_set.intersection(
        {*expected_endowments, *plan_output_ids}
    )
    if len(transition_id_set) != len(transition_ids) or transition_collisions:
        policy_error(
            CoveragePolicyErrorV2.COLLATERAL_REUSE,
            tuple(transition_collisions),
        )

    if policy.coverage_reserves:
        plan_outpoints_by_id = {
            outpoint.outpoint_id: outpoint for outpoint in plan.funding_outpoints
        }
        for transaction in plan.transactions:
            plan_outpoints_by_id.update(
                (output.outpoint_id, output) for output in transaction.outputs
            )

        reserve_values = tuple(
            reserve.amount_sat for reserve in policy.coverage_reserves
        )
        money_range_failures: set[bytes] = set()
        if _checked_money_range_total(reserve_values) is None:
            money_range_failures.update(
                reserve.funding_outpoint_id for reserve in policy.coverage_reserves
            )

        if owner is not None and all(
            input_id in plan_outpoints_by_id for input_id in owner.input_ids
        ):
            owner_input_values = (
                tuple(
                    plan_outpoints_by_id[input_id].value_sat
                    for input_id in owner.input_ids
                )
                + reserve_values
            )
            owner_output_values = tuple(
                output.value_sat for output in owner.outputs
            ) + tuple(
                reserve.owner_return_value_sat for reserve in policy.coverage_reserves
            )
            if (
                _checked_money_range_total(owner_input_values) is None
                or _checked_money_range_total(owner_output_values) is None
            ):
                money_range_failures.add(owner.template_id)

        for alternative in alternatives:
            counterproof = transactions_by_role_and_alternative.get(
                (TransactionRoleV1.COUNTERPROOF, alternative)
            )
            selected_reserve = reserves_by_alternative.get(alternative)
            if (
                counterproof is None
                or selected_reserve is None
                or not all(
                    input_id in plan_outpoints_by_id
                    for input_id in counterproof.input_ids
                )
            ):
                continue
            sibling_returns: list[int] = []
            complete_sibling_returns = True
            for reserve_alternative, reserve in reserves_by_alternative.items():
                if reserve_alternative == alternative:
                    continue
                sibling_return = next(
                    (
                        binding
                        for binding in reserve.sibling_returns
                        if binding.selecting_alternative_id == alternative
                    ),
                    None,
                )
                if sibling_return is None:
                    complete_sibling_returns = False
                    break
                sibling_returns.append(sibling_return.value_sat)
            if not complete_sibling_returns:
                continue

            counterproof_input_values = (
                tuple(
                    plan_outpoints_by_id[input_id].value_sat
                    for input_id in counterproof.input_ids
                )
                + reserve_values
            )
            counterproof_output_values = tuple(
                output.value_sat
                for output in counterproof.outputs
                if output.role is not OutpointRoleV1.RESOLUTION
            ) + (
                selected_reserve.bonded_resolution_value_sat,
                *sibling_returns,
            )
            if (
                _checked_money_range_total(counterproof_input_values) is None
                or _checked_money_range_total(counterproof_output_values) is None
            ):
                money_range_failures.add(counterproof.template_id)

        if money_range_failures:
            policy_error(
                CoveragePolicyErrorV2.ATOMIC_BOND_MONEY_RANGE,
                tuple(money_range_failures),
            )

    traces = plan._enumerate_terminal_traces()
    traces_by_key = {(trace.branch, trace.alternative_id): trace for trace in traces}
    all_outpoints = {
        outpoint.outpoint_id: outpoint for outpoint in plan.funding_outpoints
    }
    for transaction in plan.transactions:
        all_outpoints.update(
            (output.outpoint_id, output) for output in transaction.outputs
        )
    allowance_amounts = {key: value[1] for key, value in expected_allowances.items()}
    for world, alternative in sorted(
        expected_world_keys,
        key=lambda key: (
            key[0].value,
            -1 if key[1] is None else key[1],
        ),
    ):
        branch = SharedSelectionTimeoutPlanV1._terminal_branch_for_world(world)
        trace = traces_by_key.get((branch, alternative))
        if trace is None:
            policy_error(CoveragePolicyErrorV2.WORLD_ROSTER_MISMATCH)
            continue
        wealth = {principal_id: 0 for principal_id in mandatory_principal_ids}
        for outpoint_id in trace.terminal_outpoint_ids:
            outpoint = all_outpoints[outpoint_id]
            if outpoint.value_sat == 0:
                continue
            if outpoint_id in expected_endowments:
                principal_id = expected_endowments[outpoint_id][0]
            elif outpoint.beneficiary_id is not None:
                principal_id = outpoint.beneficiary_id
            else:
                policy_error(
                    CoveragePolicyErrorV2.ENDOWMENT_OWNER_OR_VALUE_MISMATCH,
                    (outpoint_id,),
                )
                continue
            wealth[principal_id] = wealth.get(principal_id, 0) + outpoint.value_sat

        for bond_alternative, reserve in reserves_by_alternative.items():
            if (
                world is TerminalWorldV1.NO_COUNTERPROOF
                or bond_alternative != alternative
                or world is TerminalWorldV1.VALID_RELEASED
            ):
                beneficiary = reserve.provider_principal_id
            else:
                beneficiary = reserve.timeout_beneficiary_principal_id
            wealth[beneficiary] = wealth.get(beneficiary, 0) + reserve.amount_sat

        assumption_failure = (
            world is TerminalWorldV1.VALID_RELEASE_WITHHELD and threshold_qualified
        )
        for principal_id in mandatory_principal_ids:
            expected_status = expected_statuses[(world, alternative, principal_id)]
            if (
                assumption_failure
                or expected_status[0] is not PrincipalStatusV2.PROTECTED
            ):
                continue
            authorized_cost = allowance_amounts.get(
                (world, alternative, principal_id), 0
            )
            actual = wealth.get(principal_id, 0)
            deficit = expected_status[1] - actual - authorized_cost
            if deficit > 0:
                if alternative is None:
                    policy_error(CoveragePolicyErrorV2.WORLD_BASELINE_MISMATCH)
                else:
                    witnesses.append(
                        PrincipalCoverageDeficitWitnessV2(
                            world=world,
                            alternative_id=alternative,
                            principal_id=principal_id,
                            baseline_wealth_sat=expected_status[1],
                            terminal_wealth_sat=actual,
                            authorized_cost_sat=authorized_cost,
                            principal_deficit_sat=deficit,
                        )
                    )

    for alternative in alternatives:
        reserve = reserves_by_alternative.get(alternative)
        available = 0 if reserve is None else reserve.amount_sat
        required = deposit.value_sat + fronting_cost_sat
        if available < required:
            witnesses.append(
                CoverageReserveDeficitWitnessV2(
                    world=TerminalWorldV1.INVALID_RELEASE_ABSENT,
                    alternative_id=alternative,
                    creditor_principal_id=plan.graph_owner.principal_id,
                    liability_principal_sat=deposit.value_sat,
                    authorized_cost_sat=fronting_cost_sat,
                    required_reserve_sat=required,
                    available_reserve_sat=available,
                    reserve_shortfall_sat=required - available,
                )
            )

    if witnesses:
        return TerminalWealthCoverageInfeasibleV2(
            policy_digest=policy.policy_digest,
            mandatory_principal_ids=mandatory_principal_ids,
            world_keys=ordered_world_keys,
            assumption_failure_world_keys=assumption_failure_keys,
            witnesses=tuple(witnesses),
        )
    return DeclaredCoverageAdequateV2(
        policy_digest=policy.policy_digest,
        mandatory_principal_ids=mandatory_principal_ids,
        world_keys=ordered_world_keys,
        assumption_failure_world_keys=assumption_failure_keys,
    )
