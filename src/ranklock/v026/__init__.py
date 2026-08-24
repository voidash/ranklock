"""Fail-closed v0.26 protocol primitives.

This package is intentionally separate from the v0.25 wire objects. Its
presence does not make a proof suite or deployment eligible for funds.
"""

from .participant_lock_context import (
    PARTICIPANT_LOCK_CONTEXT_DOMAIN,
    ParticipantLockContextError,
    ParticipantLockContextV1,
)
from .timeout_economics import (
    BeneficiaryDescriptorV1,
    OutpointRoleV1,
    PlannedOutpointV1,
    ResolutionConnectorPolicyV1,
    SharedSelectionTimeoutPlanV1,
    SlashAuthorizationPolicyV1,
    SlashHeaderPolicyV1,
    SlashOutputPolicyV1,
    TimeoutEconomicsError,
    TimeoutSafetyAssessmentV1,
    TimeoutSafetyBlockerV1,
    TransactionRoleV1,
    TransactionTemplateV1,
)

__all__ = (
    "PARTICIPANT_LOCK_CONTEXT_DOMAIN",
    "ParticipantLockContextError",
    "ParticipantLockContextV1",
    "BeneficiaryDescriptorV1",
    "OutpointRoleV1",
    "PlannedOutpointV1",
    "ResolutionConnectorPolicyV1",
    "SharedSelectionTimeoutPlanV1",
    "SlashAuthorizationPolicyV1",
    "SlashHeaderPolicyV1",
    "SlashOutputPolicyV1",
    "TimeoutEconomicsError",
    "TimeoutSafetyAssessmentV1",
    "TimeoutSafetyBlockerV1",
    "TransactionRoleV1",
    "TransactionTemplateV1",
)
