"""Closed proof-suite registry for funds qualification.

Cryptographic code must not become fundable because a caller supplies a suite
name together with optimistic booleans.  This module owns the compiled suite
inventory and exposes decisions, not an override.  The current inventory is
deliberately empty of fund-eligible suites.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

BN254_SPLIT_SUITE_ID: Final = b"RL25-BN254-SPLIT-N"
BLS381_DFB_CANDIDATE_ID: Final = b"RL26-BLS381-DFB-SPLIT-N"
BLS461_DFB_CANDIDATE_ID: Final = b"RL26-BLS461-DFB-SPLIT-N"
BN462_DFB_CANDIDATE_ID: Final = b"RL26-BN462-DFB-SPLIT-N"
BN462_DIRECT_CUSTODY_CANDIDATE_ID: Final = b"RL26-BN462-DIRECT-CUSTODY-N"
SECURITY_FLOOR_REPORT_SCHEMA: Final = "ranklock-security-floor-report-v1"
_QUALIFICATION_EVIDENCE_VERIFIER_IMPLEMENTED: Final = False


class ProofSuiteQualificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProofSuiteProfile:
    suite_id: bytes
    curve_family: str
    attack_security_upper_bound_bits: int | None
    approved_security_floor_bits: int | None
    security_floor_approval_digest: bytes | None
    security_floor_report_schema: str | None
    security_floor_approver_set_digest: bytes | None
    security_floor_lifetime_days: int | None
    security_floor_approved_at_unix: int | None
    security_floor_valid_through_unix: int | None
    end_to_end_proof_backend: bool
    canonical_subgroup_checked_encodings: bool
    native_constant_time_implementation: bool
    release_mechanism: str
    positive_lock_security_closed: bool
    release_primitive_security_closed: bool
    one_shot_state_security_closed: bool
    secret_erasure_security_closed: bool
    secret_result_transport_security_closed: bool
    independent_cryptography_audit: bool
    independent_implementation_audit: bool
    status: str
    permanent_blockers: tuple[str, ...]
    schema: str = "ranklock-proof-suite-profile-v6"

    def __post_init__(self) -> None:
        if not isinstance(self.suite_id, bytes) or not self.suite_id:
            raise ProofSuiteQualificationError("proof-suite id must be nonempty bytes")
        try:
            self.suite_id.decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise ProofSuiteQualificationError("proof-suite id must be ASCII") from exc
        if not isinstance(self.curve_family, str) or not self.curve_family:
            raise ProofSuiteQualificationError("curve family must be nonempty text")
        for field_name, bits in (
            ("attack-security upper bound", self.attack_security_upper_bound_bits),
            ("approved security floor", self.approved_security_floor_bits),
        ):
            if bits is not None and (
                isinstance(bits, bool)
                or not isinstance(bits, int)
                or not 1 <= bits <= 256
            ):
                raise ProofSuiteQualificationError(
                    f"{field_name} must be an integer in 1..256"
                )
        attack_upper_bound = self.attack_security_upper_bound_bits
        approved_floor = self.approved_security_floor_bits
        if (
            attack_upper_bound is not None
            and approved_floor is not None
            and approved_floor > attack_upper_bound
        ):
            raise ProofSuiteQualificationError(
                "approved security floor exceeds the known attack upper bound"
            )
        approval_digest = self.security_floor_approval_digest
        report_schema = self.security_floor_report_schema
        approver_set_digest = self.security_floor_approver_set_digest
        lifetime_days = self.security_floor_lifetime_days
        approved_at_unix = self.security_floor_approved_at_unix
        valid_through_unix = self.security_floor_valid_through_unix
        if approved_floor is None:
            if any(
                value is not None
                for value in (
                    approval_digest,
                    report_schema,
                    approver_set_digest,
                    lifetime_days,
                    approved_at_unix,
                    valid_through_unix,
                )
            ):
                raise ProofSuiteQualificationError(
                    "security-floor provenance exists without an approved floor"
                )
        else:
            if not isinstance(approval_digest, bytes) or len(approval_digest) != 32:
                raise ProofSuiteQualificationError(
                    "approved security floor requires a 32-byte report digest"
                )
            if report_schema != SECURITY_FLOOR_REPORT_SCHEMA:
                raise ProofSuiteQualificationError(
                    "approved security floor requires the exact typed report schema"
                )
            if (
                not isinstance(approver_set_digest, bytes)
                or len(approver_set_digest) != 32
            ):
                raise ProofSuiteQualificationError(
                    "approved security floor requires a 32-byte approver-set digest"
                )
            if (
                isinstance(lifetime_days, bool)
                or not isinstance(lifetime_days, int)
                or lifetime_days <= 0
            ):
                raise ProofSuiteQualificationError(
                    "approved security floor requires a positive lifetime"
                )
            if (
                isinstance(approved_at_unix, bool)
                or not isinstance(approved_at_unix, int)
                or approved_at_unix < 0
                or isinstance(valid_through_unix, bool)
                or not isinstance(valid_through_unix, int)
                or valid_through_unix <= approved_at_unix
            ):
                raise ProofSuiteQualificationError(
                    "approved security floor requires a valid approval interval"
                )
            maximum_lifetime_seconds = lifetime_days * 86_400
            if approved_at_unix + maximum_lifetime_seconds > valid_through_unix:
                raise ProofSuiteQualificationError(
                    "security-floor lifetime exceeds its approval interval"
                )
        if self.status not in {"disqualified", "research-candidate", "qualified"}:
            raise ProofSuiteQualificationError("unknown proof-suite status")
        if self.release_mechanism not in {
            "dfb-projectivizer",
            "direct-scalar-custody",
        }:
            raise ProofSuiteQualificationError("unknown release mechanism")
        boolean_fields = (
            self.end_to_end_proof_backend,
            self.canonical_subgroup_checked_encodings,
            self.native_constant_time_implementation,
            self.positive_lock_security_closed,
            self.release_primitive_security_closed,
            self.one_shot_state_security_closed,
            self.secret_erasure_security_closed,
            self.secret_result_transport_security_closed,
            self.independent_cryptography_audit,
            self.independent_implementation_audit,
        )
        if any(type(value) is not bool for value in boolean_fields):
            raise ProofSuiteQualificationError(
                "proof-suite qualification facts must be strict booleans"
            )
        if self.status == "qualified" and self.permanent_blockers:
            raise ProofSuiteQualificationError(
                "qualified proof suite cannot have permanent blockers"
            )
        if not isinstance(self.permanent_blockers, tuple) or any(
            not isinstance(blocker, str) or not blocker
            for blocker in self.permanent_blockers
        ):
            raise ProofSuiteQualificationError(
                "proof-suite blockers must be nonempty text in an immutable tuple"
            )
        if len(set(self.permanent_blockers)) != len(self.permanent_blockers):
            raise ProofSuiteQualificationError("proof-suite blockers are duplicated")


@dataclass(frozen=True, slots=True)
class ProofSuiteDecision:
    suite_id: bytes
    required_security_bits: int
    activation_certificate_digest: bytes
    activation_time_unix: int
    required_lifetime_days: int
    funding_eligible: bool
    blockers: tuple[str, ...]
    schema: str = "ranklock-proof-suite-decision-v3"


_SUITES: Final[tuple[ProofSuiteProfile, ...]] = (
    ProofSuiteProfile(
        suite_id=BN254_SPLIT_SUITE_ID,
        curve_family="BN254",
        attack_security_upper_bound_bits=100,
        approved_security_floor_bits=None,
        security_floor_approval_digest=None,
        security_floor_report_schema=None,
        security_floor_approver_set_digest=None,
        security_floor_lifetime_days=None,
        security_floor_approved_at_unix=None,
        security_floor_valid_through_unix=None,
        end_to_end_proof_backend=True,
        canonical_subgroup_checked_encodings=True,
        native_constant_time_implementation=False,
        release_mechanism="dfb-projectivizer",
        positive_lock_security_closed=False,
        release_primitive_security_closed=False,
        one_shot_state_security_closed=False,
        secret_erasure_security_closed=False,
        secret_result_transport_security_closed=False,
        independent_cryptography_audit=False,
        independent_implementation_audit=False,
        status="disqualified",
        permanent_blockers=(
            "BN254 is disqualified from the funds path",
            "the implementation is variable-time research code",
            "the adaptive DFB/output-mask security argument is not closed",
            "independent cryptography and implementation audits are absent",
        ),
    ),
    ProofSuiteProfile(
        suite_id=BLS381_DFB_CANDIDATE_ID,
        curve_family="BLS12-381",
        attack_security_upper_bound_bits=126,
        approved_security_floor_bits=None,
        security_floor_approval_digest=None,
        security_floor_report_schema=None,
        security_floor_approver_set_digest=None,
        security_floor_lifetime_days=None,
        security_floor_approved_at_unix=None,
        security_floor_valid_through_unix=None,
        end_to_end_proof_backend=False,
        canonical_subgroup_checked_encodings=False,
        native_constant_time_implementation=False,
        release_mechanism="dfb-projectivizer",
        positive_lock_security_closed=False,
        release_primitive_security_closed=False,
        one_shot_state_security_closed=False,
        secret_erasure_security_closed=False,
        secret_result_transport_security_closed=False,
        independent_cryptography_audit=False,
        independent_implementation_audit=False,
        status="research-candidate",
        permanent_blockers=(
            "the end-to-end BLS12-381 proof/lock backend is absent",
            "production canonical subgroup-checked encodings are absent",
            "the native constant-time implementation is absent",
            "the adaptive DFB/output-mask security argument is not closed",
            "independent cryptography and implementation audits are absent",
        ),
    ),
    ProofSuiteProfile(
        suite_id=BLS461_DFB_CANDIDATE_ID,
        curve_family="BLS12-461",
        attack_security_upper_bound_bits=None,
        approved_security_floor_bits=None,
        security_floor_approval_digest=None,
        security_floor_report_schema=None,
        security_floor_approver_set_digest=None,
        security_floor_lifetime_days=None,
        security_floor_approved_at_unix=None,
        security_floor_valid_through_unix=None,
        end_to_end_proof_backend=False,
        canonical_subgroup_checked_encodings=False,
        native_constant_time_implementation=False,
        release_mechanism="dfb-projectivizer",
        positive_lock_security_closed=False,
        release_primitive_security_closed=False,
        one_shot_state_security_closed=False,
        secret_erasure_security_closed=False,
        secret_result_transport_security_closed=False,
        independent_cryptography_audit=False,
        independent_implementation_audit=False,
        status="research-candidate",
        permanent_blockers=(
            "the end-to-end BLS12-461 proof/lock backend is absent",
            "production canonical subgroup-checked encodings are absent",
            "the native constant-time implementation is absent",
            "the adaptive DFB/output-mask security argument is not closed",
            "independent cryptography and implementation audits are absent",
        ),
    ),
    ProofSuiteProfile(
        suite_id=BN462_DFB_CANDIDATE_ID,
        curve_family="BN462",
        attack_security_upper_bound_bits=None,
        approved_security_floor_bits=None,
        security_floor_approval_digest=None,
        security_floor_report_schema=None,
        security_floor_approver_set_digest=None,
        security_floor_lifetime_days=None,
        security_floor_approved_at_unix=None,
        security_floor_valid_through_unix=None,
        end_to_end_proof_backend=False,
        canonical_subgroup_checked_encodings=False,
        native_constant_time_implementation=False,
        release_mechanism="dfb-projectivizer",
        positive_lock_security_closed=False,
        release_primitive_security_closed=False,
        one_shot_state_security_closed=False,
        secret_erasure_security_closed=False,
        secret_result_transport_security_closed=False,
        independent_cryptography_audit=False,
        independent_implementation_audit=False,
        status="research-candidate",
        permanent_blockers=(
            "the end-to-end BN462 proof/lock backend is absent",
            "production canonical subgroup-checked encodings are absent",
            "the native constant-time implementation is absent",
            "the adaptive DFB/output-mask security argument is not closed",
            "independent cryptography and implementation audits are absent",
        ),
    ),
    ProofSuiteProfile(
        suite_id=BN462_DIRECT_CUSTODY_CANDIDATE_ID,
        curve_family="BN462",
        attack_security_upper_bound_bits=None,
        approved_security_floor_bits=None,
        security_floor_approval_digest=None,
        security_floor_report_schema=None,
        security_floor_approver_set_digest=None,
        security_floor_lifetime_days=None,
        security_floor_approved_at_unix=None,
        security_floor_valid_through_unix=None,
        end_to_end_proof_backend=False,
        canonical_subgroup_checked_encodings=False,
        native_constant_time_implementation=False,
        release_mechanism="direct-scalar-custody",
        positive_lock_security_closed=False,
        release_primitive_security_closed=False,
        one_shot_state_security_closed=False,
        secret_erasure_security_closed=False,
        secret_result_transport_security_closed=False,
        independent_cryptography_audit=False,
        independent_implementation_audit=False,
        status="research-candidate",
        permanent_blockers=(
            "the end-to-end BN462 proof/lock backend is absent",
            "production canonical subgroup-checked encodings are absent",
            "the native constant-time implementation is absent",
            "the direct-scalar custody module and one-shot theorem are absent",
            (
                "positive-lock hiding with public leakage and guarded one-shot "
                "scalar-service access is not independently reviewed"
            ),
            "independent cryptography and implementation audits are absent",
        ),
    ),
)

_SUITES_BY_ID: Final = MappingProxyType(
    {profile.suite_id: profile for profile in _SUITES}
)
if len(_SUITES_BY_ID) != len(_SUITES):  # pragma: no cover - import-time invariant
    raise RuntimeError("compiled proof-suite ids are duplicated")


def registered_proof_suites() -> tuple[ProofSuiteProfile, ...]:
    """Return the immutable compiled suite inventory."""

    return _SUITES


def resolve_proof_suite(suite_id: bytes) -> ProofSuiteProfile:
    """Resolve an exact binary suite id without text coercion or fallback."""

    if not isinstance(suite_id, bytes):
        raise ProofSuiteQualificationError("proof-suite id must be immutable bytes")
    try:
        return _SUITES_BY_ID[suite_id]
    except KeyError as exc:
        raise ProofSuiteQualificationError("proof-suite id is not allowlisted") from exc


def evaluate_proof_suite(
    suite_id: bytes,
    *,
    required_security_bits: int,
    activation_certificate_digest: bytes,
    activation_time_unix: int,
    required_lifetime_days: int,
) -> ProofSuiteDecision:
    """Evaluate only compiled facts; callers cannot supply qualification flags."""

    if (
        isinstance(required_security_bits, bool)
        or not isinstance(required_security_bits, int)
        or not 1 <= required_security_bits <= 256
    ):
        raise ProofSuiteQualificationError(
            "required security floor must be an integer in 1..256"
        )
    if (
        not isinstance(activation_certificate_digest, bytes)
        or len(activation_certificate_digest) != 32
    ):
        raise ProofSuiteQualificationError(
            "activation certificate digest must be exactly 32 bytes"
        )
    if (
        isinstance(activation_time_unix, bool)
        or not isinstance(activation_time_unix, int)
        or activation_time_unix < 0
    ):
        raise ProofSuiteQualificationError(
            "activation time must be a nonnegative Unix timestamp"
        )
    if (
        isinstance(required_lifetime_days, bool)
        or not isinstance(required_lifetime_days, int)
        or required_lifetime_days <= 0
    ):
        raise ProofSuiteQualificationError(
            "required deployment lifetime must be a positive number of days"
        )
    profile = resolve_proof_suite(suite_id)
    blockers = list(profile.permanent_blockers)
    if not _QUALIFICATION_EVIDENCE_VERIFIER_IMPLEMENTED:
        blockers.append(
            "signed security-report and canonical activation-window verifier "
            "is not implemented"
        )
    attack_upper_bound = profile.attack_security_upper_bound_bits
    if attack_upper_bound is not None and attack_upper_bound < required_security_bits:
        blockers.append(
            "known attack-security upper bound is below the required security floor"
        )
    approved_floor = profile.approved_security_floor_bits
    if approved_floor is None:
        blockers.append("a conservative security floor has not been approved")
    elif approved_floor < required_security_bits:
        blockers.append("approved security floor is below the required security floor")
    else:
        approved_at_unix = profile.security_floor_approved_at_unix
        valid_through_unix = profile.security_floor_valid_through_unix
        maximum_lifetime_days = profile.security_floor_lifetime_days
        if (
            approved_at_unix is None
            or valid_through_unix is None
            or maximum_lifetime_days is None
        ):  # pragma: no cover - rejected by ProofSuiteProfile
            raise RuntimeError("approved security floor is missing validity metadata")
        if activation_time_unix < approved_at_unix:
            blockers.append("security-floor approval is not valid at activation")
        if activation_time_unix >= valid_through_unix:
            blockers.append("security-floor approval has expired before activation")
        if required_lifetime_days > maximum_lifetime_days:
            blockers.append(
                "required deployment lifetime exceeds the approved security lifetime"
            )
        required_valid_through = activation_time_unix + required_lifetime_days * 86_400
        if required_valid_through > valid_through_unix:
            blockers.append(
                "security-floor approval expires before the deployment lifetime ends"
            )
    if profile.release_mechanism == "dfb-projectivizer":
        release_mechanism_blocker = "adaptive DFB security argument is open"
    else:
        release_mechanism_blocker = (
            "direct-scalar custody and one-shot security argument is open"
        )
    checks = (
        (profile.end_to_end_proof_backend, "end-to-end proof backend is absent"),
        (
            profile.canonical_subgroup_checked_encodings,
            "canonical subgroup-checked encodings are absent",
        ),
        (
            profile.native_constant_time_implementation,
            "native constant-time implementation is absent",
        ),
        (
            profile.positive_lock_security_closed,
            "positive-lock security argument is open",
        ),
        (
            profile.release_primitive_security_closed,
            release_mechanism_blocker,
        ),
        (
            profile.one_shot_state_security_closed,
            "one-shot state security argument is open",
        ),
        (
            profile.secret_erasure_security_closed,
            "secret-erasure security argument is open",
        ),
        (
            profile.secret_result_transport_security_closed,
            "secret result transport and conditional-key security argument is open",
        ),
        (
            profile.independent_cryptography_audit,
            "independent cryptography audit is absent",
        ),
        (
            profile.independent_implementation_audit,
            "independent implementation audit is absent",
        ),
    )
    blockers.extend(message for passed, message in checks if not passed)
    unique_blockers = tuple(dict.fromkeys(blockers))
    funding_eligible = profile.status == "qualified" and not unique_blockers
    return ProofSuiteDecision(
        suite_id=profile.suite_id,
        required_security_bits=required_security_bits,
        activation_certificate_digest=activation_certificate_digest,
        activation_time_unix=activation_time_unix,
        required_lifetime_days=required_lifetime_days,
        funding_eligible=funding_eligible,
        blockers=unique_blockers,
    )


def require_funding_eligible_proof_suite(
    suite_id: bytes,
    *,
    required_security_bits: int,
    activation_certificate_digest: bytes,
    activation_time_unix: int,
    required_lifetime_days: int,
) -> ProofSuiteProfile:
    """Return a compiled qualified suite or fail closed with all blockers."""

    decision = evaluate_proof_suite(
        suite_id,
        required_security_bits=required_security_bits,
        activation_certificate_digest=activation_certificate_digest,
        activation_time_unix=activation_time_unix,
        required_lifetime_days=required_lifetime_days,
    )
    if not decision.funding_eligible:
        raise ProofSuiteQualificationError(
            "proof suite is not eligible for funds: " + "; ".join(decision.blockers)
        )
    return resolve_proof_suite(suite_id)
