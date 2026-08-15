from __future__ import annotations

"""Machine-readable local qualification for a RankLock release.

This module deliberately separates evidence that can be established by the
source tree itself from evidence that must come from an external trust domain.
A local test run may qualify an observe/canary build, but it can never mint its
own independent audit, production-operations, bridge-integration, or
Bitcoin-Core attestation.
"""

from dataclasses import dataclass, fields
from typing import Mapping


class ReleaseQualificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LocalReleaseFacts:
    complete_source_archive_reproducible: bool
    complete_test_suite_passed: bool
    retained_object_below_one_mib: bool
    committee_authorization_harness_passed: bool
    split_scalar_one_honest_harness_passed: bool
    bitcoin_policy_envelope_passed: bool
    bitcoin_core_regtest_executed: bool
    bitcoin_core_regtest_passed: bool
    current_bridge_compiled_and_tested: bool
    native_constant_time_implementation: bool
    production_rollback_witnesses_deployed: bool
    deterministic_fixture_secrets_absent: bool
    independent_cryptography_audit_passed: bool
    independent_implementation_audit_passed: bool
    active_mpc_exact_generator_passed: bool = False
    split_scalar_production_setup_passed: bool = False
    setup_security_mode: str = "split-scalar-n-of-n"
    schema: str = "ranklock-local-release-facts-v1"

    def __post_init__(self) -> None:
        if self.setup_security_mode not in {"active-mpc", "split-scalar-n-of-n"}:
            raise ReleaseQualificationError("unknown setup security mode")

    @property
    def setup_gate_passed(self) -> bool:
        if self.setup_security_mode == "active-mpc":
            return bool(self.active_mpc_exact_generator_passed)
        return bool(self.split_scalar_production_setup_passed)

    @property
    def locally_reproducible(self) -> bool:
        return bool(
            self.complete_source_archive_reproducible
            and self.complete_test_suite_passed
            and self.committee_authorization_harness_passed
            and self.split_scalar_one_honest_harness_passed
            and self.bitcoin_policy_envelope_passed
        )

    @property
    def funds_blockers(self) -> tuple[str, ...]:
        checks: tuple[tuple[str, bool], ...] = (
            ("complete source archive is not reproducible", self.complete_source_archive_reproducible),
            ("complete test suite did not pass", self.complete_test_suite_passed),
            ("committee authorization harness did not pass", self.committee_authorization_harness_passed),
            ("split-scalar one-honest harness did not pass",
             self.split_scalar_one_honest_harness_passed
             if self.setup_security_mode == "split-scalar-n-of-n" else True),
            ("Bitcoin policy envelope did not pass", self.bitcoin_policy_envelope_passed),
            ("Bitcoin Core regtest was not executed", self.bitcoin_core_regtest_executed),
            ("Bitcoin Core regtest did not pass", self.bitcoin_core_regtest_passed),
            ("current bridge commit was not compiled and tested", self.current_bridge_compiled_and_tested),
            ("native constant-time implementation is absent", self.native_constant_time_implementation),
            ("production rollback witnesses are not deployed", self.production_rollback_witnesses_deployed),
            ("deterministic fixture secrets are present", self.deterministic_fixture_secrets_absent),
            ("independent cryptography audit is absent", self.independent_cryptography_audit_passed),
            ("independent implementation audit is absent", self.independent_implementation_audit_passed),
            (f"production setup gate is open for {self.setup_security_mode}", self.setup_gate_passed),
        )
        return tuple(message for message, passed in checks if not passed)

    @property
    def safe_for_funds(self) -> bool:
        return not self.funds_blockers

    @property
    def maximum_mode(self) -> str:
        if self.safe_for_funds:
            return "enforce"
        if self.locally_reproducible:
            return "canary"
        return "observe"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "setup_security_mode": self.setup_security_mode,
            "setup_gate_passed": self.setup_gate_passed,
            "locally_reproducible": self.locally_reproducible,
            "maximum_mode": self.maximum_mode,
            "safe_for_funds": self.safe_for_funds,
            "funds_blockers": list(self.funds_blockers),
            "facts": {
                field.name: getattr(self, field.name)
                for field in fields(self)
                if field.name not in {"schema", "setup_security_mode"}
            },
        }


def facts_from_mapping(values: Mapping[str, object]) -> LocalReleaseFacts:
    """Strict constructor used by release tooling and policy frontends."""

    allowed = {
        field
        for field in LocalReleaseFacts.__dataclass_fields__
        if field != "schema"
    }
    unknown = set(values).difference(allowed)
    if unknown:
        raise ReleaseQualificationError(f"unknown release fact(s): {sorted(unknown)}")
    try:
        return LocalReleaseFacts(**dict(values))  # type: ignore[arg-type]
    except TypeError as exc:
        raise ReleaseQualificationError(str(exc)) from exc
