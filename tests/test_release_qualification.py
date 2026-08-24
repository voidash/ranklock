from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock.release_qualification import (
    LocalReleaseFacts,
    ReleaseQualificationError,
    facts_from_mapping,
)


def _facts() -> LocalReleaseFacts:
    return LocalReleaseFacts(
        complete_source_archive_reproducible=True,
        complete_test_suite_passed=True,
        retained_object_below_one_mib=True,
        committee_authorization_harness_passed=True,
        split_scalar_one_honest_harness_passed=True,
        bitcoin_policy_envelope_passed=True,
        bitcoin_core_regtest_executed=False,
        bitcoin_core_regtest_passed=False,
        current_bridge_compiled_and_tested=False,
        native_constant_time_implementation=False,
        production_rollback_witnesses_deployed=False,
        deterministic_fixture_secrets_absent=False,
        independent_cryptography_audit_passed=False,
        independent_implementation_audit_passed=False,
        split_scalar_production_setup_passed=False,
    )


def test_local_evidence_can_qualify_canary_but_not_funds():
    facts = _facts()
    assert facts.locally_reproducible
    assert facts.maximum_mode == "canary"
    assert not facts.safe_for_funds
    assert "Bitcoin Core regtest was not executed" in facts.funds_blockers
    assert "independent cryptography audit is absent" in facts.funds_blockers
    assert facts.document()["maximum_mode"] == "canary"


def test_legacy_release_facts_cannot_enable_enforce_even_when_all_booleans_are_true():
    facts = replace(
        _facts(),
        bitcoin_core_regtest_executed=True,
        bitcoin_core_regtest_passed=True,
        current_bridge_compiled_and_tested=True,
        native_constant_time_implementation=True,
        production_rollback_witnesses_deployed=True,
        deterministic_fixture_secrets_absent=True,
        independent_cryptography_audit_passed=True,
        independent_implementation_audit_passed=True,
        split_scalar_production_setup_passed=True,
    )
    assert not facts.safe_for_funds
    assert facts.maximum_mode == "canary"
    assert facts.funds_blockers == (
        "legacy v0.25 release facts cannot authorize funds; a validated v0.26 "
        "funding-subject DAG and funds protocol are absent",
    )



def test_local_security_harnesses_are_funds_blockers_even_with_external_gates():
    facts = replace(
        _facts(),
        bitcoin_core_regtest_executed=True,
        bitcoin_core_regtest_passed=True,
        current_bridge_compiled_and_tested=True,
        native_constant_time_implementation=True,
        production_rollback_witnesses_deployed=True,
        deterministic_fixture_secrets_absent=True,
        independent_cryptography_audit_passed=True,
        independent_implementation_audit_passed=True,
        split_scalar_production_setup_passed=True,
        bitcoin_policy_envelope_passed=False,
    )
    assert not facts.safe_for_funds
    assert "Bitcoin policy envelope did not pass" in facts.funds_blockers


def test_active_mpc_mode_does_not_accept_split_scalar_attestation():
    facts = replace(
        _facts(),
        setup_security_mode="active-mpc",
        split_scalar_production_setup_passed=True,
    )
    assert not facts.setup_gate_passed
    assert any("active-mpc" in blocker for blocker in facts.funds_blockers)


def test_mapping_constructor_is_strict():
    values = {
        name: getattr(_facts(), name)
        for name in LocalReleaseFacts.__dataclass_fields__
        if name != "schema"
    }
    assert facts_from_mapping(values) == _facts()
    values["invented"] = True
    with pytest.raises(ReleaseQualificationError):
        facts_from_mapping(values)
