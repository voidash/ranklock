from __future__ import annotations

from scripts.generate_v0251_security_hardening import (
    EXPECTED_BITCOIND_SHA256,
    EXPECTED_BITCOIN_CORE_VERSION,
    core_evidence_is_fail_closed_or_pinned,
)


def test_unavailable_core_evidence_must_fail_closed() -> None:
    assert core_evidence_is_fail_closed_or_pinned(
        {"executed": False, "passed": False, "error": "bitcoind unavailable"}
    )
    assert not core_evidence_is_fail_closed_or_pinned(
        {"executed": False, "passed": True, "error": "contradictory"}
    )


def test_pinned_core_execution_is_accepted() -> None:
    assert core_evidence_is_fail_closed_or_pinned(
        {
            "executed": True,
            "passed": True,
            "result": {
                "bitcoin_core_version_number": EXPECTED_BITCOIN_CORE_VERSION,
                "bitcoind_sha256": EXPECTED_BITCOIND_SHA256,
            },
        }
    )


def test_unpinned_or_incomplete_core_success_is_rejected() -> None:
    for result in (
        {},
        {
            "bitcoin_core_version_number": EXPECTED_BITCOIN_CORE_VERSION,
            "bitcoind_sha256": "00" * 32,
        },
        {
            "bitcoin_core_version_number": EXPECTED_BITCOIN_CORE_VERSION - 1,
            "bitcoind_sha256": EXPECTED_BITCOIND_SHA256,
        },
    ):
        assert not core_evidence_is_fail_closed_or_pinned(
            {"executed": True, "passed": True, "result": result}
        )
