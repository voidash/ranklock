from ranklock.validity_first_graph import (
    CounterproofStatus,
    GraphPolarity,
    Resolution,
    graph_rewrites,
    resolve_counterproof,
    validity_first_graph_checkpoint,
)


def test_current_valid_counterproof_times_out_to_ack() -> None:
    row = resolve_counterproof(
        GraphPolarity.CURRENT_INVALIDITY_FIRST,
        CounterproofStatus.VALID,
        immediate_spend_confirms=False,
    )
    assert not row.conditioned_key_available
    assert row.resolution is Resolution.ACK_AND_SLASH
    assert row.safety_preserved


def test_current_invalid_counterproof_needs_immediate_nack() -> None:
    success = resolve_counterproof(
        GraphPolarity.CURRENT_INVALIDITY_FIRST,
        CounterproofStatus.INVALID,
        immediate_spend_confirms=True,
    )
    censored = resolve_counterproof(
        GraphPolarity.CURRENT_INVALIDITY_FIRST,
        CounterproofStatus.INVALID,
        immediate_spend_confirms=False,
    )
    assert success.resolution is Resolution.NACK_AND_CONTESTED_PAYOUT
    assert success.safety_preserved
    assert not censored.safety_preserved


def test_validity_first_valid_counterproof_immediately_acks() -> None:
    row = resolve_counterproof(
        GraphPolarity.VALIDITY_FIRST,
        CounterproofStatus.VALID,
        immediate_spend_confirms=True,
    )
    assert row.conditioned_key_available
    assert row.resolution is Resolution.ACK_AND_SLASH
    assert row.safety_preserved


def test_validity_first_invalid_or_absent_counterproof_times_out_to_nack() -> None:
    for status in (CounterproofStatus.INVALID, CounterproofStatus.ABSENT):
        row = resolve_counterproof(
            GraphPolarity.VALIDITY_FIRST,
            status,
            immediate_spend_confirms=False,
        )
        assert not row.conditioned_key_available
        assert row.resolution is Resolution.NACK_AND_CONTESTED_PAYOUT
        assert row.safety_preserved


def test_censorship_failure_count_is_symmetric() -> None:
    checkpoint = validity_first_graph_checkpoint()
    symmetry = checkpoint["censorship_symmetry"]
    assert symmetry["current_safety_failures"] == 1
    assert symmetry["validity_first_safety_failures"] == 1
    assert symmetry["same_deadline_assumption"]


def test_rewrite_is_explicit_and_not_claimed_complete() -> None:
    assert len(graph_rewrites()) >= 6
    checkpoint = validity_first_graph_checkpoint()
    assert checkpoint["decision"] == "PROMISING_PROTOCOL_PIVOT_NOT_YET_A_COMPLETE_REPLACEMENT"
    assert not checkpoint["breakthrough_target_met"]
    assert not checkpoint["semantic_boundary"]["ordinary_fixed_statement_WE_alone_is_sufficient"]
