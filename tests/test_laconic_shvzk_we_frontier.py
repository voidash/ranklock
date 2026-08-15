from ranklock.laconic_shvzk_we_frontier import (
    HistogramCompilerCost,
    OneSidedSHVZKAudit,
    ProverCommunicationProfile,
    laconic_shvzk_we_frontier,
)


def test_current_prover_communication_and_support_bound() -> None:
    profile = ProverCommunicationProfile()
    assert profile.bytes == 1_280
    assert profile.bits == 10_240
    assert profile.support_log2_upper_bound == 10_240
    assert profile.decimal_digits_in_support_bound == 3_083


def test_generic_histogram_route_is_not_concrete() -> None:
    cost = HistogramCompilerCost()
    assert not cost.explicit_histogram_feasible
    assert cost.explicit_histogram_log2_bytes == 10_243.0


def test_source_protocol_does_not_establish_shvzk() -> None:
    audit = OneSidedSHVZKAudit()
    assert audit.direct_wire_commitments
    assert not audit.explicit_commitment_blinding
    assert not audit.generic_we_prerequisite_established


def test_frontier_is_not_marked_breakthrough() -> None:
    result = laconic_shvzk_we_frontier()
    assert result["breakthrough_target_met"] is False
    assert "THEORETICAL_BYPASS_ONLY" in result["concrete_decision"]
