from ranklock.direct_relation_barrier import (
    CURRENT_LOGICAL_EVENTS,
    DirectRelationBarrier,
)


def test_direct_relation_is_far_above_one_megabyte() -> None:
    result = DirectRelationBarrier()
    assert result.logical_events == CURRENT_LOGICAL_EVENTS == 2_537_122
    assert result.maximum_trace_width == 13_912
    assert result.multiplication_only_retained_bytes > 8 * (1 << 20)
    assert result.direct_retained_bytes > 150 * (1 << 20)
    assert result.direct_relation_width > result.maximum_trace_width


def test_document_labels_result_as_scoped_kill_not_universal_lower_bound() -> None:
    document = DirectRelationBarrier().document()
    assert document["decision"].startswith("KILL direct")
    assert "not a generic lower bound" in document["scope"]
    assert document["all_logical_events"]["factor_over_cap"] > 150
