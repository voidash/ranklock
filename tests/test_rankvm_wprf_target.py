from ranklock.rankvm_wprf_target import (
    FixedRankVMInstance,
    RankVMWPRFTarget,
    rankvm_wprf_target,
)


def test_naive_future_input_truth_table_is_exponential() -> None:
    instance = FixedRankVMInstance()
    assert instance.future_input_bytes == 164
    assert instance.future_input_bits == 1_312
    assert instance.naive_truth_table_log2_entries == 1_312


def test_wprf_target_is_hard_yes_extractable_and_witness_invariant() -> None:
    target = RankVMWPRFTarget().document()
    assert target["output_bytes"] == 32
    interface = target["target_interface"]
    assert "pseudorandom" in interface["hard_YES_pseudorandomness"]
    assert "extraction" in interface["extractability"]
    assert "same output" in interface["witness_invariance"]
    assert target["security_game"]["one_honest_contributor_model"]
    assert target["breakthrough_target_met"] is False


def test_validity_first_escape_hatch_is_only_a_candidate() -> None:
    target = rankvm_wprf_target()
    escape = target["protocol_level_escape_hatch"]
    assert escape["name"] == "validity-first counterproof graph"
    assert escape["eliminates_need_for_new_hard_YES_WPRF"] == "candidate only"


def test_module_entrypoint_matches_target() -> None:
    assert rankvm_wprf_target()["schema"] == "ranklock-rankvm-wprf-target-v2"
