from ranklock.fixed_yes_instance_gap import (
    FixedDepositLanguageProfile,
    HardYesSecurityRequirement,
    ToyHardYesFixture,
    fixed_yes_instance_gap,
)


def test_fixed_ranklock_statement_is_yes_before_the_future_event() -> None:
    profile = FixedDepositLanguageProfile()
    assert profile.future_input_bytes == 164
    assert profile.future_input_bits == 1_312
    assert profile.fixed_statement_is_yes_before_event
    assert not profile.standard_no_instance_we_hiding_applies


def test_toy_relation_separates_membership_from_witness_availability() -> None:
    fixture = ToyHardYesFixture.deterministic()
    assert fixture.statement_is_yes
    value, token = fixture.first_accepting_witness
    assert value != fixture.statement.valid_value
    assert fixture.statement.accepts(value, token)
    assert not fixture.statement.accepts(value, bytes(32))
    assert not fixture.brute_force_short_tokens(2)


def test_required_game_is_hard_yes_and_one_honest_contributor() -> None:
    game = HardYesSecurityRequirement().document()
    assert game["one_honest_contributor_model"] is True
    assert "already-YES" in game["standard_WE_gap"]
    assert "complete authenticated RankVM INVALID witness" in game["required_guarantees"]["extractability"]


def test_checkpoint_refuses_to_claim_breakthrough() -> None:
    report = fixed_yes_instance_gap()
    assert report["language_profile"]["fixed_statement_is_YES_before_event"] is True
    assert report["decision"].startswith("STANDARD_WE_DEFINITION_INSUFFICIENT")
    assert report["breakthrough_target_met"] is False
