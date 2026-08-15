from __future__ import annotations

from ranklock.hidden_challenge_audit import (
    hidden_challenge_audit,
    monomial_snark_challenge_stages,
)


def test_published_schedule_has_eight_hash_calls_and_ten_challenges() -> None:
    stages = monomial_snark_challenge_stages()
    assert len(stages) == 8
    assert sum(len(stage.challenges) for stage in stages) == 10
    assert stages[0].challenges == ("delta_1", "delta_2")
    assert stages[5].challenges == ("xi", "lambda_e")
    assert stages[-1].prover_outputs_after == ("Q_e",)


def test_naive_hidden_raw_challenge_route_is_killed_but_full_lip_is_not() -> None:
    report = hidden_challenge_audit()
    assert report["naive_hide_raw_fiat_shamir_challenges_killed"] is True
    assert all(
        not stage["naive_projective_hidden_challenge_possible"]
        for stage in report["stages"]
    )
    assert any("linear interactive proof" in item for item in report["not_ruled_out"])
    assert "public Fiat-Shamir proof" in report["surviving_route"]
