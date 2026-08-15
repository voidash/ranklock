from __future__ import annotations

from ranklock.fixed_statement_wrapper_candidate import (
    PerDepositCandidateCost,
    fixed_statement_wrapper_candidate,
)
from ranklock.transcript_mini_lock import TranscriptConstraintScenario


def test_medium_transcript_scenario_remains_under_one_mib_but_is_tight() -> None:
    cost = PerDepositCandidateCost(TranscriptConstraintScenario(300))
    assert cost.fixed_relation_key_bytes == 918_850
    assert cost.activation_static_bytes == 1_035_191
    assert cost.activation_plus_future_proof_bytes == 1_036_471
    assert cost.margin_to_one_mib == 12_105
    assert cost.fits_one_mib

    high = PerDepositCandidateCost(TranscriptConstraintScenario(400))
    assert not high.fits_one_mib


def test_global_crs_is_separated_from_per_deposit_material() -> None:
    report = fixed_statement_wrapper_candidate()
    scales = report["reusable_CRS_scenarios"]
    assert scales[0]["prover_time_optimised_reusable_CRS_bytes"] == 1_657_152
    assert scales[1]["prover_time_optimised_reusable_CRS_bytes"] == 8_284_736
    assert scales[2]["prover_time_optimised_reusable_CRS_bytes"] == 162_376_064
    assert scales[2]["prover_MSM_terms"] == 55_816_684


def test_candidate_does_not_claim_breakthrough() -> None:
    report = fixed_statement_wrapper_candidate()
    assert report["practical_breakthrough_size_gate_survives"] is True
    assert report["cryptographic_breakthrough_target_met"] is False
    assert "public zero-knowledge activation proof" in " ".join(
        report["missing_load_bearing_components"]
    )
