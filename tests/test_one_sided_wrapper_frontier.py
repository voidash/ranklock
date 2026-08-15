from __future__ import annotations

from ranklock.bn254_real import G1, compress_g1, multiply
from ranklock.one_sided_wrapper_frontier import (
    DFB_LEADING_EXPRESSION_BYTES,
    KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL,
    OneSidedFinalPairingEquation,
    OneSidedSnarkProfile,
    one_sided_wrapper_frontier,
    transcript_strategy_frontier,
)


def test_real_one_sided_final_pairing_equation_has_rank_two() -> None:
    equation = OneSidedFinalPairingEquation(trapdoor_s=17, challenge_alpha=19)
    witness = equation.accepting_witness(23)
    assert equation.fixed_g2_anchor_rank == 2
    assert equation.accepts(witness)

    forged = (witness[0], compress_g1(multiply(G1, 29, group="g1")))
    assert not equation.accepts(forged)
    assert not equation.accepts((witness[0],))


def test_one_sided_profile_cost_formulas_are_exact() -> None:
    profile = OneSidedSnarkProfile()
    assert profile.one_sided_pairing_interface_holds
    assert profile.proof_bytes(g1_bytes=64, scalar_bytes=32) == 1_280
    assert (
        profile.shared_crs_bytes(
            KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL,
            g1_bytes=64,
            g2_bytes=128,
            mode="prover_time",
        )
        == KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL * 64 + 256
    )
    assert (
        profile.shared_crs_bytes(
            KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL,
            g1_bytes=64,
            g2_bytes=128,
            mode="proof_size",
        )
        == 3 * KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL * 64 + 256
    )
    assert profile.prover_msm_terms(KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL) == (
        22 * KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL
    )


def test_transcript_frontier_exposes_three_non_equivalent_routes() -> None:
    by_name = {strategy.name: strategy for strategy in transcript_strategy_frontier()}
    public_fs = by_name["public Fiat-Shamir proof as witness"]
    assert public_fs.hash_inside_lock_required
    assert not public_fs.hidden_linear_response_audit_required

    hidden = by_name["underlying interactive LVA with hidden verifier challenges"]
    assert not hidden.hash_inside_lock_required
    assert hidden.hidden_linear_response_audit_required

    beacon = by_name["future Bitcoin beacon replaces Fiat-Shamir"]
    assert beacon.authentic_future_beacon_required
    assert all(not strategy.constructed for strategy in by_name.values())


def test_frontier_keeps_shared_crs_and_per_deposit_material_separate() -> None:
    report = one_sided_wrapper_frontier()
    first = report["circuit_scenarios"][0]
    assert first["circuit_gate_assumption"] == KNOWN_NATIVE_FQ_PRODUCT_SUBTOTAL
    assert first["proof_bytes"] == 1_280
    assert first["DFB_leading_expression_plus_proof_bytes"] == (
        DFB_LEADING_EXPRESSION_BYTES + 1_280
    )
    assert first["prover_time_optimised_shared_CRS_bytes"] > 1 << 20
    assert first["current_projective_layer_plus_proof_bytes"] < 1 << 20
    assert report["breakthrough_gates"]["breakthrough_target_met"] is False
