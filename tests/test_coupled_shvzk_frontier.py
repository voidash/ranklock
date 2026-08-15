from ranklock.coupled_shvzk_frontier import (
    CouplingAudit,
    SchnorrStatement,
    coupled_honest_nonce,
    coupled_shvzk_frontier,
    honest_transcript,
    simulate_fixed_challenge,
)


def test_schnorr_simulator_and_honest_prover_exactly_coin_couple() -> None:
    statement = SchnorrStatement(123456789)
    simulated = simulate_fixed_challenge(
        statement.public_key,
        challenge=987654321,
        simulated_response=111222333444,
    )
    nonce = coupled_honest_nonce(statement, simulated)
    honest = honest_transcript(statement, challenge=simulated.challenge, nonce=nonce)
    assert simulated == honest
    assert simulated.verifies(statement.public_key)


def test_different_honest_nonce_accepts_but_does_not_match_simulator() -> None:
    statement = SchnorrStatement(9988776655)
    simulated = simulate_fixed_challenge(
        statement.public_key,
        challenge=12345,
        simulated_response=678901234,
    )
    honest = honest_transcript(statement, challenge=12345, nonce=7777777)
    assert honest.verifies(statement.public_key)
    assert honest != simulated


def test_coin_coupling_is_explicitly_not_public_witness_recovery() -> None:
    audit = CouplingAudit(
        SchnorrStatement(42424242),
        challenge=31337,
        simulated_response=8675309,
    )
    result = audit.document()
    assert result["exact_coin_coupling"] is True
    assert result["public_witness_recovery_of_simulated_response"] is False


def test_frontier_requires_predictable_or_wprf_token() -> None:
    result = coupled_shvzk_frontier()
    assert result["breakthrough_target_met"] is False
    assert "witness-computable" in result["required_property"]["name"]
