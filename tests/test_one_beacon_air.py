from __future__ import annotations

from dataclasses import replace

from ranklock.kzg_we_model import generator
from ranklock.one_beacon_air import (
    LocalAirTrace,
    air_cost_inventory,
    prove_local_air,
    verify_local_air,
)
from ranklock.ppe_normal_form import FormalKzgSrs


def _trace(rows: int = 8) -> LocalAirTrace:
    a = tuple(index + 2 for index in range(rows))
    b = tuple(3 * index + 5 for index in range(rows))
    c = tuple(x * y for x, y in zip(a, b, strict=True))
    delta = 7
    state = tuple(11 + delta * index for index in range(rows))
    return LocalAirTrace(a, b, c, state, delta)


def test_one_beacon_air_binds_products_and_local_wiring() -> None:
    trace = _trace()
    srs = FormalKzgSrs(tau=101)
    output = prove_local_air(trace, beacon_point=37, srs=srs)
    assert verify_local_air(output.proof, delta=trace.delta, srs=srs)
    inventory = air_cost_inventory(output.proof)
    assert inventory["random_beacons"] == 1
    assert inventory["fiat_shamir_hashes_inside_lock"] == 0
    assert inventory["proof_shape_independent_of_rows"] is True


def test_tampered_column_opening_or_transition_fails() -> None:
    trace = _trace()
    srs = FormalKzgSrs(tau=109)
    proof = prove_local_air(trace, beacon_point=43, srs=srs).proof
    openings = dict(proof.openings_at_zeta)
    openings["a"] = replace(openings["a"], value=openings["a"].value + 1)
    assert not verify_local_air(
        replace(proof, openings_at_zeta=openings), delta=trace.delta, srs=srs
    )
    assert not verify_local_air(proof, delta=trace.delta + 1, srs=srs)


def test_tampered_quotient_commitment_fails() -> None:
    trace = _trace()
    srs = FormalKzgSrs(tau=127)
    proof = prove_local_air(trace, beacon_point=47, srs=srs).proof
    commitments = dict(proof.commitments)
    commitments["q_mul"] = commitments["q_mul"] + generator("G1", srs.modulus)
    assert not verify_local_air(
        replace(proof, commitments=commitments), delta=trace.delta, srs=srs
    )
