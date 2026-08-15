from __future__ import annotations

from ranklock.batched_opening import (
    batching_cost_inventory,
    prove_batched_opening,
    prove_with_claimed_values,
    verify_batched_opening,
    verify_known_rho_aggregate,
)
from ranklock.one_beacon_air import poly_add, poly_scale
from ranklock.ppe_normal_form import FormalKzgSrs


def test_known_batching_scalar_allows_false_values_to_cancel() -> None:
    srs = FormalKzgSrs(tau=907)
    point = 37
    rho = 41
    polynomials = ((3, 5, 7), (11, 13, 17))
    commitments = tuple(srs.commit_g1(poly) for poly in polynomials)
    true_values = tuple(srs.opening_g1(poly, point)[0] for poly in polynomials)
    aggregate = poly_add(
        polynomials[0], poly_scale(polynomials[1], rho, srs.modulus), srs.modulus
    )
    _aggregate_value, opening = srs.opening_g1(aggregate, point)
    delta = 19
    false_values = (
        (true_values[0] - rho * delta) % srs.modulus,
        (true_values[1] + delta) % srs.modulus,
    )
    assert false_values[0] != true_values[0]
    assert false_values[1] != true_values[1]
    assert verify_known_rho_aggregate(
        commitments=commitments,
        point=point,
        claimed_values=false_values,
        rho=rho,
        opening=opening,
        srs=srs,
    )


def test_value_phase_then_beacon_accepts_true_values() -> None:
    srs = FormalKzgSrs(tau=911)
    proof = prove_batched_opening(
        ((2, 3, 5), (7, 11, 13), (17, 19, 23)),
        point=43,
        beacon=bytes.fromhex("71" * 32),
        srs=srs,
    )
    assert verify_batched_opening(proof, srs=srs)


def test_false_values_fixed_before_rho_fail_except_negligible_collision() -> None:
    srs = FormalKzgSrs(tau=919)
    polynomials = ((2, 3, 5), (7, 11, 13))
    point = 47
    true_values = tuple(srs.opening_g1(poly, point)[0] for poly in polynomials)
    false_values = (
        (true_values[0] + 1) % srs.modulus,
        (true_values[1] + 1) % srs.modulus,
    )
    proof = prove_with_claimed_values(
        polynomials,
        point=point,
        claimed_values=false_values,
        beacon=bytes.fromhex("72" * 32),
        srs=srs,
    )
    assert not verify_batched_opening(proof, srs=srs)
    inventory = batching_cost_inventory(20)
    assert inventory["batched_openings"] == 1
    assert inventory["additional_external_beacon"] == 1
