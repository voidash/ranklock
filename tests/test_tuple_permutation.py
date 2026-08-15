from __future__ import annotations

from dataclasses import replace

from ranklock.ppe_normal_form import FormalKzgSrs
from ranklock.tuple_permutation import (
    commit_tuple_sequences,
    respond_tuple_permutation,
    tuple_permutation_cost,
    verify_tuple_permutation,
)


def test_tuple_permutation_accepts_reordering_without_packing_collisions() -> None:
    srs = FormalKzgSrs(tau=401)
    left = ((1, 10, 100, 0), (2, 20, 200, 1), (1, 30, 300, 1), (2, 40, 400, 0))
    right = (left[2], left[0], left[3], left[1])
    state = commit_tuple_sequences(left, right, srs=srs)
    proof = respond_tuple_permutation(state, eta=43, beta=47, zeta=67, srs=srs)
    assert verify_tuple_permutation(proof, srs=srs)
    cost = tuple_permutation_cost(len(left), len(left[0]))
    assert cost["beacons"] == 2
    assert cost["proof_shape_independent_of_rows"] is True


def test_tuple_mutation_fails_grand_product_boundary() -> None:
    srs = FormalKzgSrs(tau=409)
    left = ((1, 2), (3, 4), (5, 6), (7, 8))
    right = ((1, 2), (3, 4), (5, 6), (7, 9))
    state = commit_tuple_sequences(left, right, srs=srs)
    proof = respond_tuple_permutation(state, eta=53, beta=59, zeta=71, srs=srs)
    assert proof.z_end.value != 1
    assert not verify_tuple_permutation(proof, srs=srs)


def test_tuple_challenge_tampering_fails() -> None:
    srs = FormalKzgSrs(tau=419)
    left = ((1, 2, 3), (4, 5, 6), (7, 8, 9))
    right = (left[2], left[0], left[1])
    proof = respond_tuple_permutation(
        commit_tuple_sequences(left, right, srs=srs),
        eta=61,
        beta=67,
        zeta=73,
        srs=srs,
    )
    assert verify_tuple_permutation(proof, srs=srs)
    assert not verify_tuple_permutation(replace(proof, eta=proof.eta + 1), srs=srs)
