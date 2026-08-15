from __future__ import annotations

from dataclasses import replace

from ranklock.kzg_we_model import generator
from ranklock.ppe_normal_form import FormalKzgSrs
from ranklock.two_beacon_permutation import (
    commit_sequences,
    permutation_cost_inventory,
    respond_to_beacons,
    verify_permutation,
)


def test_two_beacon_permutation_accepts_a_real_permutation() -> None:
    srs = FormalKzgSrs(tau=211)
    left = (3, 5, 7, 11, 13, 17, 19, 23)
    right = (19, 3, 23, 11, 5, 17, 13, 7)
    state = commit_sequences(left, right, srs=srs)
    proof = respond_to_beacons(state, beta=31, zeta=47, srs=srs)
    assert verify_permutation(proof, srs=srs)
    inventory = permutation_cost_inventory(len(left))
    assert inventory["beacons"] == 2
    assert inventory["proof_shape_independent_of_rows"] is True


def test_non_permutation_fails_end_boundary() -> None:
    srs = FormalKzgSrs(tau=223)
    state = commit_sequences((1, 2, 3, 4), (1, 2, 3, 5), srs=srs)
    proof = respond_to_beacons(state, beta=37, zeta=53, srs=srs)
    assert proof.z_at_end.value != 1
    assert not verify_permutation(proof, srs=srs)


def test_tampered_phase_two_commitment_or_beacon_response_fails() -> None:
    srs = FormalKzgSrs(tau=227)
    state = commit_sequences((2, 4, 6, 8), (8, 2, 6, 4), srs=srs)
    proof = respond_to_beacons(state, beta=41, zeta=59, srs=srs)
    assert verify_permutation(proof, srs=srs)
    assert not verify_permutation(
        replace(proof, commitment_q=proof.commitment_q + generator("G1", srs.modulus)),
        srs=srs,
    )
    assert not verify_permutation(replace(proof, beta=proof.beta + 1), srs=srs)
