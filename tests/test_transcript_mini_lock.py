from __future__ import annotations

from ranklock.transcript_mini_lock import (
    Poseidon2ConstraintProfile,
    TranscriptConstraintScenario,
    TranscriptInventory,
    canonical_transcript_digest,
    transcript_mini_lock_frontier,
)


def test_poseidon2_constraint_inventory_is_exact_for_profile() -> None:
    profile = Poseidon2ConstraintProfile()
    assert profile.sboxes_per_permutation == 80
    assert profile.multiplication_constraints_per_permutation == 240
    inventory = TranscriptInventory()
    assert inventory.absorbed_field_elements == 59


def test_reference_point_binding_threshold_is_tight() -> None:
    medium = TranscriptConstraintScenario(300)
    assert medium.total_permutations == 38
    assert medium.hash_constraints == 9_120
    assert medium.wrapper_trace_width == 13_656
    assert medium.maximum_point_binding_constraints_per_g1 == 325
    assert medium.fits_reference_trace_width
    assert medium.fits_one_mib

    high = TranscriptConstraintScenario(400)
    assert high.wrapper_trace_width == 14_656
    assert not high.fits_reference_trace_width
    assert not high.fits_one_mib


def test_canonical_transcript_binding_rejects_substitution() -> None:
    points = tuple(bytes([index]) * 64 for index in range(10))
    scalars = tuple(range(20))
    first = canonical_transcript_digest(b"deposit-7", points, scalars)
    changed = list(points)
    changed[4] = b"x" * 64
    second = canonical_transcript_digest(b"deposit-7", tuple(changed), scalars)
    replay = canonical_transcript_digest(b"deposit-8", points, scalars)
    assert first != second
    assert first != replay


def test_frontier_keeps_construction_claim_false() -> None:
    report = transcript_mini_lock_frontier()
    assert report["best_surviving_reference_scenario"]["fits_one_MiB"] is True
    assert report["scenarios"][-1]["fits_one_MiB"] is False
    assert report["breakthrough_target_met"] is False
