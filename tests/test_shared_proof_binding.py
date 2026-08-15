from __future__ import annotations

from ranklock.bn254_real import G1, compress_g1, multiply
from ranklock.shared_proof_binding import (
    SplitBrainProofView,
    build_shared_proof,
    shared_binding_frontier,
)


def _points(offset: int) -> tuple[bytes, ...]:
    return tuple(
        compress_g1(multiply(G1, offset + index, group="g1")) for index in range(10)
    )


def test_split_brain_view_can_hash_one_proof_and_pair_another() -> None:
    honest = _points(11)
    forged = _points(101)
    view = SplitBrainProofView(honest, forged, tuple(range(20)), b"game-7")
    assert view.split_brain_present
    honest_view = SplitBrainProofView(honest, honest, tuple(range(20)), b"game-7")
    assert view.transcript_digest == honest_view.transcript_digest
    assert view.pairing_points != honest_view.pairing_points


def test_shared_typed_proof_has_only_one_group_view() -> None:
    encodings = _points(31)
    proof = build_shared_proof(encodings, tuple(range(20)), context=b"game-9")
    assert tuple(element.transcript_bytes for element in proof.group_elements) == encodings
    assert tuple(compress_g1(point) for point in proof.pairing_points) == encodings


def test_frontier_does_not_turn_unmeasured_binding_into_a_size_claim() -> None:
    report = shared_binding_frontier()
    assert report["separate_hash_and_pairing_witnesses_allowed"] is False
    assert report["canonical_parse_can_remove_a_separate_equality_proof"] is True
    assert report["breakthrough_target_met"] is False
