from __future__ import annotations

import pytest

from ranklock.outer_curve_candidate import (
    BN254_FQ,
    COMPRESSED_G1_BYTES,
    OUTER_G1_GENERATOR,
    OUTER_KNOWN_NON_SUBGROUP_POINT,
    OUTER_Q,
    OuterCurveCandidate,
    OuterCurveCandidateError,
    compress_g1,
    decompress_g1,
    is_in_prime_subgroup,
    is_on_curve,
    multiply,
    normalise_to_prime_subgroup,
    outer_curve_candidate_report,
)


def test_candidate_has_exact_order_embedding_and_geometry() -> None:
    report = OuterCurveCandidate().validate()
    assert report["base_bits"] == 515
    assert report["scalar_bits"] == 254
    assert report["cofactor_bits"] == 261
    assert report["embedding_degree"] == 6
    assert report["compressed_G1_bytes"] == 65
    assert report["compressed_G2_geometry_lower_bound_bytes"] == 195
    assert all(report["checks"].values())


def test_canonical_compressed_roundtrip_and_flag_rejection() -> None:
    encoded = compress_g1(OUTER_G1_GENERATOR)
    assert len(encoded) == COMPRESSED_G1_BYTES
    assert decompress_g1(encoded, allow_infinity=False) == OUTER_G1_GENERATOR

    malformed = bytearray(encoded)
    malformed[0] |= 0x20
    with pytest.raises(OuterCurveCandidateError):
        decompress_g1(bytes(malformed))

    noncanonical_x = bytearray(OUTER_Q.to_bytes(COMPRESSED_G1_BYTES, "big"))
    with pytest.raises(OuterCurveCandidateError):
        decompress_g1(bytes(noncanonical_x))


def test_subgroup_and_normalisation_are_executable() -> None:
    assert is_on_curve(OUTER_KNOWN_NON_SUBGROUP_POINT)
    assert not is_in_prime_subgroup(OUTER_KNOWN_NON_SUBGROUP_POINT)
    assert is_in_prime_subgroup(OUTER_G1_GENERATOR)
    assert multiply(OUTER_G1_GENERATOR, BN254_FQ) is None

    projected = normalise_to_prime_subgroup(OUTER_KNOWN_NON_SUBGROUP_POINT)
    assert projected is not None
    assert is_in_prime_subgroup(projected)
    assert normalise_to_prime_subgroup(OUTER_G1_GENERATOR) == OUTER_G1_GENERATOR


def test_report_does_not_mislabel_candidate_as_production_curve() -> None:
    report = outer_curve_candidate_report()
    assert "not an audited production" in report["evidence_class"]
    assert "does not publish this exact candidate" in report["source_boundary"]
    assert report["normalisation"]["projected_point_in_prime_subgroup"] is True
