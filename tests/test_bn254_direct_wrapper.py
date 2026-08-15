from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock.bn254_direct_wrapper import (
    BN254_G1_COFACTOR,
    BN254_G1_UNCOMPRESSED_BYTES,
    CanonicalOneSidedProof,
    CanonicalUncompressedG1,
    Bn254DirectWrapperError,
    Bn254UncompressedPointBindingCost,
    ONE_SIDED_G1_ELEMENTS,
    ONE_SIDED_SCALAR_ELEMENTS,
    ONE_SIDED_UNCOMPRESSED_PROOF_BYTES,
    bn254_direct_wrapper_report,
)
from ranklock.bn254_real import (
    CURVE_ORDER,
    FIELD_MODULUS,
    G1,
    multiply,
    serialize_g1_uncompressed,
)
from ranklock.field_bridge import RangeLookupModel


def _proof() -> CanonicalOneSidedProof:
    points = tuple(
        CanonicalUncompressedG1.from_point(multiply(G1, index + 1, group="g1"))
        for index in range(ONE_SIDED_G1_ELEMENTS)
    )
    return CanonicalOneSidedProof(points, tuple(range(ONE_SIDED_SCALAR_ELEMENTS)))


def test_canonical_uncompressed_parser_is_strict_and_shared() -> None:
    element = CanonicalUncompressedG1.from_point(multiply(G1, 17, group="g1"))
    assert len(element.encoded) == BN254_G1_UNCOMPRESSED_BYTES
    assert serialize_g1_uncompressed(element.point) == element.encoded

    noncanonical_x = FIELD_MODULUS.to_bytes(32, "big") + element.encoded[32:]
    with pytest.raises((ValueError, Bn254DirectWrapperError)):
        CanonicalUncompressedG1(noncanonical_x)

    off_curve = bytearray(element.encoded)
    off_curve[-1] ^= 1
    with pytest.raises((ValueError, Bn254DirectWrapperError)):
        CanonicalUncompressedG1(bytes(off_curve))


def test_one_sided_proof_uses_one_object_for_transcript_and_pairing() -> None:
    proof = _proof()
    assert len(proof.g1) == 10
    assert len(proof.pairing_points) == 10
    assert len(proof.encoded_bytes) == ONE_SIDED_UNCOMPRESSED_PROOF_BYTES == 1_280
    assert proof.transcript_digest(b"deposit-A") != proof.transcript_digest(b"deposit-B")

    changed = list(proof.g1)
    changed[0] = CanonicalUncompressedG1.from_point(multiply(G1, 99, group="g1"))
    forged = CanonicalOneSidedProof(tuple(changed), proof.scalars)
    assert forged.transcript_digest(b"deposit-A") != proof.transcript_digest(b"deposit-A")
    assert forged.pairing_points[0] != proof.pairing_points[0]

    with pytest.raises(Bn254DirectWrapperError):
        CanonicalOneSidedProof(proof.g1, proof.scalars[:-1] + (CURVE_ORDER,))


def test_exact_bn254_point_binding_passes_the_v017_gate() -> None:
    cost = Bn254UncompressedPointBindingCost(RangeLookupModel(16))
    assert cost.config.limbs == 3
    assert cost.config.limb_bits == 85
    assert cost.config.safe_no_wrap
    assert cost.x_cost.logical_rows == 36
    assert cost.y_cost.logical_rows == 36
    assert cost.product_cost.native_products == 5
    assert cost.product_cost.logical_rows == 65
    assert cost.foreign_products == 3
    assert BN254_G1_COFACTOR == 1
    assert cost.subgroup_rows == 0
    assert cost.exact_logical_rows == 267
    assert cost.threshold == 325
    assert cost.fits_threshold
    assert cost.envelope.fits_one_mib
    assert cost.envelope.margin_to_one_mib == 33_885


def test_bn254_direct_route_survives_but_does_not_claim_breakthrough() -> None:
    report = bn254_direct_wrapper_report()
    decision = report["decision"]
    assert decision["BN254_direct_point_binding_gate"] == "passes"
    assert decision["public_Fiat_Shamir_wrapper_route"] == "survives this gate"
    assert decision["reference_rows_per_G1"] == 267
    assert decision["breakthrough_target_met"] is False

    kernel = report["known_kernel_field_bridge"]
    assert kernel["native_nonlinear_products"] == 129_445
    assert kernel["logical_lookup_events_total"] == 1_967_564
    assert kernel["linear_equations_total"] == 440_113

    scenarios = report["reusable_wrapper_CRS_scenarios"]
    assert scenarios[0]["prover_time_CRS_bytes_compressed"] == 4_142_368
    assert scenarios[1]["circuit_gate_assumption"] == 2_537_122
