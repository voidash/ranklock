from __future__ import annotations

from ranklock.bn254_direct_wrapper import (
    CanonicalUncompressedG1,
    Bn254UncompressedPointBindingCost,
)
from ranklock.bn254_real import G1, multiply
from ranklock.one_sided_scalar_verifier import (
    OneSidedVerifierInputs,
    execute_scalar_verifier,
    scalar_verifier_frontier,
)


def test_paired_limb_transcript_encoding_is_native_and_injective() -> None:
    first = CanonicalUncompressedG1.from_point(multiply(G1, 17, group="g1"))
    second = CanonicalUncompressedG1.from_point(multiply(G1, 18, group="g1"))
    packed = first.transcript_field_elements
    assert len(packed) == 3
    assert all(0 <= value < 1 << 170 for value in packed)
    assert packed != second.transcript_field_elements


def test_scalar_verifier_schedule_replaces_the_1024_row_reserve() -> None:
    execution = execute_scalar_verifier(
        OneSidedVerifierInputs.deterministic(2_537_122)
    )
    assert execution.circuit_size_N == 7_611_366
    assert execution.nonlinear_constraints == 161
    assert execution.inversion_constraints == 13
    assert execution.labels["alpha^n/square"] == 21
    assert execution.labels["(alpha/gamma)^N/square"] == 22
    assert execution.outputs["beta_e"] != 0


def test_scalar_cost_changes_only_logarithmically_with_circuit_size() -> None:
    small = execute_scalar_verifier(OneSidedVerifierInputs.deterministic(25_889))
    medium = execute_scalar_verifier(OneSidedVerifierInputs.deterministic(129_445))
    large = execute_scalar_verifier(OneSidedVerifierInputs.deterministic(2_537_122))
    assert small.nonlinear_constraints == 141
    assert medium.nonlinear_constraints == 154
    assert large.nonlinear_constraints == 161


def test_integrated_bn254_wrapper_envelope_now_has_substantial_margin() -> None:
    report = scalar_verifier_frontier()
    envelope = report["integrated_envelope"]
    assert Bn254UncompressedPointBindingCost().exact_logical_rows == 267
    assert report["execution"]["nonlinear_constraints"] == 161
    assert report["transcript"]["G1_field_elements_per_point"] == 3
    assert report["transcript"]["official_KAT_passes"] is True
    assert report["transcript"]["hashed_G1_elements"] == 9
    assert report["transcript"]["challenge_phases"] == 9
    assert report["transcript"]["total_permutations"] == 32
    assert report["transcript"]["hash_constraints"] == 7_680
    assert envelope["wrapper_trace_width"] == 11_023
    assert envelope["fits_one_MiB"] is True
    assert envelope["margin_to_one_MiB_bytes"] == 185_883
    assert report["decision"]["breakthrough_target_met"] is False
