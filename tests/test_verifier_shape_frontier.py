from __future__ import annotations

from ranklock.verifier_shape_frontier import reference_shape_frontier


def test_v017_frontier_replaces_identity_target_with_timing_and_separation() -> None:
    frontier = reference_shape_frontier()
    by_name = {shape["name"]: shape for shape in frontier["shapes"]}

    fixed_kzg = by_name["fixed-statement KZG-opening witness encryption"]
    assert fixed_kzg["normalized_target_is_identity"]
    assert fixed_kzg["direct_statement_lock_holds"]
    assert fixed_kzg["lock_interface_holds"]
    assert not fixed_kzg["complete_construction_holds"]
    assert fixed_kzg["blockers"] == [
        "malicious activation does not prove ciphertext/fault-share consistency"
    ]

    leaked = by_name["reusable rank-two KZG anchors with exposed r[1]"]
    assert not leaked["lock_interface_holds"]
    assert any("leaks the unlock key" in blocker for blocker in leaked["blockers"])

    future = by_name["basis-separated KZG with future commitment/value"]
    assert not future["lock_interface_holds"]
    assert any("unavailable at activation" in blocker for blocker in future["blockers"])


def test_one_sided_wrapper_passes_group_shape_but_not_static_lift() -> None:
    frontier = reference_shape_frontier()
    by_name = {shape["name"]: shape for shape in frontier["shapes"]}

    groth16 = by_name["Groth16 normalized PPE"]
    assert not groth16["lock_interface_holds"]
    assert any("dynamic G2" in blocker for blocker in groth16["blockers"])

    one_sided = by_name["one-sided monomial/KZG wrapper final equation"]
    assert one_sided["dynamic_g2_terms"] == 0
    assert one_sided["fixed_g2_anchor_rank"] == 2
    assert not one_sided["lock_interface_holds"]
    assert any("unavailable at activation" in blocker for blocker in one_sided["blockers"])
    assert not any("challenge consistency" in blocker for blocker in one_sided["blockers"])
    assert one_sided["fiat_shamir_or_challenge_consistency_bound"]

    target = by_name["target-separated low-rank fixed-G2 direct-lock target"]
    assert target["direct_statement_lock_holds"]
    assert not target["complete_construction_holds"]
    assert "knowledge-sound proof backend is not constructed" in target["blockers"]
