#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from ranklock.bn254_direct_wrapper import bn254_direct_wrapper_report
from ranklock.coupled_shvzk_frontier import coupled_shvzk_frontier
from ranklock.fixed_yes_instance_gap import fixed_yes_instance_gap
from ranklock.laconic_shvzk_we_frontier import laconic_shvzk_we_frontier
from ranklock.lva_gadget_coverage import lva_gadget_coverage
from ranklock.one_sided_lva_decomposition import one_sided_lva_decomposition
from ranklock.one_sided_scalar_verifier import _deterministic_public_proof, scalar_verifier_frontier
from ranklock.one_sided_static_session_gap import one_sided_static_session_checkpoint
from ranklock.poseidon2_bn254_transcript import poseidon2_one_sided_transcript_report
from ranklock.rankvm_wprf_target import rankvm_wprf_target
from ranklock.validity_first_graph import validity_first_graph_checkpoint

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results"


def main() -> None:
    proof = _deterministic_public_proof()
    items = {
        "v018_bn254_direct_wrapper.json": bn254_direct_wrapper_report(),
        "v018_scalar_verifier.json": scalar_verifier_frontier(),
        "v018_poseidon2_transcript.json": poseidon2_one_sided_transcript_report(
            proof, context_field=42
        ),
        "v018_static_session_checkpoint.json": one_sided_static_session_checkpoint(),
        "v018_laconic_shvzk_frontier.json": laconic_shvzk_we_frontier(),
        "v018_coupled_shvzk_frontier.json": coupled_shvzk_frontier(),
        "v018_lva_decomposition.json": one_sided_lva_decomposition(),
        "v018_rankvm_wprf_target.json": rankvm_wprf_target(),
        "v018_yes_instance_gap.json": fixed_yes_instance_gap(),
        "v018_lva_gadget_coverage.json": lva_gadget_coverage(),
        "v018_validity_first_graph.json": validity_first_graph_checkpoint(),
    }
    OUT.mkdir(parents=True, exist_ok=True)
    for name, payload in items.items():
        (OUT / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    checkpoint = {
        "schema": "ranklock-v018-checkpoint-v1",
        "version": "0.18.0",
        "breakthrough_target_met": False,
        "passed_gates": {
            "bn254_cofactor_one_point_binding_rows_per_G1": 267,
            "point_binding_below_old_325_row_ceiling": True,
            "one_sided_scalar_verifier_nonlinear_rows": 161,
            "official_poseidon2_bn256_KAT": True,
            "typed_transcript_permutations": 32,
            "typed_transcript_nonlinear_rows": 7_680,
            "arithmetic_and_transcript_coordinate_envelope_bytes": 862_693,
            "coordinate_envelope_margin_to_one_MiB_bytes": 185_883,
        },
        "failed_or_open_gates": {
            "coordinate_envelope_is_real_conditional_key": False,
            "identity_normalized_PPE_supplies_hidden_session": False,
            "66_byte_scalar_gadget_covers_unknown_log_G1_proof": False,
            "ordinary_NO_instance_WE_covers_fixed_invalidity_relation": False,
            "hard_YES_rankvm_WPRF_constructed": False,
        },
        "new_protocol_pivot": {
            "name": "validity-first counterproof graph",
            "mechanically_expressible_in_existing_immediate_plus_timeout_connector": True,
            "positive_backend_candidate": "BABE + Duty-Free-Bits Embryo",
            "projective_backend_still_required": True,
            "complete_strata_integration": False,
            "security_proof": False,
        },
        "decision": "CONTINUE_WITH_VALIDITY_FIRST_POSITIVE_BACKEND_AND_KEEP_HARD_YES_WPRF_AS_FALLBACK",
        "evidence": sorted(items),
    }
    (OUT / "v018_checkpoint.json").write_text(
        json.dumps(checkpoint, indent=2, sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    main()
