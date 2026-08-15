#!/usr/bin/env python3
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUS = ROOT / "STATUS.json"

s = json.loads(STATUS.read_text())
s["schema"] = "ranklock-research-status-v8"
s["version"] = "0.17.0"
s["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
s["breakthrough_target_met"] = False
s["production_ready"] = False
s["test_baseline"] = {
    "command": "PYTHONPATH=src python scripts/run_test_files.py --workers 6 --timeout 420",
    "passed": 206,
    "failed": 0,
    "execution_note": "per-file clean execution avoids the monolithic pytest runner's constrained-runtime stall",
}

cd = s.setdefault("conditional_disclosure", {})
cd.update(
    {
        "split_basis_ppe_we_real_bn254": True,
        "identity_target_universal_blocker": False,
        "correct_session_security_criterion": "statement-side accepting session has no public decomposition over the scaled witness-anchor span",
        "statement_span_disclosure_attack_reproduced": True,
        "basis_separated_kzg_real_bn254": True,
        "basis_separated_kzg_static_timing_solved": False,
        "one_sided_final_pairing_real_bn254": True,
        "one_sided_dynamic_G2_proof_elements": 0,
        "one_sided_fixed_G2_anchor_rank": 2,
        "complete_one_sided_SNARK_implemented": False,
        "raw_hidden_fiat_shamir_route_killed": True,
        "public_transcript_mini_lock_constructed": False,
        "public_transcript_reference_wrapper_constraints": 13656,
        "public_transcript_max_point_binding_constraints_per_G1": 325,
        "shared_proof_object_binding_real_bn254": True,
        "ciphertext_free_fault_key_real_secp256k1": True,
        "ciphertext_or_payload_retained": False,
        "activation_relation_executable": True,
        "activation_zero_knowledge_proof_implemented": False,
        "fixed_statement_reference_static_plus_future_proof_bytes": 1036471,
        "fixed_statement_reference_one_MiB_margin_bytes": 12105,
        "fixed_statement_reference_is_cost_envelope": True,
        "fixed_statement_complete_rankvm_lock_constructed": False,
    }
)

s["next_priority"] = (
    "P0-CDS-6/P0-SETUP-3: instantiate the complete fixed-statement one-sided RankVM-invalidity wrapper, "
    "shared public transcript and rank-two PPE, session-derived Bitcoin key, and public n-1-corrupt activation proof"
)

p = s.setdefault("parallel_priorities", {})
p["conditional_disclosure_lane"] = [
    "P0-CDS-6 real one-sided wrapper and outer-curve implementation",
    "P0-SETUP-3 activation NIZK and ceremony",
    "P0-PROJ-3 noninteractive malicious-receiver projectivization",
]
p["field_backend_lane"] = [
    "physical 3x85 rank-5 versus 2x127 proof benchmark",
    "complete parsing/SHA/range inventory",
    "real prover memory, proof size, and verifier measurements",
]

safe = set(s.setdefault("safe_research_wrappers", []))
safe.update(
    {
        "split_basis_ppe_we.py",
        "basis_separated_kzg.py",
        "one_sided_wrapper_frontier.py",
        "hidden_challenge_audit.py",
        "transcript_mini_lock.py",
        "shared_proof_binding.py",
        "ciphertext_free_fault_key.py",
        "activation_nizk_frontier.py",
        "fixed_statement_wrapper_candidate.py",
    }
)
s["safe_research_wrappers"] = sorted(safe)

exact = s.setdefault("evidence_classes", {}).setdefault("exact_or_reproduced", [])
for item in [
    "real BN254 split-basis PPE conditional session and exact statement-span disclosure attack",
    "real BN254 basis-separated KZG opening relation and scaled-statement-basis disclosure attack",
    "real BN254 one-sided final pairing equation with future G1 only and fixed-G2 rank two",
    "exact nonlinear-dependency audit killing raw hidden Fiat-Shamir adaptation of the reference prover",
    "real canonical BN254 shared-proof split-brain regression and typed-object repair",
    "real BN254-session to secp256k1 fault-key derivation with no encrypted payload",
    "executable activation NP relation and fail-closed contributor ceremony state machine",
]:
    if item not in exact:
        exact.append(item)

formal = s["evidence_classes"].setdefault("formal_model_only", [])
for item in [
    "Poseidon2-style public transcript mini-lock and 325-constraint/G1 planning threshold",
    "fixed-statement one-sided wrapper relation-key and reusable-CRS byte envelope",
]:
    if item not in formal:
        formal.append(item)

open_items = s["evidence_classes"].setdefault("open", [])
# Remove superseded activation wording if present.
superseded = {
    "target-separated knowledge-sound low-rank fixed-G2 wrapper for complete RankVM invalidity",
    "public ciphertext/fault-share consistency proof for malicious distributed activation",
}
open_items[:] = [item for item in open_items if item not in superseded]
for item in [
    "complete one-sided proof-system implementation on a RankVM-compatible outer curve",
    "real canonical outer-curve G1 parsing/subgroup gadget below the current size threshold",
    "real public transcript verifier and LVA/conditional compiler",
    "complete RankVM/SP1 invalidity circuit with projective authentication, parsing, SHA and ranges",
    "public zero-knowledge activation proof binding scaled anchors, session and secp fault key",
    "n-1-corrupt contributor ceremony with epoch burn/restart and Bitcoin graph activation",
]:
    if item not in open_items:
        open_items.append(item)

s["v017_checkpoint"] = {
    "decision": "FIXED_STATEMENT_ONE_SIDED_ROUTE_SURVIVES; BREAKTHROUGH_NOT_MET",
    "results": "results/v017_checkpoint.json",
    "decision_document": "docs/41_V017_DECISION.md",
    "reference_static_plus_future_proof_bytes": 1036471,
    "reference_margin_to_one_MiB_bytes": 12105,
    "planning_assumptions": [
        "64-byte outer G1 encoding",
        "128-byte outer G2 encoding",
        "66-byte fixed-relation key slope per scalar coordinate",
        "300 constraints per canonically bound G1 proof element",
    ],
    "warning": "planning assumptions are not outer-curve/LVA-WE implementation measurements",
}

STATUS.write_text(json.dumps(s, indent=2, sort_keys=True) + "\n")
