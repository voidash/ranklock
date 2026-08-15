from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "STATUS.json"
status = json.loads(path.read_text())
status["schema"] = "ranklock-research-status-v6"
status["version"] = "0.15.0"
status["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
status["breakthrough_target_met"] = False
status["production_ready"] = False
status["test_baseline"] = {
    "command": "PYTHONPATH=src pytest -q",
    "passed": 162,
    "failed": 0,
}

cds = status.setdefault("conditional_disclosure", {})
cds.update(
    {
        "real_projective_input_execution": True,
        "projective_input_bytes": 132,
        "projective_binary_ots": 1056,
        "projective_complete_public_and_interactive_bytes": 257418,
        "projective_backend": (
            "online Chou-Orlandi-style measurement baseline; not final DFB protocol"
        ),
        "real_bn254_kzg_opening_we": True,
        "real_kzg_we_ciphertext_bytes": 112,
        "hybrid_online_trace_encapsulator_required": True,
        "hybrid_no_online_authority_target_met": False,
        "fixed_linear_static_encapsulation_constructed": True,
        "fixed_linear_ciphertext_bytes": 48,
        "fixed_linear_132_plus_64_retained_bytes": 134604,
        "fixed_linear_trace_is_rankvm_invalidity": False,
        "batched_setup_dleq": True,
        "maximum_reference_trace_width_under_one_mib": 13912,
        "direct_relation_all_events_retained_bytes": 167580432,
        "direct_relation_route_killed": True,
        "actual_duty_free_bits_projectivization_implemented": False,
        "full_rankvm_fixed_relation_constructed": False,
        "real_lva_or_ppe_we_for_full_relation_constructed": False,
        "formal_recursive_ppe_candidate": True,
        "formal_recursive_ppe_candidate_is_construction": False,
        "static_encapsulation_constructed": False,
        "static_encapsulation_scope": (
            "not constructed for complete RankVM invalidity; constructed only for a fixed linear trace predicate"
        ),
        "vector_ole_protocol_implemented": False,
        "one_time_token_delivery_constructed": True,
        "one_time_token_delivery_scope": "real online binary-OT baseline only",
    }
)

classes = status.setdefault("evidence_classes", {})
exact = classes.setdefault("exact_or_reproduced", [])
for item in (
    "real secp256k1 1,056-OT execution for 132 future bytes with exact transcript accounting",
    "actual BN254 KZG commitment/opening verification and 112-byte opening-WE ciphertext",
    "concrete hybrid split-secret construction proving the future-statement online-encapsulator barrier",
    "static fixed-linear relation with future authenticated bytes as witness variables and no post-statement holder",
    "Fiat-Shamir random-linear-combination DLEQ setup proof and exact key-size reduction",
    "direct fixed-relation byte barrier: 8.27 MiB multiplication-only and 159.82 MiB all-event material",
    "parallel v0.15 checkpoint reproduced with 109 passing and two failing tests",
):
    if item not in exact:
        exact.append(item)
formal = classes.setdefault("formal_model_only", [])
for item in (
    "recursive transparent-proof to Groth16 PPE reduction candidate",
    "projective PPE component-count envelope",
):
    if item not in formal:
        formal.append(item)
open_items = [
    item
    for item in classes.setdefault("open", [])
    if item
    not in {
        "sub-megabyte projective input encoding",
        "static conditional disclosure for future arbitrary commitment/opening statements",
        "complete LVA-WE gadget/CRS/decryption cost for the authenticated-input relation",
    }
]
for item in (
    "faithful noninteractive malicious-receiver Duty-Free-Bits projectivization",
    "complete fixed RankVM-invalidity LVA/PPE relation and exact CRS/encryption-key cost",
    "knowledge-sound transparent/folding or recursive wrapper implementation",
    "malicious distributed setup for projective inputs and fixed conditional lock",
):
    if item not in open_items:
        open_items.append(item)
classes["open"] = open_items

status["safe_research_wrappers"] = [
    "ranklock.phased_air",
    "ranklock.phased_permutation",
    "ranklock.phased_memory",
    "ranklock.batched_opening",
    "ranklock.constraint_backend (transparent constraint validation only)",
    "ranklock.real_secp (variable-time research arithmetic)",
    "ranklock.co_ot (online measurement baseline)",
    "ranklock.projective_vole_lock (real one-shot OT path; not final DFB)",
    "ranklock.real_kzg_we (actual BN254 arithmetic; local experimental SRS)",
    "ranklock.hybrid_conditional_lock (online-authority failure certificate)",
    "ranklock.static_linear_conjunction (real fixed linear predicate only)",
    "ranklock.batched_inner_product_we (ROM batch setup proof)",
    "ranklock.groth16_projective_lock (formal exponent-space candidate)",
]
status["next_priority"] = (
    "P0-CDS-4/P0-PROJ-3: compile complete RankVM invalidity into a fixed succinct "
    "LVA/PPE relation; instantiate final noninteractive DFB projectivization and "
    "malicious distributed setup"
)
status["parallel_priorities"] = {
    "conditional_disclosure_lane": (
        "P0-CDS-4 real fixed RankVM relation and LVA/PPE-WE cost; P0-PROJ-3 "
        "final DFB projectivization; P0-SETUP-1 malicious activation"
    ),
    "field_backend_lane": (
        "P0-PCS-1 physical lookup/PCS benchmark for rank-5 3x85 and 2x127 "
        "including parsing/SHA"
    ),
}
status["parallel_checkpoint_validation"] = {
    "checkpoint": "ranklock-v0.15-research-breakthrough.zip",
    "accepted_as_baseline": False,
    "tests_passed": 109,
    "tests_failed": 2,
    "evidence": "results/parallel_checkpoint_validation.json",
}

path.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n")
