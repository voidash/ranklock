from __future__ import annotations

import json
from pathlib import Path

from ranklock.algebraic_input_auth import input_auth_cost

from ranklock.authenticated_witness_lift import lift_cost_inventory
from ranklock.commitment_oblivious_lower_bound import lower_bound_scope
from ranklock.kzg_we_conjunction import conjunction_cost_inventory
from ranklock.memory_air import MemoryAccess
from ranklock.phased_memory import commit_memory_argument
from ranklock.ppe_normal_form import FormalKzgSrs
from ranklock.static_kzg_we import static_timing_inventory
from ranklock.vole_input_auth import vole_input_auth_cost
from ranklock.unified_memory_opening import (
    batch_published_openings,
    commit_unified_memory_phase_two,
    open_unified_memory,
    publish_opening_values,
    unified_opening_inventory,
)

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

accesses = (
    MemoryAccess(1, 0, 5, 1),
    MemoryAccess(1, 1, 5, 0),
    MemoryAccess(2, 2, 7, 1),
    MemoryAccess(2, 3, 7, 0),
    MemoryAccess(1, 4, 9, 1),
    MemoryAccess(1, 5, 9, 0),
)
srs = FormalKzgSrs(tau=1061)
committed = commit_memory_argument(
    accesses, address_bits=4, timestamp_bits=4, srs=srs
)
proof = open_unified_memory(
    commit_unified_memory_phase_two(
        committed, beacon_one=bytes.fromhex("83" * 32), srs=srs
    ),
    beacon_two=bytes.fromhex("84" * 32),
    srs=srs,
)
publication = publish_opening_values(proof)
batched = batch_published_openings(
    publication, beacon_three=bytes.fromhex("85" * 32), srs=srs
)
opening_inventory = unified_opening_inventory(proof, batched)

document = {
    "schema": "ranklock-cds-research-results-v1",
    "evidence_class": "FORMAL exponent-space model with executable attacks/regressions",
    "memory_opening_conjunction": opening_inventory,
    "direct_kzg_we_after_batching": conjunction_cost_inventory(
        opening_inventory["batched_kzg_openings"]
    ),
    "unbatched_kzg_we": conjunction_cost_inventory(
        opening_inventory["raw_kzg_openings"]
    ),
    "static_timing": static_timing_inventory(
        fixed_commitment=False,
        finite_point_domain=256,
        finite_value_domain=256,
    ),
    "reusable_public_update_barrier": lower_bound_scope(),
    "authenticated_witness_lift": lift_cost_inventory(
        dynamic_bytes=132, authenticated_chunks=132
    ),
    "algebraic_input_authentication": input_auth_cost().document(),
    "vole_projective_input": vole_input_auth_cost().document(),
    "decision": {
        "opening_equation_count_is_primary_blocker": False,
        "fixed_input_authentication_compresses_to_two_gadget_shapes": True,
        "one_time_token_delivery_solved": False,
        "vector_ole_interface_candidate": True,
        "vector_ole_protocol_implemented": False,
        "dynamic_four-opening_kzg_we_is_small": True,
        "static_fault_secret_lock_constructed": False,
        "next_question": (
            "instantiate a fixed authenticated-input relation in the LVA-WE framework and "
            "measure CRS/decryption work, or construct commitment-oblivious projective WE"
        ),
    },
}
(RESULTS / "cds_research.json").write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n"
)
print(json.dumps(document, indent=2, sort_keys=True))
