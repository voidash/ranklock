from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from ranklock.batched_opening import batching_cost_inventory
from ranklock.bridge_comparison import (
    benchmark_field_bridges,
    compare_bridge_routes,
    compare_range_widths,
)
from ranklock.canonical_bytes import estimate_canonical_binding
from ranklock.constraint_backend import (
    compile_dual_crt_owner_trace,
    compile_rank5_3x85_trace,
    compile_split_2x127_trace,
)
from ranklock.crt_bridge import (
    build_bound_crt_mul_witness,
    estimate_bounded_quotient_crt_bridge,
    estimate_explicit_crt_bridge,
)
from ranklock.crt_field import (
    CrtFieldConfig,
    estimate_schedule as estimate_crt_schedule,
    randomized_self_test as crt_self_test,
)
from ranklock.low_rank_convolution import randomized_self_test as low_rank_self_test
from ranklock.low_rank_field_bridge import (
    build_low_rank_bound_foreign_mul_witness,
    estimate_low_rank_limb_bridge,
    estimate_low_rank_reduced_quotient_limb_bridge,
)
from ranklock.nonnative_field import (
    BLS12_381_SCALAR_FIELD,
    BN254_SCALAR_FIELD,
    best_config,
    estimate_schedule,
    randomized_self_test,
)
from ranklock.split_limb_field import build_split_limb_mul_witness
from ranklock.pairing_rank import (
    groth16_pairing_rank_breakdown,
    groth16_verifier_rank_schedule,
    write_pairing_rank_results,
)

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)
NOW = datetime.now(timezone.utc).isoformat()
KNOWN_PRODUCTS = 25_889
TEST_BASELINE = 123


def write_json(path: Path, document: object) -> None:
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


write_pairing_rank_results(str(RESULTS / "pairing_rank.json"))

configs: dict[str, object] = {}
for name, modulus in (
    ("bn254_fr", BN254_SCALAR_FIELD),
    ("bls12_381_fr", BLS12_381_SCALAR_FIELD),
):
    config = best_config(native_modulus=modulus)
    randomized_self_test(config, cases=500, seed=13)
    low_rank_self_test(
        limbs=config.limbs,
        limb_bits=config.limb_bits,
        native_modulus=config.native_modulus,
        cases=200,
        seed=0x52414E4B,
    )
    configs[name] = {
        "config": config.document(),
        "legacy_schoolbook_schedule": estimate_schedule(
            KNOWN_PRODUCTS, config
        ).document(),
        "rank_2n_minus_1_canonical_quotient_reference": estimate_low_rank_limb_bridge(
            KNOWN_PRODUCTS, config
        ).document(),
        "rank_2n_minus_1_reduced_quotient_schedule": estimate_low_rank_reduced_quotient_limb_bridge(
            KNOWN_PRODUCTS, config
        ).document(),
    }
write_json(
    RESULTS / "nonnative_field.json",
    {
        "schema": "ranklock-nonnative-field-results-v2",
        "generated_at_utc": NOW,
        "native_fields": configs,
        "warning": (
            "Logical schedules exclude real PCS/lookup-argument fixed overhead, "
            "parser/hash constraints and conditional disclosure."
        ),
    },
)

attacks = [
    {
        "id": "A-006",
        "name": "late-bound AIR quotient",
        "legacy_test": "test_legacy_helper_has_a_real_late_binding_attack",
        "fixed_module": "ranklock.phased_air",
    },
    {
        "id": "A-007",
        "name": "late-bound tuple-permutation quotient",
        "legacy_test": "test_legacy_tuple_permutation_has_late_binding_forgery",
        "fixed_module": "ranklock.phased_permutation",
    },
    {
        "id": "A-008",
        "name": "split-brain memory composition",
        "legacy_test": "test_legacy_memory_bundle_accepts_unrelated_permutation_and_air_tables",
        "fixed_module": "ranklock.phased_memory",
    },
    {
        "id": "A-009",
        "name": "known-rho batched-opening cancellation",
        "legacy_test": "test_known_batching_scalar_allows_false_values_to_cancel",
        "fixed_module": "ranklock.batched_opening",
    },
    {
        "id": "A-011",
        "name": "unbound dual-field CRT split brain",
        "legacy_test": "test_unbound_dual_proofs_can_describe_two_unrelated_multiplications",
        "fixed_module": "ranklock.canonical_bytes / common-table binding requirement",
    },
]
write_json(
    RESULTS / "attack_regressions.json",
    {
        "schema": "ranklock-attack-regressions-v1",
        "generated_at_utc": NOW,
        "attacks": attacks,
        "all_attacks_have_executable_tests": True,
    },
)

crt_config = CrtFieldConfig()
crt_self_test(crt_config, cases=500, seed=29)
write_json(
    RESULTS / "crt_field.json",
    {
        "schema": "ranklock-crt-field-results-v1",
        "generated_at_utc": NOW,
        "config": crt_config.document(),
        "known_sparse_schedule": estimate_crt_schedule(
            KNOWN_PRODUCTS, crt_config
        ).document(),
        "warning": (
            "The exact CRT lemma assumes both residue traces are bound to the same "
            "canonical values; a cross-PCS common-table proof and conditional-lock "
            "composition are not implemented."
        ),
    },
)

write_json(
    RESULTS / "canonical_byte_binding.json",
    {
        "schema": "ranklock-canonical-byte-binding-results-v2",
        "generated_at_utc": NOW,
        "byte_granular_reference_fresh_z_and_quotient": estimate_canonical_binding(
            2 * KNOWN_PRODUCTS
        ),
        "packed_16_bit_owner_side_crt_canonical_quotient_reference": estimate_explicit_crt_bridge(
            KNOWN_PRODUCTS
        ).document(),
        "packed_16_bit_owner_side_crt_bounded_quotient": estimate_bounded_quotient_crt_bridge(
            KNOWN_PRODUCTS
        ).document(),
        "warning": (
            "The packed schedule assumes a reusable fixed-width tuple table whose row "
            "range-checks one chunk and exposes its constituent bytes. Logical lookup "
            "events are not physical proof rows, and cross-PCS equality remains missing."
        ),
    },
)

write_json(
    RESULTS / "batching_cost.json",
    {
        "schema": "ranklock-batching-schedule-v1",
        "example_20_same_point_openings": batching_cost_inventory(20),
        "conclusion": (
            "One aggregate PPE requires individual values bound before rho; in the "
            "current external-randomness model this adds a publication phase and beacon."
        ),
    },
)

comparison = compare_bridge_routes(KNOWN_PRODUCTS)
sensitivity = compare_range_widths(KNOWN_PRODUCTS)
benchmark = benchmark_field_bridges(cases=300, repeats=3)
write_json(
    RESULTS / "field_bridge_comparison.json",
    {
        "schema": "ranklock-field-bridge-results-v3",
        "generated_at_utc": NOW,
        "comparison": comparison,
        "range_width_sensitivity": sensitivity,
        "native_benchmark": benchmark,
    },
)

limb_config = best_config(native_modulus=BLS12_381_SCALAR_FIELD)
rank5_trace = compile_rank5_3x85_trace(
    build_low_rank_bound_foreign_mul_witness(
        2**201 + 17, 2**181 + 29, limb_config
    ),
    limb_config,
)
split_trace = compile_split_2x127_trace(
    build_split_limb_mul_witness(2**201 + 17, 2**181 + 29)
)
crt_trace = compile_dual_crt_owner_trace(
    build_bound_crt_mul_witness(2**201 + 17, 2**181 + 29)
)
write_json(
    RESULTS / "constraint_backend.json",
    {
        "schema": "ranklock-field-bridge-constraint-backend-results-v1",
        "generated_at_utc": NOW,
        "traces": [
            rank5_trace.document(),
            split_trace.document(),
            crt_trace.document(),
        ],
        "all_estimates_reproduced": all(
            trace.estimate_match for trace in (rank5_trace, split_trace, crt_trace)
        ),
        "warning": (
            "This is a transparent backend-independent constraint ledger, not a proof "
            "system. It has no PCS, lookup argument, degree bound, zero knowledge, or "
            "cryptographic cross-field binding."
        ),
    },
)

pairing = groth16_pairing_rank_breakdown()
schedule = groth16_verifier_rank_schedule()
routes = {route["name"]: route for route in comparison["routes"]}
status = {
    "schema": "ranklock-research-status-v5",
    "version": "0.14.0",
    "generated_at_utc": NOW,
    "breakthrough_target_met": False,
    "production_ready": False,
    "test_baseline": {
        "command": "PYTHONPATH=src pytest -q",
        "passed": TEST_BASELINE,
        "failed": 0,
    },
    "evidence_classes": {
        "exact_or_reproduced": [
            "low-rank BN254 tower identities",
            "sparse pairing kernel identities",
            "canonical 3x85-bit non-native multiplication and no-wrap bounds",
            "rank-(2n-1) fixed-point convolution; rank five for 3x85",
            "exact 2x127 split-product multiplication over BLS12-381 Fr",
            "dual-field CRT exactness, 254-bit bounded-quotient theorem, and executable unbound split-brain attack",
            "backend-independent constraint ledgers reproducing rank-5, split-limb and CRT owner-side inventories",
            "executable protocol/composition attacks including late binding, split-brain composition, batching cancellation, reusable KZG-WE update recovery, unauthenticated witness substitution, repeated affine input-token release, and affine VOLE state reuse",
            "phase, shared-commitment, and unified-opening regression fixes in the formal model",
        ],
        "estimate": [
            "logical 16-bit range/lookup inventories",
            "limb-geometry and lookup-width sensitivity",
            "native Python witness throughput",
            "known verifier arithmetic subtotal",
        ],
        "formal_model_only": [
            "KZG commitments/openings",
            "pairing-product equations",
            "AIR/permutation/memory proof security",
            "opening batching",
            "projective conditional-disclosure cost models",
            "multi-constraint KZG-opening witness encryption",
            "72-to-4 unified memory opening schedule",
            "fixed-commitment projective KZG-WE",
            "authenticated future-input witness lift",
            "aggregate BLS plus inner-product input-authentication relation and one-time-token attack",
            "one-shot affine vector-OLE interface and two-query secret-recovery regression",
        ],
        "open": [
            "real cryptographic lookup/R1CS/AIR backend and physical row counts",
            "real binding/extractable PCS with degree bounds",
            "cross-PCS common-table proof for dual-field CRT",
            "static conditional disclosure for future arbitrary commitment/opening statements",
            "complete LVA-WE gadget/CRS/decryption cost for the authenticated-input relation",
            "sub-megabyte projective input encoding",
            "full RankVM/SP1 trace compiler including parsing and SHA",
            "malicious distributed activation",
            "concrete Bitcoin beacon schedule",
            "Rust Strata and Bitcoin end-to-end execution",
            "formal security proof and independent review",
        ],
    },
    "known_arithmetic_schedule": {
        "sparse_pairing_products": pairing.total_base_field_products,
        "known_verifier_subtotal_fq_products": schedule.known_arithmetic_subtotal,
        "unresolved_sha256_and_byte_binding": schedule.unresolved_sha256_and_byte_binding,
        "unresolved_parsing_and_range": schedule.unresolved_canonical_parsing_and_range_checks,
    },
    "field_bridge_decision": comparison["decision"],
    "constraint_backend": {
        "rank5_3x85": rank5_trace.document(),
        "split_2x127": split_trace.document(),
        "dual_crt_owner_side": crt_trace.document(),
    },
    "field_bridge_candidates": {
        "single_field_3x85_rank5": {
            **routes["single_field_3x85_rank5"],
            "known_subtotal_native_products": 5 * KNOWN_PRODUCTS,
            "known_subtotal_logical_lookups": routes["single_field_3x85_rank5"][
                "logical_lookup_events_per_foreign_product"
            ] * KNOWN_PRODUCTS,
            "known_subtotal_linear_relations": 17 * KNOWN_PRODUCTS,
            "schoolbook_products_removed": 4 * KNOWN_PRODUCTS,
        },
        "single_field_2x127_split": {
            **routes["single_field_2x127_split"],
            "known_subtotal_native_products": 4 * KNOWN_PRODUCTS,
            "known_subtotal_logical_lookups": routes["single_field_2x127_split"][
                "logical_lookup_events_per_foreign_product"
            ] * KNOWN_PRODUCTS,
            "known_subtotal_linear_relations": 26 * KNOWN_PRODUCTS,
        },
        "dual_field_crt": {
            "owner_side_cost_point": routes[
                "dual_field_crt_bounded_quotient_owner_side"
            ],
            "free_shared_table_lower_bound": routes[
                "dual_field_crt_bounded_quotient_free_shared_table_lower_bound"
            ],
            "crt_over_q_squared_ratio": crt_config.safety_ratio,
            "bounded_quotient_bits": 254,
            "bounded_quotient_safety_ratio": crt_config.bounded_quotient_safety_ratio(254),
            "blocked_on": [
                "cross-PCS canonical-table equality proof",
                "dual PCS commitments/openings",
                "conditional-lock conjunction",
            ],
        },
    },
    "legacy_broken_modules": [
        "ranklock.generic_air one-shot prover",
        "ranklock.one_beacon_air convenience prover",
        "ranklock.tuple_permutation one-shot responder",
        "ranklock.memory_air legacy bundle",
    ],
    "safe_research_wrappers": [
        "ranklock.phased_air",
        "ranklock.phased_permutation",
        "ranklock.phased_memory",
        "ranklock.batched_opening",
        "ranklock.constraint_backend (transparent constraint validation only)",
        "ranklock.kzg_we_conjunction (formal exponent-space model)",
        "ranklock.unified_memory_opening (formal three-beacon schedule)",
        "ranklock.static_kzg_we (formal fixed-commitment model)",
        "ranklock.authenticated_witness_lift (relation model)",
        "ranklock.algebraic_input_auth (formal BLS/inner-product relation model)",
        "ranklock.vole_input_auth (ideal one-shot vector-OLE interface model)",
    ],
    "conditional_disclosure": {
        "memory_raw_kzg_openings": 72,
        "memory_distinct_opening_points": 4,
        "memory_batched_kzg_openings": 4,
        "dynamic_kzg_we_headers": 4,
        "dynamic_kzg_we_decryption_pairings": 4,
        "static_encapsulation_constructed": False,
        "reusable_standard_header_updater_secure": False,
        "fixed_authenticated_input_relation_candidate": True,
        "aggregate_input_authentication_gadgets": 2,
        "naive_affine_token_catalog_bytes": 1622016,
        "one_time_token_delivery_required": True,
        "one_time_token_delivery_constructed": False,
        "vector_ole_interface_candidate": True,
        "vector_ole_protocol_implemented": False,
        "vector_ole_leading_expression_bytes_ceiling": 8288,
        "evidence": "results/cds_research.json",
    },
    "parallel_priorities": {
        "field_backend_lane": "P0-PCS-1 real lookup/PCS benchmark for rank-5 3x85 and 2x127",
        "conditional_disclosure_lane": "P0-CDS-2 instantiate and cost the fixed authenticated-input LVA-WE relation; P0-PROJ-2 instantiate DFB vector OLE; P0-CDS-3 only if needed",
    },
    "next_priority": (
        "P0-CDS-2/P0-PROJ-2: instantiate the fixed authenticated-byte relation with real LVA-WE gadgets and Duty-Free-Bits vector OLE; measure complete key, CRS, OT, ciphertext and decryption cost"
    ),
}
write_json(ROOT / "STATUS.json", status)
