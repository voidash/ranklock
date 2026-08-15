from __future__ import annotations

import json
from pathlib import Path
from time import perf_counter
from datetime import datetime, timezone

from ranklock.batched_inner_product_we import key_size_comparison
from ranklock.direct_relation_barrier import DirectRelationBarrier
from ranklock.fixed_relation_budget import FixedRelationBudget, lva_wrapper_frontier
from ranklock.groth16_projective_lock import projective_ppe_reduction_report
from ranklock.hybrid_conditional_lock import online_authority_barrier
from ranklock.projective_vole_lock import benchmark_projective_lock
from ranklock.real_kzg_we import (
    KzgSrs,
    KzgStatement,
    decrypt_with_opening,
    encrypt_for_opening,
    verify_opening,
)
from ranklock.static_linear_conjunction import benchmark_static_linear_conjunction

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
RESULTS.mkdir(parents=True, exist_ok=True)
NOW = datetime.now(timezone.utc).isoformat()


def write(name: str, value: object) -> None:
    (RESULTS / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


values = bytes((17 * index + 3) % 256 for index in range(132))
projective = benchmark_projective_lock(values)
write(
    "real_projective_vole.json",
    {"generated_at_utc": NOW, **projective.document()},
)

# The pure-Python arbitrary-base batch proof is intentionally not benchmarked at
# full width: doing hundreds of scalar multiplications would measure the
# reference interpreter rather than the protocol.  Serialize/count the full
# object exactly and benchmark a small execution path.
full_budget = FixedRelationBudget()
small_static = benchmark_static_linear_conjunction(
    bytes((17 * index + 3) % 256 for index in range(4)),
    (1, 1, 2, 3, 5),
)
write(
    "static_linear_conjunction.json",
    {
        "schema": "ranklock-static-linear-conjunction-result-v2",
        "generated_at_utc": NOW,
        "full_132_byte_64_scalar_exact_serialized_model": {
            "input_bytes": 132,
            "trace_width": 64,
            "relation_width": 328,
            "retained_bytes": full_budget.retained_bytes_for_width(328),
            "constant_ciphertext_bytes": 48,
            "post_statement_encapsulator_required": False,
            "evidence_class": "EXACT byte accounting from concrete serialization law; full-width Python timing not run",
        },
        "small_executable_benchmark": small_static.document(),
    },
)

srs_started = perf_counter()
srs = KzgSrs.generate(8, tau=37)
srs_seconds = perf_counter() - srs_started
polynomial = tuple((index**3 + 11 * index + 5) for index in range(8))
started = perf_counter()
commitment = srs.commit(polynomial)
opening = srs.open(polynomial, 43)
statement = KzgStatement(commitment, opening.point, opening.value)
commit_open_seconds = perf_counter() - started
started = perf_counter()
verified = verify_opening(srs, statement, opening)
verify_seconds = perf_counter() - started
secret = bytes.fromhex("a7" * 32)
started = perf_counter()
ciphertext = encrypt_for_opening(srs, statement, secret, randomness=41)
encrypt_seconds = perf_counter() - started
started = perf_counter()
recovered = decrypt_with_opening(statement, ciphertext, opening)
decrypt_seconds = perf_counter() - started
write(
    "real_kzg_we.json",
    {
        "schema": "ranklock-real-kzg-we-benchmark-v1",
        "generated_at_utc": NOW,
        "maximum_degree": srs.maximum_degree,
        "polynomial_coefficients": len(polynomial),
        "srs_bytes": srs.encoded_bytes,
        "commitment_bytes": len(statement.commitment_g1),
        "opening_witness_bytes": len(opening.proof_g1),
        "ciphertext_bytes": ciphertext.encoded_bytes,
        "opening_verified": verified,
        "secret_recovered": recovered == secret,
        "timing_seconds": {
            "srs_generation": srs_seconds,
            "commit_and_open": commit_open_seconds,
            "verify_opening": verify_seconds,
            "encrypt": encrypt_seconds,
            "decrypt": decrypt_seconds,
        },
        "security_boundary": [
            "Actual BN254 group and pairing arithmetic; variable-time research code.",
            "The SRS trapdoor is generated locally and is not a production ceremony.",
            "The ciphertext is bound to a concrete future KZG statement.",
        ],
    },
)

budget = FixedRelationBudget()
write(
    "fixed_relation_budget.json",
    {
        "generated_at_utc": NOW,
        "budget": budget.document(),
        "wrapper_frontier": lva_wrapper_frontier(),
        "key_batching": {
            "width_328": key_size_comparison(328),
            "maximum_width_under_one_mib": budget.maximum_reference_relation_width,
            "maximum_trace_width_after_132_inputs": budget.maximum_reference_trace_width,
        },
    },
)
write(
    "direct_relation_barrier.json",
    {"generated_at_utc": NOW, **DirectRelationBarrier().document()},
)
write(
    "hybrid_online_barrier.json",
    {"generated_at_utc": NOW, **online_authority_barrier()},
)
write(
    "formal_recursive_candidate.json",
    {"generated_at_utc": NOW, **projective_ppe_reduction_report()},
)
write(
    "parallel_checkpoint_validation.json",
    {
        "schema": "ranklock-parallel-checkpoint-validation-v1",
        "generated_at_utc": NOW,
        "checkpoint": "ranklock-v0.15-research-breakthrough.zip",
        "result": "REJECTED_AS_RELEASE_BASELINE",
        "tests_passed": 109,
        "tests_failed": 2,
        "failures": [
            "empty sumcheck_messages caused an IndexError in test_r1cs_ipa",
            "toy field-bridge R1CS IPA failed its final sumcheck equation",
        ],
        "selectively_retained": [
            "formal Groth16 PPE/context encoding model",
            "recursive architecture inventory, relabeled as a formal candidate",
        ],
        "not_retained_as_evidence": [
            "broken BLS12-381 R1CS/IPA proof backend",
            "the checkpoint's breakthrough label",
        ],
    },
)
