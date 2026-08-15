from __future__ import annotations

"""Generate the v0.16 public-correlation research checkpoint."""

from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

from .bn254_real import G1, G2, compress_g1, compress_g2, multiply
from .direct_relation_barrier import CURRENT_LINEAR_RELATIONS, CURRENT_LOGICAL_EVENTS
from .low_rank_ppe_lock import (
    LowRankPpeCiphertext,
    LowRankPpeError,
    LowRankPpeRelation,
    build_example_relation,
    decrypt_from_exposed_target_preimage,
    decrypt_low_rank_ppe_lock,
    relation_cost,
    setup_low_rank_ppe_lock,
    verify_low_rank_ppe_key,
)
from .public_correlation_rank import (
    certify_independent_correlations,
    certify_public_correlation_expander,
    structured_coefficient_matrix,
)
from .verifier_shape_frontier import reference_shape_frontier


def experiment_document() -> dict[str, object]:
    generic_linear = certify_independent_correlations(
        CURRENT_LINEAR_RELATIONS,
        public_seed_elements=2,
    )
    generic_all_events = certify_independent_correlations(
        CURRENT_LOGICAL_EVENTS,
        public_seed_elements=2,
    )
    wrapper_coefficients = structured_coefficient_matrix(11, 2)
    wrapper_rank = certify_public_correlation_expander(
        wrapper_coefficients,
        public_seed_elements=2,
    )

    relation, witness, target_preimage = build_example_relation(
        ((1, 1), (2, 3), (5, 8)),
        (7, 11, 13),
        anchor_scalars=(17, 19),
        context=b"ranklock-v0.16-correlation-seed-experiment",
    )
    secret = sha256(b"ranklock-v0.16-reference-fault-secret").digest()
    key, ciphertext = setup_low_rank_ppe_lock(
        relation,
        secret,
        scale=23,
        proof_nonce=29,
    )
    direct_matches_compressed = relation.evaluate_direct(witness) == relation.evaluate(
        witness
    )
    valid_decrypts = decrypt_low_rank_ppe_lock(key, ciphertext, witness) == secret

    forged = list(witness)
    forged[0] = compress_g1(multiply(G1, 31, group="g1"))
    forged_rejected = False
    try:
        decrypt_low_rank_ppe_lock(key, ciphertext, tuple(forged))
    except LowRankPpeError:
        forged_rejected = True

    tampered_scaled = list(key.scaled_anchors_g2)
    tampered_scaled[0] = compress_g2(multiply(G2, 37, group="g2"))
    setup_substitution_rejected = not verify_low_rank_ppe_key(
        replace(key, scaled_anchors_g2=tuple(tampered_scaled))
    )

    target_preimage_unlocks_publicly = (
        decrypt_from_exposed_target_preimage(
            key, ciphertext, target_preimage
        )
        == secret
    )

    malformed_payload = LowRankPpeCiphertext(bytes(48))
    malformed_activation_detectable_before_witness = False
    malformed_activation_fails_with_witness = False
    if verify_low_rank_ppe_key(key):
        try:
            decrypt_low_rank_ppe_lock(key, malformed_payload, witness)
        except LowRankPpeError:
            malformed_activation_fails_with_witness = True

    wrapper_relation = LowRankPpeRelation(
        relation.anchors_g2,
        wrapper_coefficients,
        relation.target_gt,
        b"ranklock-v0.16-eleven-term-wrapper-cost",
    )
    wrapper_key, wrapper_ciphertext = setup_low_rank_ppe_lock(
        wrapper_relation,
        sha256(b"ranklock-v0.16-wrapper-cost-secret").digest(),
        scale=41,
        proof_nonce=43,
    )
    wrapper_cost = relation_cost(wrapper_key, wrapper_ciphertext)

    return {
        "schema": "ranklock-v0.16-public-correlation-checkpoint-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "decision": "BREAKTHROUGH TARGET NOT MET",
        "rank_lower_bound": {
            "current_linear_relations_as_independent_bases": generic_linear.document(),
            "all_current_logical_events_as_independent_bases": generic_all_events.document(),
            "eleven_term_two_anchor_wrapper": wrapper_rank.document(),
            "theorem_scope": (
                "Exact public algebraic source-group rank bound. It rules out a short public "
                "linear/group-operation seed for arbitrary independent verifier bases, not "
                "obfuscation, multilinear maps, hardware, or already-low-rank verifiers."
            ),
        },
        "real_bn254_low_rank_ppe": {
            "evidence_class": "REPRODUCED executable research prototype",
            "direct_matches_compressed": direct_matches_compressed,
            "valid_witness_decrypts": valid_decrypts,
            "changed_witness_rejected": forged_rejected,
            "setup_generator_substitution_rejected": setup_substitution_rejected,
            "public_target_preimage_unlocks": target_preimage_unlocks_publicly,
            "malformed_ciphertext_detectable_before_future_witness": (
                malformed_activation_detectable_before_witness
            ),
            "malformed_ciphertext_fails_once_future_witness_exists": (
                malformed_activation_fails_with_witness
            ),
            "warning": (
                "The common-scalar proof authenticates scaled anchors but does not prove "
                "ciphertext/plaintext correctness. Malicious distributed activation remains open."
            ),
        },
        "eleven_term_two_anchor_cost": wrapper_cost.document(),
        "verifier_shape_frontier": reference_shape_frontier(),
        "new_target": (
            "Construct a target-separated, transcript-bound, knowledge-sound proof whose final "
            "verification has only future G1 terms, a polylog-rank fixed G2 basis, and a "
            "nonidentity target with no public decomposition over the scaled anchors; then add "
            "malicious n-1-corrupt activation that proves ciphertext/share consistency."
        ),
        "claims_boundary": [
            "The public PCG route for arbitrary independent source-group bases is killed only in the stated algebraic model.",
            "The real low-rank PPE lock is not a complete RankVM-invalidity proof or witness-encryption theorem.",
            "The 11-term shape is a cost envelope, not an implemented knowledge-sound wrapper.",
            "The setup proof is single-generator and does not establish malicious distributed activation.",
        ],
    }


def write_experiment(path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(experiment_document(), indent=2, sort_keys=True) + "\n")
    return destination


if __name__ == "__main__":
    write_experiment("results/public_correlation_checkpoint.json")
