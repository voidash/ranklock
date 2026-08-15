#!/usr/bin/env python3
from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path

from ranklock.activation_nizk_frontier import activation_nizk_frontier
from ranklock.basis_separated_kzg import (
    BasisSeparatedKzgSrs,
    BasisSeparatedStatement,
    decrypt_basis_separated_opening,
    decrypt_from_published_scaled_rho,
    encrypt_basis_separated_opening,
    static_timing_frontier,
    verify_basis_separated_opening,
)
from ranklock.bn254_real import CURVE_ORDER, G1, G2, compress_g1, compress_g2, multiply
from ranklock.ciphertext_free_fault_key import (
    ciphertext_free_fault_key_frontier,
    recover_fault_scalar,
    setup_derived_fault_key_share,
    verify_activation_witness,
)
from ranklock.fixed_statement_wrapper_candidate import fixed_statement_wrapper_candidate
from ranklock.hidden_challenge_audit import hidden_challenge_audit
from ranklock.one_sided_wrapper_frontier import (
    OneSidedFinalPairingEquation,
    one_sided_wrapper_frontier,
)
from ranklock.real_secp import base_multiply, compress as compress_secp
from ranklock.shared_proof_binding import SplitBrainProofView, build_shared_proof, shared_binding_frontier
from ranklock.split_basis_ppe_we import (
    SplitBasisPpeError,
    build_scalar_fixture,
    decrypt_from_statement_span_decomposition,
    decrypt_split_basis_ppe_we,
    relation_cost,
    setup_split_basis_ppe_we,
)
from ranklock.transcript_mini_lock import canonical_transcript_digest, transcript_mini_lock_frontier

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def dump(name: str, payload: dict[str, object]) -> None:
    path = RESULTS / name
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def split_basis_result() -> dict[str, object]:
    rows = tuple((index + 1, 2 * index + 3) for index in range(11))
    witness_scalars = tuple(3 * index + 5 for index in range(11))
    relation, witness = build_scalar_fixture(
        witness_coefficients=rows,
        witness_scalars=witness_scalars,
        anchor_scalars=(17, 19),
        statement_g2_scalars=(23, 29),
        context=b"ranklock-v0.17-11x2-reference",
    )
    secret = bytes.fromhex("42" * 32)
    key, ciphertext = setup_split_basis_ppe_we(
        relation, secret, scale=31, proof_nonce=37
    )
    assert relation.accepts(witness)
    assert decrypt_split_basis_ppe_we(key, ciphertext, witness) == secret
    cost = relation_cost(key, ciphertext).document()

    forged = list(witness)
    forged[0] = compress_g1(multiply(G1, 101, group="g1"))
    changed_witness_rejected = False
    try:
        decrypt_split_basis_ppe_we(key, ciphertext, tuple(forged))
    except SplitBasisPpeError:
        changed_witness_rejected = True
    assert changed_witness_rejected
    return {
        "schema": "ranklock-v017-split-basis-result-v1",
        "evidence_class": "REAL BN254 arithmetic and exact serialization",
        "cost": cost,
        "relation_accepts": True,
        "secret_recovered": True,
        "changed_witness_rejected": changed_witness_rejected,
        "identity_target_is_fundamental_blocker": False,
        "actual_criterion": (
            "the statement-side session must not have a public decomposition over the scaled witness-anchor span"
        ),
        "breakthrough_target_met": False,
    }


def kzg_low_rank_leakage_result() -> dict[str, object]:
    # Use the dedicated basis-separated variant for its positive timing result.
    rho = 19
    randomness = 29
    srs = BasisSeparatedKzgSrs.generate(8, tau=17, rho=rho)
    polynomial = (3, 5, 7, 11, 13)
    opening = srs.open(polynomial, 23)
    statement = BasisSeparatedStatement(
        srs.commit(polynomial), opening.point, opening.value, b"ranklock-v0.17"
    )
    secret = bytes.fromhex("a6" * 32)
    ciphertext = encrypt_basis_separated_opening(
        srs, statement, secret, randomness=randomness
    )
    assert verify_basis_separated_opening(srs, statement, opening)
    assert decrypt_basis_separated_opening(statement, ciphertext, opening) == secret
    scaled_rho = compress_g2(
        multiply(G2, rho * randomness % CURVE_ORDER, group="g2")
    )
    assert decrypt_from_published_scaled_rho(statement, ciphertext, scaled_rho) == secret

    frontier = static_timing_frontier(srs)
    frontier.update(
        {
            "ciphertext_bytes": ciphertext.encoded_bytes,
            "opening_verified": True,
            "secret_recovered": True,
            "publishing_scaled_statement_basis_breaks_secrecy": True,
            "breakthrough_target_met": False,
        }
    )
    return frontier


def one_sided_result() -> dict[str, object]:
    equation = OneSidedFinalPairingEquation(trapdoor_s=17, challenge_alpha=19)
    witness = equation.accepting_witness(23)
    assert equation.accepts(witness)
    changed = list(witness)
    changed[1] = compress_g1(multiply(G1, 101, group="g1"))
    assert not equation.accepts(changed)
    report = one_sided_wrapper_frontier()
    report.update(
        {
            "real_final_equation_accepts": True,
            "changed_final_G1_rejected": True,
            "dynamic_G2_proof_elements": 0,
            "fixed_G2_anchor_rank": equation.fixed_g2_anchor_rank,
            "breakthrough_target_met": False,
        }
    )
    return report


def transcript_result() -> dict[str, object]:
    # The transcript envelope models the eventual outer curve with 64-byte G1 encodings.
    # These bytes are canonical test vectors for the encoding oracle, not BN254 points.
    points = tuple(bytes([index + 1]) * 64 for index in range(10))
    scalars = tuple(range(20))
    first = canonical_transcript_digest(b"deposit-7", points, scalars)
    changed_points = list(points)
    changed_points[0] = b"x" * 64
    changed = canonical_transcript_digest(b"deposit-7", changed_points, scalars)
    replay = canonical_transcript_digest(b"deposit-8", points, scalars)
    assert len({first, changed, replay}) == 3
    report = transcript_mini_lock_frontier()
    report.update(
        {
            "canonical_regression_digest": first.hex(),
            "proof_element_substitution_changes_digest": True,
            "deposit_context_replay_changes_digest": True,
        }
    )
    return report


def shared_binding_result() -> dict[str, object]:
    honest = tuple(
        compress_g1(multiply(G1, 31 + index, group="g1")) for index in range(10)
    )
    forged = tuple(
        compress_g1(multiply(G1, 131 + index, group="g1")) for index in range(10)
    )
    split = SplitBrainProofView(honest, forged, tuple(range(20)), b"game-9")
    assert split.split_brain_present
    repaired = build_shared_proof(honest, tuple(range(20)), context=b"game-9")
    assert tuple(item.encoded for item in repaired.group_elements) == honest
    report = shared_binding_frontier()
    report.update(
        {
            "split_brain_attack_executed": True,
            "shared_typed_object_repair_executed": True,
            "transcript_digest": repaired.transcript_digest.hex(),
        }
    )
    return report


def fault_key_and_activation_results() -> tuple[dict[str, object], dict[str, object]]:
    rows = tuple((index + 1, 2 * index + 3) for index in range(11))
    relation, witness = build_scalar_fixture(
        witness_coefficients=rows,
        witness_scalars=tuple(3 * index + 5 for index in range(11)),
        anchor_scalars=(17, 19),
        statement_g2_scalars=(23, 29),
        context=b"ranklock-v0.17-derived-fault-reference",
    )
    share, setup_witness = setup_derived_fault_key_share(
        relation,
        epoch=b"e" * 32,
        signer_id=b"alice-v017",
        scale=31,
        proof_nonce=37,
    )
    assert verify_activation_witness(share, setup_witness.scale)
    recovered = recover_fault_scalar(share, witness)
    assert recovered == setup_witness.fault_scalar
    assert compress_secp(base_multiply(recovered)) == share.fault_public_key

    fault = ciphertext_free_fault_key_frontier(share)
    fault.update(
        {
            "fault_scalar_recovered_from_accepting_session": True,
            "derived_fault_public_key_hex": share.fault_public_key.hex(),
            "reference_relation_terms": relation.witness_term_count,
            "reference_anchor_rank": relation.witness_anchor_count,
            "reference_relation_bytes": relation.encoded_bytes,
            "reference_setup_key_bytes": share.ppe_key.setup_bytes,
        }
    )
    activation = activation_nizk_frontier(share)
    activation.update(
        {
            "visible_relation_accepts_correct_scale": True,
            "visible_relation_rejects_wrong_scale": not verify_activation_witness(
                share, setup_witness.scale + 1
            ),
        }
    )
    return fault, activation


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    split = split_basis_result()
    kzg = kzg_low_rank_leakage_result()
    one_sided = one_sided_result()
    audit = hidden_challenge_audit()
    transcript = transcript_result()
    shared = shared_binding_result()
    fault, activation = fault_key_and_activation_results()
    wrapper = fixed_statement_wrapper_candidate()

    dump("split_basis_ppe.json", split)
    dump("basis_separated_kzg.json", kzg)
    dump("one_sided_wrapper.json", one_sided)
    dump("hidden_challenge_audit.json", audit)
    dump("transcript_mini_lock.json", transcript)
    dump("shared_proof_binding.json", shared)
    dump("ciphertext_free_fault_key.json", fault)
    dump("activation_nizk.json", activation)
    dump("fixed_statement_wrapper_candidate.json", wrapper)

    checkpoint = {
        "schema": "ranklock-v017-checkpoint-v1",
        "version": "0.17.0",
        "date": "2026-08-07",
        "breakthrough_target_met": False,
        "primary_decision": (
            "Continue the fixed-statement one-sided wrapper route; generic public-correlation expansion and raw hidden-Fiat-Shamir routes remain killed."
        ),
        "positive_results": {
            "split_basis_pairing_lock": split,
            "basis_separated_kzg": kzg,
            "one_sided_final_equation": {
                "fixed_G2_anchor_rank": one_sided["fixed_G2_anchor_rank"],
                "dynamic_G2_proof_elements": one_sided["dynamic_G2_proof_elements"],
                "real_final_equation_accepts": one_sided["real_final_equation_accepts"],
            },
            "transcript_reference_scenario": transcript[
                "best_surviving_reference_scenario"
            ],
            "ciphertext_free_fault_key": fault,
            "activation_relation": activation,
            "fixed_statement_wrapper_reference": wrapper[
                "reference_surviving_scenario"
            ],
        },
        "killed_or_reframed": [
            "nonidentity target as a universal requirement; basis/session separation is the stronger criterion",
            "reusable low-rank KZG anchors that publish the scaled statement-side basis",
            "hiding the published Fiat-Shamir challenges while keeping the prover unchanged",
            "separate transcript and pairing proof witnesses",
            "encrypted fault-key payload inside the conditional lock",
        ],
        "remaining_load_bearing_gates": wrapper["missing_load_bearing_components"],
        "claim_policy": (
            "This checkpoint is a real-arithmetic frontier and byte-envelope result, not a complete RankVM lock, security proof, or production implementation."
        ),
    }
    dump("v017_checkpoint.json", checkpoint)


if __name__ == "__main__":
    main()
