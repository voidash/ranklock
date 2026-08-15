from __future__ import annotations

from ranklock.bn254_direct_wrapper import (
    CanonicalOneSidedProof,
    CanonicalUncompressedG1,
)
from ranklock.bn254_real import G1, multiply
from ranklock.poseidon2_bn254_transcript import (
    OFFICIAL_KAT_INPUT,
    OFFICIAL_KAT_OUTPUT,
    PERMUTATION_CONSTRAINTS,
    ROUND_CONSTANTS,
    execute_one_sided_transcript,
    poseidon2_permutation,
)


def _proof() -> CanonicalOneSidedProof:
    return CanonicalOneSidedProof(
        tuple(
            CanonicalUncompressedG1.from_point(
                multiply(G1, index + 1, group="g1")
            )
            for index in range(10)
        ),
        tuple(range(20)),
    )


def test_official_bn256_poseidon2_known_answer_vector() -> None:
    assert len(ROUND_CONSTANTS) == 64
    assert PERMUTATION_CONSTRAINTS == 240
    assert poseidon2_permutation(OFFICIAL_KAT_INPUT) == OFFICIAL_KAT_OUTPUT


def test_protocol_31_transcript_executes_exact_typed_schedule() -> None:
    execution = execute_one_sided_transcript(_proof(), context_field=42)
    assert execution.absorbed_field_elements == 56
    assert execution.challenge_phases == 9
    assert len(execution.challenges.as_tuple()) == 10
    assert execution.counter.permutations == 32
    assert execution.counter.sboxes == 2_560
    assert execution.counter.multiplication_constraints == 7_680
    assert execution.counter.labels == {
        "alpha": 2,
        "alpha_e": 2,
        "delta": 11,
        "gamma": 2,
        "lambda": 1,
        "lambda_b": 3,
        "lambda_e": 1,
        "xi": 6,
        "xi_e": 4,
    }
    assert execution.challenges.delta_1 == int(
        "2fac49b457a5a939f352636134592e5adf646672ecde72af7080a1a6c1b0e369",
        16,
    )
    assert execution.challenges.xi_e == int(
        "26b44dd7d3bb54e0dcfd851a868e329581d50c2f20a5b31d8e3956473c976484",
        16,
    )


def test_transcript_binds_context_and_every_prechallenge_message() -> None:
    proof = _proof()
    baseline = execute_one_sided_transcript(proof, context_field=42)
    changed_context = execute_one_sided_transcript(proof, context_field=43)
    assert baseline.challenges.as_tuple() != changed_context.challenges.as_tuple()

    changed_points = list(proof.g1)
    changed_points[4] = CanonicalUncompressedG1.from_point(
        multiply(G1, 99, group="g1")
    )
    changed_message = execute_one_sided_transcript(
        CanonicalOneSidedProof(tuple(changed_points), proof.scalars),
        context_field=42,
    )
    assert baseline.challenges.as_tuple() != changed_message.challenges.as_tuple()

    changed_scalars = list(proof.scalars)
    changed_scalars[13] += 1
    changed_opening = execute_one_sided_transcript(
        CanonicalOneSidedProof(proof.g1, tuple(changed_scalars)),
        context_field=42,
    )
    assert baseline.challenges.xi_e != changed_opening.challenges.xi_e


def test_final_qe_is_not_hashed_but_remains_in_shared_pairing_object() -> None:
    proof = _proof()
    baseline = execute_one_sided_transcript(proof, context_field=42)
    changed_points = list(proof.g1)
    changed_points[9] = CanonicalUncompressedG1.from_point(
        multiply(G1, 101, group="g1")
    )
    changed_proof = CanonicalOneSidedProof(tuple(changed_points), proof.scalars)
    changed = execute_one_sided_transcript(changed_proof, context_field=42)

    # Q_e is the final response; no subsequent Fiat--Shamir challenge hashes it.
    assert baseline.challenges.as_tuple() == changed.challenges.as_tuple()
    # The same canonical proof object still gives a different final pairing input.
    assert proof.pairing_points[9] != changed_proof.pairing_points[9]
