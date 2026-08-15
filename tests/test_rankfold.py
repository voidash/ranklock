from __future__ import annotations

from dataclasses import replace
import hashlib

from ranklock.rankfold import (
    AcceptAllOpeningOracle,
    InMemoryMultilinearOracle,
    RankFoldOpening,
    estimate_rankfold,
    forge_with_unbound_openings,
    product_tables,
    prove_rankfold,
    verify_rankfold,
)
from ranklock.tower_compiler import compile_fq12_multiplication


def _context(label: bytes = b"rankfold-test") -> bytes:
    return hashlib.sha256(label).digest()


def test_rankfold_accepts_valid_batch_and_rejects_invalid_relation() -> None:
    a = (2, 3, 5, 7, 11)
    b = (13, 17, 19, 23, 29)
    c = tuple(left * right for left, right in zip(a, b, strict=True))
    oracle = InMemoryMultilinearOracle(a, b, c, context_digest=_context())
    proof = prove_rankfold(oracle)
    assert verify_rankfold(oracle.statement, proof, oracle)

    invalid = list(c)
    invalid[2] += 1
    bad_oracle = InMemoryMultilinearOracle(a, b, invalid, context_digest=_context())
    bad_proof = prove_rankfold(bad_oracle)
    assert not verify_rankfold(bad_oracle.statement, bad_proof, bad_oracle)


def test_rankfold_transcript_and_openings_are_binding() -> None:
    a = tuple(range(1, 9))
    b = tuple(range(11, 19))
    c = tuple(left * right for left, right in zip(a, b, strict=True))
    oracle = InMemoryMultilinearOracle(a, b, c, context_digest=_context())
    proof = prove_rankfold(oracle)

    changed_round = list(proof.rounds)
    values = list(changed_round[0])
    values[3] += 1
    changed_round[0] = tuple(values)  # type: ignore[assignment]
    assert not verify_rankfold(
        oracle.statement, replace(proof, rounds=tuple(changed_round)), oracle
    )

    changed_opening = replace(proof.opening, c=proof.opening.c + 1)
    assert not verify_rankfold(
        oracle.statement, replace(proof, opening=changed_opening), oracle
    )

    other_context = InMemoryMultilinearOracle(
        a, b, c, context_digest=_context(b"another-program")
    )
    assert not verify_rankfold(other_context.statement, proof, other_context)


def test_rankfold_covers_the_certified_rank_54_fq12_module() -> None:
    decomposition = compile_fq12_multiplication()
    left = tuple(range(1, 13))
    right = tuple(range(101, 113))
    a, b, c = product_tables(decomposition, left, right)
    assert len(a) == decomposition.rank == 54
    oracle = InMemoryMultilinearOracle(
        a,
        b,
        c,
        context_digest=bytes.fromhex(decomposition.digest),
        modulus=decomposition.modulus,
    )
    proof = prove_rankfold(oracle)
    assert verify_rankfold(oracle.statement, proof, oracle)


def test_sumcheck_without_a_binding_pcs_is_forgeable() -> None:
    # Commitments claim an invalid relation, but the insecure opening oracle accepts
    # arbitrary terminal values.  The all-zero forged transcript then verifies.
    a = (1, 2, 3, 4)
    b = (5, 6, 7, 8)
    invalid_c = (5, 12, 21, 999)
    committed = InMemoryMultilinearOracle(
        a, b, invalid_c, context_digest=_context(b"pcs-gap")
    )
    forged = forge_with_unbound_openings(committed.statement)
    assert verify_rankfold(
        committed.statement, forged, AcceptAllOpeningOracle(committed.statement)
    )
    assert not verify_rankfold(committed.statement, forged, committed)


def test_sp1_rankfold_estimate_is_small_but_excludes_the_open_pcs_lock() -> None:
    estimate = estimate_rankfold(645_221)
    assert estimate.padded_constraints == 1_048_576
    assert estimate.rounds == 20
    assert estimate.sumcheck_field_elements == 83
    assert estimate.transcript_bytes_excluding_pcs == 2_720
    assert estimate.conservative_soundness_bits > 240
    assert estimate.pcs_openings == 3
