from __future__ import annotations

from dataclasses import replace
import hashlib

from ranklock.grumpkin import (
    GENERATOR,
    GRUMPKIN_SCALAR_FIELD,
    compress,
    decompress,
    is_on_curve,
    scalar_multiply,
)
from ranklock.ipa_pcs import (
    IpaMultilinearOracle,
    IpaParameters,
    IpaProof,
    commit_vector,
    ipa_metrics,
    prove_inner_product,
    verify_inner_product,
)
from ranklock.rankfold import prove_rankfold, verify_rankfold


def test_grumpkin_cycle_group_basics() -> None:
    assert is_on_curve(GENERATOR)
    assert decompress(compress(GENERATOR)) == GENERATOR
    assert scalar_multiply(GENERATOR, GRUMPKIN_SCALAR_FIELD) is None
    assert scalar_multiply(GENERATOR, 1) == GENERATOR


def test_ipa_inner_product_opening_binds_vector_and_value() -> None:
    parameters = IpaParameters.derive(8, domain=b"ipa-unit-test")
    vector = tuple(range(1, 9))
    weights = tuple(range(11, 19))
    value = sum(a * b for a, b in zip(vector, weights, strict=True)) % GRUMPKIN_SCALAR_FIELD
    commitment = commit_vector(parameters, vector)
    proof = prove_inner_product(
        parameters,
        vector=vector,
        public_weights=weights,
        claimed_value=value,
        commitment=commitment,
        transcript_seed=hashlib.sha256(b"ipa-test").digest(),
    )
    assert verify_inner_product(
        parameters,
        public_weights=weights,
        claimed_value=value,
        commitment=commitment,
        transcript_seed=hashlib.sha256(b"ipa-test").digest(),
        proof=proof,
    )
    assert not verify_inner_product(
        parameters,
        public_weights=weights,
        claimed_value=value + 1,
        commitment=commitment,
        transcript_seed=hashlib.sha256(b"ipa-test").digest(),
        proof=proof,
    )
    tampered = replace(proof, final_a=proof.final_a + 1)
    assert not verify_inner_product(
        parameters,
        public_weights=weights,
        claimed_value=value,
        commitment=commitment,
        transcript_seed=hashlib.sha256(b"ipa-test").digest(),
        proof=tampered,
    )


def test_rankfold_with_real_ipa_binding_rejects_opening_tampering() -> None:
    a = (2, 3, 5, 7, 11, 13, 17, 19)
    b = (23, 29, 31, 37, 41, 43, 47, 53)
    c = tuple(left * right for left, right in zip(a, b, strict=True))
    oracle = IpaMultilinearOracle(
        a,
        b,
        c,
        context_digest=hashlib.sha256(b"rankfold-ipa").digest(),
    )
    proof = prove_rankfold(oracle)
    assert verify_rankfold(oracle.statement, proof, oracle)
    assert not verify_rankfold(
        oracle.statement,
        replace(proof, opening=replace(proof.opening, a=proof.opening.a + 1)),
        oracle,
    )


def test_ipa_metrics_expose_linear_verifier_wall() -> None:
    metrics = ipa_metrics(1 << 20)
    assert metrics.rounds == 20
    assert metrics.proof_bytes == 1359
    assert metrics.verifier_generator_scalar_multiplications > 4_000_000
