from dataclasses import replace

import pytest

from ranklock.batched_inner_product_we import (
    BatchedInnerProductWeError,
    decrypt_batched_inner_product_we,
    key_size_comparison,
    setup_batched_inner_product_we,
    verify_batched_inner_product_key,
)
from ranklock.inner_product_we import derive_relation
from ranklock.real_secp import DeterministicScalars, base_multiply, compress


def test_batched_key_decrypts_and_is_smaller() -> None:
    witness = (3, 5, 8, 13, 21, 34)
    relation = derive_relation(witness, context=b"batched-key-test")
    secret = bytes.fromhex("a5" * 32)
    key, ciphertext = setup_batched_inner_product_we(
        relation,
        secret,
        scalar_source=DeterministicScalars(b"batched-key-seed"),
    )
    assert verify_batched_inner_product_key(key)
    assert decrypt_batched_inner_product_we(key, ciphertext, witness) == secret
    comparison = key_size_comparison(len(witness))
    assert key.encoded_bytes == comparison["batched_dleq_bytes"]
    assert comparison["batched_dleq_bytes"] < comparison["per_coordinate_dleq_bytes"]


def test_wrong_witness_does_not_decrypt() -> None:
    witness = (1, 2, 3, 5)
    relation = derive_relation(witness, context=b"batched-wrong-witness")
    key, ciphertext = setup_batched_inner_product_we(
        relation,
        bytes(32),
        scalar_source=DeterministicScalars(b"batched-wrong-seed"),
    )
    with pytest.raises(BatchedInnerProductWeError):
        decrypt_batched_inner_product_we(key, ciphertext, (1, 2, 3, 6))


def test_one_bad_scaled_coordinate_breaks_aggregate_proof() -> None:
    witness = (7, 11, 13, 17, 19)
    relation = derive_relation(witness, context=b"batched-tamper")
    key, _ciphertext = setup_batched_inner_product_we(
        relation,
        bytes.fromhex("42" * 32),
        scalar_source=DeterministicScalars(b"batched-tamper-seed"),
    )
    scaled = list(key.scaled_bases)
    scaled[2] = compress(base_multiply(1234567))
    assert not verify_batched_inner_product_key(
        replace(key, scaled_bases=tuple(scaled))
    )


def test_proof_tampering_fails() -> None:
    relation = derive_relation((2, 4, 6), context=b"batched-proof-tamper")
    key, _ = setup_batched_inner_product_we(
        relation,
        bytes.fromhex("ff" * 32),
        scalar_source=DeterministicScalars(b"batched-proof-seed"),
    )
    proof = replace(key.aggregate_proof, response=key.aggregate_proof.response + 1)
    assert not verify_batched_inner_product_key(replace(key, aggregate_proof=proof))
