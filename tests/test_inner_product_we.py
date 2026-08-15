from dataclasses import replace

import pytest

from ranklock.inner_product_we import (
    InnerProductWeError,
    decrypt_inner_product_we,
    derive_relation,
    setup_inner_product_we,
    verify_inner_product_key,
)
from ranklock.real_secp import DeterministicScalars, N


def test_fixed_relation_decrypts_only_with_valid_linear_witness() -> None:
    witness = (3, 5, 7, 11)
    relation = derive_relation(witness, context=b"relation-a")
    secret = bytes.fromhex("42" * 32)
    key, ciphertext = setup_inner_product_we(
        relation, secret, scalar_source=DeterministicScalars(b"inner-setup")
    )
    assert ciphertext.encoded_bytes == 48
    assert decrypt_inner_product_we(key, ciphertext, witness) == secret
    with pytest.raises(InnerProductWeError, match="does not satisfy"):
        decrypt_inner_product_we(key, ciphertext, (3, 5, 7, 12))


def test_setup_tampering_and_context_substitution_fail() -> None:
    witness = (9, 2)
    relation = derive_relation(witness, context=b"context-a")
    key, ciphertext = setup_inner_product_we(
        relation, bytes(32), scalar_source=DeterministicScalars(b"inner-setup-2")
    )
    bad_proof = replace(key.proofs[0], response=(key.proofs[0].response + 1) % N)
    assert not verify_inner_product_key(replace(key, proofs=(bad_proof,) + key.proofs[1:]))
    other = derive_relation(witness, context=b"context-b")
    assert other.digest != relation.digest
    with pytest.raises(InnerProductWeError):
        decrypt_inner_product_we(replace(key, relation=other), ciphertext, witness)


def test_ciphertext_constant_but_relation_key_linear() -> None:
    small = derive_relation((1, 2))
    large = derive_relation(tuple(range(1, 18)))
    key_small, ct_small = setup_inner_product_we(
        small, bytes(32), scalar_source=DeterministicScalars(b"small")
    )
    key_large, ct_large = setup_inner_product_we(
        large, bytes(32), scalar_source=DeterministicScalars(b"large")
    )
    assert ct_small.encoded_bytes == ct_large.encoded_bytes == 48
    assert key_large.encoded_bytes > key_small.encoded_bytes
    assert key_large.encoded_bytes - key_small.encoded_bytes == 15 * (33 + 33 + 64)
