from __future__ import annotations

from dataclasses import replace
from hashlib import sha256

import pytest

from ranklock.bn254_real import CURVE_ORDER, G1, G2, compress_g1, compress_g2, multiply
from ranklock.low_rank_ppe_lock import (
    LowRankPpeError,
    LowRankPpeCiphertext,
    LowRankPpeLockKey,
    LowRankPpeRelation,
    build_example_relation,
    decrypt_from_exposed_target_preimage,
    decrypt_low_rank_ppe_lock,
    derive_scaled_term_bases,
    relation_cost,
    setup_low_rank_ppe_lock,
    verify_low_rank_ppe_key,
)
from ranklock.public_correlation_rank import structured_coefficient_matrix


@pytest.fixture(scope="module")
def real_fixture() -> tuple[object, ...]:
    coefficients = ((1, 1), (2, 3), (5, 8))
    relation, witness, target_preimage = build_example_relation(
        coefficients,
        (7, 11, 13),
        anchor_scalars=(17, 19),
        context=b"ranklock-v0.16-low-rank-ppe-real-fixture",
    )
    secret = bytes(range(32))
    key, ciphertext = setup_low_rank_ppe_lock(
        relation,
        secret,
        scale=23,
        proof_nonce=29,
    )
    return relation, witness, target_preimage, secret, key, ciphertext


def test_real_low_rank_ppe_relation_and_lock(real_fixture: tuple[object, ...]) -> None:
    relation, witness, _target_preimage, secret, key, ciphertext = real_fixture
    assert isinstance(relation, LowRankPpeRelation)
    assert relation.evaluate_direct(witness) == relation.evaluate(witness)
    assert relation.evaluate(witness) == relation.target
    assert verify_low_rank_ppe_key(key)
    assert decrypt_low_rank_ppe_lock(key, ciphertext, witness) == secret

    scaled_terms = derive_scaled_term_bases(key)
    assert len(scaled_terms) == relation.term_count
    assert key.relation.anchor_count == 2
    assert len(key.scaled_anchors_g2) == 2


def test_changed_witness_does_not_unlock(real_fixture: tuple[object, ...]) -> None:
    _relation, witness, _target_preimage, _secret, key, ciphertext = real_fixture
    forged = list(witness)
    forged[0] = compress_g1(multiply(G1, 31, group="g1"))
    with pytest.raises(LowRankPpeError, match="does not unlock"):
        decrypt_low_rank_ppe_lock(key, ciphertext, tuple(forged))


def test_setup_generator_substitution_is_rejected(real_fixture: tuple[object, ...]) -> None:
    _relation, _witness, _target_preimage, _secret, key, _ciphertext = real_fixture
    assert isinstance(key, LowRankPpeLockKey)
    tampered_scaled = list(key.scaled_anchors_g2)
    tampered_scaled[0] = compress_g2(multiply(G2, 37, group="g2"))
    tampered = replace(key, scaled_anchors_g2=tuple(tampered_scaled))
    assert not verify_low_rank_ppe_key(tampered)


def test_same_scalar_proof_does_not_certify_ciphertext_correctness(
    real_fixture: tuple[object, ...]
) -> None:
    _relation, witness, _target_preimage, _secret, key, _ciphertext = real_fixture
    # A malicious setup party can retain a perfectly valid common-scalar proof while
    # replacing the encrypted payload.  This is an undetectable activation-time DoS
    # until a future satisfying witness exists.
    malformed = LowRankPpeCiphertext(bytes(48))
    assert verify_low_rank_ppe_key(key)
    with pytest.raises(LowRankPpeError, match="does not unlock"):
        decrypt_low_rank_ppe_lock(key, malformed, witness)


def test_public_target_preimage_is_a_complete_break(
    real_fixture: tuple[object, ...]
) -> None:
    _relation, _witness, target_preimage, secret, key, ciphertext = real_fixture
    # Publishing these aggregate G1 points is equivalent to publishing a satisfying
    # target decomposition.  Anybody can then recover T^r from the public scaled anchors.
    assert (
        decrypt_from_exposed_target_preimage(
            key, ciphertext, target_preimage
        )
        == secret
    )


def test_eleven_term_two_anchor_wrapper_fits_in_a_few_kib(
    real_fixture: tuple[object, ...]
) -> None:
    base_relation, _witness, _target_preimage, _secret, _key, _ciphertext = real_fixture
    coefficients = structured_coefficient_matrix(11, 2)
    relation = LowRankPpeRelation(
        base_relation.anchors_g2,
        coefficients,
        base_relation.target_gt,
        b"ranklock-v0.16-eleven-term-wrapper-cost",
    )
    key, ciphertext = setup_low_rank_ppe_lock(
        relation,
        sha256(b"wrapper-cost-model-secret").digest(),
        scale=41,
        proof_nonce=43,
    )
    cost = relation_cost(key, ciphertext)
    assert cost.term_count == 11
    assert cost.anchor_count == 2
    assert cost.compressed_pairings == 2
    assert cost.direct_pairings == 11
    assert cost.direct_scaled_g2_bytes == 704
    assert cost.compressed_scaled_g2_bytes == 128
    assert cost.total_retained_bytes < 3_000


def test_relation_rejects_redundant_anchor_basis(real_fixture: tuple[object, ...]) -> None:
    base_relation, _witness, _target_preimage, _secret, _key, _ciphertext = real_fixture
    with pytest.raises(LowRankPpeError, match="redundant"):
        LowRankPpeRelation(
            base_relation.anchors_g2,
            ((1, 2), (2, 4)),
            base_relation.target_gt,
            b"redundant-anchor-test",
        )
