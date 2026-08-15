from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock.bn254_real import (
    CURVE_ORDER,
    G1,
    G2,
    add,
    compress_g1,
    compress_g2,
    decompress_g1,
    multiply,
    neg,
)
from ranklock.real_kzg_we import (
    KzgStatement,
    KzgSrs,
    decrypt_with_opening,
    encrypt_for_opening,
)
from ranklock.split_basis_ppe_we import (
    SplitBasisPpeCiphertext,
    SplitBasisPpeError,
    SplitBasisPpeRelation,
    build_scalar_fixture,
    decrypt_from_statement_span_decomposition,
    decrypt_split_basis_ppe_we,
    relation_cost,
    setup_split_basis_ppe_we,
    verify_split_basis_key,
)


def test_real_split_basis_relation_and_lock() -> None:
    relation, witness = build_scalar_fixture(
        witness_coefficients=((1, 1), (2, 3), (5, 8)),
        witness_scalars=(7, 11, 13),
        anchor_scalars=(17, 19),
        statement_g2_scalars=(23, 29),
        context=b"ranklock-v0.17-split-basis-real",
    )
    assert relation.witness_value_direct(witness) == relation.witness_value(witness)
    assert relation.accepts(witness)

    secret = bytes(range(32))
    key, ciphertext = setup_split_basis_ppe_we(
        relation, secret, scale=31, proof_nonce=37
    )
    assert verify_split_basis_key(key)
    assert decrypt_split_basis_ppe_we(key, ciphertext, witness) == secret
    cost = relation_cost(key, ciphertext)
    assert cost.compressed_witness_pairings == 2
    assert cost.direct_witness_pairings == 3
    assert cost.total_retained_bytes < 3_000

    forged = list(witness)
    forged[0] = compress_g1(multiply(G1, 41, group="g1"))
    with pytest.raises(SplitBasisPpeError, match="does not unlock"):
        decrypt_split_basis_ppe_we(key, ciphertext, tuple(forged))


def test_ciphertext_substitution_remains_an_activation_attack() -> None:
    relation, witness = build_scalar_fixture(
        witness_coefficients=((1,),),
        witness_scalars=(7,),
        anchor_scalars=(11,),
        statement_g2_scalars=(13,),
        context=b"ranklock-v0.17-split-basis-substitution",
    )
    key, _ciphertext = setup_split_basis_ppe_we(
        relation, bytes.fromhex("42" * 32), scale=17, proof_nonce=19
    )
    assert verify_split_basis_key(key)
    with pytest.raises(SplitBasisPpeError, match="does not unlock"):
        decrypt_split_basis_ppe_we(
            key, SplitBasisPpeCiphertext(bytes(48)), witness
        )


def test_standard_kzg_opening_we_is_a_split_basis_special_case() -> None:
    tau = 17
    z = 19
    randomness = 23
    secret = bytes.fromhex("a5" * 32)
    polynomial = (3, 5, 7, 11, 13)
    srs = KzgSrs.generate(8, tau=tau)
    opening = srs.open(polynomial, z)
    statement = KzgStatement(srs.commit(polynomial), opening.point, opening.value)
    standard = encrypt_for_opening(srs, statement, secret, randomness=randomness)
    assert decrypt_with_opening(statement, standard, opening) == secret

    tau_minus_z = add(
        multiply(G2, tau, group="g2"),
        neg(multiply(G2, z, group="g2")),
        group="g2",
    )
    commitment_minus_value = add(
        decompress_g1(statement.commitment_g1),
        neg(multiply(G1, statement.value, group="g1")),
        group="g1",
    )
    relation = SplitBasisPpeRelation(
        (compress_g2(tau_minus_z),),
        ((1,),),
        ((compress_g1(commitment_minus_value), compress_g2(G2)),),
        b"ranklock-v0.17-kzg-as-split-basis",
    )
    assert relation.accepts((opening.proof_g1,))
    key, ciphertext = setup_split_basis_ppe_we(
        relation, secret, scale=randomness, proof_nonce=29
    )
    assert key.scaled_witness_anchors_g2 == (standard.header_g2,)
    assert decrypt_split_basis_ppe_we(
        key, ciphertext, (opening.proof_g1,)
    ) == secret


def test_low_rank_kzg_anchor_expansion_leaks_session() -> None:
    """Publishing r[tau] and r[1] exposes the KZG statement-side session."""

    tau = 31
    z = 37
    polynomial = (2, 3, 5, 7)
    srs = KzgSrs.generate(8, tau=tau)
    opening = srs.open(polynomial, z)
    statement = KzgStatement(srs.commit(polynomial), opening.point, opening.value)
    commitment_minus_value = add(
        decompress_g1(statement.commitment_g1),
        neg(multiply(G1, statement.value, group="g1")),
        group="g1",
    )

    # Instead of the safe one-dimensional anchor [tau-z], attempt a reusable
    # two-anchor expansion [tau], [1].  The witness base row is (1,-z).
    relation = SplitBasisPpeRelation(
        (
            compress_g2(multiply(G2, tau, group="g2")),
            compress_g2(G2),
        ),
        ((1, (-z) % CURVE_ORDER),),
        ((compress_g1(commitment_minus_value), compress_g2(G2)),),
        b"ranklock-v0.17-kzg-low-rank-leakage",
        require_minimal_witness_basis=False,
    )
    assert relation.accepts((opening.proof_g1,))
    secret = bytes.fromhex("5a" * 32)
    key, ciphertext = setup_split_basis_ppe_we(
        relation, secret, scale=41, proof_nonce=43
    )

    # G2 = 0*[tau] + 1*[1] is a public decomposition, so anybody can recover
    # the statement-side session from the published scaled anchors.
    assert decrypt_from_statement_span_decomposition(
        key, ciphertext, ((0, 1),)
    ) == secret


def test_statement_span_attack_rejects_false_decomposition() -> None:
    relation, witness = build_scalar_fixture(
        witness_coefficients=((1, 0), (0, 1)),
        witness_scalars=(3, 5),
        anchor_scalars=(7, 11),
        statement_g2_scalars=(13,),
        context=b"ranklock-v0.17-false-span",
    )
    key, ciphertext = setup_split_basis_ppe_we(
        relation, bytes.fromhex("77" * 32), scale=17, proof_nonce=19
    )
    assert decrypt_split_basis_ppe_we(key, ciphertext, witness) == bytes.fromhex("77" * 32)
    with pytest.raises(SplitBasisPpeError, match="do not decompose"):
        decrypt_from_statement_span_decomposition(key, ciphertext, ((1, 1),))


def test_tampered_scaled_anchor_is_rejected() -> None:
    relation, _witness = build_scalar_fixture(
        witness_coefficients=((1,),),
        witness_scalars=(3,),
        anchor_scalars=(5,),
        statement_g2_scalars=(7,),
        context=b"ranklock-v0.17-tampered-anchor",
    )
    key, _ciphertext = setup_split_basis_ppe_we(
        relation, bytes.fromhex("11" * 32), scale=13, proof_nonce=17
    )
    tampered = replace(
        key,
        scaled_witness_anchors_g2=(
            compress_g2(multiply(G2, 23, group="g2")),
        ),
    )
    assert not verify_split_basis_key(tampered)
