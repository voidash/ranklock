from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock.basis_separated_kzg import (
    BasisSeparatedKzgError,
    BasisSeparatedKzgSrs,
    BasisSeparatedStatement,
    decrypt_basis_separated_opening,
    decrypt_from_published_scaled_rho,
    encrypt_basis_separated_opening,
    static_timing_frontier,
    verify_basis_separated_opening,
)
from ranklock.bn254_real import G2, compress_g2, multiply
from ranklock.real_kzg_we import CURVE_ORDER


def test_basis_separated_kzg_opening_and_we() -> None:
    srs = BasisSeparatedKzgSrs.generate(8, tau=17, rho=19)
    polynomial = (3, 5, 7, 11, 13)
    opening = srs.open(polynomial, 23)
    statement = BasisSeparatedStatement(
        srs.commit(polynomial), opening.point, opening.value, b"ranklock-v0.17"
    )
    assert verify_basis_separated_opening(srs, statement, opening)

    secret = bytes.fromhex("a6" * 32)
    ciphertext = encrypt_basis_separated_opening(
        srs, statement, secret, randomness=29
    )
    assert ciphertext.encoded_bytes == 64 + 64 + 48
    assert decrypt_basis_separated_opening(statement, ciphertext, opening) == secret

    wrong = replace(opening, value=(opening.value + 1) % CURVE_ORDER)
    assert not verify_basis_separated_opening(
        srs, replace(statement, value=wrong.value), wrong
    )
    with pytest.raises(BasisSeparatedKzgError):
        decrypt_basis_separated_opening(statement, ciphertext, wrong)


def test_reusable_header_supports_future_point_without_scaled_rho() -> None:
    srs = BasisSeparatedKzgSrs.generate(16, tau=31, rho=37)
    polynomial = (2, 3, 5, 7, 11, 13)
    secret = bytes.fromhex("44" * 32)

    for point in (41, 43):
        opening = srs.open(polynomial, point)
        statement = BasisSeparatedStatement(
            srs.commit(polynomial), opening.point, opening.value, b"future-point"
        )
        ciphertext = encrypt_basis_separated_opening(
            srs, statement, secret, randomness=47
        )
        # One pair of r[tau], r[1] anchors derives the statement-specific r[tau-z].
        assert decrypt_basis_separated_opening(statement, ciphertext, opening) == secret

    frontier = static_timing_frontier(srs)
    assert frontier["reusable_witness_header_anchors"] == 2
    assert frontier["post_statement_encapsulator_required"] is True


def test_publishing_scaled_rho_breaks_the_ciphertext_after_statement_exists() -> None:
    rho = 53
    randomness = 59
    srs = BasisSeparatedKzgSrs.generate(8, tau=61, rho=rho)
    polynomial = (1, 4, 9, 16)
    opening = srs.open(polynomial, 67)
    statement = BasisSeparatedStatement(
        srs.commit(polynomial), opening.point, opening.value, b"scaled-rho-break"
    )
    secret = bytes.fromhex("99" * 32)
    ciphertext = encrypt_basis_separated_opening(
        srs, statement, secret, randomness=randomness
    )

    scaled_rho = compress_g2(
        multiply(G2, rho * randomness % CURVE_ORDER, group="g2")
    )
    assert decrypt_from_published_scaled_rho(
        statement, ciphertext, scaled_rho
    ) == secret
