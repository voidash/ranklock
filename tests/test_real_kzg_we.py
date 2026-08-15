from dataclasses import replace

import pytest

from ranklock.real_kzg_we import (
    CURVE_ORDER,
    KzgOpening,
    KzgStatement,
    KzgWeError,
    aggregate_same_point,
    decrypt_with_opening,
    encrypt_for_opening,
    verify_opening,
    KzgSrs,
)


def test_real_bn254_kzg_opening_and_witness_encryption() -> None:
    srs = KzgSrs.generate(8, tau=17)
    polynomial = (3, 5, 7, 11, 13)
    opening = srs.open(polynomial, 19)
    statement = KzgStatement(srs.commit(polynomial), opening.point, opening.value)
    assert verify_opening(srs, statement, opening)
    secret = bytes.fromhex("a5" * 32)
    ciphertext = encrypt_for_opening(srs, statement, secret, randomness=23)
    assert decrypt_with_opening(statement, ciphertext, opening) == secret
    assert ciphertext.encoded_bytes == 64 + 48

    wrong = replace(opening, value=(opening.value + 1) % CURVE_ORDER)
    assert not verify_opening(srs, replace(statement, value=wrong.value), wrong)
    with pytest.raises(KzgWeError):
        decrypt_with_opening(statement, ciphertext, wrong)


def test_real_same_point_batching_and_tampering() -> None:
    srs = KzgSrs.generate(8, tau=29)
    polynomials = ((1, 2, 3), (5, 8, 13, 21), (34, 55))
    _aggregate, statement, opening = aggregate_same_point(
        polynomials, point=31, challenge=37, srs=srs
    )
    assert verify_opening(srs, statement, opening)
    secret = bytes.fromhex("5a" * 32)
    ciphertext = encrypt_for_opening(srs, statement, secret, randomness=41)
    assert decrypt_with_opening(statement, ciphertext, opening) == secret
    corrupted = bytearray(ciphertext.payload)
    corrupted[-1] ^= 1
    with pytest.raises(KzgWeError):
        decrypt_with_opening(statement, replace(ciphertext, payload=bytes(corrupted)), opening)
