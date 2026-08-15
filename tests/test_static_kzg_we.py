from __future__ import annotations

import pytest

from ranklock.kzg_we_conjunction import opening_statement_and_witness
from ranklock.kzg_we_model import generator, pairing
from ranklock.ppe_normal_form import FormalKzgSrs
from ranklock.static_kzg_we import (
    StaticKzgWeError,
    build_fixed_commitment_projective_artifact,
    decrypt_selected_projective_ciphertext,
    prepare_public_affine_update,
    public_session_without_witness,
    public_update_header,
    static_timing_inventory,
)


def test_fixed_commitment_allows_projective_point_and_value_selection() -> None:
    srs = FormalKzgSrs(tau=1031)
    statement, witness = opening_statement_and_witness((7, 11, 13), 17, srs=srs)
    secret = generator("GT", srs.modulus).scale(123456)
    artifact = build_fixed_commitment_projective_artifact(
        commitment=statement.commitment,
        secret=secret,
        points=(17, 19),
        values=(statement.value, statement.value + 1),
        randomizer=79,
        srs=srs,
    )
    header, payload = artifact.select(point=17, value=statement.value)
    assert (
        decrypt_selected_projective_ciphertext(
            header=header, masked_payload=payload, witness=witness, srs=srs
        )
        == secret
    )
    _wrong_header, wrong_payload = artifact.select(
        point=17, value=statement.value + 1
    )
    assert (
        decrypt_selected_projective_ciphertext(
            header=header,
            masked_payload=wrong_payload,
            witness=witness,
            srs=srs,
        )
        != secret
    )


def test_public_affine_update_exposes_session_and_breaks_witness_only_secrecy() -> None:
    srs = FormalKzgSrs(tau=1033)
    statement, witness = opening_statement_and_witness((3, 5, 8), 23, srs=srs)
    material = prepare_public_affine_update(
        83, expose_randomizer_base=True, srs=srs
    )
    header = public_update_header(material, statement.point, srs=srs)
    public_session = public_session_without_witness(material, statement, srs=srs)
    witness_session = pairing(witness.opening, header)
    assert public_session == witness_session


def test_hiding_randomizer_base_prevents_public_statement_update() -> None:
    srs = FormalKzgSrs(tau=1039)
    statement, _witness = opening_statement_and_witness((2, 7, 9), 29, srs=srs)
    material = prepare_public_affine_update(
        89, expose_randomizer_base=False, srs=srs
    )
    with pytest.raises(StaticKzgWeError, match="requires"):
        public_update_header(material, statement.point, srs=srs)
    with pytest.raises(StaticKzgWeError, match="hidden"):
        public_session_without_witness(material, statement, srs=srs)


def test_dynamic_commitment_remains_the_static_timing_blocker() -> None:
    inventory = static_timing_inventory(
        fixed_commitment=False, finite_point_domain=256, finite_value_domain=256
    )
    assert inventory["future_arbitrary_commitment_supported"] is False
    assert "r*C" in inventory["barrier"]
