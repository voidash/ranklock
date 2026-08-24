from __future__ import annotations

import shutil
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from ranklock.v026.sp1_babe_compatibility import (
    BABE_PAPER_SHA256,
    SP1_GNARK_PROVE_SOURCE_SHA256,
    SP1_GROTH16_VK_BYTES,
    SP1_GROTH16_VK_SHA256,
    Sp1BabeCompatibilityError,
    Sp1GnarkVerifyingKeyV1,
    Sp1Groth16StatementV1,
    assess_sp1_babe_compatibility,
    inspect_imported_counterproof_artifacts,
)
from ranklock.v026.threshold_signature_release import (
    BabePublicSideInformationProfileV2,
    ThresholdSignatureReleaseError,
    exact_proof_statement_digest,
)

_ARTIFACT_BUNDLE = (
    Path(__file__).resolve().parents[2]
    / "artifacts/upstream/sp1-bridge-guests-prod-v0.3.0-rc.2-29570989611"
)
_COUNTERPROOF_PROGRAM_VKEY = bytes.fromhex(
    "00fc65c2f437f49e8cb93e196c917724ca679eaee622295320ecc25b07e4d189"
)


def _digest(label: str) -> bytes:
    return sha256(label.encode("ascii")).digest()


def _field_digest(label: str) -> bytes:
    result = bytearray(_digest(label))
    result[0] &= 0x1F
    return bytes(result)


def _side_information() -> BabePublicSideInformationProfileV2:
    return BabePublicSideInformationProfileV2(
        _digest("relation-circuit"),
        _digest("complete-crs"),
        _digest("proving-key"),
        _digest("projectivizer"),
        _digest("ceremony-transcript"),
    )


def _statement() -> Sp1Groth16StatementV1:
    return Sp1Groth16StatementV1.for_counterproof_output(
        program_vkey_hash=_COUNTERPROOF_PROGRAM_VKEY,
        operator_xonly_pubkey=bytes.fromhex(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        ),
        game_index=0x0102_0304,
        vk_root=_field_digest("vk-root"),
        proof_nonce=_field_digest("proof-nonce"),
    )


def test_exact_sp1_universal_vk_parses_to_five_public_inputs() -> None:
    parsed = Sp1GnarkVerifyingKeyV1.parse(SP1_GROTH16_VK_BYTES)
    statement = _statement()

    assert len(SP1_GROTH16_VK_BYTES) == 492
    assert sha256(SP1_GROTH16_VK_BYTES).hexdigest() == SP1_GROTH16_VK_SHA256
    assert parsed.digest.hex() == SP1_GROTH16_VK_SHA256
    assert parsed.public_input_count == 5
    assert len(parsed.positive_vk.ic_g1) == 6
    assert parsed.commitment_index_arrays == ()
    assert parsed.commitment_key_count == 0
    assert len(statement.public_inputs) == 5
    parsed.positive_vk.accumulator(statement.public_inputs)


def test_counterproof_statement_uses_exact_ssz_bytes_and_sp1_hash_rule() -> None:
    operator = bytes.fromhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    game_index = 0x0102_0304
    statement = Sp1Groth16StatementV1.for_counterproof_output(
        program_vkey_hash=_COUNTERPROOF_PROGRAM_VKEY,
        operator_xonly_pubkey=operator,
        game_index=game_index,
        vk_root=_field_digest("vk-root"),
        proof_nonce=_field_digest("proof-nonce"),
    )
    expected = bytearray(sha256(operator + game_index.to_bytes(4, "little")).digest())
    expected[0] &= 0x1F

    assert statement.program_vkey_hash == _COUNTERPROOF_PROGRAM_VKEY
    assert statement.committed_values_digest == bytes(expected)
    assert statement.exit_code == bytes(32)
    assert statement.public_inputs[1] == int.from_bytes(expected, "big")
    with pytest.raises(Sp1BabeCompatibilityError, match="u32"):
        Sp1Groth16StatementV1.for_counterproof_output(
            program_vkey_hash=_COUNTERPROOF_PROGRAM_VKEY,
            operator_xonly_pubkey=operator,
            game_index=1 << 32,
            vk_root=_field_digest("vk-root"),
            proof_nonce=_field_digest("proof-nonce"),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda raw: raw[:-1], "truncated"),
        (lambda raw: raw + b"\x00", "trailing"),
        (
            lambda raw: raw[:288] + (5).to_bytes(4, "big") + raw[292:],
            "trailing|invalid|commitment",
        ),
        (lambda raw: bytes(32) + raw[32:], "invalid group point"),
        (
            lambda raw: raw[:484] + (1).to_bytes(4, "big") + raw[488:],
            "commitment arrays",
        ),
        (
            lambda raw: raw[:488] + (1).to_bytes(4, "big"),
            "commitment keys",
        ),
    ),
)
def test_sp1_vk_parser_rejects_malformed_wire_bytes(mutation, message: str) -> None:
    with pytest.raises(Sp1BabeCompatibilityError, match=message):
        Sp1GnarkVerifyingKeyV1.parse(mutation(SP1_GROTH16_VK_BYTES))


def test_sp1_vk_schema_relabelling_is_rejected() -> None:
    parsed = Sp1GnarkVerifyingKeyV1.parse(SP1_GROTH16_VK_BYTES)
    with pytest.raises(Sp1BabeCompatibilityError, match="unknown.*schema"):
        replace(parsed, schema="ranklock-sp1-gnark-groth16-vk-v2")
    with pytest.raises(Sp1BabeCompatibilityError, match="projection disagrees"):
        replace(
            parsed,
            positive_vk=replace(parsed.positive_vk, context=b"unbound-context"),
        )


def test_production_vk_rejects_ranklock_two_limb_extension_early() -> None:
    parsed = Sp1GnarkVerifyingKeyV1.parse(SP1_GROTH16_VK_BYTES)
    with pytest.raises(
        ThresholdSignatureReleaseError,
        match="not compiled.*base-input-plus-two-counterproof-limb",
    ):
        exact_proof_statement_digest(
            parsed.positive_vk,
            _statement().public_inputs,
            counterproof_template_digest=_digest("counterproof-template"),
            side_information_profile=_side_information(),
        )


def test_imported_counterproof_artifacts_are_exact_and_not_a_complete_crs() -> None:
    evidence = inspect_imported_counterproof_artifacts(_ARTIFACT_BUNDLE)
    assessment = assess_sp1_babe_compatibility(_ARTIFACT_BUNDLE)

    assert evidence.manifest_sha256.hex() == (
        "989ebdaea348ddfbe9042c9dabbb31fd261e82d0bfcac29791093f47af43e723"
    )
    assert evidence.counterproof_elf_sha256.hex() == (
        "9ae1d4ef5816b598cf9b02be659d3bae6535151834f1fd77a5f4b572a60be8b7"
    )
    assert evidence.counterproof_predicate_sha256.hex() == (
        "50d8da4a706e4c07f3e4d8323557554ef6c476eaa340af468d5237f7a63437bd"
    )
    assert evidence.counterproof_program_vkey == _COUNTERPROOF_PROGRAM_VKEY
    assert evidence.predicate_universal_vk_hash_prefix == bytes.fromhex("4388a21c")
    assert evidence.manifest_schema == 3
    assert evidence.environment == "prod"
    assert evidence.strata_bridge_ref == "refs/tags/v0.3.0-rc.4"
    assert evidence.strata_bridge_sha == "3362fa450c48bd7df4009d827f01107945658e40"
    assert "groth16.r1cs" not in evidence.imported_file_names
    assert "groth16.pk" not in evidence.imported_file_names
    assert "projectivizer.bin" not in evidence.imported_file_names

    assert assessment.production_public_input_count == 5
    assert assessment.ranklock_extended_public_input_count == 7
    assert assessment.production_vk_accepts_ranklock_extended_layout is False
    assert assessment.selected_commitment_in_counterproof_public_values is False
    assert assessment.sp1_gnark_prover_samples_random_r_and_s is True
    assert assessment.babe_deterministic_r_prime_instantiated is False
    assert assessment.complete_r1cs_present_in_import is False
    assert assessment.complete_proving_key_present_in_import is False
    assert assessment.projectivizer_present_in_import is False
    assert assessment.direct_integration_compatible is False
    assert assessment.funding_eligible is False
    assert assessment.gnark_prove_source_sha256 == SP1_GNARK_PROVE_SOURCE_SHA256
    assert assessment.counterproof_types_source_sha256 == (
        "9068a5a2f8ae302c8f4d4a09dcd4ad88447068f2eca321f0a240dfcf7cdf3d84"
    )
    assert len(BABE_PAPER_SHA256) == 64

    with pytest.raises(Sp1BabeCompatibilityError, match="binding digest"):
        replace(evidence, binding_digest=_digest("forged-binding"))
    with pytest.raises(ValueError, match="init=False"):
        replace(assessment, direct_integration_compatible=True)
    with pytest.raises(ValueError, match="init=False"):
        replace(assessment, funding_eligible=True)


@pytest.mark.parametrize(
    "relative_path",
    (
        "manifest.json",
        "counterproof.elf",
        "counterproof.predicate",
        "counterproof-vkey.bin",
    ),
)
def test_imported_artifact_mutation_is_rejected(
    tmp_path: Path, relative_path: str
) -> None:
    copied = tmp_path / relative_path.replace(".", "-")
    shutil.copytree(_ARTIFACT_BUNDLE, copied)
    target = copied / relative_path
    target.write_bytes(target.read_bytes() + b"\x00")

    with pytest.raises(Sp1BabeCompatibilityError, match="pinned production artifact"):
        inspect_imported_counterproof_artifacts(copied)


def test_imported_artifact_roster_mutation_is_rejected(tmp_path: Path) -> None:
    copied = tmp_path / "extra-file"
    shutil.copytree(_ARTIFACT_BUNDLE, copied)
    (copied / "unbound-proving-key.bin").write_bytes(b"not-a-proving-key")

    with pytest.raises(Sp1BabeCompatibilityError, match="roster is not exact"):
        inspect_imported_counterproof_artifacts(copied)
