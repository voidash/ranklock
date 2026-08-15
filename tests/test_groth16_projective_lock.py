from __future__ import annotations

from dataclasses import replace
import hashlib

from ranklock.groth16_projective_lock import (
    FormalGroth16Ppe,
    FormalGroth16VerifyingKey,
    ProjectiveInputEnvelope,
    combine_context_scalars,
    projective_ppe_reduction_report,
    recursive_context_digest,
    single_scalar_collision,
    split_context_digest,
    synthesize_formal_proof,
    unsafe_single_scalar_encoding,
)


def _context(
    *,
    deployment: bytes = b"deployment-a",
    wrapper_vk: bytes = b"wrapper-vk",
    program: bytes = b"program",
    statement: bytes = b"statement",
    transparent_vk: bytes = b"transparent-vk",
    result_tag: bytes = b"invalid",
) -> bytes:
    return recursive_context_digest(
        program_digest=hashlib.sha256(program).digest(),
        statement_digest=hashlib.sha256(statement).digest(),
        transparent_verifier_digest=hashlib.sha256(transparent_vk).digest(),
        wrapper_verifying_key_digest=hashlib.sha256(wrapper_vk).digest(),
        deployment_id=deployment,
        result_tag=result_tag,
    )


def test_two_scalar_context_encoding_is_exact_and_canonical() -> None:
    digest = _context()
    public_inputs = split_context_digest(digest)
    assert combine_context_scalars(public_inputs) == digest
    assert all(0 <= value < 2**128 for value in public_inputs)


def test_one_scalar_modular_encoding_has_concrete_collision() -> None:
    left, right, image = single_scalar_collision()
    assert left != right
    assert unsafe_single_scalar_encoding(left) == image
    assert unsafe_single_scalar_encoding(right) == image


def test_formal_groth16_ppe_binds_both_context_coordinates() -> None:
    vk = FormalGroth16VerifyingKey.derive(b"context-binding-test")
    public_inputs = split_context_digest(_context())
    proof = synthesize_formal_proof(vk, public_inputs, a_g1=17, b_g2=29)
    equation = FormalGroth16Ppe(vk, public_inputs, proof)
    assert equation.satisfied

    assert not FormalGroth16Ppe(
        vk,
        (public_inputs[0] ^ 1, public_inputs[1]),
        proof,
    ).satisfied
    assert not FormalGroth16Ppe(
        vk,
        (public_inputs[0], public_inputs[1] ^ 1),
        proof,
    ).satisfied
    assert not FormalGroth16Ppe(
        vk,
        public_inputs,
        replace(proof, c_g1=proof.c_g1 + 1),
    ).satisfied


def test_context_domain_blocks_replay_and_vk_substitution() -> None:
    vk = FormalGroth16VerifyingKey.derive(b"replay-test")
    original = split_context_digest(_context())
    proof = synthesize_formal_proof(vk, original, a_g1=31, b_g2=43)
    assert FormalGroth16Ppe(vk, original, proof).satisfied

    altered_contexts = (
        _context(deployment=b"deployment-b"),
        _context(wrapper_vk=b"other-wrapper-vk"),
        _context(program=b"other-program"),
        _context(statement=b"other-statement"),
        _context(transparent_vk=b"other-transparent-vk"),
        _context(result_tag=b"valid"),
    )
    for altered in altered_contexts:
        assert not FormalGroth16Ppe(
            vk,
            split_context_digest(altered),
            proof,
        ).satisfied


def test_projective_digest_catalog_fits_one_mib_envelope() -> None:
    envelope = ProjectiveInputEnvelope()
    assert envelope.total_bytes == 852_448
    assert envelope.maximum_components_per_bit == 39
    assert envelope.fits_cap

    report = projective_ppe_reduction_report()
    assert report["status"] == "FORMAL_RECURSIVE_REDUCTION_CANDIDATE"
    assert report["dynamic_predicate"]["pairing_product_equations"] == 1
    assert report["context_encoding"]["injective_on_digest_values"] is True
    assert report["legacy_input_comparison"]["choice_count_reduction"] == 66.0
