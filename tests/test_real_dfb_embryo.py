from __future__ import annotations

from functools import lru_cache

import pytest

from ranklock.bn254_real import G1, affine, multiply
from ranklock.dfb_real import (
    DfbError,
    DfbGeneration,
    DfbProfile,
    DeterministicRng,
    bind_input_values,
    body_pad_statistical_distance,
    ccrh_golden_vector,
    evaluate_program,
    generate_program,
    generate_program_template,
    parse_decode_state,
    parse_input_labels,
    parse_program,
    parse_standalone_bundle,
    reconstruct_crt_columns,
    serialize_standalone_bundle,
    verify_affine_residues,
)
from ranklock.embryo_real import (
    EMBRYO_X_DIMENSION,
    EMBRYO_Y_DIMENSION,
    FIELD_MODULUS,
    ConditionalMapSecret,
    Monomial,
    direct_conditional_map_check,
    execute_embryo,
    garble_embryo,
    garble_sum_of_monomials,
)


FULL_HIDDEN_SCALAR = 0x123456789ABCDEF00112233445566778899AABBCCDDEEFF
FULL_PROGRAM_SHA256 = "8048bd63f1da493971fdac9b17be2b08f80854ce0bc00c13574ccac967271d61"


@lru_cache(maxsize=1)
def _full_execution():
    return execute_embryo(hidden_scalar=FULL_HIDDEN_SCALAR)


def test_reference_ccrh_golden_vector():
    assert ccrh_golden_vector() == bytes([175, 72, 194, 184, 45, 188, 159, 234, 245, 163])


def test_reference_profile_exact_program_and_decoder_accounting():
    profile = DfbProfile()
    document = profile.document((EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION))
    assert document["sub_widths"] == [8, 8, 6]
    assert document["program_bits"] == 3_598_229
    assert document["program_bytes"] == 449_779
    assert document["standalone_decode_bits"] == 1_824_661
    assert document["standalone_decode_bytes"] == 228_083
    assert document["standalone_bundle_bytes"] == 677_862
    assert 2 * document["program_bytes"] + 748 == 900_306
    assert (1 << 20) - (2 * document["program_bytes"] + 748) == 148_270
    assert 2 * document["standalone_bundle_bytes"] + 748 == 1_356_472
    assert 2 * document["standalone_bundle_bytes"] + 748 - (1 << 20) == 307_896


def test_small_program_serializes_parses_and_executes_affine_maps():
    profile = DfbProfile(input_bits=8, primes=(2, 3, 5, 7), batch_size=4)
    value = 173
    a_values = [17, 23, 5, 99]
    b_values = [31, 2, 200, 7]
    generation = generate_program(
        values=(value,),
        coefficients=((a_values, b_values),),
        profile=profile,
        seed=b"ranklock-small-dfb-test",
    )
    parsed = parse_program(
        generation.program.encoded,
        dimensions=generation.program.dimensions,
        profile=profile,
    )
    assert parsed.encoded == generation.program.encoded
    evaluation = evaluate_program(generation, values=(value,))
    verify_affine_residues(
        evaluation,
        values=(value,),
        coefficients=((a_values, b_values),),
        profile=profile,
    )


def test_standalone_bundle_and_future_labels_replay_from_bytes():
    profile = DfbProfile(input_bits=8, primes=(2, 3, 5, 7), batch_size=4)
    value = 173
    coefficients = (([17, 23, 5, 99], [31, 2, 200, 7]),)
    generation = generate_program(
        values=(value,),
        coefficients=coefficients,
        profile=profile,
        seed=b"ranklock-standalone-byte-replay",
    )
    bundle = serialize_standalone_bundle(generation.program, generation.decode_state)
    program, state = parse_standalone_bundle(
        bundle,
        dimensions=generation.program.dimensions,
        profile=profile,
    )
    labels = parse_input_labels(generation.input_encodings[0].encoded_labels, profile=profile)
    replay = DfbGeneration(
        program=program,
        decode_state=state,
        input_encodings=(labels,),
        garbler_hash_blocks=0,
    )
    evaluation = evaluate_program(replay, values=(value,))
    verify_affine_residues(
        evaluation,
        values=(value,),
        coefficients=coefficients,
        profile=profile,
    )
    assert state.canonical_bytes(profile) == generation.decode_state.canonical_bytes(profile)


def test_serialized_artifacts_fail_closed_on_truncation_padding_and_mutation():
    profile = DfbProfile(input_bits=8, primes=(2, 3, 5, 7), batch_size=4)
    value = 173
    coefficients = (([17, 23, 5, 99], [31, 2, 200, 7]),)
    generation = generate_program(
        values=(value,),
        coefficients=coefficients,
        profile=profile,
        seed=b"ranklock-artifact-mutation-test",
    )
    raw = generation.program.encoded
    with pytest.raises(DfbError):
        parse_program(raw[:-1], dimensions=generation.program.dimensions, profile=profile)

    padded = bytearray(raw)
    used = generation.program.bit_length % 8
    assert used
    padded[-1] |= 1 << used
    with pytest.raises(DfbError, match="padding"):
        parse_program(bytes(padded), dimensions=generation.program.dimensions, profile=profile)

    mutated = bytearray(raw)
    mutated[-1] ^= 1
    try:
        bad_program = parse_program(
            bytes(mutated), dimensions=generation.program.dimensions, profile=profile
        )
    except DfbError:
        pass
    else:
        bad_generation = DfbGeneration(
            program=bad_program,
            decode_state=generation.decode_state,
            input_encodings=generation.input_encodings,
            garbler_hash_blocks=generation.garbler_hash_blocks,
            effective_coefficients=generation.effective_coefficients,
            field_modulus=generation.field_modulus,
            statistical_security_bits=generation.statistical_security_bits,
        )
        bad_evaluation = evaluate_program(bad_generation, values=(value,))
        with pytest.raises(DfbError, match="affine residue mismatch"):
            verify_affine_residues(
                bad_evaluation,
                values=(value,),
                coefficients=coefficients,
                profile=profile,
            )

    decode_raw = generation.decode_state.canonical_bytes(profile)
    parsed_state = parse_decode_state(
        decode_raw, dimensions=generation.program.dimensions, profile=profile
    )
    assert parsed_state.canonical_bytes(profile) == decode_raw
    with pytest.raises(DfbError):
        parse_decode_state(
            decode_raw[:-1], dimensions=generation.program.dimensions, profile=profile
        )


def test_public_program_is_generated_before_input_binding():
    profile = DfbProfile(input_bits=8, primes=(2, 3, 5, 7), batch_size=4)
    coefficients = (([1, 2], [3, 4]),)
    template = generate_program_template(
        coefficients=coefficients,
        profile=profile,
        seed=b"ranklock-late-binding-test",
    )
    first = bind_input_values(template, values=(5,))
    second = bind_input_values(template, values=(7,))
    assert first.program.encoded == second.program.encoded == template.program.encoded
    assert first.decode_state.canonical_bytes(profile) == second.decode_state.canonical_bytes(profile)
    assert first.input_encodings[0].encoded_labels != second.input_encodings[0].encoded_labels
    for generation, value in ((first, 5), (second, 7)):
        evaluation = evaluate_program(generation, values=(value,))
        verify_affine_residues(
            evaluation,
            values=(value,),
            coefficients=coefficients,
            profile=profile,
        )


def test_sum_of_monomials_and_conditional_jacobian_maps():
    rng = DeterministicRng(b"ranklock-pgs-polynomial-test")
    monomials = (
        Monomial(7, ("x",)),
        Monomial(11, ("x", "y")),
        Monomial(13, ("y", "y")),
    )
    encoding = garble_sum_of_monomials(constant=19, monomials=monomials, rng=rng)
    x, y = 23, 29
    c_x = [(a * x + b) % FIELD_MODULUS for a, b in zip(encoding.a_x, encoding.b_x)]
    c_y = [(a * y + b) % FIELD_MODULUS for a, b in zip(encoding.a_y, encoding.b_y)]
    expected = (19 + 7 * x + 11 * x * y + 13 * y * y) % FIELD_MODULUS
    assert encoding.plan.evaluate(c_x, c_y, x, y) == expected

    input_point = multiply(G1, 1_234_567, group="g1")
    for bit in (0, 1):
        phi_scalar = 7_654_321 + bit
        phi = affine(multiply(G1, phi_scalar, group="g1"))
        assert phi is not None
        secret = ConditionalMapSecret(
            bit=bit,
            phi_scalar=phi_scalar,
            phi_x=phi[0].n,
            phi_y=phi[1].n,
            jacobian_scale=17,
        )
        assert direct_conditional_map_check(secret, input_point)


@pytest.mark.skip(
    reason=(
        "heavy 128-bit fixture is regenerated by the v0.22.1 and v0.23 "
        "release generators"
    )
)
def test_full_real_dfb_embryo_execution():
    execution = _full_execution()
    assert execution.garbling.dimensions == (EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION)
    assert execution.program_bytes == 508_395
    assert execution.decoder_bytes == 262_699
    assert execution.dfb_generation.program.sha256 == FULL_PROGRAM_SHA256
    assert execution.result.curve_check_valid
    assert execution.result.recovered_curve_secret == execution.garbling.curve_secret
    assert execution.result.map_points_verified == 256
    assert execution.result.output_matches
    assert execution.dfb_generation.garbler_hash_blocks == 7_697_526
    assert execution.dfb_evaluation.evaluator_hash_blocks == 7_661_830


def test_bn254_smudging_profiles_and_corrected_storage_frontier():
    from ranklock.dfb_real import FIRST_80_PRIMES, FIRST_90_PRIMES

    p80 = DfbProfile(primes=FIRST_80_PRIMES)
    p90 = DfbProfile(primes=FIRST_90_PRIMES)
    assert p80.statistical_smudging_bits(FIELD_MODULUS) == 44
    assert p90.statistical_smudging_bits(FIELD_MODULUS) >= 128

    doc = p90.document((EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION))
    assert doc["prime_count"] == 90
    assert doc["program_bytes"] == 508_395
    assert doc["standalone_decode_bytes"] == 262_699
    assert doc["standalone_bundle_bytes"] == 771_094
    assert 2 * doc["program_bytes"] + 748 == 1_017_538
    assert (1 << 20) - (2 * doc["program_bytes"] + 748) == 31_038


def test_coordinate_instances_use_independent_deltas_and_nonce_namespaces():
    from ranklock.dfb_real import NONCE_NAMESPACE_STRIDE, NonceLayout

    profile = DfbProfile(input_bits=8, primes=(2, 3, 5, 7), batch_size=4)
    coefficients = (([1, 2], [3, 4]), ([5, 6], [7, 8]))
    generation = generate_program(
        values=(5, 7),
        coefficients=coefficients,
        profile=profile,
        seed=b"ranklock-independent-coordinate-test",
    )
    assert generation.input_encodings[0].delta is not None
    assert generation.input_encodings[1].delta is not None
    assert generation.input_encodings[0].delta != generation.input_encodings[1].delta

    first = NonceLayout.build(profile, 2, coordinate_index=0)
    second = NonceLayout.build(profile, 2, coordinate_index=1)
    assert first.solo_chunk_base == 0
    assert second.solo_chunk_base == NONCE_NAMESPACE_STRIDE
    assert max(first.prime_bases) + max(first.prime_window_sizes) < NONCE_NAMESPACE_STRIDE
    assert second.prime_bases[0] >= NONCE_NAMESPACE_STRIDE + (1 << 32)


def test_statistical_smudging_lifts_and_reduces_back_to_target_field():
    profile = DfbProfile(
        input_bits=8,
        primes=(2, 3, 5, 7, 11, 13, 17, 19, 23, 29),
        batch_size=4,
    )
    field = 251
    value = 173
    coefficients = (([17, 23, 5], [31, 2, 200]),)
    generation = generate_program(
        values=(value,),
        coefficients=coefficients,
        profile=profile,
        seed=b"ranklock-smudging-test",
        field_modulus=field,
        statistical_security_bits=8,
    )
    assert generation.effective_coefficients is not None
    a_lift, b_lift = generation.effective_coefficients[0]
    assert a_lift == tuple(a % field for a in coefficients[0][0])
    assert all((lift - original) % field == 0 for lift, original in zip(b_lift, coefficients[0][1]))
    assert any(lift >= field for lift in b_lift)

    evaluation = evaluate_program(generation, values=(value,))
    verify_affine_residues(
        evaluation,
        values=(value,),
        coefficients=generation.effective_coefficients,
        profile=profile,
    )
    reconstructed = reconstruct_crt_columns(evaluation.decoded_residues[0], profile)
    expected = [
        (a * value + b) % field
        for a, b in zip(coefficients[0][0], coefficients[0][1], strict=True)
    ]
    assert [entry % field for entry in reconstructed] == expected
    assert any(entry != (a * value + b) for entry, a, b in zip(
        reconstructed, coefficients[0][0], coefficients[0][1], strict=True
    ))


def test_smudged_profile_rejects_noncanonical_target_field_input():
    profile = DfbProfile(
        input_bits=8,
        primes=(2, 3, 5, 7, 11, 13, 17, 19, 23, 29),
        batch_size=4,
    )
    template = generate_program_template(
        coefficients=(([1], [2]),),
        profile=profile,
        seed=b"ranklock-canonical-input-test",
        field_modulus=251,
        statistical_security_bits=8,
    )
    with pytest.raises(DfbError, match="canonical"):
        bind_input_values(template, values=(251,))


def test_v024_body_pad_sampler_uses_exact_u32_rejection_sampling():
    profile = DfbProfile(primes=tuple(list(DfbProfile().primes) + [419, 421, 431, 433, 439, 443, 449, 457, 461, 463]))
    document = profile.document((1,))
    assert document["body_pad_sampler"] == "exact 32-bit rejection sampling into each CRT group"
    assert document["body_pad_candidate_bits"] == 32
    assert document["body_pad_watchdog_attempts"] == 65536
    assert document["body_pad_max_total_variation_distance"] == 0.0
    assert document["uniform_body_pad_sampling_implemented"] is True
    # This helper now records only the bias that the removed modulo sampler
    # would have had; it is not the distribution used by hash_bulk_pads.
    assert body_pad_statistical_distance(181) > 0.0
