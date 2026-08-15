from __future__ import annotations

from dataclasses import replace

import numpy as np
import pytest

from ranklock.bn254_real import CURVE_ORDER, FIELD_MODULUS, eq_points
from ranklock.dfb_real import (
    DfbProfile,
    bind_input_values,
    evaluate_program,
    evaluate_program_labels,
    generate_program_template,
    reconstruct_crt_columns,
    serialize_program,
)
from ranklock.embryo_mask_fusion import (
    CURRENT_MANIFEST_BYTES,
    FUSED_MAP_MASKS,
    FIRST_91_PRIMES,
    MaskFusionError,
    build_public_embryo_layout,
    execute_mask_fused_embryo,
    evaluate_mask_fused_outputs,
    parse_compact_program,
    parse_fused_mask_state,
    parse_fused_retained_object,
    parse_fused_slot,
    replay_fused_slot,
)
from ranklock.embryo_real import EmbryoError


@pytest.fixture(scope="module")
def full_execution():
    return execute_mask_fused_embryo(
        hidden_scalar=0x1234_5678_9ABC_DEF % CURVE_ORDER,
        dfb_seed=b"ranklock/v023/test/dfb-template/v1",
        garbling_seed=b"ranklock/v023/test/embryo-fusion/v1",
        input_scalar_start=987_654,
    )


def test_raw_label_api_matches_standalone_decode() -> None:
    profile = DfbProfile(input_bits=8, primes=(2, 3, 5, 7, 11))
    coefficients = (((3, 4, 5), (6, 7, 8)),)
    template = generate_program_template(
        coefficients=coefficients,
        profile=profile,
        seed=b"ranklock/v023/raw-label-api",
    )
    generation = bind_input_values(template, values=(173,))
    labels = evaluate_program_labels(generation, values=(173,))
    decoded = evaluate_program(generation, values=(173,))
    for prime_index, prime in enumerate(profile.primes):
        masks = generation.decode_state.coordinates[0].output_masks[prime_index]
        recovered = (
            labels.label_residues[0][prime_index]
            + np.uint64(prime)
            - masks.astype(np.uint64)
        ) % np.uint64(prime)
        assert np.array_equal(recovered, decoded.decoded_residues[0][prime_index])


def test_full_fusion_executes_and_meets_exact_target(full_execution) -> None:
    execution = full_execution
    assert execution.result.output_matches
    assert execution.result.curve_check_valid
    assert execution.result.recovered_curve_secret == execution.garbling.curve_secret
    assert execution.result.map_points_verified == 256

    assert len(execution.generation.program.encoded) == 497_718
    assert execution.generation.program.bit_length == 3_981_741
    assert len(execution.mask_state.encoded_bytes) == 24_384
    assert len(execution.retained_slot_bytes) == 522_102
    assert execution.accounting.manifest_and_positive_lock_bytes == CURRENT_MANIFEST_BYTES
    assert execution.accounting.complete_retained_bytes == 1_044_952
    assert execution.accounting.margin_bytes == 3_624
    assert execution.accounting.target_met
    parsed_program, parsed_masks = parse_fused_slot(
        execution.retained_slot_bytes, profile=execution.generation.program.profile
    )
    assert parsed_program.encoded == execution.generation.program.encoded
    assert parsed_masks == execution.mask_state


def test_fusion_eliminates_all_nonterminal_masks(full_execution) -> None:
    metadata = full_execution.lift_metadata
    all_masks = metadata.individual_masks_x + metadata.individual_masks_y
    # Eight monomial chains per map and two curve-check chains are terminal.
    assert len(all_masks) == 3_077
    assert metadata.nonzero_individual_masks == 8 * 256 + 2
    assert sum(mask == 0 for mask in all_masks) == 3_077 - (8 * 256 + 2)
    assert len(full_execution.mask_state.map_coordinate_masks) == FUSED_MAP_MASKS
    assert full_execution.mask_state.curve_mask == 0


def test_compact_crt_program_is_canonical_and_saves_16539_bytes(full_execution) -> None:
    compact = full_execution.generation.program
    parsed = parse_compact_program(
        compact.encoded,
        dimensions=compact.dimensions,
        profile=compact.profile,
    )
    assert parsed.encoded == compact.encoded
    assert parsed.bit_length == compact.bit_length

    standard = serialize_program(compact.coordinates, compact.profile)
    assert len(standard.encoded) == 514_257
    assert len(standard.encoded) - len(compact.encoded) == 16_539

    for got_coordinate, expected_coordinate in zip(
        parsed.coordinates, compact.coordinates, strict=True
    ):
        for got_body, expected_body in zip(
            got_coordinate.bodies, expected_coordinate.bodies, strict=True
        ):
            assert len(got_body.batches) == len(expected_body.batches)
            for got, expected in zip(got_body.batches, expected_body.batches, strict=True):
                assert np.array_equal(got, expected)


def test_fused_mask_state_roundtrip_and_noncanonical_rejection(full_execution) -> None:
    raw = full_execution.mask_state.encoded_bytes
    assert parse_fused_mask_state(raw) == full_execution.mask_state
    with pytest.raises(MaskFusionError):
        parse_fused_mask_state(raw[:-1])


def test_mutating_one_final_mask_breaks_the_embryo_result(full_execution) -> None:
    execution = full_execution
    from ranklock.dfb_real import reconstruct_crt_columns

    raw_x = reconstruct_crt_columns(
        execution.label_evaluation.label_residues[0], execution.generation.program.profile
    )
    raw_y = reconstruct_crt_columns(
        execution.label_evaluation.label_residues[1], execution.generation.program.profile
    )
    masks = list(execution.mask_state.map_coordinate_masks)
    masks[0] = (masks[0] + 1) % FIELD_MODULUS
    mutated = replace(execution.mask_state, map_coordinate_masks=tuple(masks))
    with pytest.raises(EmbryoError):
        evaluate_mask_fused_outputs(
            execution.garbling,
            mask_state=mutated,
            input_point=execution.result.input_point,
            raw_x=raw_x,
            raw_y=raw_y,
        )


def test_91_prime_profile_is_the_conservative_128_bit_frontier() -> None:
    profile = DfbProfile(primes=FIRST_91_PRIMES)
    assert profile.statistical_smudging_bits(FIELD_MODULUS) == 141
    assert profile.primorial.bit_length() == 649
    assert profile.crt_bits == 692


def test_generated_two_slot_retained_object_is_canonical() -> None:
    from pathlib import Path

    raw = Path("artifacts/ranklock-v023-two-slot-retained-object.bin").read_bytes()
    profile = DfbProfile(primes=FIRST_91_PRIMES)
    parsed = parse_fused_retained_object(raw, profile=profile)
    assert parsed.encoded_bytes == 1_044_952
    assert len(parsed.slots) == 2
    assert parsed.slots[0] != parsed.slots[1]
    assert parsed.manifest.encoded_bytes == 748
    assert parsed.manifest.verify(
        required_pubkeys=parsed.manifest.unsigned.contributor_pubkeys,
        expected_context_digest=parsed.manifest.unsigned.context_digest,
        expected_generator_code_hash=parsed.manifest.unsigned.generator_code_hash,
    )


def test_public_layout_matches_generator_layout(full_execution) -> None:
    layout = build_public_embryo_layout()
    assert layout.map_plans == full_execution.garbling.map_plans
    assert layout.curve_plan == full_execution.garbling.curve_plan


def test_parsed_slot_replays_without_generator_state(full_execution) -> None:
    program, masks = parse_fused_slot(
        full_execution.retained_slot_bytes,
        profile=full_execution.generation.program.profile,
    )
    replay = replay_fused_slot(
        program=program,
        mask_state=masks,
        input_point=full_execution.result.input_point,
        x_input_labels=full_execution.generation.input_encodings[0].encoded_labels,
        y_input_labels=full_execution.generation.input_encodings[1].encoded_labels,
    )
    assert replay.result.curve_check_valid
    assert replay.result.recovered_curve_secret == full_execution.garbling.curve_secret
    assert replay.result.maps_evaluated == 256
    assert eq_points(replay.result.output_point, full_execution.result.expected_point)
    assert replay.raw_x == tuple(
        reconstruct_crt_columns(
            full_execution.label_evaluation.label_residues[0],
            full_execution.generation.program.profile,
        )
    )
