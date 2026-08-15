from __future__ import annotations

import pytest

from ranklock.algebraic_input_auth import verify_authenticated_input
from ranklock.vole_input_auth import (
    OneShotAffineVoleSender,
    VoleInputAuthError,
    delivery_to_aggregate_witness,
    recover_coordinate_from_two_deliveries,
    vole_input_auth_cost,
)


def test_one_shot_vole_outputs_authenticate_the_selected_byte_vector() -> None:
    sender = OneShotAffineVoleSender.generate(
        132, session_context=b"ranklock-vole-deposit-91", seed=31
    )
    values = tuple((29 * i + 7) % 256 for i in range(132))
    delivery = sender.evaluate_once(values)
    witness = delivery_to_aggregate_witness(delivery, sender=sender)
    assert witness.values == values
    assert verify_authenticated_input(
        witness, tag_point=sender.tag_point, public_keys=sender.public_keys
    )


def test_sender_state_is_consumed_even_for_same_vector_retry() -> None:
    sender = OneShotAffineVoleSender.generate(
        3, session_context=b"ranklock-vole-consume", seed=37
    )
    sender.evaluate_once((1, 2, 3))
    with pytest.raises(VoleInputAuthError, match="already consumed"):
        sender.evaluate_once((1, 2, 3))


def test_two_receiver_vectors_recover_affine_sender_secret_and_all_values() -> None:
    sender = OneShotAffineVoleSender.generate(
        4, session_context=b"ranklock-vole-two-query", seed=41
    )
    first = sender.unsafe_evaluate_for_attack((5, 17, 29, 41))
    second = sender.unsafe_evaluate_for_attack((6, 99, 31, 200))
    for coordinate in range(4):
        recovered = recover_coordinate_from_two_deliveries(
            first, second, coordinate, modulus=sender.modulus
        )
        assert recovered.base == sender.bases[coordinate]
        assert recovered.slope == sender.slopes[coordinate]
        for value in (0, 1, 77, 255):
            assert recovered.at(value, sender.modulus) == (
                sender.bases[coordinate] + value * sender.slopes[coordinate]
            ) % sender.modulus


def test_cross_session_deliveries_cannot_be_combined() -> None:
    first = OneShotAffineVoleSender.generate(
        2, session_context=b"ranklock-vole-a", seed=43
    )
    second = OneShotAffineVoleSender.generate(
        2, session_context=b"ranklock-vole-b", seed=43
    )
    d0 = first.unsafe_evaluate_for_attack((1, 2))
    d1 = second.unsafe_evaluate_for_attack((3, 4))
    with pytest.raises(VoleInputAuthError, match="different sessions"):
        recover_coordinate_from_two_deliveries(d0, d1, 0)


def test_duty_free_bits_leading_expression_is_not_reported_as_concrete_bytes() -> None:
    cost = vole_input_auth_cost()
    assert cost.asymptotic_leading_expression_bits == (128 + 132) * 255
    assert cost.asymptotic_leading_expression_bytes_ceiling == 8_288
    assert cost.receiver_output_scalar_bytes == 4_224
    document = cost.document()
    assert "big-O constants" in document["warning"]
    assert document["eliminated_naive_token_catalog_bytes"] == 1_622_016
