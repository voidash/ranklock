from __future__ import annotations

from ranklock.algebraic_input_auth import (
    AlgebraicInputAuthority,
    AggregateInputWitness,
    aggregate_tokens,
    expected_aggregate_key,
    forge_fresh_signature_only_witness,
    forge_token_from_two,
    input_auth_cost,
    verify_authenticated_input,
    verify_inner_product_gadget,
    verify_signature_gadget,
)


def test_honest_selected_vector_compresses_to_signature_and_inner_product() -> None:
    authority = AlgebraicInputAuthority.generate(
        132, session_context=b"ranklock-deposit-7", seed=11
    )
    values = tuple((17 * index + 3) % 256 for index in range(132))
    tokens = authority.select(values)
    witness = aggregate_tokens(tokens, authority.public_keys)
    assert witness.values == values
    assert verify_signature_gadget(witness, tag_point=authority.tag_point)
    assert verify_inner_product_gadget(witness, public_keys=authority.public_keys)
    assert verify_authenticated_input(
        witness, tag_point=authority.tag_point, public_keys=authority.public_keys
    )


def test_signature_gadget_alone_does_not_bind_values_or_authority_keys() -> None:
    authority = AlgebraicInputAuthority.generate(
        8, session_context=b"ranklock-signature-only-attack", seed=13
    )
    attacker = forge_fresh_signature_only_witness(
        (9,) * 8, tag_point=authority.tag_point, attacker_secret=1234567
    )
    assert verify_signature_gadget(attacker, tag_point=authority.tag_point)
    assert not verify_inner_product_gadget(attacker, public_keys=authority.public_keys)
    assert not verify_authenticated_input(
        attacker, tag_point=authority.tag_point, public_keys=authority.public_keys
    )


def test_two_values_for_one_coordinate_reveal_every_token_for_that_session() -> None:
    authority = AlgebraicInputAuthority.generate(
        4, session_context=b"ranklock-one-time-delivery", seed=17
    )
    token_5 = authority.token(2, 5)
    token_201 = authority.token(2, 201)
    forged = forge_token_from_two(token_5, token_201, 77)
    assert forged == authority.token(2, 77)

    honest_values = [11, 22, 5, 44]
    honest_tokens = list(authority.select(honest_values))
    honest_tokens[2] = forged
    forged_values = tuple([11, 22, 77, 44])
    witness = aggregate_tokens(honest_tokens, authority.public_keys)
    assert witness.values == forged_values
    assert verify_authenticated_input(
        witness, tag_point=authority.tag_point, public_keys=authority.public_keys
    )


def test_all_value_catalog_public_trivially_removes_projective_selection() -> None:
    authority = AlgebraicInputAuthority.generate(
        6, session_context=b"ranklock-public-catalog", seed=19
    )
    chosen = (255, 0, 91, 17, 42, 188)
    # A public 256-entry catalog gives the evaluator exactly these tokens for free.
    public_catalog = {
        (coordinate, value): authority.token(coordinate, value)
        for coordinate in range(authority.coordinates)
        for value in range(256)
    }
    witness = aggregate_tokens(
        tuple(public_catalog[(i, value)] for i, value in enumerate(chosen)),
        authority.public_keys,
    )
    assert verify_authenticated_input(
        witness, tag_point=authority.tag_point, public_keys=authority.public_keys
    )


def test_cost_inventory_is_explicit_and_not_a_static_lock_claim() -> None:
    cost = input_auth_cost()
    assert cost.naive_catalog_group_elements == 132 * 256
    assert cost.naive_catalog_bytes == 1_622_016
    assert cost.selected_token_bytes == 6_336
    assert cost.public_basis_bytes == 25_344
    assert cost.aggregate_witness_group_elements == 2
    document = cost.document()
    assert document["one_time_delivery_required"] is True
    assert "CRS" in " ".join(document["not_counted"])


def test_session_tag_prevents_cross_deposit_token_replay() -> None:
    first = AlgebraicInputAuthority.generate(
        5, session_context=b"ranklock-session-a", seed=23
    )
    second = AlgebraicInputAuthority.generate(
        5, session_context=b"ranklock-session-b", seed=23
    )
    # Same affine secret coefficients, distinct tag point.
    assert first.public_keys == second.public_keys
    values = (1, 2, 3, 4, 5)
    replayed = aggregate_tokens(first.select(values), second.public_keys)
    assert not verify_signature_gadget(replayed, tag_point=second.tag_point)
    assert not verify_authenticated_input(
        replayed, tag_point=second.tag_point, public_keys=second.public_keys
    )
