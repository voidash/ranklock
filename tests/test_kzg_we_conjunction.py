from __future__ import annotations

from ranklock.kzg_we_conjunction import (
    KzgOpeningStatement,
    aggregate_claimed_values,
    aggregate_same_point,
    conjunction_cost_inventory,
    decapsulate_conjunction,
    encapsulate_conjunction,
    opening_statement_and_witness,
)
from ranklock.ppe_normal_form import FormalKzgSrs


def test_multi_constraint_kzg_we_requires_every_valid_opening() -> None:
    srs = FormalKzgSrs(tau=1009)
    pairs = tuple(
        opening_statement_and_witness(poly, 43, srs=srs)
        for poly in ((3, 5, 7), (11, 13, 17), (19, 23, 29))
    )
    statements = tuple(pair[0] for pair in pairs)
    witnesses = tuple(pair[1] for pair in pairs)
    message = b"ranklock-fault-secret"
    ciphertext = encapsulate_conjunction(
        statements, message, randomizers=(31, 37, 41), srs=srs
    )
    assert decapsulate_conjunction(ciphertext, witnesses, srs=srs) == message
    wrong = list(witnesses)
    wrong[1] = pairs[0][1]
    assert decapsulate_conjunction(ciphertext, wrong, srs=srs) is None


def test_published_multi_constraint_shape_is_linear() -> None:
    inventory = conjunction_cost_inventory(137)
    assert inventory["ciphertext_group_elements"] == 137
    assert inventory["decryption_pairings"] == 137
    assert inventory["ciphertext_header_bytes"] == 137 * 96


def test_same_point_random_batch_reduces_to_one_kzg_we_instance() -> None:
    srs = FormalKzgSrs(tau=1013)
    pairs = tuple(
        opening_statement_and_witness(poly, 47, srs=srs)
        for poly in ((2, 3, 5), (7, 11, 13), (17, 19, 23))
    )
    statement, witness = aggregate_same_point(
        tuple(pair[0] for pair in pairs),
        tuple(pair[1] for pair in pairs),
        rho=53,
        srs=srs,
    )
    ciphertext = encapsulate_conjunction(
        (statement,), b"one-header", randomizers=(59,), srs=srs
    )
    assert decapsulate_conjunction(ciphertext, (witness,), srs=srs) == b"one-header"


def test_known_batch_challenge_allows_false_values_to_cancel() -> None:
    srs = FormalKzgSrs(tau=1019)
    rho = 61
    pairs = tuple(
        opening_statement_and_witness(poly, 71, srs=srs)
        for poly in ((5, 7, 11), (13, 17, 19))
    )
    true_statements = tuple(pair[0] for pair in pairs)
    true_aggregate, true_witness = aggregate_same_point(
        true_statements, tuple(pair[1] for pair in pairs), rho=rho, srs=srs
    )
    delta = 23
    false_statements = (
        KzgOpeningStatement(
            true_statements[0].commitment,
            true_statements[0].point,
            true_statements[0].value - rho * delta,
        ),
        KzgOpeningStatement(
            true_statements[1].commitment,
            true_statements[1].point,
            true_statements[1].value + delta,
        ),
    )
    false_aggregate = aggregate_claimed_values(false_statements, rho=rho, srs=srs)
    assert tuple(statement.value % srs.modulus for statement in false_statements) != tuple(
        statement.value for statement in true_statements
    )
    assert false_aggregate == true_aggregate
    ciphertext = encapsulate_conjunction(
        (false_aggregate,), b"cancellation", randomizers=(73,), srs=srs
    )
    assert decapsulate_conjunction(ciphertext, (true_witness,), srs=srs) == b"cancellation"
