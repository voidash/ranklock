from __future__ import annotations

from ranklock.authenticated_witness_lift import (
    AuthenticatedDynamicWitness,
    FixedRelationStatement,
    lamport_keygen,
    lamport_sign,
    lift_cost_inventory,
    verify_authenticated_fixed_relation,
    verify_unsafe_fixed_relation,
)


def invalidity_verifier(dynamic_input: bytes, proof: bytes) -> bool:
    return proof == b"proof" and dynamic_input.startswith(b"invalid:")


def test_unbound_fixed_relation_accepts_substituted_invalid_input() -> None:
    actual = b"valid:actual-counterproof"
    substituted = b"invalid:attacker-chosen-counterproof"
    assert not verify_unsafe_fixed_relation(
        actual, b"proof", invalidity_verifier=invalidity_verifier
    )
    assert verify_unsafe_fixed_relation(
        substituted, b"proof", invalidity_verifier=invalidity_verifier
    )


def test_authenticated_dynamic_input_can_be_witness_of_static_relation() -> None:
    secret_key = lamport_keygen(b"ranklock-deposit-7")
    statement = FixedRelationStatement(b"deposit-7", secret_key.public_key)
    dynamic_input = b"invalid:actual-counterproof"
    witness = AuthenticatedDynamicWitness(
        dynamic_input,
        lamport_sign(
            secret_key, context=statement.context, dynamic_input=dynamic_input
        ),
        b"proof",
    )
    assert verify_authenticated_fixed_relation(
        statement, witness, invalidity_verifier=invalidity_verifier
    )


def test_authentication_for_valid_input_cannot_be_retargeted_to_invalid_input() -> None:
    secret_key = lamport_keygen(b"ranklock-deposit-8")
    statement = FixedRelationStatement(b"deposit-8", secret_key.public_key)
    signed_input = b"valid:actual-counterproof"
    signature = lamport_sign(
        secret_key, context=statement.context, dynamic_input=signed_input
    )
    substituted = AuthenticatedDynamicWitness(
        b"invalid:attacker-chosen-counterproof", signature, b"proof"
    )
    assert not verify_authenticated_fixed_relation(
        statement, substituted, invalidity_verifier=invalidity_verifier
    )
    inventory = lift_cost_inventory(dynamic_bytes=132, authenticated_chunks=132)
    assert inventory["ciphertext_statement_can_remain_static"] is True
