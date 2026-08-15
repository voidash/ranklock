from dataclasses import replace

import pytest

from ranklock.projective_vole_lock import ProjectiveVoleReceiver
from ranklock.real_secp import DeterministicScalars, N
from ranklock.static_linear_conjunction import (
    LinearTraceRelation,
    StaticLinearConjunctionError,
    benchmark_static_linear_conjunction,
    decrypt_static_linear_conjunction,
    input_witness,
    setup_static_linear_conjunction,
    static_relation_frontier,
)


def _execute(values: bytes, trace_witness: tuple[int, ...]):
    secret = bytes.fromhex("99" * 32)
    trace_relation = LinearTraceRelation.derive_for_witness(
        trace_witness, domain=b"ranklock-linear-trace-test"
    )
    setup = setup_static_linear_conjunction(
        secret,
        trace_relation,
        input_bytes=len(values),
        seed=b"ranklock-static-conjunction-test",
    )
    receiver = ProjectiveVoleReceiver(
        setup.public.projective_public,
        values,
        scalar_source=DeterministicScalars(b"ranklock-static-conjunction-receiver"),
    )
    response = setup.projective_sender.respond(receiver.request)
    projective_witness = receiver.finalize(response)
    return secret, setup, projective_witness


def test_fixed_ciphertext_decrypts_for_future_input_and_valid_linear_trace() -> None:
    values = b"\x00\x80\xff"
    trace = (3, 5, 8, 13)
    secret, setup, projective_witness = _execute(values, trace)
    assert (
        decrypt_static_linear_conjunction(
            setup.public, projective_witness, trace
        )
        == secret
    )
    assert setup.public.ciphertext.encoded_bytes == 48
    assert setup.public.relation_width == 2 * len(values) + len(trace)


def test_wrong_trace_witness_cannot_decrypt_static_ciphertext() -> None:
    trace = (2, 7, 11)
    _secret, setup, projective_witness = _execute(b"\x42\x24", trace)
    with pytest.raises(StaticLinearConjunctionError):
        decrypt_static_linear_conjunction(
            setup.public, projective_witness, (2, 7, 12)
        )


def test_byte_and_selected_scalar_are_shared_relation_variables() -> None:
    trace = (17, 19)
    _secret, setup, projective_witness = _execute(b"\x55", trace)
    # Changing the byte while keeping the OT-derived scalar destroys the input equation.
    altered = replace(projective_witness, values=b"\x54")
    with pytest.raises(StaticLinearConjunctionError):
        decrypt_static_linear_conjunction(setup.public, altered, trace)
    # Changing the selected scalar has the same effect.
    altered_scalar = replace(
        projective_witness,
        selected_scalars=((projective_witness.selected_scalars[0] + 1) % N,),
    )
    with pytest.raises(StaticLinearConjunctionError):
        decrypt_static_linear_conjunction(setup.public, altered_scalar, trace)


def test_trace_relation_cannot_be_omitted_without_changing_the_static_relation() -> None:
    trace = (23, 29, 31)
    _secret, setup, projective_witness = _execute(b"\x01", trace)
    assert len(input_witness(projective_witness)) == 2
    with pytest.raises(StaticLinearConjunctionError):
        decrypt_static_linear_conjunction(setup.public, projective_witness, ())


def test_132_byte_frontier_remains_sub_megabyte_for_small_linear_wrapper() -> None:
    report = static_relation_frontier(input_bytes=132, trace_width=64)
    assert report["post_statement_encapsulator_required"] is False
    assert report["constant_ciphertext_bytes"] == 48
    assert report["reference_we_key_bytes"] < 128 * 1024


def test_small_static_linear_benchmark_has_exact_ot_accounting() -> None:
    result = benchmark_static_linear_conjunction(bytes(range(4)), (1, 1, 2, 3, 5))
    assert result.secret_recovered
    assert result.runtime_request_bytes == 4 * 8 * 37
    assert result.runtime_response_bytes == 4 * 8 * 100
    assert result.retained_bytes < 128 * 1024
