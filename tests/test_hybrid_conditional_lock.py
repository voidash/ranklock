from dataclasses import replace

import pytest

from ranklock.hybrid_conditional_lock import (
    HybridLockError,
    build_bound_trace_opening,
    online_authority_barrier,
    setup_hybrid_lock,
    unlock_hybrid_lock,
)
from ranklock.projective_vole_lock import ProjectiveVoleReceiver
from ranklock.bn254_real import G1, compress_g1
from ranklock.real_secp import DeterministicScalars


def _execute(values: bytes = b"\x01\x7f\xff"):
    full_secret = bytes.fromhex("42" * 32)
    state = setup_hybrid_lock(
        full_secret,
        input_bytes=len(values),
        kzg_maximum_degree=16,
        seed=b"ranklock-hybrid-test",
    )
    receiver = ProjectiveVoleReceiver(
        state.setup.projective_public,
        values,
        scalar_source=DeterministicScalars(b"ranklock-hybrid-receiver"),
    )
    response = state.projective_sender.respond(receiver.request)
    projective_witness = receiver.finalize(response)
    trace = build_bound_trace_opening(
        srs=state.setup.kzg_srs,
        projective_public=state.setup.projective_public,
        values=values,
        trace_values=(3, 5, 8, 13, 21),
    )
    future = state.trace_encapsulator.encapsulate(
        trace, expected_values=values, randomness=71
    )
    return full_secret, state, projective_witness, trace, future


def test_concrete_projective_and_kzg_shares_reconstruct_only_together() -> None:
    full_secret, state, witness, _trace, future = _execute()
    assert (
        unlock_hybrid_lock(
            state.setup, witness, future, expected_values=witness.values
        )
        == full_secret
    )
    assert state.setup.static_bytes > state.setup.projective_public.preprocessed_bytes
    assert future.public_bytes < 512


def test_input_trace_split_brain_is_rejected_by_online_encapsulator() -> None:
    values = b"\x01\x02"
    state = setup_hybrid_lock(
        bytes.fromhex("11" * 32),
        input_bytes=2,
        kzg_maximum_degree=8,
        seed=b"split-brain",
    )
    trace = build_bound_trace_opening(
        srs=state.setup.kzg_srs,
        projective_public=state.setup.projective_public,
        values=b"\x01\x03",
        trace_values=(1, 2, 3),
    )
    with pytest.raises(HybridLockError, match="another future input"):
        state.trace_encapsulator.encapsulate(
            trace, expected_values=values, randomness=19
        )


def test_wrong_opening_or_wrong_expected_values_cannot_unlock() -> None:
    _secret, state, witness, trace, future = _execute(b"\x10\x20")
    bad_opening = replace(trace.opening, proof_g1=compress_g1(G1))
    # Keep point/value consistent but replace the proof with another canonical point.
    bad_trace = replace(trace, opening=bad_opening)
    bad_future = replace(future, trace=bad_trace)
    with pytest.raises((HybridLockError, ValueError)):
        unlock_hybrid_lock(
            state.setup, witness, bad_future, expected_values=witness.values
        )
    with pytest.raises(HybridLockError, match="another byte vector"):
        unlock_hybrid_lock(
            state.setup, witness, future, expected_values=b"\x10\x21"
        )


def test_trace_encapsulator_is_one_shot_and_is_explicit_target_failure() -> None:
    _secret, state, _witness, trace, _future = _execute(b"\xaa")
    with pytest.raises(HybridLockError, match="consumed"):
        state.trace_encapsulator.encapsulate(
            trace, expected_values=b"\xaa", randomness=73
        )
    barrier = online_authority_barrier()
    assert barrier["no_online_authority_target_met"] is False
    assert "statement-bound" in barrier["breakthrough_failure"]
