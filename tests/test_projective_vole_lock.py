from dataclasses import replace

import pytest

from ranklock.co_ot import OtResponse
from ranklock.projective_vole_lock import (
    ProjectiveVoleError,
    ProjectiveVoleReceiver,
    benchmark_projective_lock,
    recover_reused_affine_state,
    setup_projective_lock,
    synthesize_affine_scalar,
    unlock_share,
    verify_public_setup,
)
from ranklock.real_secp import DeterministicScalars, N


def _run(values: bytes):
    secret = bytes.fromhex("ab" * 32)
    public, sender = setup_projective_lock(secret, input_bytes=len(values), seed=b"test-lock")
    receiver = ProjectiveVoleReceiver(
        public, values, scalar_source=DeterministicScalars(b"test-receiver")
    )
    response = sender.respond(receiver.request)
    witness = receiver.finalize(response)
    return secret, public, sender, receiver, response, witness


def test_real_ot_to_projective_lock_releases_fixed_share() -> None:
    secret, public, _sender, _receiver, _response, witness = _run(b"\x00\x7f\xff")
    assert verify_public_setup(public)
    assert unlock_share(public, witness) == secret
    assert public.offer_bytes == 3 * 8 * 37
    assert public.preprocessed_bytes < 64 * 1024


def test_public_setup_and_selected_message_tampering_fail() -> None:
    _secret, public, _sender, _receiver, response, _witness = _run(b"\x42")
    coordinate = public.coordinates[0]
    bad_public = replace(
        public,
        coordinates=(replace(coordinate, proof_sp=replace(coordinate.proof_sp, response=(coordinate.proof_sp.response + 1) % N)),),
    )
    assert not verify_public_setup(bad_public)

    public2, sender2 = setup_projective_lock(bytes(32), input_bytes=1, seed=b"tamper")
    receiver2 = ProjectiveVoleReceiver(
        public2, b"\x01", scalar_source=DeterministicScalars(b"tamper-r")
    )
    raw = sender2.respond(receiver2.request)
    first = raw.responses[0]
    corrupt = bytearray(first.ciphertext1)
    corrupt[0] ^= 1
    tampered = replace(raw, responses=(replace(first, ciphertext1=bytes(corrupt)),) + raw.responses[1:])
    with pytest.raises(Exception):
        receiver2.finalize(tampered)


def test_sender_receiver_and_affine_state_are_one_shot() -> None:
    secret, public, sender, receiver, response, witness = _run(b"\x10")
    assert unlock_share(public, witness) == secret
    with pytest.raises(ProjectiveVoleError, match="consumed"):
        sender.respond(receiver.request)
    with pytest.raises(ProjectiveVoleError, match="consumed"):
        receiver.finalize(response)


def test_two_reuses_recover_entire_affine_line() -> None:
    q, b = 123456789, 987654321
    v0, v1 = 5, 201
    t0 = synthesize_affine_scalar(q, b, v0)
    t1 = synthesize_affine_scalar(q, b, v1)
    recovered_q, recovered_b = recover_reused_affine_state(v0, t0, v1, t1)
    assert (recovered_q, recovered_b) == (q, b)
    for value in range(256):
        assert synthesize_affine_scalar(recovered_q, recovered_b, value) == synthesize_affine_scalar(q, b, value)


def test_small_benchmark_has_exact_transcript_accounting() -> None:
    result = benchmark_projective_lock(bytes(range(4)), seed=b"bench-small")
    assert result.share_recovered
    assert result.binary_ots == 32
    assert result.offer_bytes == 32 * 37
    assert result.request_bytes == 32 * 37
    assert result.response_bytes == 32 * 100
    assert result.total_public_and_interactive_bytes < 64 * 1024
