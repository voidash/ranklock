from __future__ import annotations

"""The production ACK exporter must not behave like the unsafe fixture.

The fixture derives its preimage from a fixed public seed and stores it in a
plaintext ``fixture-secrets/`` directory, so anyone who can read the bundle
can drive the bridge to ACK. These tests pin the properties that make the
real exporter usable instead: real entropy, one context per commitment, no
secret at rest outside the single unlock file, and idempotent retries.
"""

from hashlib import sha256
from pathlib import Path

import pytest

from ranklock.strata_exporter import (
    AckContext,
    StrataAckExporter,
    StrataExportError,
    ack_commitment,
    commitment_is_valid_xonly,
    derive_setup_payload,
)


def _context(**overrides) -> AckContext:
    base = dict(
        network="regtest",
        chain_genesis_hash=sha256(b"genesis").digest(),
        graph_owner=1,
        deposit_index=2,
        game_index=3,
        watchtower_index=4,
        slot_id=0,
        epoch=7,
        bridge_proof_txid=sha256(b"bridge").digest(),
        counterproof_txid=sha256(b"counterproof").digest(),
        counterproof_ack_txid=sha256(b"ack").digest(),
    )
    base.update(overrides)
    return AckContext(**base)  # type: ignore[arg-type]


def _setup(entropy: bytes = b"E" * 32):
    return derive_setup_payload(
        entropy=entropy, graph_owner=1, deposit_index=2, game_index=3, watchtower_index=4
    )


def test_setup_payload_commitment_is_always_xonly_compatible():
    """The graph carries the commitment in an x-only-typed field."""

    for index in range(12):
        payload, commitment = _setup(entropy=bytes([index]) * 32)
        assert len(payload) == 32
        assert commitment == ack_commitment(payload)
        assert commitment_is_valid_xonly(commitment)


def test_setup_refuses_short_or_public_entropy():
    """A guessable seed would let anyone reconstruct the ACK preimage."""

    with pytest.raises(StrataExportError, match="entropy"):
        derive_setup_payload(
            entropy=b"short", graph_owner=1, deposit_index=2, game_index=3, watchtower_index=4
        )


def test_export_publishes_only_to_the_bound_context(tmp_path: Path):
    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    context = _context()

    path, created = exporter.export_unlock(allow_unverified_payload=True, 
        payload=payload, context=context, expected_commitment=commitment
    )
    assert created
    assert path.read_bytes() == payload
    assert path == exporter.unlock_path(context)


def test_exact_retry_is_idempotent(tmp_path: Path):
    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    context = _context()

    first, created_first = exporter.export_unlock(allow_unverified_payload=True, 
        payload=payload, context=context, expected_commitment=commitment
    )
    second, created_second = exporter.export_unlock(allow_unverified_payload=True, 
        payload=payload, context=context, expected_commitment=commitment
    )
    assert created_first and not created_second
    assert first == second
    assert first.read_bytes() == payload
    assert exporter.released_contexts() == 1


def test_a_second_context_is_a_terminal_conflict(tmp_path: Path):
    """One proof must never authorize two different ACK transactions."""

    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    exporter.export_unlock(allow_unverified_payload=True, 
        payload=payload, context=_context(), expected_commitment=commitment
    )

    other = _context(counterproof_ack_txid=sha256(b"different ack").digest())
    with pytest.raises(StrataExportError, match="different bridge context"):
        exporter.export_unlock(allow_unverified_payload=True, 
            payload=payload, context=other, expected_commitment=commitment
        )
    assert not exporter.unlock_path(other).exists()

    # The commitment is now permanently unusable -- even for the original
    # context, which is the fail-closed choice.
    with pytest.raises(StrataExportError, match="permanently unusable"):
        exporter.export_unlock(allow_unverified_payload=True, 
            payload=payload, context=_context(), expected_commitment=commitment
        )


def test_payload_not_matching_the_commitment_is_refused(tmp_path: Path):
    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    wrong = bytes([payload[0] ^ 0xFF]) + payload[1:]

    with pytest.raises(StrataExportError, match="does not match the published"):
        exporter.export_unlock(allow_unverified_payload=True, 
            payload=wrong, context=_context(), expected_commitment=commitment
        )
    assert not exporter.unlock_path(_context()).exists()


def test_malformed_payload_length_is_refused(tmp_path: Path):
    _payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    with pytest.raises(StrataExportError, match="32 bytes"):
        exporter.export_unlock(allow_unverified_payload=True, 
            payload=b"\x01" * 31, context=_context(), expected_commitment=commitment
        )


def test_the_payload_never_appears_in_an_error_message(tmp_path: Path):
    """Error text is surfaced in logs; it must not leak the secret."""

    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    exporter.export_unlock(allow_unverified_payload=True, payload=payload, context=_context(), expected_commitment=commitment)

    other = _context(counterproof_ack_txid=sha256(b"another").digest())
    with pytest.raises(StrataExportError) as excinfo:
        exporter.export_unlock(allow_unverified_payload=True, payload=payload, context=other, expected_commitment=commitment)
    assert payload.hex() not in str(excinfo.value)
    assert payload not in str(excinfo.value).encode()


def test_no_secret_is_written_outside_the_single_unlock_file(tmp_path: Path):
    """The fixture's plaintext fixture-secrets/ directory must have no analogue."""

    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    context = _context()
    exporter.publish_commitment(context, commitment)
    unlock, _created = exporter.export_unlock(allow_unverified_payload=True, 
        payload=payload, context=context, expected_commitment=commitment
    )

    carrying = [
        path
        for path in tmp_path.rglob("*")
        if path.is_file() and payload in path.read_bytes()
    ]
    assert carrying == [unlock], f"payload found outside the unlock file: {carrying}"


def test_unlock_file_is_not_world_readable(tmp_path: Path):
    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    path, _created = exporter.export_unlock(allow_unverified_payload=True, 
        payload=payload, context=_context(), expected_commitment=commitment
    )
    assert path.stat().st_mode & 0o077 == 0


def test_commitment_publication_rejects_non_xonly(tmp_path: Path):
    exporter = StrataAckExporter(tmp_path)
    # All-0xFF exceeds the secp256k1 field modulus, so it cannot be an x-only key.
    with pytest.raises(StrataExportError, match="x-only"):
        exporter.publish_commitment(_context(), b"\xff" * 32)


def test_context_digest_covers_every_binding_field():
    """Changing any bound field must change the context identity."""

    base = _context().digest
    mutations = (
        _context(network="signet"),
        _context(chain_genesis_hash=sha256(b"other genesis").digest()),
        _context(graph_owner=99),
        _context(deposit_index=99),
        _context(game_index=99),
        _context(watchtower_index=99),
        _context(slot_id=1),
        _context(epoch=8),
        _context(bridge_proof_txid=sha256(b"x").digest()),
        _context(counterproof_txid=sha256(b"y").digest()),
        _context(counterproof_ack_txid=sha256(b"z").digest()),
    )
    for mutated in mutations:
        assert mutated.digest != base


def test_a_colliding_context_cannot_silently_destroy_a_released_secret(tmp_path: Path):
    """Two contexts sharing the three txids must not overwrite each other.

    Found by cryptography review, which demonstrated the destruction. The
    unlock filename is ``bridge{}-counterproof{}-ack{}.preimage``, built from
    three txids on both sides of the language boundary -- bridge-exec's
    graph/ranklock.rs builds the identical string -- while the ledger is keyed
    on the commitment, a different partition of the context. Two contexts
    differing only outside those txids therefore share a filename.

    The guard existed but was unreachable: the write was
    ``if created or not path.is_file()``, and ``created`` is always true for a
    new commitment, so the second release silently replaced the first while
    the ledger reported both as released.

    The filename is deliberately NOT changed. It is a cross-language contract
    with the Rust reader, so binding more of the context into it requires
    changing both sides together; failing loudly is the correct bounded fix.
    """

    exporter = StrataAckExporter(tmp_path)

    payload_one, commitment_one = _setup(entropy=b"A" * 32)
    payload_two, commitment_two = _setup(entropy=b"B" * 32)
    assert commitment_one != commitment_two
    assert payload_one != payload_two

    # Same three txids, different slot: identical filename, distinct context.
    context_one = _context(slot_id=0)
    context_two = _context(slot_id=1)
    assert context_one.unlock_stem == context_two.unlock_stem
    assert context_one.digest != context_two.digest

    path_one, created_one = exporter.export_unlock(allow_unverified_payload=True, 
        payload=payload_one, context=context_one, expected_commitment=commitment_one
    )
    assert created_one
    original = path_one.read_bytes()
    assert original == payload_one

    with pytest.raises(StrataExportError, match="refusing to overwrite"):
        exporter.export_unlock(allow_unverified_payload=True, 
            payload=payload_two, context=context_two, expected_commitment=commitment_two
        )

    assert path_one.read_bytes() == original, "the first released secret must survive"


# ---------------------------------------------------------------------------
# The proof-to-ACK binding.
#
# Before this existed, no code path conditioned release of the ACK preimage on
# possession of a valid proof: export_unlock took a caller-supplied payload,
# derive_setup_payload produced the same value from entropy alone, and every
# caller of export_unlock was a test. See V0252_THREAT_MODEL.md section 3b.
# ---------------------------------------------------------------------------


def _lock_fixture():
    from ranklock.babe_positive_lock import deterministic_fixture, setup_positive_lock
    from ranklock.bn254_real import compress_g1, decompress_g1, multiply

    session = b"ranklock-proof-to-ack-binding-test"
    vk, public_inputs, proof = deterministic_fixture(context=session)
    scale = 17
    payload, commitment = derive_setup_payload(
        entropy=b"P" * 32, graph_owner=1, deposit_index=2, game_index=3, watchtower_index=4
    )
    lock = setup_positive_lock(
        vk, public_inputs, payload, scale=scale, session_context=session
    )
    r_a = compress_g1(multiply(decompress_g1(proof.a_g1), scale, group="g1"))
    return vk, public_inputs, proof, lock, r_a, session, payload, commitment


def test_a_valid_proof_releases_the_ack_preimage(tmp_path: Path):
    """The payload is produced inside the call, never supplied by the caller."""

    from ranklock.strata_exporter import export_ack_from_verified_unlock

    vk, public_inputs, proof, lock, r_a, session, payload, commitment = _lock_fixture()
    exporter = StrataAckExporter(tmp_path)

    path, created = export_ack_from_verified_unlock(
        exporter,
        vk=vk,
        public_inputs=public_inputs,
        proof=proof,
        lock=lock,
        r_a_g1=r_a,
        session_context=session,
        context=_context(),
        expected_commitment=commitment,
    )
    assert created
    assert path.read_bytes() == payload


def test_a_wrong_projective_output_releases_nothing(tmp_path: Path):
    """[r]A must be certified; a forged one must not yield the preimage."""

    from ranklock.babe_positive_lock import BabePositiveLockError
    from ranklock.bn254_real import compress_g1, decompress_g1, multiply
    from ranklock.strata_exporter import export_ack_from_verified_unlock

    vk, public_inputs, proof, lock, _r_a, session, _payload, commitment = _lock_fixture()
    exporter = StrataAckExporter(tmp_path)

    # The right shape, the wrong scalar.
    forged = compress_g1(multiply(decompress_g1(proof.a_g1), 18, group="g1"))

    with pytest.raises((BabePositiveLockError, StrataExportError)):
        export_ack_from_verified_unlock(
            exporter,
            vk=vk,
            public_inputs=public_inputs,
            proof=proof,
            lock=lock,
            r_a_g1=forged,
            session_context=session,
            context=_context(),
            expected_commitment=commitment,
        )
    assert not any(tmp_path.glob("*.preimage")), "nothing may be published"


def test_the_binding_takes_no_payload_argument():
    """Structural: a caller cannot substitute a payload obtained elsewhere."""

    import inspect

    from ranklock.strata_exporter import export_ack_from_verified_unlock

    parameters = inspect.signature(export_ack_from_verified_unlock).parameters
    assert "payload" not in parameters


def test_the_unverified_path_cannot_be_reached_by_forgetting_which_function_to_use(
    tmp_path: Path,
):
    """A release path must not accept a payload it cannot attribute to a proof.

    export_unlock validates only that the payload hashes to the expected
    commitment, which derive_setup_payload satisfies from setup entropy alone.
    That made the proof-gated path optional: a caller could publish a forged
    ACK simply by calling the wrong function. It now refuses unless the caller
    states that this is not a release path.
    """

    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)

    with pytest.raises(StrataExportError, match="export_ack_from_verified_unlock"):
        exporter.export_unlock(
            payload=payload, context=_context(), expected_commitment=commitment
        )
    assert not any(tmp_path.glob("*.preimage")), "nothing may be published"
