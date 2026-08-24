from __future__ import annotations

"""The production ACK exporter must not behave like the unsafe fixture.

The fixture derives its preimage from a fixed public seed and stores it in a
plaintext ``fixture-secrets/`` directory, so anyone who can read the bundle
can drive the bridge to ACK. These tests pin the properties that make the
real exporter usable instead: real entropy, one context per commitment, no
secret at rest outside the single unlock file, and idempotent retries.
"""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import os
from pathlib import Path
import threading

import pytest

from ranklock.strata_exporter import (
    AckContext,
    StrataAckExporter,
    StrataExportError,
    StrataPublicationAmbiguousError,
    ack_commitment,
    ack_proof_session_context,
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


def test_setup_refuses_integer_bytes_coercion():
    with pytest.raises(StrataExportError, match="explicit byte string"):
        derive_setup_payload(
            entropy=32,  # type: ignore[arg-type] -- bytes(32) would be public zeros
            graph_owner=1,
            deposit_index=2,
            game_index=3,
            watchtower_index=4,
        )


def test_setup_refuses_noncanonical_indices():
    with pytest.raises(StrataExportError, match="graph owner must be an integer"):
        derive_setup_payload(
            entropy=b"e" * 32,
            graph_owner=True,
            deposit_index=2,
            game_index=3,
            watchtower_index=4,
        )


def test_ack_context_requires_immutable_exact_bytes():
    with pytest.raises(StrataExportError, match="bridge proof txid must be immutable"):
        _context(bridge_proof_txid=bytearray(b"b" * 32))


def test_export_publishes_only_to_the_bound_context(tmp_path: Path):
    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    context = _context()

    path, created = exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload,
        context=context,
        expected_commitment=commitment,
    )
    assert created
    assert path.read_bytes() == payload
    assert path == exporter.unlock_path(context)


def test_exact_retry_is_idempotent(tmp_path: Path):
    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    context = _context()

    first, created_first = exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload,
        context=context,
        expected_commitment=commitment,
    )
    second, created_second = exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload,
        context=context,
        expected_commitment=commitment,
    )
    assert created_first and not created_second
    assert first == second
    assert first.read_bytes() == payload
    assert exporter.released_contexts() == 1


def test_a_second_context_is_a_terminal_conflict(tmp_path: Path):
    """One proof must never authorize two different ACK transactions."""

    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload,
        context=_context(),
        expected_commitment=commitment,
    )

    other = _context(counterproof_ack_txid=sha256(b"different ack").digest())
    with pytest.raises(StrataExportError, match="different bridge context"):
        exporter.export_unlock(
            allow_unverified_payload=True,
            payload=payload,
            context=other,
            expected_commitment=commitment,
        )
    assert not exporter.unlock_path(other).exists()

    # The commitment is now permanently unusable -- even for the original
    # context, which is the fail-closed choice.
    with pytest.raises(StrataExportError, match="permanently unusable"):
        exporter.export_unlock(
            allow_unverified_payload=True,
            payload=payload,
            context=_context(),
            expected_commitment=commitment,
        )


def test_payload_not_matching_the_commitment_is_refused(tmp_path: Path):
    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    wrong = bytes([payload[0] ^ 0xFF]) + payload[1:]

    with pytest.raises(StrataExportError, match="does not match the published"):
        exporter.export_unlock(
            allow_unverified_payload=True,
            payload=wrong,
            context=_context(),
            expected_commitment=commitment,
        )
    assert not exporter.unlock_path(_context()).exists()


def test_malformed_payload_length_is_refused(tmp_path: Path):
    _payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    with pytest.raises(StrataExportError, match="32 bytes"):
        exporter.export_unlock(
            allow_unverified_payload=True,
            payload=b"\x01" * 31,
            context=_context(),
            expected_commitment=commitment,
        )


def test_the_payload_never_appears_in_an_error_message(tmp_path: Path):
    """Error text is surfaced in logs; it must not leak the secret."""

    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload,
        context=_context(),
        expected_commitment=commitment,
    )

    other = _context(counterproof_ack_txid=sha256(b"another").digest())
    with pytest.raises(StrataExportError) as excinfo:
        exporter.export_unlock(
            allow_unverified_payload=True,
            payload=payload,
            context=other,
            expected_commitment=commitment,
        )
    assert payload.hex() not in str(excinfo.value)
    assert payload not in str(excinfo.value).encode()


def test_no_secret_is_written_outside_the_single_unlock_file(tmp_path: Path):
    """The fixture's plaintext fixture-secrets/ directory must have no analogue."""

    payload, commitment = _setup()
    exporter = StrataAckExporter(tmp_path)
    context = _context()
    exporter.publish_commitment(context, commitment)
    unlock, _created = exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload,
        context=context,
        expected_commitment=commitment,
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
    path, _created = exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload,
        context=_context(),
        expected_commitment=commitment,
    )
    assert path.stat().st_mode & 0o077 == 0


def test_commitment_publication_rejects_non_xonly(tmp_path: Path):
    exporter = StrataAckExporter(tmp_path)
    # All-0xFF exceeds the secp256k1 field modulus, so it cannot be an x-only key.
    with pytest.raises(StrataExportError, match="x-only"):
        exporter.publish_commitment(_context(), b"\xff" * 32)


def test_commitment_publication_is_write_once(tmp_path: Path):
    exporter = StrataAckExporter(tmp_path)
    _payload_one, commitment_one = _setup(b"1" * 32)
    _payload_two, commitment_two = _setup(b"2" * 32)
    assert commitment_one != commitment_two
    path = exporter.publish_commitment(_context(), commitment_one)
    assert path.read_bytes() == commitment_one
    assert exporter.publish_commitment(_context(), commitment_one) == path

    with pytest.raises(StrataExportError, match="already exists with different bytes"):
        exporter.publish_commitment(_context(), commitment_two)
    assert path.read_bytes() == commitment_one


def test_commitment_publication_rejects_insecure_existing_file(tmp_path: Path):
    exporter = StrataAckExporter(tmp_path)
    _payload, commitment = _setup(b"private-commitment" * 2)
    path = exporter.commitment_path(_context())
    path.parent.mkdir(mode=0o700)
    path.write_bytes(commitment)
    os.chmod(path, 0o644)

    with pytest.raises(StrataExportError, match="private-file validation"):
        exporter.publish_commitment(_context(), commitment)


def test_exporter_rejects_world_writable_root(tmp_path: Path):
    root = tmp_path / "unsafe-root"
    root.mkdir(mode=0o700)
    os.chmod(root, 0o777)
    with pytest.raises(StrataExportError, match="group/world writable"):
        StrataAckExporter(root)


def test_exporter_rejects_symlinked_ledger(tmp_path: Path):
    root = tmp_path / "export-root"
    root.mkdir(mode=0o700)
    target = tmp_path / "attacker-controlled.sqlite"
    target.write_bytes(b"")
    ledger = root / "export-ledger.sqlite"
    ledger.symlink_to(target)

    with pytest.raises(StrataExportError, match="private regular file"):
        StrataAckExporter(root)


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

    path_one, created_one = exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload_one,
        context=context_one,
        expected_commitment=commitment_one,
    )
    assert created_one
    original = path_one.read_bytes()
    assert original == payload_one

    with pytest.raises(StrataExportError, match="already exists with different bytes"):
        exporter.export_unlock(
            allow_unverified_payload=True,
            payload=payload_two,
            context=context_two,
            expected_commitment=commitment_two,
        )

    assert path_one.read_bytes() == original, "the first released secret must survive"


def test_concurrent_unlock_publishers_cannot_overwrite_each_other(tmp_path: Path):
    exporter = StrataAckExporter(tmp_path)
    payload_one, commitment_one = _setup(b"A" * 32)
    payload_two, commitment_two = _setup(b"B" * 32)
    assert commitment_one != commitment_two
    context_one = _context(slot_id=0)
    context_two = _context(slot_id=1)
    assert context_one.unlock_stem == context_two.unlock_stem
    start = threading.Barrier(2)

    def publish(payload: bytes, commitment: bytes, context: AckContext):
        start.wait()
        return exporter.export_unlock(
            allow_unverified_payload=True,
            payload=payload,
            context=context,
            expected_commitment=commitment,
        )

    outcomes: list[object] = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (
            pool.submit(publish, payload_one, commitment_one, context_one),
            pool.submit(publish, payload_two, commitment_two, context_two),
        )
        for future in futures:
            try:
                outcomes.append(future.result())
            except StrataExportError as exc:
                outcomes.append(exc)

    successes = [value for value in outcomes if isinstance(value, tuple)]
    failures = [value for value in outcomes if isinstance(value, StrataExportError)]
    assert len(successes) == 1
    assert len(failures) == 1
    published = exporter.unlock_path(context_one).read_bytes()
    assert published in {payload_one, payload_two}
    assert exporter.released_contexts() == 1


def test_visible_unlock_after_directory_sync_failure_requires_exact_retry(
    tmp_path: Path, monkeypatch
):
    import ranklock.strata_exporter as exporter_module

    exporter = StrataAckExporter(tmp_path)
    payload, commitment = _setup(b"durability-retry" * 2)
    context = _context()
    real_write_once = exporter_module.atomic_write_once

    def publish_then_report_sync_failure(path, data, *, mode):
        real_write_once(path, data, mode=mode)
        raise OSError("simulated directory fsync failure")

    monkeypatch.setattr(
        exporter_module, "atomic_write_once", publish_then_report_sync_failure
    )
    with pytest.raises(StrataPublicationAmbiguousError, match="exact retry required"):
        exporter.export_unlock(
            allow_unverified_payload=True,
            payload=payload,
            context=context,
            expected_commitment=commitment,
        )

    assert exporter.unlock_path(context).read_bytes() == payload
    assert exporter.released_contexts() == 1

    monkeypatch.setattr(exporter_module, "atomic_write_once", real_write_once)
    path, created = exporter.export_unlock(
        allow_unverified_payload=True,
        payload=payload,
        context=context,
        expected_commitment=commitment,
    )
    assert path == exporter.unlock_path(context)
    assert created is False
    assert exporter.released_contexts() == 1


# ---------------------------------------------------------------------------
# The proof-to-ACK binding.
#
# Before this existed, no code path conditioned release of the ACK preimage on
# possession of a valid proof: export_unlock took a caller-supplied payload,
# derive_setup_payload produced the same value from entropy alone, and every
# caller of export_unlock was a test. See V0252_THREAT_MODEL.md section 3b.
# ---------------------------------------------------------------------------


def _lock_fixture(context: AckContext | None = None):
    from ranklock.babe_positive_lock import deterministic_fixture, setup_positive_lock
    from ranklock.bn254_real import compress_g1, decompress_g1, multiply

    bound_context = _context() if context is None else context
    session = ack_proof_session_context(bound_context)
    vk, public_inputs, proof = deterministic_fixture(context=session)
    scale = 17
    payload, commitment = derive_setup_payload(
        entropy=b"P" * 32, graph_owner=1, deposit_index=2, game_index=3, watchtower_index=4
    )
    lock = setup_positive_lock(
        vk, public_inputs, payload, scale=scale, session_context=session
    )
    r_a = compress_g1(multiply(decompress_g1(proof.a_g1), scale, group="g1"))
    return vk, public_inputs, proof, lock, r_a, payload, commitment


def test_a_valid_proof_releases_the_ack_preimage(tmp_path: Path):
    """The payload is produced inside the call, never supplied by the caller."""

    from ranklock.strata_exporter import export_ack_from_verified_unlock

    vk, public_inputs, proof, lock, r_a, payload, commitment = _lock_fixture()
    exporter = StrataAckExporter(tmp_path)
    exporter.publish_commitment(_context(), commitment)

    path, created = export_ack_from_verified_unlock(
        exporter,
        vk=vk,
        public_inputs=public_inputs,
        proof=proof,
        lock=lock,
        r_a_g1=r_a,
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

    vk, public_inputs, proof, lock, _r_a, _payload, commitment = _lock_fixture()
    exporter = StrataAckExporter(tmp_path)
    exporter.publish_commitment(_context(), commitment)

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
            context=_context(),
            expected_commitment=commitment,
        )
    assert not any(tmp_path.glob("*.preimage")), "nothing may be published"


def test_proof_gated_export_requires_the_published_graph_commitment(tmp_path: Path):
    from ranklock.strata_exporter import export_ack_from_verified_unlock

    vk, public_inputs, proof, lock, r_a, _payload, commitment = _lock_fixture()
    exporter = StrataAckExporter(tmp_path)

    with pytest.raises(StrataExportError, match="published ACK commitment"):
        export_ack_from_verified_unlock(
            exporter,
            vk=vk,
            public_inputs=public_inputs,
            proof=proof,
            lock=lock,
            r_a_g1=r_a,
            context=_context(),
            expected_commitment=commitment,
        )
    assert not exporter.unlock_path(_context()).exists()


def test_the_binding_takes_no_payload_argument():
    """Structural: a caller cannot substitute a payload obtained elsewhere."""

    import inspect

    from ranklock.strata_exporter import export_ack_from_verified_unlock

    parameters = inspect.signature(export_ack_from_verified_unlock).parameters
    assert "payload" not in parameters
    assert "session_context" not in parameters


def test_a_valid_unlock_cannot_be_redirected_to_another_ack_context(tmp_path: Path):
    """The proof session and publication destination must be one identity."""

    from ranklock.babe_positive_lock import BabePositiveLockError
    from ranklock.strata_exporter import export_ack_from_verified_unlock

    original = _context()
    redirected = _context(counterproof_ack_txid=sha256(b"redirected ack").digest())
    vk, public_inputs, proof, lock, r_a, _payload, commitment = _lock_fixture(original)
    exporter = StrataAckExporter(tmp_path)

    # These contexts deliberately share the old, partial setup path. This
    # reproduces the split-brain that existed when session_context was a
    # caller-controlled argument independent from context.
    assert exporter.commitment_path(original) == exporter.commitment_path(redirected)
    exporter.publish_commitment(original, commitment)

    with pytest.raises(BabePositiveLockError, match="another statement"):
        export_ack_from_verified_unlock(
            exporter,
            vk=vk,
            public_inputs=public_inputs,
            proof=proof,
            lock=lock,
            r_a_g1=r_a,
            context=redirected,
            expected_commitment=commitment,
        )

    assert not exporter.unlock_path(redirected).exists()
    assert exporter.released_contexts() == 0


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
