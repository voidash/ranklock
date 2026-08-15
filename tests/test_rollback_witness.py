from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from ranklock.bip340 import public_key
from ranklock.durable_slot_ledger import DurableSlotLedger
from ranklock.rollback_witness import (
    RollbackDetectedError,
    SignedLedgerCheckpoint,
    SqliteRollbackWitness,
    anchor_ledger_at_all_witnesses,
)


CONTEXT = bytes.fromhex("11" * 32)
PARTICIPANT_SECRET = 17
WITNESS_SECRET = 23


def _burn(ledger: DurableSlotLedger, slot: int = 0) -> None:
    ledger.begin(
        slot,
        context_digest=CONTEXT,
        input_digest=bytes.fromhex("22" * 32),
        authorization_digest=bytes.fromhex("33" * 32),
        chain_binding_digest=bytes.fromhex("44" * 32),
    )


def _finish(ledger: DurableSlotLedger, slot: int = 0) -> None:
    ledger.finalize(slot, outcome="success")


def test_witness_bootstrap_then_monotonic_anchor(tmp_path: Path) -> None:
    ledger = DurableSlotLedger(tmp_path / "ledger.sqlite", context_digest=CONTEXT, slot_count=2)
    witness = SqliteRollbackWitness(tmp_path / "witness.sqlite", witness_secret=WITNESS_SECRET)
    genesis = anchor_ledger_at_all_witnesses(
        ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
    )[0]
    assert genesis.generation == 0
    _burn(ledger)
    burned = anchor_ledger_at_all_witnesses(
        ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
    )[0]
    assert burned.generation == 1
    assert burned.previous_receipt_digest == genesis.digest
    assert burned.verify()
    _finish(ledger)
    consumed = anchor_ledger_at_all_witnesses(
        ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
    )[0]
    assert consumed.generation == 2
    assert consumed.previous_receipt_digest == burned.digest
    assert consumed.verify()


def test_restored_preburn_snapshot_is_rejected(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.sqlite"
    ledger = DurableSlotLedger(ledger_path, context_digest=CONTEXT, slot_count=1)
    witness = SqliteRollbackWitness(tmp_path / "witness.sqlite", witness_secret=WITNESS_SECRET)
    anchor_ledger_at_all_witnesses(
        ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
    )
    ledger.checkpoint()
    backup = tmp_path / "preburn.sqlite"
    shutil.copy2(ledger_path, backup)
    _burn(ledger)
    anchor_ledger_at_all_witnesses(
        ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
    )
    _finish(ledger)
    anchor_ledger_at_all_witnesses(
        ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
    )

    # Simulate an operator restoring the participant database while the
    # independently administered witness keeps its latest state.
    for suffix in ("", "-wal", "-shm"):
        Path(str(ledger_path) + suffix).unlink(missing_ok=True)
    shutil.copy2(backup, ledger_path)
    rolled_back = DurableSlotLedger(ledger_path, context_digest=CONTEXT, slot_count=1)
    with pytest.raises(RollbackDetectedError):
        anchor_ledger_at_all_witnesses(
            rolled_back, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
        )


def test_first_anchor_must_be_genesis(tmp_path: Path) -> None:
    ledger = DurableSlotLedger(tmp_path / "ledger.sqlite", context_digest=CONTEXT, slot_count=1)
    _burn(ledger)
    _finish(ledger)
    witness = SqliteRollbackWitness(tmp_path / "witness.sqlite", witness_secret=WITNESS_SECRET)
    with pytest.raises(RollbackDetectedError):
        anchor_ledger_at_all_witnesses(
            ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
        )


def test_witness_rejects_available_to_terminal_without_anchored_burn(tmp_path: Path) -> None:
    ledger = DurableSlotLedger(tmp_path / "ledger.sqlite", context_digest=CONTEXT, slot_count=1)
    witness = SqliteRollbackWitness(tmp_path / "witness.sqlite", witness_secret=WITNESS_SECRET)
    anchor_ledger_at_all_witnesses(
        ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
    )
    _burn(ledger)
    _finish(ledger)
    with pytest.raises(RollbackDetectedError):
        anchor_ledger_at_all_witnesses(
            ledger, participant_secret=PARTICIPANT_SECRET, witnesses=(witness,)
        )


def test_checkpoint_signature_and_identity(tmp_path: Path) -> None:
    ledger = DurableSlotLedger(tmp_path / "ledger.sqlite", context_digest=CONTEXT, slot_count=1)
    checkpoint = SignedLedgerCheckpoint.create(ledger, participant_secret=PARTICIPANT_SECRET)
    assert checkpoint.verify()
    assert checkpoint.unsigned.participant_pubkey == public_key(PARTICIPANT_SECRET)
    assert SignedLedgerCheckpoint.parse(checkpoint.encoded) == checkpoint


def test_rollback_witness_set_digest_is_canonical_and_rejects_duplicates():
    from ranklock.bip340 import public_key
    from ranklock.rollback_witness import RollbackWitnessError, rollback_witness_set_digest

    a, b = public_key(401), public_key(409)
    assert rollback_witness_set_digest((a, b)) == rollback_witness_set_digest((b, a))
    with pytest.raises(RollbackWitnessError, match="duplicated"):
        rollback_witness_set_digest((a, a))


def test_rollback_witness_database_requires_private_storage(tmp_path):
    import os
    from ranklock.rollback_witness import RollbackWitnessError

    unsafe = tmp_path / "unsafe-witness-dir"
    unsafe.mkdir()
    os.chmod(unsafe, 0o777)
    with pytest.raises(RollbackWitnessError, match="must not be group/world writable"):
        SqliteRollbackWitness(unsafe / "witness.sqlite", witness_secret=431)

    safe = tmp_path / "safe-witness-dir"
    safe.mkdir(mode=0o700)
    witness = SqliteRollbackWitness(safe / "witness.sqlite", witness_secret=433)
    os.chmod(witness.path, 0o644)
    with pytest.raises(RollbackWitnessError, match="permissions"):
        SqliteRollbackWitness(witness.path, witness_secret=433)
