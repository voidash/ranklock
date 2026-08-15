from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import sqlite3
import threading

import pytest

from ranklock.durable_slot_ledger import (
    DurableSlotLedger,
    SlotConflictError,
    SlotTerminalError,
)


def _d(tag: bytes) -> bytes:
    return sha256(tag).digest()


def _ledger(tmp_path, *, slots: int = 2) -> DurableSlotLedger:
    return DurableSlotLedger(
        tmp_path / "ranklock-slots.sqlite",
        context_digest=_d(b"context"),
        slot_count=slots,
    )


def test_burn_survives_restart_and_exact_replay_is_idempotent(tmp_path):
    ledger = _ledger(tmp_path)
    first = ledger.begin(
        0,
        context_digest=_d(b"context"),
        input_digest=_d(b"input"),
        authorization_digest=_d(b"authorization"),
        chain_binding_digest=_d(b"wtxid"),
    )
    assert first.state == "burned"
    assert ledger.remaining == 1

    reopened = _ledger(tmp_path)
    persisted = reopened.use(0)
    assert persisted.state == "burned"
    replay = reopened.begin(
        0,
        context_digest=_d(b"context"),
        input_digest=_d(b"input"),
        authorization_digest=_d(b"authorization"),
        chain_binding_digest=_d(b"wtxid"),
    )
    assert replay.exact_replay
    assert replay.state == "burned"
    assert reopened.finalize(0, outcome="success").state == "success"
    assert reopened.finalize(0, outcome="success").exact_replay
    with pytest.raises(SlotTerminalError):
        reopened.finalize(0, outcome="malformed")
    assert reopened.verify_audit_chain()


def test_two_process_style_writers_serialize_and_only_one_binding_wins(tmp_path):
    path = tmp_path / "ranklock-slots.sqlite"
    context = _d(b"context")
    DurableSlotLedger(path, context_digest=context, slot_count=1)
    barrier = threading.Barrier(2)

    def attempt(tag: bytes):
        local = DurableSlotLedger(path, context_digest=context, slot_count=1)
        barrier.wait()
        try:
            use = local.begin(
                0,
                context_digest=context,
                input_digest=_d(b"input" + tag),
                authorization_digest=_d(b"authorization" + tag),
                chain_binding_digest=_d(b"wtxid" + tag),
            )
            return ("won", tag, use)
        except SlotConflictError:
            return ("lost", tag, None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (b"A", b"B")))
    assert sorted(item[0] for item in outcomes) == ["lost", "won"]
    winner = next(item for item in outcomes if item[0] == "won")
    final = DurableSlotLedger(path, context_digest=context, slot_count=1)
    assert final.remaining == 0
    assert final.use(0).input_digest == _d(b"input" + winner[1])
    assert [event.event_type for event in final.events()] == [
        "burn",
        "conflict-rejected",
    ]
    assert final.verify_audit_chain()


def test_reorg_is_recorded_but_never_reopens_slot(tmp_path):
    ledger = _ledger(tmp_path, slots=1)
    ledger.begin(
        0,
        context_digest=_d(b"context"),
        input_digest=_d(b"input"),
        authorization_digest=_d(b"authorization"),
        chain_binding_digest=_d(b"wtxid"),
    )
    ledger.finalize(0, outcome="success")
    after = ledger.record_chain_observation(
        0,
        event_type="reorg-observed",
        block_hash=_d(b"orphaned block"),
        height=101,
    )
    assert after.state == "success"
    assert ledger.remaining == 0
    assert ledger.use(0).state == "success"


def test_audit_chain_detects_database_tampering(tmp_path):
    ledger = _ledger(tmp_path, slots=1)
    ledger.begin(
        0,
        context_digest=_d(b"context"),
        input_digest=_d(b"input"),
        authorization_digest=_d(b"authorization"),
        chain_binding_digest=_d(b"wtxid"),
    )
    assert ledger.verify_audit_chain()
    with sqlite3.connect(ledger.path) as conn:
        conn.execute("UPDATE audit_events SET event_type='forged' WHERE sequence=1")
    assert not ledger.verify_audit_chain()


def test_ledger_requires_private_directory_and_database_permissions(tmp_path):
    import os
    from ranklock.durable_slot_ledger import DurableSlotLedgerError

    unsafe = tmp_path / "unsafe-ledger-dir"
    unsafe.mkdir()
    os.chmod(unsafe, 0o777)
    with pytest.raises(DurableSlotLedgerError, match="must not be group/world writable"):
        DurableSlotLedger(
            unsafe / "ledger.sqlite", context_digest=_d(b"private-context"), slot_count=1
        )

    safe = tmp_path / "safe-ledger-dir"
    safe.mkdir(mode=0o700)
    ledger = DurableSlotLedger(
        safe / "ledger.sqlite", context_digest=_d(b"private-context"), slot_count=1
    )
    os.chmod(ledger.path, 0o644)
    with pytest.raises(DurableSlotLedgerError, match="permissions"):
        DurableSlotLedger(
            ledger.path, context_digest=_d(b"private-context"), slot_count=1
        )


def test_ledger_database_and_sqlite_sidecars_remain_private(tmp_path):
    import os
    import stat

    ledger = _ledger(tmp_path, slots=1)
    ledger.begin(
        0,
        context_digest=_d(b"context"),
        input_digest=_d(b"input-private"),
        authorization_digest=_d(b"authorization-private"),
        chain_binding_digest=_d(b"wtxid-private"),
    )
    for path in (ledger.path, *[type(ledger.path)(str(ledger.path) + suffix) for suffix in ("-wal", "-shm")]):
        if path.exists():
            assert stat.S_IMODE(os.lstat(path).st_mode) & 0o077 == 0


def test_authenticated_conflict_is_terminal_and_never_completes(tmp_path):
    """CORE-014: a conflicting binding permanently closes the slot.

    Only a validly signed preauthorization reaches ``begin``, so a conflict
    means one one-shot slot was bound to two different transactions.  The slot
    must fail closed: neither the conflicting request nor the original honest
    one may drive it forward afterwards.
    """

    ledger = _ledger(tmp_path, slots=1)
    context = _d(b"context")
    original = dict(
        context_digest=context,
        input_digest=_d(b"input"),
        authorization_digest=_d(b"authorization"),
        chain_binding_digest=_d(b"wtxid"),
    )
    assert ledger.begin(0, **original).state == "burned"

    with pytest.raises(SlotConflictError):
        ledger.begin(
            0,
            context_digest=context,
            input_digest=_d(b"other input"),
            authorization_digest=_d(b"other authorization"),
            chain_binding_digest=_d(b"other wtxid"),
        )

    conflicted = ledger.use(0)
    assert conflicted.state == "retry-rejected"
    assert conflicted.terminal
    # The original binding is preserved for audit even though it can no
    # longer complete.
    assert conflicted.input_digest == _d(b"input")

    # The honest request cannot resume the slot either.
    with pytest.raises(SlotConflictError):
        ledger.begin(0, **original)
    assert ledger.use(0).state == "retry-rejected"

    # A terminal slot cannot be finalized into a different outcome.
    with pytest.raises(SlotTerminalError):
        ledger.finalize(0, outcome="success")

    assert ledger.remaining == 0
    assert ledger.verify_audit_chain()


def test_conflict_after_success_is_audit_only_and_keeps_the_terminal_outcome(tmp_path):
    """A late conflict must not rewrite an already-released outcome.

    Once a slot has released on its original binding, that information cannot
    be recalled, so the terminal outcome stands and the conflict is recorded
    as audit only.
    """

    ledger = _ledger(tmp_path, slots=1)
    context = _d(b"context")
    ledger.begin(
        0,
        context_digest=context,
        input_digest=_d(b"input"),
        authorization_digest=_d(b"authorization"),
        chain_binding_digest=_d(b"wtxid"),
    )
    ledger.finalize(0, outcome="success")

    with pytest.raises(SlotConflictError):
        ledger.begin(
            0,
            context_digest=context,
            input_digest=_d(b"late input"),
            authorization_digest=_d(b"late authorization"),
            chain_binding_digest=_d(b"late wtxid"),
        )

    assert ledger.use(0).state == "success"
    assert [event.event_type for event in ledger.events()] == [
        "burn",
        "finalize",
        "conflict-rejected",
    ]
    assert ledger.verify_audit_chain()
