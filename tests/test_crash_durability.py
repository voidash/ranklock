from __future__ import annotations

"""CORE-016/017: the slot ledger must survive a real process kill.

Existing coverage reopens a ``DurableSlotLedger`` object in the same
interpreter, which exercises SQLite reads but not durability: a process that
is still alive has flushed nothing the OS could lose. These tests SIGKILL a
child *between* the commit and the response write, then inspect the database
from a fresh process.

SIGKILL specifically, not SIGTERM: it cannot be caught, so no atexit hook,
context manager or finally block can tidy up on the way out. That is what
makes the surviving state attributable to the WAL/synchronous=FULL commit
rather than to orderly shutdown.
"""

from hashlib import sha256
import os
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

from ranklock.durable_slot_ledger import DurableSlotLedger, SlotConflictError

import pytest


def _d(tag: bytes) -> bytes:
    return sha256(tag).digest()


def _run_child(script: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    source = tmp_path / "child.py"
    source.write_text(textwrap.dedent(script))
    return subprocess.run(
        [sys.executable, str(source)],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_slot_stays_burned_after_a_kill_between_burn_and_response(tmp_path: Path):
    """CORE-016: crash after burn, before the response is published."""

    ledger_path = tmp_path / "slots.sqlite"
    child = _run_child(
        f"""
        import os, signal
        from hashlib import sha256
        from ranklock.durable_slot_ledger import DurableSlotLedger

        def d(tag):
            return sha256(tag).digest()

        ledger = DurableSlotLedger(
            {str(ledger_path)!r}, context_digest=d(b"context"), slot_count=1
        )
        ledger.begin(
            0,
            context_digest=d(b"context"),
            input_digest=d(b"input"),
            authorization_digest=d(b"authorization"),
            chain_binding_digest=d(b"wtxid"),
        )
        # The burn is committed; the response has NOT been written yet.
        # SIGKILL cannot be caught, so nothing can clean up after this point.
        os.kill(os.getpid(), signal.SIGKILL)
        """,
        tmp_path,
    )
    assert child.returncode == -signal.SIGKILL, (child.returncode, child.stderr)

    # Fresh process: the burn must have survived.
    reopened = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=1)
    use = reopened.use(0)
    assert use.state == "burned"
    assert use.consumed
    assert reopened.remaining == 0
    assert reopened.verify_audit_chain()


def test_a_killed_burn_still_blocks_a_conflicting_binding(tmp_path: Path):
    """A crash must not become a way to rebind a consumed slot."""

    ledger_path = tmp_path / "slots.sqlite"
    child = _run_child(
        f"""
        import os, signal
        from hashlib import sha256
        from ranklock.durable_slot_ledger import DurableSlotLedger

        def d(tag):
            return sha256(tag).digest()

        ledger = DurableSlotLedger(
            {str(ledger_path)!r}, context_digest=d(b"context"), slot_count=1
        )
        ledger.begin(
            0,
            context_digest=d(b"context"),
            input_digest=d(b"input"),
            authorization_digest=d(b"authorization"),
            chain_binding_digest=d(b"wtxid"),
        )
        os.kill(os.getpid(), signal.SIGKILL)
        """,
        tmp_path,
    )
    assert child.returncode == -signal.SIGKILL

    reopened = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=1)
    with pytest.raises(SlotConflictError):
        reopened.begin(
            0,
            context_digest=_d(b"context"),
            input_digest=_d(b"other input"),
            authorization_digest=_d(b"other authorization"),
            chain_binding_digest=_d(b"other wtxid"),
        )
    # And per CORE-014 that conflict is terminal.
    assert reopened.use(0).state == "retry-rejected"


def test_exact_replay_after_a_killed_burn_is_deterministic(tmp_path: Path):
    """CORE-016 recovery: the same request resumes rather than re-burning."""

    ledger_path = tmp_path / "slots.sqlite"
    child = _run_child(
        f"""
        import os, signal
        from hashlib import sha256
        from ranklock.durable_slot_ledger import DurableSlotLedger

        def d(tag):
            return sha256(tag).digest()

        ledger = DurableSlotLedger(
            {str(ledger_path)!r}, context_digest=d(b"context"), slot_count=1
        )
        ledger.begin(
            0,
            context_digest=d(b"context"),
            input_digest=d(b"input"),
            authorization_digest=d(b"authorization"),
            chain_binding_digest=d(b"wtxid"),
        )
        os.kill(os.getpid(), signal.SIGKILL)
        """,
        tmp_path,
    )
    assert child.returncode == -signal.SIGKILL

    reopened = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=1)
    resumed = reopened.begin(
        0,
        context_digest=_d(b"context"),
        input_digest=_d(b"input"),
        authorization_digest=_d(b"authorization"),
        chain_binding_digest=_d(b"wtxid"),
    )
    assert resumed.exact_replay
    assert resumed.state == "burned"
    # Exactly one burn event, however many times recovery runs.
    assert [event.event_type for event in reopened.events()].count("burn") == 1
    assert reopened.verify_audit_chain()


def test_finalized_outcome_survives_a_kill_after_the_response(tmp_path: Path):
    """CORE-017: crash after the response write; restart returns the same state."""

    ledger_path = tmp_path / "slots.sqlite"
    child = _run_child(
        f"""
        import os, signal
        from hashlib import sha256
        from ranklock.durable_slot_ledger import DurableSlotLedger

        def d(tag):
            return sha256(tag).digest()

        ledger = DurableSlotLedger(
            {str(ledger_path)!r}, context_digest=d(b"context"), slot_count=1
        )
        ledger.begin(
            0,
            context_digest=d(b"context"),
            input_digest=d(b"input"),
            authorization_digest=d(b"authorization"),
            chain_binding_digest=d(b"wtxid"),
        )
        ledger.finalize(0, outcome="success")
        os.kill(os.getpid(), signal.SIGKILL)
        """,
        tmp_path,
    )
    assert child.returncode == -signal.SIGKILL

    reopened = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=1)
    use = reopened.use(0)
    assert use.state == "success"
    assert use.terminal
    assert reopened.verify_audit_chain()


# ---------------------------------------------------------------------------
# Tamper evidence: the audit chain must be bound to live slot state.
#
# Found by an adversarial review, which reproduced both of these against the
# previous implementation. verify_audit_chain() used to hash only the event
# rows, so the chain and the `slots` table -- separate tables in the same
# writable file -- could disagree while verification still returned True.
#
# This is tamper *evidence*, not tamper proofing: the hashes are unkeyed and
# the head lives in the same database, so a writer who rewrites events, head
# and slot rows consistently still produces a self-consistent file. Catching
# that needs an external authenticated witness (the deployed-rollback-witness
# release gate) and is not claimed here.
# ---------------------------------------------------------------------------

import sqlite3


def _burned_ledger(tmp_path: Path) -> Path:
    ledger_path = tmp_path / "tamper.sqlite"
    ledger = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=1)
    ledger.begin(
        0,
        context_digest=_d(b"context"),
        input_digest=_d(b"input"),
        authorization_digest=_d(b"authorization"),
        chain_binding_digest=_d(b"wtxid"),
    )
    assert ledger.verify_audit_chain(), "an untampered ledger must verify"
    return ledger_path


def test_rewinding_a_burned_slot_is_detected(tmp_path: Path):
    """Resetting slot state while leaving the audit rows intact must fail.

    Without this the slot reopens and can be burned a second time, leaving
    two `burn` events for a one-shot slot while verification reports success.
    """

    ledger_path = _burned_ledger(tmp_path)
    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "UPDATE slots SET state=?, input_digest=NULL, authorization_digest=NULL, "
            "chain_binding_digest=NULL, outcome=NULL, started_at_ns=NULL, "
            "finalized_at_ns=NULL, first_event_hash=NULL, latest_event_hash=NULL "
            "WHERE slot_id=0",
            ("available",),
        )

    reopened = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=1)
    assert not reopened.verify_audit_chain(), (
        "a slot rewound behind the audit log must not verify"
    )


def test_truncating_the_audit_log_is_detected(tmp_path: Path):
    """An emptied log beside a consumed slot must not verify.

    An empty chain is trivially self-consistent, so hashing events alone
    accepted it. A slot with no events must be `available`.
    """

    ledger_path = _burned_ledger(tmp_path)
    with sqlite3.connect(ledger_path) as connection:
        connection.execute("DELETE FROM audit_events")
        connection.execute(
            "UPDATE metadata SET value=? WHERE key=?", (bytes(32), "audit_chain_head")
        )

    reopened = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=1)
    assert not reopened.verify_audit_chain(), (
        "a truncated audit log beside a burned slot must not verify"
    )


def test_forging_a_binding_on_a_burned_slot_is_detected(tmp_path: Path):
    """Swapping the recorded binding must not verify either.

    The slot stays `burned`, so a state-only comparison would miss it; the
    per-column digest comparison is what catches a redirected authorization.
    """

    ledger_path = _burned_ledger(tmp_path)
    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "UPDATE slots SET chain_binding_digest=? WHERE slot_id=0",
            (_d(b"attacker wtxid"),),
        )

    reopened = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=1)
    assert not reopened.verify_audit_chain(), (
        "a rewritten chain binding must not verify"
    )


def test_an_untampered_multi_slot_ledger_still_verifies(tmp_path: Path):
    """The check must not be so strict that honest ledgers fail."""

    ledger_path = tmp_path / "honest.sqlite"
    ledger = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=4)
    ledger.begin(
        0,
        context_digest=_d(b"context"),
        input_digest=_d(b"input-0"),
        authorization_digest=_d(b"auth-0"),
        chain_binding_digest=_d(b"wtxid-0"),
    )
    ledger.finalize(0, outcome="success")
    ledger.begin(
        2,
        context_digest=_d(b"context"),
        input_digest=_d(b"input-2"),
        authorization_digest=_d(b"auth-2"),
        chain_binding_digest=_d(b"wtxid-2"),
    )
    assert ledger.verify_audit_chain()

    reopened = DurableSlotLedger(ledger_path, context_digest=_d(b"context"), slot_count=4)
    assert reopened.verify_audit_chain()
    assert reopened.use(0).state == "success"
    assert reopened.use(2).state == "burned"
    assert reopened.use(1).state == "available"
