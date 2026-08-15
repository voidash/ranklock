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
