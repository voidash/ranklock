from __future__ import annotations

"""Crash-durable, conflict-detecting one-shot slot consumption.

The v0.24 in-memory ledger was sufficient to demonstrate burn-before-evaluate
ordering, but it could not survive process crashes and did not serialize two
concurrent evaluators.  This module makes the security state persistent in an
SQLite database.

Security policy
---------------

* A slot transitions from ``available`` to ``burned`` in a ``BEGIN IMMEDIATE``
  transaction before any secret release or evaluator parsing.
* The first request permanently binds the slot to a context, input,
  authorization and exact chain/witness binding.
* An exact replay is idempotent.  A conflicting request is durably recorded and
  rejected.
* Reorg observations are audit events only.  They never reopen a slot because
  information published on an orphaned Bitcoin branch cannot be made secret
  again.
* Every mutation is linked into an append-only SHA-256 audit chain.

SQLite with WAL and ``synchronous=FULL`` gives crash durability under SQLite's
filesystem assumptions.  Production deployment still needs a hardened host,
backups, anti-rollback storage and independent audit; copying an older database
snapshot can otherwise roll security state backwards.
"""

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
import time
from typing import Final

from .private_sqlite import (
    prepare_private_sqlite_path,
    validate_private_file,
    validate_sqlite_sidecars,
)


_DIGEST_BYTES: Final = 32
_SCHEMA_VERSION: Final = 1
_AUDIT_DOMAIN: Final = b"ranklock/durable-slot-audit/v1\x00"
_DB_CONTEXT_KEY: Final = "context_digest"
_DB_SLOT_COUNT_KEY: Final = "slot_count"
_DB_SCHEMA_KEY: Final = "schema_version"
_DB_CHAIN_HEAD_KEY: Final = "audit_chain_head"
_ZERO_HASH: Final = bytes(_DIGEST_BYTES)
_ALLOWED_OUTCOMES: Final = {
    "success",
    "malformed",
    "abort",
    "timeout",
    "retry-rejected",
}
_TERMINAL_STATES: Final = set(_ALLOWED_OUTCOMES)


class DurableSlotLedgerError(RuntimeError):
    """Base class for persistent slot-state failures."""


class SlotConflictError(DurableSlotLedgerError):
    """The slot was already bound to a different request."""


class SlotTerminalError(DurableSlotLedgerError):
    """An operation attempted to change an incompatible terminal state."""


def _require_digest(value: bytes, name: str) -> bytes:
    encoded = bytes(value)
    if len(encoded) != _DIGEST_BYTES:
        raise DurableSlotLedgerError(f"{name} must be exactly 32 bytes")
    return encoded


def _u(value: int, width: int) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (width * 8):
        raise DurableSlotLedgerError(f"integer does not fit u{width * 8}")
    return value.to_bytes(width, "big")


def _lp(value: bytes) -> bytes:
    encoded = bytes(value)
    return _u(len(encoded), 8) + encoded


@dataclass(frozen=True, slots=True)
class DurableSlotUse:
    slot_id: int
    context_digest: bytes
    input_digest: bytes | None
    authorization_digest: bytes | None
    chain_binding_digest: bytes | None
    state: str
    outcome: str | None
    first_event_hash: bytes | None
    latest_event_hash: bytes | None
    exact_replay: bool = False
    schema: str = "ranklock-durable-slot-use-v1"

    @property
    def consumed(self) -> bool:
        return self.state != "available"

    @property
    def terminal(self) -> bool:
        return self.state in _TERMINAL_STATES


@dataclass(frozen=True, slots=True)
class AuditEvent:
    sequence: int
    slot_id: int
    event_type: str
    state: str
    input_digest: bytes | None
    authorization_digest: bytes | None
    chain_binding_digest: bytes | None
    outcome: str | None
    created_at_ns: int
    previous_hash: bytes
    event_hash: bytes
    schema: str = "ranklock-durable-slot-audit-event-v1"


class DurableSlotLedger:
    """SQLite-backed monotonic slot ledger.

    A new connection is opened for each operation so separate processes and
    threads coordinate through SQLite's file locking rather than shared Python
    state.  The class is therefore safe to instantiate independently in each
    worker.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        context_digest: bytes,
        slot_count: int,
        busy_timeout_ms: int = 30_000,
    ) -> None:
        self.path = Path(path)
        self.context_digest = _require_digest(context_digest, "context digest")
        self.slot_count = int(slot_count)
        self.busy_timeout_ms = int(busy_timeout_ms)
        if not 1 <= self.slot_count < 2**16:
            raise DurableSlotLedgerError("slot count must be in [1, 65535]")
        if self.busy_timeout_ms <= 0:
            raise DurableSlotLedgerError("busy timeout must be positive")
        self.path, self._file_identity, self._newly_created = prepare_private_sqlite_path(
            self.path,
            error_type=DurableSlotLedgerError,
            label="slot ledger",
        )
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        validate_private_file(
            self.path,
            error_type=DurableSlotLedgerError,
            label="slot ledger",
            expected=self._file_identity,
        )
        conn = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            validate_private_file(
                self.path,
                error_type=DurableSlotLedgerError,
                label="slot ledger",
                expected=self._file_identity,
            )
            conn.row_factory = sqlite3.Row
            conn.execute(f"PRAGMA busy_timeout={self.busy_timeout_ms}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA secure_delete=ON")
            # WAL lets readers inspect state while a release worker serializes a
            # write. FULL ensures a commit syncs the WAL before success is returned.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            try:
                conn.execute("PRAGMA fullfsync=ON")
            except sqlite3.DatabaseError:  # pragma: no cover - platform-specific
                pass
            validate_sqlite_sidecars(
                self.path,
                error_type=DurableSlotLedgerError,
                label="slot ledger",
            )
            return conn
        except Exception:
            conn.close()
            raise

    def _initialize(self) -> None:
        newly_created = self._newly_created
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS slots (
                    slot_id INTEGER PRIMARY KEY,
                    state TEXT NOT NULL,
                    context_digest BLOB NOT NULL,
                    input_digest BLOB,
                    authorization_digest BLOB,
                    chain_binding_digest BLOB,
                    outcome TEXT,
                    started_at_ns INTEGER,
                    finalized_at_ns INTEGER,
                    first_event_hash BLOB,
                    latest_event_hash BLOB,
                    CHECK (state IN (
                        'available', 'burned', 'success', 'malformed',
                        'abort', 'timeout', 'retry-rejected'
                    ))
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY,
                    slot_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    state TEXT NOT NULL,
                    input_digest BLOB,
                    authorization_digest BLOB,
                    chain_binding_digest BLOB,
                    outcome TEXT,
                    created_at_ns INTEGER NOT NULL,
                    previous_hash BLOB NOT NULL,
                    event_hash BLOB NOT NULL UNIQUE
                );
                """
            )
            conn.execute("BEGIN EXCLUSIVE")
            existing = {
                row["key"]: bytes(row["value"])
                for row in conn.execute("SELECT key, value FROM metadata")
            }
            expected = {
                _DB_SCHEMA_KEY: _u(_SCHEMA_VERSION, 4),
                _DB_CONTEXT_KEY: self.context_digest,
                _DB_SLOT_COUNT_KEY: _u(self.slot_count, 4),
            }
            if existing:
                for key, value in expected.items():
                    if existing.get(key) != value:
                        raise DurableSlotLedgerError(
                            f"ledger metadata mismatch for {key}"
                        )
                if len(existing.get(_DB_CHAIN_HEAD_KEY, b"")) != _DIGEST_BYTES:
                    raise DurableSlotLedgerError("ledger audit-chain head is malformed")
            else:
                conn.executemany(
                    "INSERT INTO metadata(key, value) VALUES(?, ?)",
                    [
                        (_DB_SCHEMA_KEY, expected[_DB_SCHEMA_KEY]),
                        (_DB_CONTEXT_KEY, expected[_DB_CONTEXT_KEY]),
                        (_DB_SLOT_COUNT_KEY, expected[_DB_SLOT_COUNT_KEY]),
                        (_DB_CHAIN_HEAD_KEY, _ZERO_HASH),
                    ],
                )
                conn.executemany(
                    """
                    INSERT INTO slots(
                        slot_id, state, context_digest, input_digest,
                        authorization_digest, chain_binding_digest, outcome,
                        started_at_ns, finalized_at_ns, first_event_hash,
                        latest_event_hash
                    ) VALUES(?, 'available', ?, NULL, NULL, NULL, NULL,
                             NULL, NULL, NULL, NULL)
                    """,
                    [(slot_id, self.context_digest) for slot_id in range(self.slot_count)],
                )
            slot_rows = conn.execute("SELECT COUNT(*) AS n FROM slots").fetchone()["n"]
            if int(slot_rows) != self.slot_count:
                raise DurableSlotLedgerError("ledger slot table has the wrong cardinality")
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        if newly_created:
            validate_private_file(
                self.path,
                error_type=DurableSlotLedgerError,
                label="slot ledger",
                expected=self._file_identity,
            )

    @staticmethod
    def _event_hash(
        *,
        sequence: int,
        slot_id: int,
        event_type: str,
        state: str,
        input_digest: bytes | None,
        authorization_digest: bytes | None,
        chain_binding_digest: bytes | None,
        outcome: str | None,
        created_at_ns: int,
        previous_hash: bytes,
    ) -> bytes:
        h = sha256(_AUDIT_DOMAIN)
        h.update(_u(sequence, 8))
        h.update(_u(slot_id, 4))
        h.update(_lp(event_type.encode("utf-8")))
        h.update(_lp(state.encode("utf-8")))
        for value in (input_digest, authorization_digest, chain_binding_digest):
            h.update(b"\x00" if value is None else b"\x01" + bytes(value))
        h.update(b"\x00" if outcome is None else b"\x01" + _lp(outcome.encode()))
        h.update(_u(created_at_ns, 16))
        h.update(previous_hash)
        return h.digest()

    def _append_event(
        self,
        conn: sqlite3.Connection,
        *,
        slot_id: int,
        event_type: str,
        state: str,
        input_digest: bytes | None,
        authorization_digest: bytes | None,
        chain_binding_digest: bytes | None,
        outcome: str | None,
    ) -> bytes:
        row = conn.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM audit_events"
        ).fetchone()
        sequence = int(row["next_sequence"])
        head_row = conn.execute(
            "SELECT value FROM metadata WHERE key=?", (_DB_CHAIN_HEAD_KEY,)
        ).fetchone()
        previous_hash = bytes(head_row["value"])
        created_at_ns = time.time_ns()
        event_hash = self._event_hash(
            sequence=sequence,
            slot_id=slot_id,
            event_type=event_type,
            state=state,
            input_digest=input_digest,
            authorization_digest=authorization_digest,
            chain_binding_digest=chain_binding_digest,
            outcome=outcome,
            created_at_ns=created_at_ns,
            previous_hash=previous_hash,
        )
        conn.execute(
            """
            INSERT INTO audit_events(
                sequence, slot_id, event_type, state, input_digest,
                authorization_digest, chain_binding_digest, outcome,
                created_at_ns, previous_hash, event_hash
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence,
                slot_id,
                event_type,
                state,
                input_digest,
                authorization_digest,
                chain_binding_digest,
                outcome,
                created_at_ns,
                previous_hash,
                event_hash,
            ),
        )
        conn.execute(
            "UPDATE metadata SET value=? WHERE key=?",
            (event_hash, _DB_CHAIN_HEAD_KEY),
        )
        return event_hash

    def _validate_slot(self, slot_id: int) -> int:
        slot_id = int(slot_id)
        if not 0 <= slot_id < self.slot_count:
            raise DurableSlotLedgerError("slot id is outside the activated range")
        return slot_id

    @staticmethod
    def _to_use(row: sqlite3.Row, *, exact_replay: bool = False) -> DurableSlotUse:
        def opt(name: str) -> bytes | None:
            value = row[name]
            return None if value is None else bytes(value)

        return DurableSlotUse(
            slot_id=int(row["slot_id"]),
            context_digest=bytes(row["context_digest"]),
            input_digest=opt("input_digest"),
            authorization_digest=opt("authorization_digest"),
            chain_binding_digest=opt("chain_binding_digest"),
            state=str(row["state"]),
            outcome=None if row["outcome"] is None else str(row["outcome"]),
            first_event_hash=opt("first_event_hash"),
            latest_event_hash=opt("latest_event_hash"),
            exact_replay=exact_replay,
        )

    def begin(
        self,
        slot_id: int,
        *,
        context_digest: bytes,
        input_digest: bytes,
        authorization_digest: bytes,
        chain_binding_digest: bytes,
    ) -> DurableSlotUse:
        """Atomically burn or idempotently resume an exact request.

        A conflicting request is appended to the audit chain before
        :class:`SlotConflictError` is raised.
        """

        slot_id = self._validate_slot(slot_id)
        context = _require_digest(context_digest, "context digest")
        input_digest = _require_digest(input_digest, "input digest")
        authorization_digest = _require_digest(
            authorization_digest, "authorization digest"
        )
        chain_binding_digest = _require_digest(
            chain_binding_digest, "chain binding digest"
        )
        if context != self.context_digest:
            raise DurableSlotLedgerError("slot attempt is bound to another context")

        conn = self._connect()
        conflict = False
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM slots WHERE slot_id=?", (slot_id,)).fetchone()
            if row is None:  # pragma: no cover - initialization invariant
                raise DurableSlotLedgerError("slot row is missing")
            if row["state"] == "available":
                event_hash = self._append_event(
                    conn,
                    slot_id=slot_id,
                    event_type="burn",
                    state="burned",
                    input_digest=input_digest,
                    authorization_digest=authorization_digest,
                    chain_binding_digest=chain_binding_digest,
                    outcome=None,
                )
                now = time.time_ns()
                conn.execute(
                    """
                    UPDATE slots SET
                        state='burned', input_digest=?, authorization_digest=?,
                        chain_binding_digest=?, outcome=NULL, started_at_ns=?,
                        first_event_hash=?, latest_event_hash=?
                    WHERE slot_id=? AND state='available'
                    """,
                    (
                        input_digest,
                        authorization_digest,
                        chain_binding_digest,
                        now,
                        event_hash,
                        event_hash,
                        slot_id,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM slots WHERE slot_id=?", (slot_id,)
                ).fetchone()
                conn.execute("COMMIT")
                return self._to_use(row)

            exact = (
                bytes(row["context_digest"]) == context
                and bytes(row["input_digest"]) == input_digest
                and bytes(row["authorization_digest"]) == authorization_digest
                and bytes(row["chain_binding_digest"]) == chain_binding_digest
            )
            if exact and str(row["state"]) == "retry-rejected":
                # The slot was poisoned by a conflicting authenticated binding
                # and never completed, so there is no published result to be
                # idempotent about.  Refuse even the original request rather
                # than letting it resume and release fresh material.
                conn.execute("COMMIT")
                raise SlotConflictError(
                    "slot was terminally rejected after a conflicting binding "
                    "and can no longer be used"
                )
            if exact:
                event_hash = self._append_event(
                    conn,
                    slot_id=slot_id,
                    event_type="exact-replay",
                    state=str(row["state"]),
                    input_digest=input_digest,
                    authorization_digest=authorization_digest,
                    chain_binding_digest=chain_binding_digest,
                    outcome=None if row["outcome"] is None else str(row["outcome"]),
                )
                conn.execute(
                    "UPDATE slots SET latest_event_hash=? WHERE slot_id=?",
                    (event_hash, slot_id),
                )
                row = conn.execute(
                    "SELECT * FROM slots WHERE slot_id=?", (slot_id,)
                ).fetchone()
                conn.execute("COMMIT")
                return self._to_use(row, exact_replay=True)

            # An authenticated request that conflicts with the binding this
            # slot was burned for is a terminal event, not a recoverable one.
            # Only a validly signed preauthorization reaches this method, so a
            # conflict means the authorizer bound one one-shot slot to two
            # different transactions -- the slot must fail closed and can
            # never complete.  A slot that is already terminal keeps its
            # existing outcome; the conflict is recorded as audit only, since
            # information released on the original binding cannot be recalled.
            already_terminal = str(row["state"]) in _TERMINAL_STATES
            resulting_state = str(row["state"]) if already_terminal else "retry-rejected"
            event_hash = self._append_event(
                conn,
                slot_id=slot_id,
                event_type="conflict-rejected",
                state=resulting_state,
                input_digest=input_digest,
                authorization_digest=authorization_digest,
                chain_binding_digest=chain_binding_digest,
                outcome="retry-rejected",
            )
            if already_terminal:
                conn.execute(
                    "UPDATE slots SET latest_event_hash=? WHERE slot_id=?",
                    (event_hash, slot_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE slots SET state='retry-rejected', outcome='retry-rejected',
                                     finalized_at_ns=?, latest_event_hash=?
                    WHERE slot_id=? AND state='burned'
                    """,
                    (time.time_ns(), event_hash, slot_id),
                )
            conn.execute("COMMIT")
            conflict = True
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        if conflict:
            raise SlotConflictError(
                "slot is permanently bound to a different input/authorization/witness"
            )
        raise DurableSlotLedgerError("unreachable begin state")  # pragma: no cover

    def finalize(self, slot_id: int, *, outcome: str) -> DurableSlotUse:
        slot_id = self._validate_slot(slot_id)
        outcome = str(outcome)
        if outcome not in _ALLOWED_OUTCOMES:
            raise DurableSlotLedgerError("unknown slot outcome")
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM slots WHERE slot_id=?", (slot_id,)).fetchone()
            if row["state"] == "available":
                raise DurableSlotLedgerError("slot was not started")
            if row["state"] in _TERMINAL_STATES:
                if row["state"] != outcome:
                    raise SlotTerminalError(
                        f"slot already finalized as {row['state']}, not {outcome}"
                    )
                conn.execute("COMMIT")
                return self._to_use(row, exact_replay=True)
            event_hash = self._append_event(
                conn,
                slot_id=slot_id,
                event_type="finalize",
                state=outcome,
                input_digest=bytes(row["input_digest"]),
                authorization_digest=bytes(row["authorization_digest"]),
                chain_binding_digest=bytes(row["chain_binding_digest"]),
                outcome=outcome,
            )
            conn.execute(
                """
                UPDATE slots SET state=?, outcome=?, finalized_at_ns=?,
                                 latest_event_hash=?
                WHERE slot_id=? AND state='burned'
                """,
                (outcome, outcome, time.time_ns(), event_hash, slot_id),
            )
            row = conn.execute("SELECT * FROM slots WHERE slot_id=?", (slot_id,)).fetchone()
            conn.execute("COMMIT")
            return self._to_use(row)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_chain_observation(
        self,
        slot_id: int,
        *,
        event_type: str,
        block_hash: bytes,
        height: int,
    ) -> DurableSlotUse:
        """Record confirmation, reorg or fork information without reopening.

        ``event_type`` is deliberately limited to observational events.  The
        block hash and height are folded into the audit authorization field so
        the exact observation is tamper evident.
        """

        slot_id = self._validate_slot(slot_id)
        if event_type not in {"confirmed", "reorg-observed", "fork-observed"}:
            raise DurableSlotLedgerError("unsupported chain observation")
        block_hash = _require_digest(block_hash, "block hash")
        observation = sha256(
            b"ranklock/chain-observation/v1\x00"
            + event_type.encode()
            + block_hash
            + _u(int(height), 8)
        ).digest()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM slots WHERE slot_id=?", (slot_id,)).fetchone()
            if row["state"] == "available":
                raise DurableSlotLedgerError("cannot observe chain state for an unused slot")
            event_hash = self._append_event(
                conn,
                slot_id=slot_id,
                event_type=event_type,
                state=str(row["state"]),
                input_digest=bytes(row["input_digest"]),
                authorization_digest=observation,
                chain_binding_digest=bytes(row["chain_binding_digest"]),
                outcome=None if row["outcome"] is None else str(row["outcome"]),
            )
            conn.execute(
                "UPDATE slots SET latest_event_hash=? WHERE slot_id=?",
                (event_hash, slot_id),
            )
            row = conn.execute("SELECT * FROM slots WHERE slot_id=?", (slot_id,)).fetchone()
            conn.execute("COMMIT")
            return self._to_use(row)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def use(self, slot_id: int) -> DurableSlotUse:
        slot_id = self._validate_slot(slot_id)
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM slots WHERE slot_id=?", (slot_id,)).fetchone()
            return self._to_use(row)
        finally:
            conn.close()

    @property
    def remaining(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM slots WHERE state='available'"
            ).fetchone()
            return int(row["n"])
        finally:
            conn.close()

    def events(self) -> tuple[AuditEvent, ...]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY sequence").fetchall()
        finally:
            conn.close()
        return tuple(
            AuditEvent(
                sequence=int(row["sequence"]),
                slot_id=int(row["slot_id"]),
                event_type=str(row["event_type"]),
                state=str(row["state"]),
                input_digest=None
                if row["input_digest"] is None
                else bytes(row["input_digest"]),
                authorization_digest=None
                if row["authorization_digest"] is None
                else bytes(row["authorization_digest"]),
                chain_binding_digest=None
                if row["chain_binding_digest"] is None
                else bytes(row["chain_binding_digest"]),
                outcome=None if row["outcome"] is None else str(row["outcome"]),
                created_at_ns=int(row["created_at_ns"]),
                previous_hash=bytes(row["previous_hash"]),
                event_hash=bytes(row["event_hash"]),
            )
            for row in rows
        )

    def verify_audit_chain(self) -> bool:
        previous = _ZERO_HASH
        for event in self.events():
            if event.previous_hash != previous:
                return False
            expected = self._event_hash(
                sequence=event.sequence,
                slot_id=event.slot_id,
                event_type=event.event_type,
                state=event.state,
                input_digest=event.input_digest,
                authorization_digest=event.authorization_digest,
                chain_binding_digest=event.chain_binding_digest,
                outcome=event.outcome,
                created_at_ns=event.created_at_ns,
                previous_hash=event.previous_hash,
            )
            if expected != event.event_hash:
                return False
            previous = event.event_hash
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key=?", (_DB_CHAIN_HEAD_KEY,)
            ).fetchone()
            return bytes(row["value"]) == previous
        finally:
            conn.close()

    def checkpoint(self) -> None:
        """Force a full WAL checkpoint for backup/export tooling."""

        conn = self._connect()
        try:
            row = conn.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
            # SQLite returns (busy, log, checkpointed). A busy checkpoint is an
            # operational error for release snapshotting.
            if row is not None and int(row[0]) != 0:
                raise DurableSlotLedgerError("ledger WAL checkpoint was busy")
        finally:
            conn.close()
