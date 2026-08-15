from __future__ import annotations

"""Observe-only RankLock/Mosaic comparison ledger.

The observer records deterministic output comparisons in an append-only hash
chain.  It has no signing key, no committee shares, and no method that can
produce an ACK/NACK authorization.  This keeps early deployments useful without
silently turning a canary into a custody component.
"""

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
import time


_ZERO = bytes(32)
_EVENT_DOMAIN = b"ranklock/canary-observation/v1\x00"


class CanaryObserverError(RuntimeError):
    pass


def _d(value: bytes, name: str) -> bytes:
    value = bytes(value)
    if len(value) != 32:
        raise CanaryObserverError(f"{name} must be 32 bytes")
    return value


def _event_hash(
    *,
    sequence: int,
    context_digest: bytes,
    request_digest: bytes,
    ranklock_output_digest: bytes,
    reference_output_digest: bytes,
    matched: bool,
    observed_at_ns: int,
    previous_hash: bytes,
) -> bytes:
    return sha256(
        _EVENT_DOMAIN
        + int(sequence).to_bytes(8, "big")
        + context_digest
        + request_digest
        + ranklock_output_digest
        + reference_output_digest
        + bytes((1 if matched else 0,))
        + int(observed_at_ns).to_bytes(8, "big")
        + previous_hash
    ).digest()


@dataclass(frozen=True, slots=True)
class CanaryObservation:
    sequence: int
    context_digest: bytes
    request_digest: bytes
    ranklock_output_digest: bytes
    reference_output_digest: bytes
    matched: bool
    observed_at_ns: int
    previous_hash: bytes
    event_hash: bytes
    schema: str = "ranklock-canary-observation-v1"


class CanaryObserver:
    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        if self.path.exists() and self.path.is_symlink():
            raise CanaryObserverError("canary database path must not be a symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        new = not self.path.exists()
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS observations(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    context_digest BLOB NOT NULL,
                    request_digest BLOB NOT NULL,
                    ranklock_output_digest BLOB NOT NULL,
                    reference_output_digest BLOB NOT NULL,
                    matched INTEGER NOT NULL CHECK(matched IN (0,1)),
                    observed_at_ns INTEGER NOT NULL,
                    previous_hash BLOB NOT NULL,
                    event_hash BLOB NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                ) WITHOUT ROWID;
                INSERT OR IGNORE INTO metadata(key,value) VALUES('head', zeroblob(32));
                """
            )
        finally:
            conn.close()
        if new:
            os.chmod(self.path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA trusted_schema=OFF")
        return conn

    @staticmethod
    def digest_output(output: bytes) -> bytes:
        return sha256(b"ranklock/canary-output/v1\x00" + bytes(output)).digest()

    def compare(
        self,
        *,
        context_digest: bytes,
        request_digest: bytes,
        ranklock_output: bytes,
        reference_output: bytes,
    ) -> CanaryObservation:
        context_digest = _d(context_digest, "context digest")
        request_digest = _d(request_digest, "request digest")
        ranklock_digest = self.digest_output(ranklock_output)
        reference_digest = self.digest_output(reference_output)
        matched = bytes(ranklock_output) == bytes(reference_output)
        observed_at = time.time_ns()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            head = bytes(
                conn.execute("SELECT value FROM metadata WHERE key='head'").fetchone()["value"]
            )
            row = conn.execute("SELECT COALESCE(MAX(sequence), 0) + 1 AS n FROM observations").fetchone()
            sequence = int(row["n"])
            event = _event_hash(
                sequence=sequence,
                context_digest=context_digest,
                request_digest=request_digest,
                ranklock_output_digest=ranklock_digest,
                reference_output_digest=reference_digest,
                matched=matched,
                observed_at_ns=observed_at,
                previous_hash=head,
            )
            conn.execute(
                """
                INSERT INTO observations(sequence,context_digest,request_digest,
                  ranklock_output_digest,reference_output_digest,matched,
                  observed_at_ns,previous_hash,event_hash)
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    sequence,
                    context_digest,
                    request_digest,
                    ranklock_digest,
                    reference_digest,
                    1 if matched else 0,
                    observed_at,
                    head,
                    event,
                ),
            )
            conn.execute("UPDATE metadata SET value=? WHERE key='head'", (event,))
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return CanaryObservation(
            sequence,
            context_digest,
            request_digest,
            ranklock_digest,
            reference_digest,
            matched,
            observed_at,
            head,
            event,
        )

    def observations(self) -> tuple[CanaryObservation, ...]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM observations ORDER BY sequence").fetchall()
        finally:
            conn.close()
        return tuple(
            CanaryObservation(
                int(row["sequence"]),
                bytes(row["context_digest"]),
                bytes(row["request_digest"]),
                bytes(row["ranklock_output_digest"]),
                bytes(row["reference_output_digest"]),
                bool(row["matched"]),
                int(row["observed_at_ns"]),
                bytes(row["previous_hash"]),
                bytes(row["event_hash"]),
            )
            for row in rows
        )

    def verify_chain(self) -> bool:
        previous = _ZERO
        for observation in self.observations():
            if observation.previous_hash != previous:
                return False
            expected = _event_hash(
                sequence=observation.sequence,
                context_digest=observation.context_digest,
                request_digest=observation.request_digest,
                ranklock_output_digest=observation.ranklock_output_digest,
                reference_output_digest=observation.reference_output_digest,
                matched=observation.matched,
                observed_at_ns=observation.observed_at_ns,
                previous_hash=observation.previous_hash,
            )
            if expected != observation.event_hash:
                return False
            previous = observation.event_hash
        conn = self._connect()
        try:
            head = bytes(conn.execute("SELECT value FROM metadata WHERE key='head'").fetchone()["value"])
        finally:
            conn.close()
        return head == previous

    @property
    def summary(self) -> dict[str, int | bool]:
        rows = self.observations()
        return {
            "observations": len(rows),
            "matches": sum(item.matched for item in rows),
            "mismatches": sum(not item.matched for item in rows),
            "audit_chain_valid": self.verify_chain(),
            "authoritative": False,
        }
