from __future__ import annotations

"""Publish a RankLock positive-lock payload as a Strata ACK preimage.

``integration/.../ranklock_sidecar_fixture.py`` is deterministic test plumbing:
it derives the preimage from a fixed public seed and stores it in a plaintext
``fixture-secrets/`` directory.  It is explicitly unsafe and must never protect
funds.  This module is the production-shaped replacement.

Two phases, mirroring where the secret actually exists:

* **Setup** picks the 32-byte payload the retained object will protect.  It
  must be rejection-sampled so ``sha256(payload)`` parses as a secp256k1
  x-only key, because the Strata graph transports the ACK commitment in a
  field typed as an x-only pubkey.  Only the commitment is published.
* **Export** runs after the two-phase protocol has recovered that payload.  It
  re-derives the commitment, checks it against the one the graph was built
  with, binds the release to exactly one ACK context, and publishes the
  preimage atomically.

Security properties this module is responsible for:

* the payload is never written anywhere except the single unlock file the
  bridge reads, and never appears in a log, exception message or ledger row;
* one commitment binds to exactly one ACK context -- an attempt to export the
  same payload under a different bridge/counterproof/ACK triple is a terminal
  conflict, not a second release;
* an exact retry republishes byte-identical content and does not re-derive or
  re-release anything.

The bridge-side file parser is deliberately not this module's concern; it is
hardened separately in the Rust overlay.
"""

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import sqlite3
from typing import Final

from .real_secp import P as SECP_FIELD_MODULUS

_COMMITMENT_DOMAIN: Final = b"ranklock/strata-ack-commitment/v1\x00"
_CONTEXT_DOMAIN: Final = b"ranklock/strata-ack-context/v1\x00"
_PAYLOAD_BYTES: Final = 32
# Bound on rejection sampling.  Roughly half of all 32-byte digests are valid
# x-only keys, so exhausting this many attempts indicates a broken derivation
# rather than bad luck.
_MAX_SAMPLING_ATTEMPTS: Final = 1024


class StrataExportError(RuntimeError):
    """Raised when an export is unsafe, inconsistent or conflicting."""


def commitment_is_valid_xonly(commitment: bytes) -> bool:
    """Does ``commitment`` parse as a secp256k1 x-only public key?

    The Strata graph reuses an x-only-typed field to carry the ACK
    commitment, so a commitment that does not lift is unusable -- the graph
    could not be constructed with it.
    """

    encoded = bytes(commitment)
    if len(encoded) != 32:
        return False
    x = int.from_bytes(encoded, "big")
    if x >= SECP_FIELD_MODULUS:
        return False
    rhs = (pow(x, 3, SECP_FIELD_MODULUS) + 7) % SECP_FIELD_MODULUS
    if rhs == 0:
        return True
    return pow(rhs, (SECP_FIELD_MODULUS - 1) // 2, SECP_FIELD_MODULUS) == 1


def ack_commitment(payload: bytes) -> bytes:
    """The value published into the graph for ``payload``.

    This is a bare ``sha256`` because the Bitcoin ACK leaf performs
    ``OP_SHA256`` on the revealed preimage; a domain-separated hash here would
    not match what consensus computes.
    """

    encoded = bytes(payload)
    if len(encoded) != _PAYLOAD_BYTES:
        raise StrataExportError("positive-lock payload must be exactly 32 bytes")
    return sha256(encoded).digest()


@dataclass(frozen=True, slots=True)
class AckContext:
    """The exact bridge context one payload is allowed to unlock."""

    network: str
    chain_genesis_hash: bytes
    graph_owner: int
    deposit_index: int
    game_index: int
    watchtower_index: int
    slot_id: int
    epoch: int
    bridge_proof_txid: bytes
    counterproof_txid: bytes
    counterproof_ack_txid: bytes
    schema: str = "ranklock-strata-ack-context-v1"

    def __post_init__(self) -> None:
        if len(bytes(self.chain_genesis_hash)) != 32:
            raise StrataExportError("chain genesis hash must be 32 bytes")
        for value, name in (
            (self.bridge_proof_txid, "bridge proof txid"),
            (self.counterproof_txid, "counterproof txid"),
            (self.counterproof_ack_txid, "counterproof ACK txid"),
        ):
            if len(bytes(value)) != 32:
                raise StrataExportError(f"{name} must be 32 bytes")
        for value, name in (
            (self.graph_owner, "graph owner"),
            (self.deposit_index, "deposit index"),
            (self.game_index, "game index"),
            (self.watchtower_index, "watchtower index"),
            (self.slot_id, "slot id"),
            (self.epoch, "epoch"),
        ):
            if not 0 <= int(value) < 2**32:
                raise StrataExportError(f"{name} does not fit u32")
        if not self.network:
            raise StrataExportError("network must be named")

    @property
    def encoded(self) -> bytes:
        return (
            _CONTEXT_DOMAIN
            + self.network.encode()
            + b"\x00"
            + bytes(self.chain_genesis_hash)
            + int(self.graph_owner).to_bytes(4, "big")
            + int(self.deposit_index).to_bytes(4, "big")
            + int(self.game_index).to_bytes(4, "big")
            + int(self.watchtower_index).to_bytes(4, "big")
            + int(self.slot_id).to_bytes(4, "big")
            + int(self.epoch).to_bytes(4, "big")
            + bytes(self.bridge_proof_txid)
            + bytes(self.counterproof_txid)
            + bytes(self.counterproof_ack_txid)
        )

    @property
    def digest(self) -> bytes:
        return sha256(self.encoded).digest()

    @property
    def unlock_stem(self) -> str:
        """Filename the bridge executor reads, in its display-order convention."""

        return (
            f"bridge{bytes(self.bridge_proof_txid).hex()}"
            f"-counterproof{bytes(self.counterproof_txid).hex()}"
            f"-ack{bytes(self.counterproof_ack_txid).hex()}"
        )


def derive_setup_payload(
    *,
    entropy: bytes,
    graph_owner: int,
    deposit_index: int,
    game_index: int,
    watchtower_index: int,
) -> tuple[bytes, bytes]:
    """Choose the payload the retained object will protect.

    ``entropy`` must be real setup entropy, not a public constant: whoever can
    reproduce it can reconstruct the ACK preimage without any proof and
    unilaterally drive the bridge to ACK.  Returns ``(payload, commitment)``;
    only the commitment may be published.
    """

    entropy = bytes(entropy)
    if len(entropy) < 32:
        raise StrataExportError(
            "setup entropy must be at least 32 bytes; a short or public seed "
            "would let anyone reconstruct the ACK preimage"
        )
    base = (
        _COMMITMENT_DOMAIN
        + entropy
        + int(graph_owner).to_bytes(4, "big")
        + int(deposit_index).to_bytes(4, "big")
        + int(game_index).to_bytes(4, "big")
        + int(watchtower_index).to_bytes(4, "big")
    )
    for counter in range(_MAX_SAMPLING_ATTEMPTS):
        payload = sha256(base + counter.to_bytes(4, "big")).digest()
        commitment = ack_commitment(payload)
        if commitment_is_valid_xonly(commitment):
            return payload, commitment
    raise StrataExportError(
        "failed to sample an x-only-compatible ACK commitment; the derivation "
        "is broken rather than unlucky"
    )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".partial")
    # 0o600 before any content lands: the unlock file is the released secret.
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    os.replace(temporary, path)


class StrataAckExporter:
    """Publishes ACK preimages under a durable one-context-per-commitment rule."""

    def __init__(self, root: str | os.PathLike[str], *, ledger_path: str | os.PathLike[str] | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.ledger_path = Path(ledger_path) if ledger_path else self.root / "export-ledger.sqlite"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.ledger_path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS exports (
                    commitment BLOB PRIMARY KEY,
                    context_digest BLOB NOT NULL,
                    unlock_stem TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('released', 'conflict'))
                ) WITHOUT ROWID
                """
            )
        finally:
            connection.close()

    def commitment_path(self, context: AckContext) -> Path:
        stem = (
            f"owner{context.graph_owner}-deposit{context.deposit_index}"
            f"-game{context.game_index}-watchtower{context.watchtower_index}"
        )
        return self.root / "setup" / f"{stem}.commitment"

    def unlock_path(self, context: AckContext) -> Path:
        return self.root / "unlock" / f"{context.unlock_stem}.preimage"

    def publish_commitment(self, context: AckContext, commitment: bytes) -> Path:
        """Publish the setup commitment.  Never accepts the payload itself."""

        encoded = bytes(commitment)
        if len(encoded) != 32:
            raise StrataExportError("ACK commitment must be 32 bytes")
        if not commitment_is_valid_xonly(encoded):
            raise StrataExportError(
                "ACK commitment does not parse as an x-only key, so the graph "
                "cannot carry it; re-run setup derivation"
            )
        path = self.commitment_path(context)
        _atomic_write(path, encoded)
        return path

    def export_unlock(
        self,
        *,
        payload: bytes,
        context: AckContext,
        expected_commitment: bytes,
    ) -> tuple[Path, bool]:
        """Publish ``payload`` for exactly one ACK context.

        Returns ``(path, created)``.  ``created`` is ``False`` for an exact
        retry, which republishes nothing.  Raises rather than releasing if the
        payload does not match the commitment the graph was built with, or if
        this commitment already released under a different context.
        """

        payload = bytes(payload)
        expected = bytes(expected_commitment)
        # Deliberately no payload material in any error text below.
        derived = ack_commitment(payload)
        if derived != expected:
            raise StrataExportError(
                "recovered payload does not match the published ACK commitment; "
                "refusing to release"
            )
        if not commitment_is_valid_xonly(expected):
            raise StrataExportError(
                "published ACK commitment is not x-only-compatible; the graph "
                "could not have been built with it"
            )

        context_digest = context.digest
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM exports WHERE commitment=?", (expected,)
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO exports (commitment, context_digest, unlock_stem, state)"
                    " VALUES (?, ?, ?, 'released')",
                    (expected, context_digest, context.unlock_stem),
                )
                connection.execute("COMMIT")
                created = True
            elif str(row["state"]) == "conflict":
                connection.execute("COMMIT")
                raise StrataExportError(
                    "this ACK commitment was already bound to a different "
                    "context and is permanently unusable"
                )
            elif bytes(row["context_digest"]) != context_digest:
                # One commitment released under two contexts would let a
                # single proof authorize two different ACK transactions.
                connection.execute(
                    "UPDATE exports SET state='conflict' WHERE commitment=?", (expected,)
                )
                connection.execute("COMMIT")
                raise StrataExportError(
                    "this ACK commitment already released under a different "
                    "bridge context; marking it terminally conflicted"
                )
            else:
                connection.execute("COMMIT")
                created = False
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            raise StrataExportError(f"export ledger failure: {exc}") from exc
        finally:
            connection.close()

        path = self.unlock_path(context)
        # Compare unconditionally. The previous form was
        # ``if created or not path.is_file()``, which made the guard below
        # unreachable for any new commitment -- and `created` is always true
        # for one. Two contexts that differ only outside the three txids in
        # `unlock_stem` share a filename, so the second release silently
        # destroyed the first while the ledger reported both as released.
        # The Rust reader re-checks SHA-256 and hard-fails, so the effect was
        # a blocked ACK rather than a wrong one; a destroyed secret should
        # still be loud.
        if path.is_file():
            existing = path.read_bytes()
            if existing != payload:
                raise StrataExportError(
                    "an unlock file already exists for this context with "
                    "different content; refusing to overwrite a released "
                    f"secret at {path}"
                )
            return path, created
        _atomic_write(path, payload)
        return path, created

    def released_contexts(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) AS n FROM exports WHERE state='released'"
            ).fetchone()
            return int(row["n"])
        finally:
            connection.close()
