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

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import sqlite3
from typing import Final

from .babe_positive_lock import (
    PositiveGroth16Proof,
    PositiveGroth16VerifyingKey,
    PositiveLock,
    unlock_positive_lock,
)
from .private_sqlite import (
    prepare_private_sqlite_path,
    require_private_directory,
    validate_private_file,
    validate_sqlite_sidecars,
)
from .real_secp import P as SECP_FIELD_MODULUS
from .release_sidecar import (
    ReleaseSidecarError,
    atomic_write_once,
    read_secret_file_secure,
)

# v2 adds an explicit entropy-length prefix and intentionally does not
# reproduce v1 setup material. No v1 fixture is eligible for funding.
_COMMITMENT_DOMAIN: Final = b"ranklock/strata-ack-commitment/v2\x00"
_CONTEXT_DOMAIN: Final = b"ranklock/strata-ack-context/v1\x00"
_PROOF_SESSION_DOMAIN: Final = b"ranklock/strata-ack-proof-session/v1\x00"
_PAYLOAD_BYTES: Final = 32
# Bound on rejection sampling.  Roughly half of all 32-byte digests are valid
# x-only keys, so exhausting this many attempts indicates a broken derivation
# rather than bad luck.
_MAX_SAMPLING_ATTEMPTS: Final = 1024


class StrataExportError(RuntimeError):
    """Raised when an export is unsafe, inconsistent or conflicting."""


class StrataPublicationAmbiguousError(StrataExportError):
    """Raised when bytes are visible but their directory sync did not complete."""


def _strict_bytes(value: object, *, label: str) -> bytes:
    """Accept explicit byte containers, never ``bytes(integer)`` coercion."""

    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise StrataExportError(f"{label} must be an explicit byte string")
    return bytes(value)


def _strict_u32(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StrataExportError(f"{label} must be an integer")
    if not 0 <= value < 2**32:
        raise StrataExportError(f"{label} does not fit u32")
    return value


def commitment_is_valid_xonly(commitment: bytes) -> bool:
    """Does ``commitment`` parse as a secp256k1 x-only public key?

    The Strata graph reuses an x-only-typed field to carry the ACK
    commitment, so a commitment that does not lift is unusable -- the graph
    could not be constructed with it.
    """

    if not isinstance(commitment, (bytes, bytearray, memoryview)):
        return False
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

    encoded = _strict_bytes(payload, label="positive-lock payload")
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
        if not isinstance(self.network, str) or not self.network:
            raise StrataExportError("network must be a nonempty string")
        if "\x00" in self.network:
            raise StrataExportError("network must not contain NUL")
        try:
            encoded_network = self.network.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise StrataExportError("network is not valid UTF-8 text") from exc
        if len(encoded_network) > 255:
            raise StrataExportError("network name is too long")
        if self.schema != "ranklock-strata-ack-context-v1":
            raise StrataExportError("unsupported ACK context schema")
        if not isinstance(self.chain_genesis_hash, bytes):
            raise StrataExportError("chain genesis hash must be immutable bytes")
        if len(self.chain_genesis_hash) != 32:
            raise StrataExportError("chain genesis hash must be 32 bytes")
        for value, name in (
            (self.bridge_proof_txid, "bridge proof txid"),
            (self.counterproof_txid, "counterproof txid"),
            (self.counterproof_ack_txid, "counterproof ACK txid"),
        ):
            if not isinstance(value, bytes):
                raise StrataExportError(f"{name} must be immutable bytes")
            if len(value) != 32:
                raise StrataExportError(f"{name} must be 32 bytes")
        for value, name in (
            (self.graph_owner, "graph owner"),
            (self.deposit_index, "deposit index"),
            (self.game_index, "game index"),
            (self.watchtower_index, "watchtower index"),
            (self.slot_id, "slot id"),
            (self.epoch, "epoch"),
        ):
            _strict_u32(value, label=name)

    @property
    def encoded(self) -> bytes:
        return (
            _CONTEXT_DOMAIN
            + self.network.encode()
            + b"\x00"
            + self.chain_genesis_hash
            + self.graph_owner.to_bytes(4, "big")
            + self.deposit_index.to_bytes(4, "big")
            + self.game_index.to_bytes(4, "big")
            + self.watchtower_index.to_bytes(4, "big")
            + self.slot_id.to_bytes(4, "big")
            + self.epoch.to_bytes(4, "big")
            + self.bridge_proof_txid
            + self.counterproof_txid
            + self.counterproof_ack_txid
        )

    @property
    def digest(self) -> bytes:
        return sha256(self.encoded).digest()

    @property
    def unlock_stem(self) -> str:
        """Filename the bridge executor reads, in its display-order convention."""

        return (
            f"bridge{self.bridge_proof_txid.hex()}"
            f"-counterproof{self.counterproof_txid.hex()}"
            f"-ack{self.counterproof_ack_txid.hex()}"
        )


def ack_proof_session_context(context: AckContext) -> bytes:
    """Derive the positive-lock session from the exact ACK destination.

    Setup and release must both use this value. Accepting a separate session
    byte string at release would let a valid unlock be redirected to another
    bridge/transaction context that happens to share the same setup
    commitment path. Deriving it here makes that split-brain state
    unrepresentable at the proof-gated exporter boundary.
    """

    if not isinstance(context, AckContext):
        raise StrataExportError("ACK proof session requires an AckContext")
    return sha256(_PROOF_SESSION_DOMAIN + context.encoded).digest()


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

    entropy = _strict_bytes(entropy, label="setup entropy")
    if len(entropy) < 32:
        raise StrataExportError(
            "setup entropy must be at least 32 bytes; a short or public seed "
            "would let anyone reconstruct the ACK preimage"
        )
    owner = _strict_u32(graph_owner, label="graph owner")
    deposit = _strict_u32(deposit_index, label="deposit index")
    game = _strict_u32(game_index, label="game index")
    watchtower = _strict_u32(watchtower_index, label="watchtower index")
    base = (
        _COMMITMENT_DOMAIN
        + len(entropy).to_bytes(4, "big")
        + entropy
        + owner.to_bytes(4, "big")
        + deposit.to_bytes(4, "big")
        + game.to_bytes(4, "big")
        + watchtower.to_bytes(4, "big")
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


def _write_once(path: Path, data: bytes, *, label: str) -> bool:
    try:
        created = atomic_write_once(path, data, mode=0o600)
    except ReleaseSidecarError as exc:
        raise StrataExportError(f"failed to publish {label} safely: {exc}") from exc
    except OSError as exc:
        # atomic_write_once may have linked the final name before a directory
        # fsync or temporary-file cleanup failed.  The output is then visible
        # and must not be mislabeled as an ordinary failed publication: an ACK
        # consumer may already have read it.  Leave the ledger binding intact
        # and require an exact retry, which will validate the existing bytes.
        try:
            published = read_secret_file_secure(path, maximum_bytes=len(data))
        except ReleaseSidecarError as inspection_error:
            raise StrataExportError(
                f"failed to publish {label} and could not establish whether "
                "the final output exists safely"
            ) from ExceptionGroup(
                f"{label} publication and recovery inspection failures",
                [exc, inspection_error],
            )
        if published == bytes(data):
            raise StrataPublicationAmbiguousError(
                f"{label} is present with the expected private bytes, but "
                "durable directory synchronization failed; exact retry required"
            ) from exc
        raise StrataExportError(
            f"failed to publish {label}; the final output contains unexpected bytes"
        ) from exc

    try:
        published = read_secret_file_secure(path, maximum_bytes=len(data))
    except ReleaseSidecarError as exc:
        raise StrataExportError(
            f"published {label} failed private-file validation: {exc}"
        ) from exc
    if published != bytes(data):
        raise StrataExportError(
            f"published {label} changed before post-publication validation"
        )
    return created


def _rollback_after_failure(
    connection: sqlite3.Connection, primary_error: BaseException, *, label: str
) -> None:
    if not connection.in_transaction:
        return
    try:
        connection.execute("ROLLBACK")
    except sqlite3.Error as rollback_error:
        raise StrataExportError(f"{label}; SQLite rollback also failed") from ExceptionGroup(
            f"{label} and rollback failure",
            [primary_error, rollback_error],
        )


class StrataAckExporter:
    """Publishes ACK preimages under a durable one-context-per-commitment rule."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        ledger_path: str | os.PathLike[str] | None = None,
    ) -> None:
        self.root = Path(root)
        root_existed = self.root.exists()
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not root_existed:
                os.chmod(self.root, 0o700)
        except OSError as exc:
            raise StrataExportError(
                f"could not prepare Strata ACK exporter root: {exc}"
            ) from exc
        require_private_directory(
            self.root,
            error_type=StrataExportError,
            label="Strata ACK exporter root",
        )
        requested_ledger = (
            Path(ledger_path) if ledger_path else self.root / "export-ledger.sqlite"
        )
        self.ledger_path, self._ledger_identity, _created = prepare_private_sqlite_path(
            requested_ledger,
            error_type=StrataExportError,
            label="Strata ACK export ledger",
        )
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        validate_private_file(
            self.ledger_path,
            error_type=StrataExportError,
            label="Strata ACK export ledger",
            expected=self._ledger_identity,
        )
        connection = sqlite3.connect(self.ledger_path, timeout=30, isolation_level=None)
        try:
            validate_private_file(
                self.ledger_path,
                error_type=StrataExportError,
                label="Strata ACK export ledger",
                expected=self._ledger_identity,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            validate_sqlite_sidecars(
                self.ledger_path,
                error_type=StrataExportError,
                label="Strata ACK export ledger",
            )
            return connection
        except StrataExportError:
            connection.close()
            raise
        except sqlite3.Error as exc:
            connection.close()
            raise StrataExportError(f"failed to open ACK export ledger: {exc}") from exc

    def _initialize(self) -> None:
        connection = self._connect()
        try:
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
            except sqlite3.Error as exc:
                raise StrataExportError(
                    f"failed to initialize ACK export ledger: {exc}"
                ) from exc
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
        """Publish the setup commitment once. Never accepts the payload itself."""

        encoded = _strict_bytes(commitment, label="ACK commitment")
        if len(encoded) != 32:
            raise StrataExportError("ACK commitment must be 32 bytes")
        if not commitment_is_valid_xonly(encoded):
            raise StrataExportError(
                "ACK commitment does not parse as an x-only key, so the graph "
                "cannot carry it; re-run setup derivation"
            )
        path = self.commitment_path(context)
        _write_once(path, encoded, label="ACK commitment")
        return path

    def require_published_commitment(
        self, context: AckContext, expected_commitment: bytes
    ) -> Path:
        """Require the proof-gated export to match the graph setup artifact."""

        expected = _strict_bytes(
            expected_commitment, label="expected ACK commitment"
        )
        if len(expected) != 32:
            raise StrataExportError("expected ACK commitment must be 32 bytes")
        path = self.commitment_path(context)
        try:
            published = read_secret_file_secure(path, maximum_bytes=32)
        except ReleaseSidecarError as exc:
            raise StrataExportError(
                f"published ACK commitment is unavailable or unsafe at {path}: {exc}"
            ) from exc
        if published != expected:
            raise StrataExportError(
                "proof-gated ACK commitment differs from the commitment published "
                "for graph setup"
            )
        return path

    def _mark_conflict_after_publish_failure(
        self, commitment: bytes, context_digest: bytes
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE exports SET state='conflict' "
                "WHERE commitment=? AND context_digest=?",
                (commitment, context_digest),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                raise StrataExportError(
                    "ACK export ledger changed while recording a publish failure"
                )
            connection.execute("COMMIT")
        except Exception as exc:
            _rollback_after_failure(
                connection,
                exc,
                label="failed to mark ACK commitment conflicted",
            )
            if isinstance(exc, StrataExportError):
                raise
            raise StrataExportError(
                f"failed to mark ACK commitment conflicted: {exc}"
            ) from exc
        finally:
            connection.close()

    def export_unlock(
        self,
        *,
        payload: bytes,
        context: AckContext,
        expected_commitment: bytes,
        allow_unverified_payload: bool = False,
    ) -> tuple[Path, bool]:
        """Publish ``payload`` for exactly one ACK context.

        Returns ``(path, created)``.  ``created`` is ``False`` for an exact
        retry, which republishes nothing.  Raises rather than releasing if the
        payload does not match the commitment the graph was built with, or if
        this commitment already released under a different context.
        """

        # A payload passed in here is only checked against its commitment,
        # which derive_setup_payload can satisfy from setup entropy alone --
        # no proof required. The proof-gated entry point is
        # export_ack_from_verified_unlock, which computes the payload itself.
        # Callers that genuinely need the raw path (ledger and conflict tests)
        # must say so, so that a production caller cannot reach it by
        # forgetting which function to use.
        if not allow_unverified_payload:
            raise StrataExportError(
                "export_unlock publishes a payload it cannot prove came from a "
                "valid proof; use export_ack_from_verified_unlock, or pass "
                "allow_unverified_payload=True if this is not a release path"
            )
        payload = _strict_bytes(payload, label="recovered ACK payload")
        expected = _strict_bytes(
            expected_commitment, label="expected ACK commitment"
        )
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
        except Exception as exc:
            _rollback_after_failure(
                connection,
                exc,
                label="ACK export ledger operation failed",
            )
            if isinstance(exc, StrataExportError):
                raise
            raise StrataExportError(f"ACK export ledger operation failed: {exc}") from exc
        finally:
            connection.close()

        path = self.unlock_path(context)
        try:
            _write_once(path, payload, label="ACK unlock")
        except StrataPublicationAmbiguousError:
            # The exact authorized payload is already visible.  Marking this
            # commitment conflicted would contradict the durable context
            # binding and would not retract bytes a bridge may have consumed.
            # An exact retry revalidates the file and returns idempotently.
            raise
        except StrataExportError as publish_error:
            try:
                self._mark_conflict_after_publish_failure(expected, context_digest)
            except Exception as conflict_error:
                raise StrataExportError(
                    "ACK unlock publication failed and the exporter could not "
                    "durably mark the commitment conflicted"
                ) from ExceptionGroup(
                    "ACK publish and conflict-recording failures",
                    [publish_error, conflict_error],
                )
            raise
        return path, created

    def released_contexts(self) -> int:
        connection = self._connect()
        try:
            try:
                row = connection.execute(
                    "SELECT COUNT(*) AS n FROM exports WHERE state='released'"
                ).fetchone()
            except sqlite3.Error as exc:
                raise StrataExportError(
                    f"failed to count released ACK contexts: {exc}"
                ) from exc
            if row is None:
                raise StrataExportError("ACK export ledger returned no release count")
            return int(row["n"])
        finally:
            connection.close()


def export_ack_from_verified_unlock(
    exporter: StrataAckExporter,
    *,
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Sequence[int],
    proof: PositiveGroth16Proof,
    lock: PositiveLock,
    r_a_g1: bytes,
    context: AckContext,
    expected_commitment: bytes,
) -> tuple[Path, bool]:
    """Release the ACK preimage **only** as the output of a verified unlock.

    This is the proof-to-ACK binding, and until now it did not exist anywhere
    in the codebase. ``export_unlock`` accepts a caller-supplied payload and
    can only check that it hashes to the expected commitment; it has no way to
    know the payload came from a proof rather than from setup entropy, and
    ``derive_setup_payload`` produces the identical value from entropy alone.
    Every existing caller of ``export_unlock`` was a test, so no path bound
    release to proof possession.

    Here the payload is not an argument. It is produced inside this function
    by ``unlock_positive_lock``, which refuses unless the lock is bound to
    this exact statement and ACK context, and
    ``certify_projective_output`` confirms the supplied ``[r]A`` is the
    genuine projective output for this proof. The session context is derived
    from ``context`` rather than supplied separately, so a valid unlock cannot
    be redirected to another bridge/transaction tuple. A caller cannot
    substitute a payload it obtained another way, because there is no
    parameter through which to pass one.

    What this does NOT do, stated so the boundary is not overread: it does not
    make setup entropy safe. Whoever holds the entropy can still recompute the
    preimage via ``derive_setup_payload`` and publish it through
    ``export_unlock`` directly. Closing that requires removing the
    entropy-only derivation from the release path entirely, which is a larger
    change to how commitments are provisioned. This function makes the
    proof-gated path *exist*; it does not yet make it the only one.
    """

    exporter.require_published_commitment(context, expected_commitment)
    payload = unlock_positive_lock(
        vk,
        public_inputs,
        proof,
        lock,
        r_a_g1,
        session_context=ack_proof_session_context(context),
    )
    return exporter.export_unlock(
        payload=payload,
        context=context,
        expected_commitment=expected_commitment,
        # Legitimate: the payload above is the output of a verified unlock.
        allow_unverified_payload=True,
    )
