from __future__ import annotations

"""Independent monotonic witness for durable one-shot ledgers.

A local SQLite ledger is crash durable, but an operator who can restore an old
filesystem snapshot can roll it back.  This module adds a second, independently
persisted monotonic state.  Before any response bytes leave a participant, the
participant signs its complete slot-state checkpoint and every configured
witness must accept it.

The reference witness is SQLite-backed and suitable for conformance tests.  A
funded deployment must run witnesses on independently administered machines or
an append-only transparency service; placing the witness database beside the
participant database does not add rollback resistance.
"""

from dataclasses import dataclass
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import sqlite3
import ssl
import stat
from typing import Final, Protocol, Sequence
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from .bip340 import public_key, sign, verify
from .durable_slot_ledger import DurableSlotLedger, DurableSlotUse
from .private_sqlite import (
    prepare_private_sqlite_path,
    validate_private_file,
    validate_sqlite_sidecars,
)


_DIGEST: Final = 32
_SIG: Final = 64
_ZERO: Final = bytes(_DIGEST)
_CHECKPOINT_DOMAIN: Final = b"ranklock/ledger-checkpoint/v1\x00"
_CHECKPOINT_SIGN_DOMAIN: Final = b"ranklock/ledger-checkpoint-sign/v1\x00"
_RECEIPT_DOMAIN: Final = b"ranklock/rollback-witness-receipt/v1\x00"
_RECEIPT_SIGN_DOMAIN: Final = b"ranklock/rollback-witness-receipt-sign/v1\x00"
_LEDGER_ID_DOMAIN: Final = b"ranklock/rollback-ledger-id/v1\x00"
_ROLLBACK_WITNESS_SET_DOMAIN: Final = b"ranklock/rollback-witness-set/v1\x00"
_STATE_CODES: Final = {
    "available": 0,
    "burned": 1,
    "success": 2,
    "malformed": 3,
    "abort": 4,
    "timeout": 5,
    "retry-rejected": 6,
}
_CODE_STATES: Final = {value: key for key, value in _STATE_CODES.items()}
_TERMINAL: Final = {"success", "malformed", "abort", "timeout", "retry-rejected"}


class RollbackWitnessError(RuntimeError):
    pass


class RollbackDetectedError(RollbackWitnessError):
    pass


class _NoRedirect(urllib_request.HTTPRedirectHandler):
    """Reject redirects so witness credentials never cross an origin boundary."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        del req, fp, code, msg, headers, newurl
        return None


def _d(value: bytes, name: str) -> bytes:
    value = bytes(value)
    if len(value) != _DIGEST:
        raise RollbackWitnessError(f"{name} must be 32 bytes")
    return value


def _u(value: int, width: int) -> bytes:
    value = int(value)
    if value < 0 or value >= 1 << (8 * width):
        raise RollbackWitnessError(f"integer does not fit u{8 * width}")
    return value.to_bytes(width, "big")


def _optional(value: bytes | None) -> bytes:
    if value is None:
        return b"\x00" + _ZERO
    return b"\x01" + _d(value, "optional digest")


def canonical_rollback_witness_pubkeys(pubkeys: Sequence[bytes]) -> tuple[bytes, ...]:
    """Return the canonical unique rollback-witness identity set.

    The identities, rather than only a minimum count, are part of the signed
    authorization boundary.  Sorting makes the set digest independent of local
    client configuration order, while duplicate identities remain a hard error.
    """

    keys = tuple(sorted(_d(key, "rollback witness public key") for key in pubkeys))
    if not keys:
        raise RollbackWitnessError("at least one independent rollback witness is required")
    if len(set(keys)) != len(keys):
        raise RollbackWitnessError("rollback witness identities are duplicated")
    if len(keys) >= 2**16:
        raise RollbackWitnessError("rollback witness set is too large")
    return keys


def rollback_witness_set_digest(pubkeys: Sequence[bytes]) -> bytes:
    keys = canonical_rollback_witness_pubkeys(pubkeys)
    return sha256(
        _ROLLBACK_WITNESS_SET_DOMAIN + _u(len(keys), 2) + b"".join(keys)
    ).digest()


def require_rollback_witness_set(
    witnesses: Sequence["RollbackWitnessClient"],
    *,
    expected_digest: bytes,
) -> tuple[bytes, ...]:
    expected = _d(expected_digest, "expected rollback witness set digest")
    keys = canonical_rollback_witness_pubkeys(
        tuple(bytes(witness.witness_pubkey) for witness in witnesses)
    )
    if rollback_witness_set_digest(keys) != expected:
        raise RollbackWitnessError(
            "configured rollback witness identities differ from the signed activation"
        )
    return keys


def _monotonic(previous: "SlotCheckpoint", current: "SlotCheckpoint") -> bool:
    if previous.slot_id != current.slot_id:
        return False
    # Once a binding exists it can never change or disappear.
    for before, after in (
        (previous.input_digest, current.input_digest),
        (previous.authorization_digest, current.authorization_digest),
        (previous.chain_binding_digest, current.chain_binding_digest),
    ):
        if before is not None and before != after:
            return False
    if previous.state == "available":
        # A witness must observe the durable burn before it accepts any
        # terminal result.  Allowing ``available -> success`` would let a
        # participant skip the externally witnessed burn checkpoint and then
        # restore a pre-use snapshot after response bytes had escaped.
        return current.state in {"available", "burned"}
    if previous.state == "burned":
        return current.state == "burned" or current.state in _TERMINAL
    # Terminal results are permanent and exact.
    return current.state == previous.state


@dataclass(frozen=True, slots=True)
class SlotCheckpoint:
    slot_id: int
    state: str
    input_digest: bytes | None
    authorization_digest: bytes | None
    chain_binding_digest: bytes | None
    schema: str = "ranklock-slot-checkpoint-v1"

    def __post_init__(self) -> None:
        if not 0 <= int(self.slot_id) < 2**16:
            raise RollbackWitnessError("slot id is outside u16")
        if self.state not in _STATE_CODES:
            raise RollbackWitnessError("unknown slot state")
        for name in ("input_digest", "authorization_digest", "chain_binding_digest"):
            value = getattr(self, name)
            if value is not None:
                _d(value, name)
        if self.state == "available" and any(
            value is not None
            for value in (
                self.input_digest,
                self.authorization_digest,
                self.chain_binding_digest,
            )
        ):
            raise RollbackWitnessError("available slot cannot carry a binding")
        if self.state != "available" and any(
            value is None
            for value in (
                self.input_digest,
                self.authorization_digest,
                self.chain_binding_digest,
            )
        ):
            raise RollbackWitnessError("consumed slot is missing its permanent binding")

    @classmethod
    def from_use(cls, use: DurableSlotUse) -> "SlotCheckpoint":
        return cls(
            slot_id=use.slot_id,
            state=use.state,
            input_digest=use.input_digest,
            authorization_digest=use.authorization_digest,
            chain_binding_digest=use.chain_binding_digest,
        )

    @property
    def encoded(self) -> bytes:
        return (
            _u(self.slot_id, 2)
            + bytes((_STATE_CODES[self.state],))
            + _optional(self.input_digest)
            + _optional(self.authorization_digest)
            + _optional(self.chain_binding_digest)
        )

    @classmethod
    def parse(cls, raw: bytes) -> "SlotCheckpoint":
        raw = bytes(raw)
        if len(raw) != 102:
            raise RollbackWitnessError("slot checkpoint length mismatch")
        slot_id = int.from_bytes(raw[:2], "big")
        state = _CODE_STATES.get(raw[2])
        if state is None:
            raise RollbackWitnessError("slot checkpoint state code is invalid")
        cursor = 3
        values: list[bytes | None] = []
        for _ in range(3):
            present = raw[cursor]
            digest = raw[cursor + 1 : cursor + 33]
            cursor += 33
            if present == 0:
                if digest != _ZERO:
                    raise RollbackWitnessError("absent checkpoint digest is nonzero")
                values.append(None)
            elif present == 1:
                values.append(digest)
            else:
                raise RollbackWitnessError("invalid optional checkpoint flag")
        result = cls(slot_id, state, values[0], values[1], values[2])
        if result.encoded != raw:
            raise RollbackWitnessError("non-canonical slot checkpoint")
        return result


@dataclass(frozen=True, slots=True)
class UnsignedLedgerCheckpoint:
    ledger_id: bytes
    context_digest: bytes
    participant_pubkey: bytes
    event_count: int
    audit_chain_head: bytes
    slots: tuple[SlotCheckpoint, ...]
    schema: str = "ranklock-unsigned-ledger-checkpoint-v1"

    def __post_init__(self) -> None:
        _d(self.ledger_id, "ledger id")
        _d(self.context_digest, "context digest")
        _d(self.participant_pubkey, "participant public key")
        _d(self.audit_chain_head, "audit chain head")
        if not 0 <= int(self.event_count) < 2**64:
            raise RollbackWitnessError("event count is outside u64")
        if not 1 <= len(self.slots) < 2**16:
            raise RollbackWitnessError("checkpoint slot count is invalid")
        if tuple(slot.slot_id for slot in self.slots) != tuple(range(len(self.slots))):
            raise RollbackWitnessError("checkpoint slots are not canonical")
        expected_id = sha256(
            _LEDGER_ID_DOMAIN
            + self.context_digest
            + self.participant_pubkey
            + _u(len(self.slots), 2)
        ).digest()
        if self.ledger_id != expected_id:
            raise RollbackWitnessError("ledger id does not match checkpoint identity")
        if self.event_count == 0:
            if self.audit_chain_head != _ZERO:
                raise RollbackWitnessError("empty audit chain has nonzero head")
            if any(slot.state != "available" for slot in self.slots):
                raise RollbackWitnessError("genesis checkpoint has consumed slots")

    @property
    def encoded(self) -> bytes:
        return (
            b"RLCPv1\x00\x00"
            + self.ledger_id
            + self.context_digest
            + self.participant_pubkey
            + _u(self.event_count, 8)
            + self.audit_chain_head
            + _u(len(self.slots), 2)
            + b"".join(slot.encoded for slot in self.slots)
        )

    @property
    def digest(self) -> bytes:
        return sha256(_CHECKPOINT_DOMAIN + self.encoded).digest()

    @classmethod
    def from_ledger(
        cls,
        ledger: DurableSlotLedger,
        *,
        participant_pubkey: bytes,
    ) -> "UnsignedLedgerCheckpoint":
        participant_pubkey = _d(participant_pubkey, "participant public key")
        events = ledger.events()
        slots = tuple(SlotCheckpoint.from_use(ledger.use(i)) for i in range(ledger.slot_count))
        ledger_id = sha256(
            _LEDGER_ID_DOMAIN
            + ledger.context_digest
            + participant_pubkey
            + _u(ledger.slot_count, 2)
        ).digest()
        return cls(
            ledger_id=ledger_id,
            context_digest=ledger.context_digest,
            participant_pubkey=participant_pubkey,
            event_count=len(events),
            audit_chain_head=events[-1].event_hash if events else _ZERO,
            slots=slots,
        )

    @classmethod
    def parse(cls, raw: bytes) -> "UnsignedLedgerCheckpoint":
        raw = bytes(raw)
        fixed = 8 + 32 + 32 + 32 + 8 + 32 + 2
        if len(raw) < fixed or raw[:8] != b"RLCPv1\x00\x00":
            raise RollbackWitnessError("invalid ledger checkpoint framing")
        cursor = 8
        ledger_id = raw[cursor : cursor + 32]; cursor += 32
        context = raw[cursor : cursor + 32]; cursor += 32
        participant = raw[cursor : cursor + 32]; cursor += 32
        event_count = int.from_bytes(raw[cursor : cursor + 8], "big"); cursor += 8
        head = raw[cursor : cursor + 32]; cursor += 32
        slot_count = int.from_bytes(raw[cursor : cursor + 2], "big"); cursor += 2
        expected = fixed + 102 * slot_count
        if len(raw) != expected:
            raise RollbackWitnessError("ledger checkpoint length mismatch")
        slots = tuple(
            SlotCheckpoint.parse(raw[cursor + 102 * i : cursor + 102 * (i + 1)])
            for i in range(slot_count)
        )
        result = cls(ledger_id, context, participant, event_count, head, slots)
        if result.encoded != raw:
            raise RollbackWitnessError("non-canonical ledger checkpoint")
        return result


@dataclass(frozen=True, slots=True)
class SignedLedgerCheckpoint:
    unsigned: UnsignedLedgerCheckpoint
    signature: bytes
    schema: str = "ranklock-signed-ledger-checkpoint-v1"

    def __post_init__(self) -> None:
        if len(bytes(self.signature)) != _SIG:
            raise RollbackWitnessError("checkpoint signature must be 64 bytes")

    @property
    def signing_message(self) -> bytes:
        return sha256(_CHECKPOINT_SIGN_DOMAIN + self.unsigned.digest).digest()

    def verify(self) -> bool:
        return verify(self.signing_message, self.unsigned.participant_pubkey, self.signature)

    @property
    def encoded(self) -> bytes:
        return self.unsigned.encoded + bytes(self.signature)

    @property
    def digest(self) -> bytes:
        return sha256(_CHECKPOINT_DOMAIN + self.encoded).digest()

    @classmethod
    def create(cls, ledger: DurableSlotLedger, *, participant_secret: int) -> "SignedLedgerCheckpoint":
        unsigned = UnsignedLedgerCheckpoint.from_ledger(
            ledger, participant_pubkey=public_key(participant_secret)
        )
        placeholder = cls(unsigned, bytes(_SIG))
        return cls(unsigned, sign(placeholder.signing_message, participant_secret))

    @classmethod
    def parse(cls, raw: bytes) -> "SignedLedgerCheckpoint":
        raw = bytes(raw)
        if len(raw) < _SIG:
            raise RollbackWitnessError("signed checkpoint is truncated")
        result = cls(UnsignedLedgerCheckpoint.parse(raw[:-_SIG]), raw[-_SIG:])
        if result.encoded != raw:
            raise RollbackWitnessError("non-canonical signed checkpoint")
        return result


@dataclass(frozen=True, slots=True)
class RollbackWitnessReceipt:
    witness_pubkey: bytes
    ledger_id: bytes
    generation: int
    checkpoint_digest: bytes
    previous_receipt_digest: bytes
    signature: bytes
    schema: str = "ranklock-rollback-witness-receipt-v1"

    def __post_init__(self) -> None:
        _d(self.witness_pubkey, "witness public key")
        _d(self.ledger_id, "ledger id")
        _d(self.checkpoint_digest, "checkpoint digest")
        _d(self.previous_receipt_digest, "previous receipt digest")
        if not 0 <= int(self.generation) < 2**64:
            raise RollbackWitnessError("receipt generation is outside u64")
        if len(bytes(self.signature)) != _SIG:
            raise RollbackWitnessError("receipt signature must be 64 bytes")

    @property
    def unsigned_bytes(self) -> bytes:
        return (
            b"RLRWv1\x00\x00"
            + self.witness_pubkey
            + self.ledger_id
            + _u(self.generation, 8)
            + self.checkpoint_digest
            + self.previous_receipt_digest
        )

    @property
    def signing_message(self) -> bytes:
        return sha256(_RECEIPT_SIGN_DOMAIN + self.unsigned_bytes).digest()

    def verify(self) -> bool:
        return verify(self.signing_message, self.witness_pubkey, self.signature)

    @property
    def encoded(self) -> bytes:
        return self.unsigned_bytes + bytes(self.signature)

    @property
    def digest(self) -> bytes:
        return sha256(_RECEIPT_DOMAIN + self.encoded).digest()

    @classmethod
    def parse(cls, raw: bytes) -> "RollbackWitnessReceipt":
        raw = bytes(raw)
        if len(raw) != 8 + 32 + 32 + 8 + 32 + 32 + 64 or raw[:8] != b"RLRWv1\x00\x00":
            raise RollbackWitnessError("invalid witness receipt framing")
        cursor = 8
        result = cls(
            raw[cursor : cursor + 32],
            raw[cursor + 32 : cursor + 64],
            int.from_bytes(raw[cursor + 64 : cursor + 72], "big"),
            raw[cursor + 72 : cursor + 104],
            raw[cursor + 104 : cursor + 136],
            raw[cursor + 136 :],
        )
        if result.encoded != raw:
            raise RollbackWitnessError("non-canonical witness receipt")
        return result


class RollbackWitnessClient(Protocol):
    @property
    def witness_pubkey(self) -> bytes: ...
    def anchor(self, checkpoint: SignedLedgerCheckpoint) -> RollbackWitnessReceipt: ...
    def latest(self, ledger_id: bytes) -> RollbackWitnessReceipt | None: ...


@dataclass(frozen=True, slots=True)
class HttpRollbackWitnessClient:
    """mTLS-capable client for an independently hosted rollback witness.

    Remote witnesses are intentionally stricter than ordinary HTTPS clients:
    they require a pinned CA file and a client certificate/key pair.  This keeps
    a bearer token from becoming the sole network authorization boundary.  A
    loopback service may omit mTLS for local conformance tests.
    """

    base_url: str
    configured_witness_pubkey: bytes
    bearer_token: str | None = None
    timeout_seconds: float = 10.0
    maximum_response_bytes: int = 1024 * 1024
    ca_file: str | os.PathLike[str] | None = None
    client_cert_file: str | os.PathLike[str] | None = None
    client_key_file: str | os.PathLike[str] | None = None

    def __post_init__(self) -> None:
        _d(self.configured_witness_pubkey, "configured witness public key")
        parsed = urllib_parse.urlparse(self.base_url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise RollbackWitnessError("rollback witness URL must be HTTP(S)")
        if parsed.username is not None or parsed.password is not None:
            raise RollbackWitnessError("rollback witness credentials must not appear in the URL")
        if parsed.query or parsed.fragment:
            raise RollbackWitnessError("rollback witness URL must not contain a query or fragment")
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not loopback:
            raise RollbackWitnessError("remote rollback witnesses require HTTPS")
        if (self.client_cert_file is None) != (self.client_key_file is None):
            raise RollbackWitnessError(
                "rollback witness client certificate and key must be supplied together"
            )
        if not loopback and (
            self.ca_file is None
            or self.client_cert_file is None
            or self.client_key_file is None
        ):
            raise RollbackWitnessError(
                "remote rollback witnesses require a pinned CA and mutual TLS client credentials"
            )
        for value, name, private in (
            (self.ca_file, "rollback witness CA file", False),
            (self.client_cert_file, "rollback witness client certificate", False),
            (self.client_key_file, "rollback witness client key", True),
        ):
            if value is not None:
                path = Path(value)
                try:
                    metadata = path.lstat()
                except OSError as exc:
                    raise RollbackWitnessError(f"{name} is absent or unsafe: {path}") from exc
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                    raise RollbackWitnessError(f"{name} is absent or unsafe: {path}")
                if private:
                    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                        raise RollbackWitnessError(f"{name} must be owned by the client user")
                    if stat.S_IMODE(metadata.st_mode) & 0o077:
                        raise RollbackWitnessError(f"{name} permissions must be 0600 or stricter")
        if self.timeout_seconds <= 0:
            raise RollbackWitnessError("rollback witness timeout must be positive")
        if not 1024 <= int(self.maximum_response_bytes) <= 8 * 1024 * 1024:
            raise RollbackWitnessError("rollback witness response limit is outside the safe range")
        if self.bearer_token is not None and (
            not self.bearer_token
            or "\r" in self.bearer_token
            or "\n" in self.bearer_token
        ):
            raise RollbackWitnessError("rollback witness bearer token is malformed")

    @property
    def witness_pubkey(self) -> bytes:
        return bytes(self.configured_witness_pubkey)

    def _tls_context(self) -> ssl.SSLContext | None:
        parsed = urllib_parse.urlparse(self.base_url)
        if parsed.scheme != "https":
            return None
        context = ssl.create_default_context(
            cafile=None if self.ca_file is None else os.fspath(self.ca_file)
        )
        if self.client_cert_file is not None:
            context.load_cert_chain(
                certfile=os.fspath(self.client_cert_file),
                keyfile=os.fspath(self.client_key_file),
            )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    def _call(self, path: str, payload: dict[str, object]) -> dict[str, object]:
        if path not in {"/v1/anchor", "/v1/latest"}:
            raise RollbackWitnessError("rollback witness path is not allowed")
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.bearer_token is not None:
            headers["Authorization"] = "Bearer " + self.bearer_token
        req = urllib_request.Request(
            self.base_url.rstrip("/") + path, data=body, headers=headers, method="POST"
        )
        handlers: list[object] = [_NoRedirect()]
        tls_context = self._tls_context()
        if tls_context is not None:
            handlers.append(urllib_request.HTTPSHandler(context=tls_context))
        opener = urllib_request.build_opener(*handlers)
        try:
            with opener.open(req, timeout=float(self.timeout_seconds)) as response:
                if getattr(response, "status", 200) != 200:
                    raise RollbackWitnessError(
                        f"rollback witness returned HTTP {response.status}"
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > int(
                    self.maximum_response_bytes
                ):
                    raise RollbackWitnessError("rollback witness response exceeds size limit")
                raw = response.read(int(self.maximum_response_bytes) + 1)
                if len(raw) > int(self.maximum_response_bytes):
                    raise RollbackWitnessError("rollback witness response exceeds size limit")
                result = json.loads(raw.decode("utf-8", "strict"))
        except RollbackWitnessError:
            raise
        except Exception as exc:  # pragma: no cover - exercised by integration deployment
            raise RollbackWitnessError(f"rollback witness transport failed: {exc}") from exc
        if not isinstance(result, dict) or result.get("error") is not None:
            raise RollbackWitnessError(f"rollback witness rejected request: {result!r}")
        returned_key = result.get("witness_pubkey")
        if returned_key is not None and str(returned_key).lower() != self.witness_pubkey.hex():
            raise RollbackWitnessError("rollback witness endpoint returned an unexpected identity")
        return result

    def anchor(self, checkpoint: SignedLedgerCheckpoint) -> RollbackWitnessReceipt:
        result = self._call(
            "/v1/anchor",
            {"checkpoint": base64.b64encode(checkpoint.encoded).decode("ascii")},
        )
        try:
            receipt = RollbackWitnessReceipt.parse(
                base64.b64decode(str(result["receipt"]), validate=True)
            )
        except Exception as exc:
            raise RollbackWitnessError("rollback witness returned a malformed receipt") from exc
        if receipt.witness_pubkey != self.witness_pubkey or not receipt.verify():
            raise RollbackWitnessError("rollback witness receipt signature/key mismatch")
        return receipt

    def latest(self, ledger_id: bytes) -> RollbackWitnessReceipt | None:
        result = self._call("/v1/latest", {"ledger_id": _d(ledger_id, "ledger id").hex()})
        encoded = result.get("receipt")
        if encoded is None:
            return None
        try:
            receipt = RollbackWitnessReceipt.parse(
                base64.b64decode(str(encoded), validate=True)
            )
        except Exception as exc:
            raise RollbackWitnessError("rollback witness returned a malformed latest receipt") from exc
        if receipt.witness_pubkey != self.witness_pubkey or not receipt.verify():
            raise RollbackWitnessError("latest rollback witness receipt is invalid")
        return receipt


class SqliteRollbackWitness:
    """Reference independently persisted monotonic witness."""

    def __init__(self, path: str | os.PathLike[str], *, witness_secret: int) -> None:
        self.path, self._file_identity, new = prepare_private_sqlite_path(
            path,
            error_type=RollbackWitnessError,
            label="rollback witness",
        )
        self._secret = int(witness_secret)
        self._pubkey = public_key(self._secret)
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledgers(
                    ledger_id BLOB PRIMARY KEY,
                    participant_pubkey BLOB NOT NULL,
                    generation INTEGER NOT NULL,
                    event_count INTEGER NOT NULL,
                    audit_chain_head BLOB NOT NULL,
                    checkpoint BLOB NOT NULL,
                    receipt BLOB NOT NULL
                ) WITHOUT ROWID;
                """
            )
        finally:
            conn.close()
        if new:
            validate_private_file(
                self.path,
                error_type=RollbackWitnessError,
                label="rollback witness",
                expected=self._file_identity,
            )

    @property
    def witness_pubkey(self) -> bytes:
        return self._pubkey

    def _connect(self) -> sqlite3.Connection:
        validate_private_file(
            self.path,
            error_type=RollbackWitnessError,
            label="rollback witness",
            expected=self._file_identity,
        )
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            validate_private_file(
                self.path,
                error_type=RollbackWitnessError,
                label="rollback witness",
                expected=self._file_identity,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA trusted_schema=OFF")
            validate_sqlite_sidecars(
                self.path,
                error_type=RollbackWitnessError,
                label="rollback witness",
            )
            return conn
        except Exception:
            conn.close()
            raise

    def latest(self, ledger_id: bytes) -> RollbackWitnessReceipt | None:
        ledger_id = _d(ledger_id, "ledger id")
        conn = self._connect()
        try:
            row = conn.execute("SELECT receipt FROM ledgers WHERE ledger_id=?", (ledger_id,)).fetchone()
        finally:
            conn.close()
        return None if row is None else RollbackWitnessReceipt.parse(bytes(row["receipt"]))

    @staticmethod
    def _validate_transition(
        previous: SignedLedgerCheckpoint,
        current: SignedLedgerCheckpoint,
    ) -> None:
        a, b = previous.unsigned, current.unsigned
        if (
            a.ledger_id != b.ledger_id
            or a.context_digest != b.context_digest
            or a.participant_pubkey != b.participant_pubkey
            or len(a.slots) != len(b.slots)
        ):
            raise RollbackDetectedError("checkpoint identity changed")
        if b.event_count < a.event_count:
            raise RollbackDetectedError("audit event count rolled backwards")
        if b.event_count == a.event_count and b.audit_chain_head != a.audit_chain_head:
            raise RollbackDetectedError("audit head changed without a new event")
        if b.event_count > a.event_count and b.audit_chain_head == a.audit_chain_head:
            raise RollbackDetectedError("audit count increased without changing the head")
        for before, after in zip(a.slots, b.slots, strict=True):
            if not _monotonic(before, after):
                raise RollbackDetectedError(f"slot {before.slot_id} rolled back or changed binding")

    def anchor(self, checkpoint: SignedLedgerCheckpoint) -> RollbackWitnessReceipt:
        if not checkpoint.verify():
            raise RollbackWitnessError("participant checkpoint signature is invalid")
        unsigned = checkpoint.unsigned
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM ledgers WHERE ledger_id=?", (unsigned.ledger_id,)).fetchone()
            if row is None:
                if unsigned.event_count != 0 or any(slot.state != "available" for slot in unsigned.slots):
                    raise RollbackDetectedError("witness must be bootstrapped before first release")
                generation = 0
                previous_receipt = _ZERO
            else:
                previous_checkpoint = SignedLedgerCheckpoint.parse(bytes(row["checkpoint"]))
                existing_receipt = RollbackWitnessReceipt.parse(bytes(row["receipt"]))
                if checkpoint.digest == previous_checkpoint.digest:
                    conn.execute("COMMIT")
                    return existing_receipt
                self._validate_transition(previous_checkpoint, checkpoint)
                generation = int(row["generation"]) + 1
                previous_receipt = existing_receipt.digest
            placeholder = RollbackWitnessReceipt(
                self._pubkey,
                unsigned.ledger_id,
                generation,
                checkpoint.digest,
                previous_receipt,
                bytes(_SIG),
            )
            receipt = RollbackWitnessReceipt(
                placeholder.witness_pubkey,
                placeholder.ledger_id,
                placeholder.generation,
                placeholder.checkpoint_digest,
                placeholder.previous_receipt_digest,
                sign(placeholder.signing_message, self._secret),
            )
            conn.execute(
                """
                INSERT INTO ledgers(ledger_id, participant_pubkey, generation,
                                    event_count, audit_chain_head, checkpoint, receipt)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ledger_id) DO UPDATE SET
                    generation=excluded.generation,
                    event_count=excluded.event_count,
                    audit_chain_head=excluded.audit_chain_head,
                    checkpoint=excluded.checkpoint,
                    receipt=excluded.receipt
                """,
                (
                    unsigned.ledger_id,
                    unsigned.participant_pubkey,
                    generation,
                    unsigned.event_count,
                    unsigned.audit_chain_head,
                    checkpoint.encoded,
                    receipt.encoded,
                ),
            )
            conn.execute("COMMIT")
            return receipt
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()


def anchor_ledger_at_all_witnesses(
    ledger: DurableSlotLedger,
    *,
    participant_secret: int,
    witnesses: Sequence[RollbackWitnessClient],
) -> tuple[RollbackWitnessReceipt, ...]:
    if not witnesses:
        raise RollbackWitnessError("at least one independent rollback witness is required")
    witness_keys = tuple(bytes(witness.witness_pubkey) for witness in witnesses)
    if len(set(witness_keys)) != len(witness_keys):
        raise RollbackWitnessError("rollback witness identities are duplicated")
    checkpoint = SignedLedgerCheckpoint.create(ledger, participant_secret=participant_secret)
    receipts = tuple(witness.anchor(checkpoint) for witness in witnesses)
    if any(
        not receipt.verify()
        or receipt.ledger_id != checkpoint.unsigned.ledger_id
        or receipt.checkpoint_digest != checkpoint.digest
        or receipt.witness_pubkey != witness.witness_pubkey
        for witness, receipt in zip(witnesses, receipts, strict=True)
    ):
        raise RollbackWitnessError("rollback witness returned an invalid receipt")
    return receipts
