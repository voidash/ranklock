from __future__ import annotations

"""Fail-closed participant release sidecar with Bitcoin Core verification."""

from dataclasses import dataclass
import base64
import json
import os
from pathlib import Path
import stat
import ssl
import tempfile
import threading
from typing import Any, Protocol
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from .bitcoin_authorization import BitcoinAuthorizationBinding
from .committee_authorization import (
    CommitteeAuthorizationError,
    CommitteeAuthorizationRequest,
    CommitteeLabelGuide,
    ParticipantShareResponse,
    ParticipantSlotSecrets,
    SignedCommitteeActivation,
    prepare_participant_response,
)
from .durable_slot_ledger import DurableSlotLedger
from .private_sqlite import require_private_directory
from .bitcoin_witness_selection import (
    BitcoinWitnessSelectionError,
    SignedBitcoinWitnessPolicy,
    verify_request_matches_witness,
)
from .rollback_witness import (
    RollbackWitnessClient,
    RollbackWitnessError,
    RollbackWitnessReceipt,
    anchor_ledger_at_all_witnesses,
    require_rollback_witness_set,
)


class ReleaseSidecarError(RuntimeError):
    pass


class BitcoinCoreReader(Protocol):
    def call(self, method: str, *params: object) -> object: ...


class _NoRedirect(urllib_request.HTTPRedirectHandler):
    """Reject redirects so RPC credentials never cross an origin boundary."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True, slots=True)
class BitcoinCoreRpcConfig:
    url: str
    username: str | None = None
    password: str | None = None
    cookie_path: Path | None = None
    timeout_seconds: float = 30.0
    maximum_response_bytes: int = 8 * 1024 * 1024
    ca_file: Path | None = None
    client_cert_file: Path | None = None
    client_key_file: Path | None = None

    def __post_init__(self) -> None:
        parsed = urllib_parse.urlparse(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ReleaseSidecarError("Bitcoin Core RPC URL must be HTTP(S)")
        if parsed.username is not None or parsed.password is not None:
            raise ReleaseSidecarError("Bitcoin Core RPC credentials must not appear in the URL")
        if parsed.query or parsed.fragment:
            raise ReleaseSidecarError("Bitcoin Core RPC URL must not contain a query or fragment")
        loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if parsed.scheme != "https" and not loopback:
            raise ReleaseSidecarError("remote Bitcoin Core RPC requires HTTPS")
        if float(self.timeout_seconds) <= 0:
            raise ReleaseSidecarError("Bitcoin Core RPC timeout must be positive")
        if not 1024 <= int(self.maximum_response_bytes) <= 64 * 1024 * 1024:
            raise ReleaseSidecarError("Bitcoin Core RPC response limit is outside the safe range")
        if self.cookie_path is not None and (self.username is not None or self.password is not None):
            raise ReleaseSidecarError("Bitcoin Core cookie and explicit credentials are mutually exclusive")
        if (self.client_cert_file is None) != (self.client_key_file is None):
            raise ReleaseSidecarError(
                "Bitcoin Core client certificate and key must be supplied together"
            )
        if not loopback and (
            self.ca_file is None
            or self.client_cert_file is None
            or self.client_key_file is None
        ):
            raise ReleaseSidecarError(
                "remote Bitcoin Core RPC requires a pinned CA and mutual TLS credentials"
            )
        for value, name, private in (
            (self.ca_file, "Bitcoin Core CA file", False),
            (self.client_cert_file, "Bitcoin Core client certificate", False),
            (self.client_key_file, "Bitcoin Core client key", True),
        ):
            if value is None:
                continue
            path = Path(value)
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise ReleaseSidecarError(f"{name} is absent: {value}") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ReleaseSidecarError(f"{name} must be a regular non-symlink file")
            if private:
                if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
                    raise ReleaseSidecarError(f"{name} must be owned by the sidecar user")
                if stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise ReleaseSidecarError(f"{name} permissions must be 0600 or stricter")

    def tls_context(self) -> ssl.SSLContext | None:
        parsed = urllib_parse.urlparse(self.url)
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

    def credentials(self) -> tuple[str, str]:
        if self.cookie_path is not None:
            raw = read_secret_file_secure(self.cookie_path, maximum_bytes=4096).decode(
                "utf-8", "strict"
            ).strip()
            if ":" not in raw:
                raise ReleaseSidecarError("Bitcoin Core cookie is malformed")
            username, password = raw.split(":", 1)
            if not username or not password or ":" in username:
                raise ReleaseSidecarError("Bitcoin Core cookie is malformed")
            return username, password
        if self.username is None or self.password is None:
            raise ReleaseSidecarError("Bitcoin Core RPC credentials are absent")
        if not self.username or not self.password or ":" in self.username:
            raise ReleaseSidecarError("Bitcoin Core RPC credentials are malformed")
        return self.username, self.password


class JsonRpcBitcoinCore:
    def __init__(self, config: BitcoinCoreRpcConfig) -> None:
        self.config = config
        self._request_id = 0
        self._request_lock = threading.Lock()
        handlers: list[object] = [_NoRedirect()]
        tls_context = config.tls_context()
        if tls_context is not None:
            handlers.append(urllib_request.HTTPSHandler(context=tls_context))
        self._opener = urllib_request.build_opener(*handlers)

    def _next_request_id(self) -> int:
        with self._request_lock:
            self._request_id += 1
            return self._request_id

    def call(self, method: str, *params: object) -> object:
        method = str(method)
        if not method or len(method) > 128 or not method.isascii() or any(
            character.isspace() or ord(character) < 0x20 for character in method
        ):
            raise ReleaseSidecarError("Bitcoin Core RPC method is malformed")
        request_id = self._next_request_id()
        username, password = self.config.credentials()
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": list(params),
            },
            separators=(",", ":"),
        ).encode()
        rpc_request = urllib_request.Request(
            self.config.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Basic "
                + base64.b64encode(f"{username}:{password}".encode()).decode(),
            },
        )
        try:
            with self._opener.open(
                rpc_request, timeout=float(self.config.timeout_seconds)
            ) as response:
                if getattr(response, "status", 200) != 200:
                    raise ReleaseSidecarError(
                        f"Bitcoin Core RPC returned HTTP {response.status}"
                    )
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > int(
                    self.config.maximum_response_bytes
                ):
                    raise ReleaseSidecarError("Bitcoin Core RPC response exceeds size limit")
                raw = response.read(int(self.config.maximum_response_bytes) + 1)
                if len(raw) > int(self.config.maximum_response_bytes):
                    raise ReleaseSidecarError("Bitcoin Core RPC response exceeds size limit")
                payload = json.loads(raw.decode("utf-8", "strict"))
        except ReleaseSidecarError:
            raise
        except Exception as exc:  # pragma: no cover - network integration
            raise ReleaseSidecarError(f"Bitcoin Core RPC transport failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise ReleaseSidecarError(f"Bitcoin Core RPC {method} returned a non-object")
        if payload.get("id") != request_id:
            raise ReleaseSidecarError("Bitcoin Core RPC response id mismatch")
        if payload.get("error") is not None:
            raise ReleaseSidecarError(f"Bitcoin Core RPC {method} failed: {payload!r}")
        if "result" not in payload:
            raise ReleaseSidecarError("Bitcoin Core RPC response omitted result")
        return payload["result"]


@dataclass(frozen=True, slots=True)
class ConfirmedBitcoinObservation:
    txid: str
    wtxid: str
    block_hash: str
    confirmations: int
    block_height: int
    schema: str = "ranklock-confirmed-bitcoin-observation-v1"


def verify_confirmed_bitcoin_binding(
    reader: BitcoinCoreReader,
    *,
    binding: BitcoinAuthorizationBinding,
    raw_transaction: bytes,
    block_hash: str,
    minimum_confirmations: int,
) -> ConfirmedBitcoinObservation:
    """Cross-check local parsing against Bitcoin Core's active-chain view."""

    minimum_confirmations = int(minimum_confirmations)
    if minimum_confirmations < 1:
        raise ReleaseSidecarError("minimum confirmations must be at least one")
    if len(block_hash) != 64:
        raise ReleaseSidecarError("block hash must be 64 hexadecimal characters")
    try:
        bytes.fromhex(block_hash)
    except ValueError as exc:
        raise ReleaseSidecarError("block hash is not hexadecimal") from exc
    if not binding.verify_raw_transaction(raw_transaction):
        raise ReleaseSidecarError("raw transaction does not match signed txid/wtxid binding")

    genesis = reader.call("getblockhash", 0)
    if not isinstance(genesis, str) or len(genesis) != 64:
        raise ReleaseSidecarError("Bitcoin Core returned a malformed genesis block hash")
    try:
        bytes.fromhex(genesis)
    except ValueError as exc:
        raise ReleaseSidecarError("Bitcoin Core genesis block hash is not hexadecimal") from exc
    if genesis.lower() != binding.chain_genesis_hash.hex():
        raise ReleaseSidecarError("Bitcoin Core chain genesis differs from authorization binding")

    txid_hex = binding.counterproof_txid.hex()
    wtxid_hex = binding.counterproof_wtxid.hex()
    result = reader.call("getrawtransaction", txid_hex, True, block_hash)
    if not isinstance(result, dict):
        raise ReleaseSidecarError("Bitcoin Core returned a malformed transaction object")
    required = {"hex", "txid", "hash", "confirmations", "blockhash"}
    if not required.issubset(result):
        raise ReleaseSidecarError("Bitcoin Core transaction result is incomplete")
    try:
        core_raw = bytes.fromhex(str(result["hex"]))
        confirmations = int(result["confirmations"])
    except (ValueError, TypeError) as exc:
        raise ReleaseSidecarError("Bitcoin Core transaction result is malformed") from exc
    if core_raw != bytes(raw_transaction):
        raise ReleaseSidecarError("Bitcoin Core raw transaction differs byte-for-byte")
    if str(result["txid"]).lower() != txid_hex:
        raise ReleaseSidecarError("Bitcoin Core txid differs from authorization binding")
    if str(result["hash"]).lower() != wtxid_hex:
        raise ReleaseSidecarError("Bitcoin Core wtxid differs from authorization binding")
    if str(result["blockhash"]).lower() != block_hash.lower():
        raise ReleaseSidecarError("Bitcoin Core reports another containing block")
    if confirmations < minimum_confirmations:
        raise ReleaseSidecarError(
            f"counterproof has {confirmations} confirmations; need {minimum_confirmations}"
        )

    header = reader.call("getblockheader", block_hash, True)
    if not isinstance(header, dict) or "height" not in header or "confirmations" not in header:
        raise ReleaseSidecarError("Bitcoin Core block-header result is incomplete")
    try:
        header_confirmations = int(header["confirmations"])
        height = int(header["height"])
    except (ValueError, TypeError) as exc:
        raise ReleaseSidecarError("Bitcoin Core block-header result is malformed") from exc
    if header_confirmations < minimum_confirmations or header_confirmations < 0:
        raise ReleaseSidecarError("containing block is not sufficiently buried in active chain")
    if confirmations != header_confirmations:
        # Core normally reports the same depth for a transaction and its block.
        # Reject rather than guessing during a concurrent reorg/RPC race.
        raise ReleaseSidecarError("Bitcoin Core confirmation views changed during release")
    return ConfirmedBitcoinObservation(
        txid=txid_hex,
        wtxid=wtxid_hex,
        block_hash=block_hash.lower(),
        confirmations=confirmations,
        block_height=height,
    )


def _secure_secret_stat(path: str | os.PathLike[str]) -> os.stat_result:
    secret_path = Path(path)
    try:
        metadata = os.lstat(secret_path)
    except FileNotFoundError as exc:
        raise ReleaseSidecarError(f"secret file is absent: {secret_path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ReleaseSidecarError("secret file must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseSidecarError("secret path must be a regular file")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise ReleaseSidecarError("secret file must be owned by the sidecar user")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077:
        raise ReleaseSidecarError(
            f"secret file permissions must exclude group/other access, found {mode:o}"
        )
    return metadata


def require_secret_file_permissions(path: str | os.PathLike[str]) -> None:
    _secure_secret_stat(path)


def read_secret_file_secure(
    path: str | os.PathLike[str], *, maximum_bytes: int = 64 * 1024 * 1024
) -> bytes:
    """Read one owner-only regular file without following a final symlink."""

    maximum_bytes = int(maximum_bytes)
    if maximum_bytes <= 0:
        raise ReleaseSidecarError("secret-file size limit must be positive")
    expected = _secure_secret_stat(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.fspath(path), flags)
    except OSError as exc:
        raise ReleaseSidecarError(f"could not open secret file safely: {exc}") from exc
    try:
        actual = os.fstat(fd)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise ReleaseSidecarError("secret file changed during secure open")
        if not stat.S_ISREG(actual.st_mode):
            raise ReleaseSidecarError("secret path stopped being a regular file")
        if actual.st_size > maximum_bytes:
            raise ReleaseSidecarError("secret file exceeds configured size limit")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(fd, min(1 << 20, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum_bytes:
            raise ReleaseSidecarError("secret file exceeds configured size limit")
        return data
    finally:
        os.close(fd)


def _read_existing_output(destination: Path) -> bytes | None:
    try:
        fd = os.open(
            destination,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReleaseSidecarError(f"could not inspect existing release output: {exc}") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReleaseSidecarError("release output must be a regular file")
        output = bytearray()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            output.extend(chunk)
        return bytes(output)
    finally:
        os.close(fd)


def atomic_write_once(path: str | os.PathLike[str], data: bytes, *, mode: int = 0o600) -> bool:
    """Create one response without overwriting a concurrent writer.

    A temporary inode is fsynced and then hard-linked into the destination name.
    ``link(2)`` fails atomically when another process won the race.  Exact bytes
    are idempotent; different bytes are a permanent conflict.
    """

    destination = Path(path)
    existing = _read_existing_output(destination)
    if existing is not None:
        if existing == bytes(data):
            return False
        raise ReleaseSidecarError("release output already exists with different bytes")
    parent_existed = destination.parent.exists()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not parent_existed:
        os.chmod(destination.parent, 0o700)
    require_private_directory(
        destination.parent, error_type=ReleaseSidecarError, label="release output"
    )
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(bytes(data))
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination, follow_symlinks=False)
            created = True
        except FileExistsError:
            existing = _read_existing_output(destination)
            if existing == bytes(data):
                created = False
            elif existing is None:  # pragma: no cover - adversarial racing unlink
                raise ReleaseSidecarError("release output raced with an unlink")
            else:
                raise ReleaseSidecarError("release output already exists with different bytes")
        directory_fd = os.open(
            destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return created
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)


@dataclass(slots=True)
class ParticipantReleaseSidecar:
    activation: SignedCommitteeActivation
    label_guide: CommitteeLabelGuide
    participant: ParticipantSlotSecrets
    ledger: DurableSlotLedger
    bitcoin_core: BitcoinCoreReader
    minimum_confirmations: int
    rollback_witnesses: tuple[RollbackWitnessClient, ...]
    witness_policy: SignedBitcoinWitnessPolicy

    def __post_init__(self) -> None:
        if not self.activation.verify():
            raise ReleaseSidecarError("committee activation failed verification")
        unsigned = self.activation.unsigned
        if (
            self.label_guide.context_digest != self.activation.unsigned.context_digest
            or self.label_guide.slot_id != self.activation.unsigned.slot_id
            or self.label_guide.digest != self.activation.unsigned.guide_digest
        ):
            raise ReleaseSidecarError("label guide is for another activation")
        if self.participant.context_digest != self.activation.unsigned.context_digest:
            raise ReleaseSidecarError("participant secrets are for another activation context")
        if self.ledger.context_digest != self.activation.unsigned.context_digest:
            raise ReleaseSidecarError("durable ledger is for another activation context")
        if int(self.minimum_confirmations) < int(unsigned.minimum_confirmations):
            raise ReleaseSidecarError(
                "configured confirmation depth is below the signed activation minimum"
            )
        if not self.witness_policy.verify(self.activation):
            raise ReleaseSidecarError("Bitcoin witness-selection policy failed committee verification")
        try:
            require_rollback_witness_set(
                self.rollback_witnesses,
                expected_digest=self.activation.unsigned.rollback_witness_set_digest,
            )
            anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant.participant_secret,
                witnesses=self.rollback_witnesses,
            )
        except RollbackWitnessError as exc:
            raise ReleaseSidecarError(f"rollback-witness bootstrap failed: {exc}") from exc

    def issue(
        self,
        *,
        request: CommitteeAuthorizationRequest,
        raw_transaction: bytes,
        block_hash: str,
        output_path: str | os.PathLike[str],
    ) -> tuple[
        ParticipantShareResponse,
        ConfirmedBitcoinObservation,
        tuple[RollbackWitnessReceipt, ...],
        bool,
    ]:
        try:
            verify_request_matches_witness(
                request,
                raw_transaction=raw_transaction,
                policy=self.witness_policy,
                activation=self.activation,
            )
        except BitcoinWitnessSelectionError as exc:
            raise ReleaseSidecarError(f"Bitcoin witness selection failed: {exc}") from exc
        observation = verify_confirmed_bitcoin_binding(
            self.bitcoin_core,
            binding=request.bitcoin_binding,
            raw_transaction=raw_transaction,
            block_hash=block_hash,
            minimum_confirmations=self.minimum_confirmations,
        )
        try:
            response = prepare_participant_response(
                activation=self.activation,
                request=request,
                observed_raw_transaction=raw_transaction,
                participant=self.participant,
                guide=self.label_guide,
                ledger=self.ledger,
            )
        except CommitteeAuthorizationError as exc:
            raise ReleaseSidecarError(str(exc)) from exc

        self.ledger.record_chain_observation(
            request.slot_id,
            event_type="confirmed",
            block_hash=bytes.fromhex(observation.block_hash),
            height=observation.block_height,
        )
        try:
            anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant.participant_secret,
                witnesses=self.rollback_witnesses,
            )
        except RollbackWitnessError as exc:
            # The slot is already burned.  Fail closed and emit no share bytes.
            raise ReleaseSidecarError(f"rollback-witness anchor failed: {exc}") from exc

        # Re-read Core after the potentially slow witness anchoring step.  A
        # change here burns the slot but never emits its label shares.
        try:
            final_observation = verify_confirmed_bitcoin_binding(
                self.bitcoin_core,
                binding=request.bitcoin_binding,
                raw_transaction=raw_transaction,
                block_hash=block_hash,
                minimum_confirmations=self.minimum_confirmations,
            )
            verify_request_matches_witness(
                request,
                raw_transaction=raw_transaction,
                policy=self.witness_policy,
                activation=self.activation,
            )
            if (
                final_observation.txid != observation.txid
                or final_observation.wtxid != observation.wtxid
                or final_observation.block_hash != observation.block_hash
                or final_observation.block_height != observation.block_height
            ):
                raise ReleaseSidecarError(
                    "Bitcoin Core inclusion changed while authorizing the release"
                )
        except Exception as exc:
            try:
                self.ledger.finalize(request.slot_id, outcome="abort")
                anchor_ledger_at_all_witnesses(
                    self.ledger,
                    participant_secret=self.participant.participant_secret,
                    witnesses=self.rollback_witnesses,
                )
            except Exception as recovery_exc:
                raise ReleaseSidecarError(
                    "Bitcoin recheck failed and abort/rollback-witness "
                    "recovery also failed"
                ) from ExceptionGroup(
                    "release-sidecar primary and fail-closed recovery failures",
                    [exc, recovery_exc],
                )
            if isinstance(exc, ReleaseSidecarError):
                raise
            raise ReleaseSidecarError(
                f"Bitcoin recheck failed after durable burn: {exc}"
            ) from exc

        self.ledger.finalize(request.slot_id, outcome="success")
        try:
            receipts = anchor_ledger_at_all_witnesses(
                self.ledger,
                participant_secret=self.participant.participant_secret,
                witnesses=self.rollback_witnesses,
            )
        except RollbackWitnessError as exc:
            # Exact replay can finish this terminal anchor later.  The response
            # is still private because the output file has not been created.
            raise ReleaseSidecarError(
                f"terminal rollback-witness anchor failed: {exc}"
            ) from exc
        created = atomic_write_once(output_path, response.compact_bytes)
        return response, final_observation, receipts, created
