from __future__ import annotations

"""Restartable Bitcoin Core regtest node for scenario-based qualification.

``bitcoin_core_regtest.run_bitcoin_core_regtest`` runs one long happy-path
protocol trace.  The v0.25.2 acceptance matrix instead needs many independent
scenarios against a node whose lifecycle the scenario controls -- including
stopping and restarting it on the same datadir (CORE-029), building competing
branches (CORE-018..020), and recording raw RPC evidence per case.

This module owns only the node: start, RPC, restart, stop.  Protocol logic
stays in the scenario that uses it.

The node is deliberately started with ``-acceptnonstdtxn=0`` so standardness
is enforced: a transaction that only passes because policy checks were
disabled is not qualification evidence.
"""

from dataclasses import dataclass, field
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import time
from typing import Any
from urllib import request as urllib_request


class RegtestNodeError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def binary_sha256(path: str | os.PathLike[str]) -> str:
    digest = sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_bitcoind(bitcoind: str | os.PathLike[str]) -> str:
    candidate = str(bitcoind)
    resolved = candidate if Path(candidate).is_file() else shutil.which(candidate)
    if resolved is None:
        raise RegtestNodeError(f"bitcoind was not found: {candidate}")
    return resolved


@dataclass
class RpcCall:
    """One recorded JSON-RPC exchange, for per-case Bitcoin evidence."""

    method: str
    params: tuple[object, ...]
    result_digest: str
    error: str | None


class RegtestRpc:
    """Minimal authenticated JSON-RPC client that records what it called.

    Credentials are never recorded -- only method, parameters and a digest of
    the result -- so an evidence bundle can prove which calls were made
    without leaking the node's RPC password.
    """

    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url
        self._authorization = "Basic " + base64.b64encode(
            f"{user}:{password}".encode()
        ).decode()
        self.counter = 0
        self.calls: list[RpcCall] = []

    def call(self, method: str, *params: object) -> Any:
        self.counter += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": list(params)},
            separators=(",", ":"),
        ).encode()
        request = urllib_request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": self._authorization,
            },
        )
        try:
            with urllib_request.urlopen(request, timeout=60) as response:
                payload = json.loads(response.read())
        except Exception as exc:
            self.calls.append(RpcCall(method, tuple(params), "", str(exc)))
            raise RegtestNodeError(f"Bitcoin Core RPC {method} failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise RegtestNodeError(f"Bitcoin Core RPC {method} returned malformed data")
        if payload.get("error") is not None:
            message = json.dumps(payload["error"], sort_keys=True)
            self.calls.append(RpcCall(method, tuple(params), "", message))
            raise RegtestNodeError(f"Bitcoin Core RPC {method} failed: {message}")
        result = payload.get("result")
        self.calls.append(
            RpcCall(
                method,
                tuple(params),
                sha256(json.dumps(result, sort_keys=True, default=str).encode()).hexdigest(),
                None,
            )
        )
        return result

    def try_call(self, method: str, *params: object) -> tuple[bool, Any]:
        """Call ``method`` and report failure instead of raising.

        Negative scenarios expect RPC-level rejection; a raised exception
        there would be indistinguishable from harness breakage.
        """

        try:
            return True, self.call(method, *params)
        except RegtestNodeError as exc:
            return False, str(exc)


@dataclass
class RegtestNode:
    """A regtest ``bitcoind`` whose lifetime the caller controls."""

    bitcoind: str
    datadir: Path
    rpc_port: int
    p2p_port: int
    rpc_user: str
    rpc_password: str
    process: subprocess.Popen[bytes] | None = None
    rpc: RegtestRpc | None = None
    extra_args: tuple[str, ...] = ()
    restarts: int = field(default=0)

    @classmethod
    def create(
        cls,
        *,
        bitcoind: str | os.PathLike[str],
        root: str | os.PathLike[str],
        extra_args: tuple[str, ...] = (),
    ) -> "RegtestNode":
        executable = resolve_bitcoind(bitcoind)
        datadir = Path(root) / "node"
        datadir.mkdir(parents=True, exist_ok=True)
        return cls(
            bitcoind=executable,
            datadir=datadir,
            rpc_port=_free_port(),
            p2p_port=_free_port(),
            rpc_user="ranklock",
            rpc_password=secrets.token_hex(24),
            extra_args=tuple(extra_args),
        )

    @property
    def command(self) -> list[str]:
        return [
            self.bitcoind,
            f"-datadir={self.datadir}",
            "-regtest=1",
            "-server=1",
            "-listen=0",
            "-discover=0",
            "-dnsseed=0",
            "-txindex=1",
            "-fallbackfee=0.0001",
            "-persistmempool=0",
            # Standardness must stay enabled: a transaction that is only
            # accepted because policy was relaxed is not qualifying evidence.
            "-acceptnonstdtxn=0",
            f"-rpcport={self.rpc_port}",
            f"-port={self.p2p_port}",
            f"-rpcuser={self.rpc_user}",
            f"-rpcpassword={self.rpc_password}",
            "-printtoconsole=0",
            *self.extra_args,
        ]

    def start(self, *, timeout_seconds: float = 60.0) -> RegtestRpc:
        if self.process is not None:
            raise RegtestNodeError("regtest node is already running")
        self.process = subprocess.Popen(
            self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        rpc = RegtestRpc(f"http://127.0.0.1:{self.rpc_port}", self.rpc_user, self.rpc_password)
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                rpc.call("getnetworkinfo")
                break
            except RegtestNodeError:
                if self.process.poll() is not None:
                    stderr = b"" if self.process.stderr is None else self.process.stderr.read()
                    raise RegtestNodeError(
                        f"bitcoind exited during startup: {stderr.decode(errors='replace')}"
                    )
                if time.monotonic() >= deadline:
                    raise RegtestNodeError("Bitcoin Core RPC startup timed out")
                time.sleep(0.2)
        # Drop the startup probe so recorded calls reflect scenario work only.
        rpc.calls.clear()
        self.rpc = rpc
        return rpc

    def stop(self, *, timeout_seconds: float = 60.0) -> None:
        if self.process is None:
            return
        try:
            if self.rpc is not None:
                try:
                    self.rpc.call("stop")
                except RegtestNodeError:
                    self.process.terminate()
            else:
                self.process.terminate()
            self.process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=timeout_seconds)
        finally:
            for stream in (self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()
            self.process = None
            self.rpc = None

    def restart(self, *, timeout_seconds: float = 60.0) -> RegtestRpc:
        """Stop and restart on the same datadir, preserving chain state.

        This is the CORE-029 primitive: a clean shutdown followed by a restart
        must not duplicate a release or regress persisted state.
        """

        self.stop(timeout_seconds=timeout_seconds)
        self.restarts += 1
        # Ports are re-picked: the previous listener may still be in TIME_WAIT.
        self.rpc_port = _free_port()
        self.p2p_port = _free_port()
        return self.start(timeout_seconds=timeout_seconds)

    def version(self) -> tuple[int, str]:
        if self.rpc is None:
            raise RegtestNodeError("regtest node is not running")
        info = self.rpc.call("getnetworkinfo")
        if not isinstance(info, dict):
            raise RegtestNodeError("getnetworkinfo returned malformed data")
        number = int(info.get("version", -1))
        return number, str(info.get("subversion", number))

    @property
    def debug_log_sha256(self) -> str | None:
        log = self.datadir / "regtest" / "debug.log"
        return binary_sha256(log) if log.is_file() else None

    def __enter__(self) -> "RegtestNode":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()
