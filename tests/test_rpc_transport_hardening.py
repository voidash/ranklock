from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

import pytest

from ranklock.release_sidecar import (
    BitcoinCoreRpcConfig,
    JsonRpcBitcoinCore,
    ReleaseSidecarError,
)
from ranklock.rollback_witness import HttpRollbackWitnessClient, RollbackWitnessError


class _Server:
    def __init__(self) -> None:
        self.mode = "valid"
        self.ids: list[int] = []
        self.capture_count = 0
        self.authorization_headers: list[str | None] = []
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                with owner._lock:
                    owner.authorization_headers.append(self.headers.get("Authorization"))
                if self.path == "/capture":
                    with owner._lock:
                        owner.capture_count += 1
                    self.send_response(200)
                    self.end_headers()
                    return
                if owner.mode == "redirect":
                    self.send_response(307)
                    self.send_header("Location", "/capture")
                    self.end_headers()
                    return
                if owner.mode == "oversize":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "4096")
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return
                payload = json.loads(raw.decode("utf-8"))
                if self.path == "/rpc":
                    request_id = int(payload["id"])
                    with owner._lock:
                        owner.ids.append(request_id)
                    response_id = request_id + 1 if owner.mode == "wrong-id" else request_id
                    body = json.dumps(
                        {"result": payload["method"], "error": None, "id": response_id}
                    ).encode()
                elif self.path == "/v1/latest":
                    body = json.dumps(
                        {
                            "receipt": None,
                            "error": None,
                            "witness_pubkey": "11" * 32,
                        }
                    ).encode()
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format: str, *args: object) -> None:
                del args

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


def test_bitcoin_core_rpc_checks_id_bounds_redirects_and_concurrency() -> None:
    server = _Server()
    try:
        client = JsonRpcBitcoinCore(
            BitcoinCoreRpcConfig(
                url=server.base_url + "/rpc",
                username="rpc-user",
                password="rpc-password",
                maximum_response_bytes=1024,
            )
        )
        assert client.call("getblockhash", 0) == "getblockhash"

        server.mode = "wrong-id"
        with pytest.raises(ReleaseSidecarError, match="response id mismatch"):
            client.call("getblockhash", 0)

        server.mode = "oversize"
        with pytest.raises(ReleaseSidecarError, match="size limit"):
            client.call("getblockhash", 0)

        server.mode = "redirect"
        with pytest.raises(ReleaseSidecarError, match="transport failed"):
            client.call("getblockhash", 0)
        assert server.capture_count == 0

        server.mode = "valid"
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = tuple(pool.map(lambda _: client.call("getblockcount"), range(24)))
        assert results == ("getblockcount",) * 24
        assert len(server.ids) == len(set(server.ids))
        assert all(header and header.startswith("Basic ") for header in server.authorization_headers)

        with pytest.raises(ReleaseSidecarError, match="method is malformed"):
            client.call("getblockhash\nInjected")
    finally:
        server.close()


def test_rollback_witness_http_client_checks_bounds_and_redirects() -> None:
    server = _Server()
    try:
        client = HttpRollbackWitnessClient(
            server.base_url,
            bytes.fromhex("11" * 32),
            bearer_token="secret-token",
            maximum_response_bytes=1024,
        )
        assert client.latest(bytes.fromhex("22" * 32)) is None

        server.mode = "oversize"
        with pytest.raises(RollbackWitnessError, match="size limit"):
            client.latest(bytes.fromhex("22" * 32))

        server.mode = "redirect"
        with pytest.raises(RollbackWitnessError, match="transport failed"):
            client.latest(bytes.fromhex("22" * 32))
        assert server.capture_count == 0
        assert all(header == "Bearer secret-token" for header in server.authorization_headers)
    finally:
        server.close()


def test_transport_urls_reject_embedded_credentials_and_query_material() -> None:
    with pytest.raises(RollbackWitnessError, match="credentials must not appear"):
        HttpRollbackWitnessClient(
            "http://user:password@127.0.0.1:1234",
            bytes.fromhex("11" * 32),
        )
    with pytest.raises(RollbackWitnessError, match="query or fragment"):
        HttpRollbackWitnessClient(
            "http://127.0.0.1:1234?token=secret",
            bytes.fromhex("11" * 32),
        )
