#!/usr/bin/env python3
from __future__ import annotations

"""Reference HTTP service for an independently hosted rollback witness.

Use TLS directly (`--tls-cert/--tls-key`) or place it behind an authenticated
mTLS reverse proxy.  Running this database on the same host/storage as the
release participant does not protect against snapshot rollback.
"""

import argparse
import base64
import hmac
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl

from ranklock.release_sidecar import require_secret_file_permissions
from ranklock.rollback_witness import (
    RollbackDetectedError,
    RollbackWitnessError,
    SignedLedgerCheckpoint,
    SqliteRollbackWitness,
)


def _read_scalar(path: Path) -> int:
    require_secret_file_permissions(path)
    raw = path.read_bytes().strip()
    try:
        if len(raw) == 32:
            value = int.from_bytes(raw, "big")
        else:
            value = int(raw.decode("ascii"), 16)
    except Exception as exc:
        raise SystemExit("witness secret file must be 32 raw bytes or hexadecimal") from exc
    if value == 0:
        raise SystemExit("witness secret must be nonzero")
    return value


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run an independent RankLock rollback witness")
    p.add_argument("--database", type=Path, required=True)
    p.add_argument("--secret-file", type=Path, required=True)
    p.add_argument("--bearer-token-file", type=Path)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=18450)
    p.add_argument("--tls-cert", type=Path)
    p.add_argument("--tls-key", type=Path)
    p.add_argument(
        "--client-ca",
        type=Path,
        help="CA certificate used to require and verify mTLS client certificates",
    )
    return p


def main() -> None:
    args = parser().parse_args()
    if (args.tls_cert is None) != (args.tls_key is None):
        raise SystemExit("--tls-cert and --tls-key must be supplied together")
    if args.client_ca is not None and args.tls_cert is None:
        raise SystemExit("--client-ca requires --tls-cert and --tls-key")
    if args.tls_key is not None:
        require_secret_file_permissions(args.tls_key)
    remote = args.host not in {"127.0.0.1", "localhost", "::1"}
    if remote and (args.tls_cert is None or args.client_ca is None):
        raise SystemExit("non-loopback witness service requires mutual TLS")
    witness = SqliteRollbackWitness(args.database, witness_secret=_read_scalar(args.secret_file))
    token: bytes | None = None
    if args.bearer_token_file is not None:
        require_secret_file_permissions(args.bearer_token_file)
        token = args.bearer_token_file.read_bytes().strip()
        if not token:
            raise SystemExit("bearer token file is empty")

    class Handler(BaseHTTPRequestHandler):
        server_version = "RankLockRollbackWitness/1"

        def _reply(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            if token is not None:
                supplied = self.headers.get("Authorization", "").encode()
                expected = b"Bearer " + token
                if not hmac.compare_digest(supplied, expected):
                    self._reply(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 1_000_000:
                    raise RollbackWitnessError("invalid request length")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise RollbackWitnessError("JSON request must be an object")
                if self.path == "/v1/anchor":
                    checkpoint = SignedLedgerCheckpoint.parse(
                        base64.b64decode(str(payload["checkpoint"]), validate=True)
                    )
                    receipt = witness.anchor(checkpoint)
                    self._reply(HTTPStatus.OK, {
                        "receipt": base64.b64encode(receipt.encoded).decode("ascii"),
                        "witness_pubkey": witness.witness_pubkey.hex(),
                    })
                elif self.path == "/v1/latest":
                    ledger_id = bytes.fromhex(str(payload["ledger_id"]))
                    receipt = witness.latest(ledger_id)
                    self._reply(HTTPStatus.OK, {
                        "receipt": None if receipt is None else base64.b64encode(receipt.encoded).decode("ascii"),
                        "witness_pubkey": witness.witness_pubkey.hex(),
                    })
                else:
                    self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
            except RollbackDetectedError as exc:
                self._reply(HTTPStatus.CONFLICT, {"error": str(exc)})
            except Exception as exc:
                self._reply(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        def log_message(self, fmt: str, *values: object) -> None:
            print("rollback-witness:", fmt % values, flush=True)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    if args.tls_cert is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        if args.client_ca is not None:
            context.load_verify_locations(cafile=args.client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({
        "schema": "ranklock-rollback-witness-server-v1",
        "host": args.host,
        "port": args.port,
        "tls": args.tls_cert is not None,
        "mutual_tls": args.client_ca is not None,
        "witness_pubkey": witness.witness_pubkey.hex(),
    }, sort_keys=True), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
