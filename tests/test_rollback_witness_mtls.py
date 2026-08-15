from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import threading

import pytest

from ranklock.durable_slot_ledger import DurableSlotLedger
from ranklock.rollback_witness import (
    HttpRollbackWitnessClient,
    RollbackWitnessError,
    SignedLedgerCheckpoint,
    SqliteRollbackWitness,
)


CONTEXT = bytes.fromhex("61" * 32)
PARTICIPANT_SECRET = 67
WITNESS_SECRET = 71


def _run(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["openssl", *args],
        cwd=cwd,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _certificates(root: Path) -> dict[str, Path]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required for the mTLS integration test")
    _run(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
        "-subj", "/CN=RankLock test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
        "-keyout", "ca.key", "-out", "ca.crt", cwd=root,
    )
    _run(
        "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
        "-keyout", "server.key", "-out", "server.csr", cwd=root,
    )
    (root / "server.ext").write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"
    )
    _run(
        "x509", "-req", "-days", "2", "-in", "server.csr",
        "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
        "-extfile", "server.ext", "-out", "server.crt", cwd=root,
    )
    _run(
        "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=ranklock-participant",
        "-keyout", "client.key", "-out", "client.csr", cwd=root,
    )
    (root / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
    _run(
        "x509", "-req", "-days", "2", "-in", "client.csr",
        "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
        "-extfile", "client.ext", "-out", "client.crt", cwd=root,
    )
    return {name: root / name for name in ("ca.crt", "server.crt", "server.key", "client.crt", "client.key")}


def test_remote_client_requires_pinned_mutual_tls() -> None:
    with pytest.raises(RollbackWitnessError, match="mutual TLS"):
        HttpRollbackWitnessClient(
            "https://witness.example.invalid",
            bytes.fromhex("11" * 32),
        )


def test_mutual_tls_transport_and_witness_identity(tmp_path: Path) -> None:
    certs = _certificates(tmp_path)
    backend = SqliteRollbackWitness(tmp_path / "witness.sqlite", witness_secret=WITNESS_SECRET)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            if self.path == "/v1/anchor":
                checkpoint = SignedLedgerCheckpoint.parse(
                    base64.b64decode(payload["checkpoint"], validate=True)
                )
                receipt = backend.anchor(checkpoint)
                body = json.dumps(
                    {
                        "receipt": base64.b64encode(receipt.encoded).decode(),
                        "witness_pubkey": backend.witness_pubkey.hex(),
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_error(404)

        def log_message(self, _format: str, *args: object) -> None:
            del args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certs["server.crt"], certs["server.key"])
    context.load_verify_locations(cafile=certs["ca.crt"])
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        ledger = DurableSlotLedger(
            tmp_path / "ledger.sqlite", context_digest=CONTEXT, slot_count=1
        )
        checkpoint = SignedLedgerCheckpoint.create(
            ledger, participant_secret=PARTICIPANT_SECRET
        )
        base_url = f"https://localhost:{server.server_port}"

        no_client_certificate = HttpRollbackWitnessClient(
            base_url,
            backend.witness_pubkey,
            ca_file=certs["ca.crt"],
        )
        with pytest.raises(RollbackWitnessError, match="transport failed"):
            no_client_certificate.anchor(checkpoint)

        client = HttpRollbackWitnessClient(
            base_url,
            backend.witness_pubkey,
            ca_file=certs["ca.crt"],
            client_cert_file=certs["client.crt"],
            client_key_file=certs["client.key"],
        )
        receipt = client.anchor(checkpoint)
        assert receipt.verify()
        assert receipt.witness_pubkey == backend.witness_pubkey

        wrong_identity = HttpRollbackWitnessClient(
            base_url,
            bytes.fromhex("22" * 32),
            ca_file=certs["ca.crt"],
            client_cert_file=certs["client.crt"],
            client_key_file=certs["client.key"],
        )
        with pytest.raises(RollbackWitnessError, match="unexpected identity"):
            wrong_identity.anchor(checkpoint)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
