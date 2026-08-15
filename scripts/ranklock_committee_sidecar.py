#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ranklock.committee_authorization import (
    CommitteeAuthorizationRequest,
    CommitteeLabelGuide,
    ParticipantSlotSecrets,
    SignedCommitteeActivation,
)
from ranklock.durable_slot_ledger import DurableSlotLedger
from ranklock.release_sidecar import (
    BitcoinCoreRpcConfig,
    JsonRpcBitcoinCore,
    ParticipantReleaseSidecar,
    read_secret_file_secure,
    require_secret_file_permissions,
)
from ranklock.rollback_witness import HttpRollbackWitnessClient
from ranklock.bitcoin_witness_selection import SignedBitcoinWitnessPolicy


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Legacy single-phase RankLock conformance sidecar (not for funded deployment)"
    )
    result.add_argument("--activation", type=Path, required=True)
    result.add_argument("--label-guide", type=Path, required=True)
    result.add_argument("--participant-secrets", type=Path, required=True)
    result.add_argument("--witness-policy", type=Path, required=True)
    result.add_argument("--ledger", type=Path, required=True)
    result.add_argument("--slot-count", type=int, required=True)
    result.add_argument("--request", type=Path, required=True)
    result.add_argument("--raw-transaction", type=Path, required=True)
    result.add_argument("--block-hash", required=True)
    result.add_argument("--minimum-confirmations", type=int, default=6)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument(
        "--allow-legacy-single-phase-conformance",
        action="store_true",
        help="explicitly acknowledge this compatibility path is not the funded two-phase protocol",
    )
    result.add_argument(
        "--rollback-witness-config",
        type=Path,
        required=True,
        help="JSON list of independent HTTPS witness URLs, public keys and optional token files",
    )
    result.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    result.add_argument("--rpc-ca", type=Path)
    result.add_argument("--rpc-client-cert", type=Path)
    result.add_argument("--rpc-client-key", type=Path)
    credentials = result.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--rpc-cookie", type=Path)
    credentials.add_argument("--rpc-user")
    result.add_argument("--rpc-password")
    return result


def main() -> None:
    args = parser().parse_args()
    if not args.allow_legacy_single_phase_conformance:
        raise SystemExit(
            "legacy single-phase sidecar is disabled; use ranklock_two_phase_sidecar.py"
        )
    if args.rpc_user is not None and args.rpc_password is None:
        raise SystemExit("--rpc-password is required with --rpc-user")
    require_secret_file_permissions(args.participant_secrets)
    if (args.rpc_client_cert is None) != (args.rpc_client_key is None):
        raise SystemExit("--rpc-client-cert and --rpc-client-key must be supplied together")
    if args.rpc_client_key is not None:
        require_secret_file_permissions(args.rpc_client_key)
    activation = SignedCommitteeActivation.parse_compact(args.activation.read_bytes())
    label_guide = CommitteeLabelGuide.parse_compact(args.label_guide.read_bytes())
    participant = ParticipantSlotSecrets.parse_secret_bytes(
        read_secret_file_secure(args.participant_secrets)
    )
    witness_policy = SignedBitcoinWitnessPolicy.parse_compact(args.witness_policy.read_bytes())
    request = CommitteeAuthorizationRequest.parse_compact(args.request.read_bytes())
    witness_config = json.loads(args.rollback_witness_config.read_text())
    if not isinstance(witness_config, dict) or not isinstance(witness_config.get("witnesses"), list):
        raise SystemExit("rollback-witness config must contain a witnesses list")
    rollback_witnesses = []
    for row in witness_config["witnesses"]:
        if not isinstance(row, dict):
            raise SystemExit("rollback-witness entry must be an object")
        token = None
        token_path = row.get("bearer_token_file")
        if token_path is not None:
            token_file = Path(str(token_path))
            require_secret_file_permissions(token_file)
            token = read_secret_file_secure(token_file, maximum_bytes=64 * 1024).decode(
                "utf-8", "strict"
            ).strip()
            if not token:
                raise SystemExit("rollback-witness bearer token is empty")
        client_key = row.get("client_key_file")
        if client_key is not None:
            require_secret_file_permissions(Path(str(client_key)))
        rollback_witnesses.append(
            HttpRollbackWitnessClient(
                base_url=str(row["url"]),
                configured_witness_pubkey=bytes.fromhex(str(row["pubkey"])),
                bearer_token=token,
                timeout_seconds=float(row.get("timeout_seconds", 10.0)),
                ca_file=None if row.get("ca_file") is None else Path(str(row["ca_file"])),
                client_cert_file=None
                if row.get("client_cert_file") is None
                else Path(str(row["client_cert_file"])),
                client_key_file=None if client_key is None else Path(str(client_key)),
            )
        )
    if not rollback_witnesses:
        raise SystemExit("at least one rollback witness is required")
    ledger = DurableSlotLedger(
        args.ledger,
        context_digest=activation.unsigned.context_digest,
        slot_count=args.slot_count,
    )
    rpc = JsonRpcBitcoinCore(
        BitcoinCoreRpcConfig(
            url=args.rpc_url,
            username=args.rpc_user,
            password=args.rpc_password,
            cookie_path=args.rpc_cookie,
            ca_file=args.rpc_ca,
            client_cert_file=args.rpc_client_cert,
            client_key_file=args.rpc_client_key,
        )
    )
    service = ParticipantReleaseSidecar(
        activation=activation,
        label_guide=label_guide,
        participant=participant,
        ledger=ledger,
        bitcoin_core=rpc,
        minimum_confirmations=args.minimum_confirmations,
        rollback_witnesses=tuple(rollback_witnesses),
        witness_policy=witness_policy,
    )
    response, observation, witness_receipts, created = service.issue(
        request=request,
        raw_transaction=args.raw_transaction.read_bytes(),
        block_hash=args.block_hash,
        output_path=args.output,
    )
    print(
        json.dumps(
            {
                "schema": "ranklock-v025-sidecar-result-v1",
                "participant_index": response.participant_index,
                "slot_id": request.slot_id,
                "request_digest": request.digest.hex(),
                "response_bytes": len(response.compact_bytes),
                "response_created": created,
                "txid": observation.txid,
                "wtxid": observation.wtxid,
                "block_hash": observation.block_hash,
                "confirmations": observation.confirmations,
                "block_height": observation.block_height,
                "ledger_audit_chain_valid": ledger.verify_audit_chain(),
                "rollback_witness_receipts": [
                    {
                        "witness_pubkey": receipt.witness_pubkey.hex(),
                        "generation": receipt.generation,
                        "checkpoint_digest": receipt.checkpoint_digest.hex(),
                        "receipt_digest": receipt.digest.hex(),
                    }
                    for receipt in witness_receipts
                ],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
