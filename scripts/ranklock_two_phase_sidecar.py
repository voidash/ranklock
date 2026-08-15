#!/usr/bin/env python3
from __future__ import annotations

"""Production-shaped CLI for RankLock's two-phase participant sidecar.

Phase one emits selected input-label shares only.  Phase two emits the program
seed share only after the exact witness transaction is stable in Bitcoin Core
and every configured rollback witness has accepted the monotonic ledger state.
"""

import argparse
import json
from pathlib import Path

from ranklock.authorization_transaction_plan import AuthorizationTransactionPlan
from ranklock.bitcoin_witness_selection import SignedBitcoinWitnessPolicy
from ranklock.committee_authorization import (
    CommitteeAuthorizationRequest,
    ParticipantSlotSecrets,
    SignedCommitteeActivation,
)
from ranklock.durable_slot_ledger import DurableSlotLedger
from ranklock.release_sidecar import (
    BitcoinCoreRpcConfig,
    JsonRpcBitcoinCore,
    read_secret_file_secure,
    require_secret_file_permissions,
)
from ranklock.rollback_witness import HttpRollbackWitnessClient
from ranklock.two_phase_authorization import WitnessPreauthorizationRequest
from ranklock.two_phase_sidecar import TwoPhaseParticipantSidecar


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--transaction-plan", type=Path, required=True)
    parser.add_argument("--participant-secrets", type=Path, required=True)
    parser.add_argument("--witness-policy", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--slot-count", type=int, required=True)
    parser.add_argument("--preauthorization", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--rollback-witness-config",
        type=Path,
        required=True,
        help="JSON configuration for every signed rollback-witness identity",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Run one phase of a crash-durable RankLock participant release"
    )
    commands = result.add_subparsers(dest="phase", required=True)
    phase_one = commands.add_parser("phase-one", help="burn and emit selected label shares")
    _common(phase_one)

    phase_two = commands.add_parser(
        "phase-two", help="confirm Bitcoin witness and emit only the program-seed share"
    )
    _common(phase_two)
    phase_two.add_argument("--confirmation-request", type=Path, required=True)
    phase_two.add_argument("--raw-transaction", type=Path, required=True)
    phase_two.add_argument("--block-hash", required=True)
    phase_two.add_argument("--minimum-confirmations", type=int, default=6)
    phase_two.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    phase_two.add_argument("--rpc-ca", type=Path)
    phase_two.add_argument("--rpc-client-cert", type=Path)
    phase_two.add_argument("--rpc-client-key", type=Path)
    credentials = phase_two.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--rpc-cookie", type=Path)
    credentials.add_argument("--rpc-user")
    phase_two.add_argument("--rpc-password")
    return result


def _rollback_witnesses(path: Path) -> tuple[HttpRollbackWitnessClient, ...]:
    configuration = json.loads(path.read_text())
    if not isinstance(configuration, dict) or not isinstance(
        configuration.get("witnesses"), list
    ):
        raise SystemExit("rollback-witness config must contain a witnesses list")
    witnesses: list[HttpRollbackWitnessClient] = []
    for row in configuration["witnesses"]:
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
        witnesses.append(
            HttpRollbackWitnessClient(
                base_url=str(row["url"]),
                configured_witness_pubkey=bytes.fromhex(str(row["pubkey"])),
                bearer_token=token,
                timeout_seconds=float(row.get("timeout_seconds", 10.0)),
                maximum_response_bytes=int(row.get("maximum_response_bytes", 1024 * 1024)),
                ca_file=None if row.get("ca_file") is None else Path(str(row["ca_file"])),
                client_cert_file=None
                if row.get("client_cert_file") is None
                else Path(str(row["client_cert_file"])),
                client_key_file=None if client_key is None else Path(str(client_key)),
            )
        )
    if not witnesses:
        raise SystemExit("at least one rollback witness is required")
    return tuple(witnesses)


def _load(args: argparse.Namespace):
    require_secret_file_permissions(args.participant_secrets)
    activation = SignedCommitteeActivation.parse_compact(args.activation.read_bytes())
    plan = AuthorizationTransactionPlan.parse(args.transaction_plan.read_bytes())
    participant = ParticipantSlotSecrets.parse_secret_bytes(
        read_secret_file_secure(args.participant_secrets)
    )
    witness_policy = SignedBitcoinWitnessPolicy.parse_compact(
        args.witness_policy.read_bytes()
    )
    preauthorization = WitnessPreauthorizationRequest.parse_compact(
        args.preauthorization.read_bytes()
    )
    ledger = DurableSlotLedger(
        args.ledger,
        context_digest=activation.unsigned.context_digest,
        slot_count=args.slot_count,
    )
    return (
        activation,
        plan,
        participant,
        witness_policy,
        preauthorization,
        ledger,
        _rollback_witnesses(args.rollback_witness_config),
    )


def _rpc(args: argparse.Namespace) -> JsonRpcBitcoinCore:
    if args.rpc_user is not None and args.rpc_password is None:
        raise SystemExit("--rpc-password is required with --rpc-user")
    if (args.rpc_client_cert is None) != (args.rpc_client_key is None):
        raise SystemExit("--rpc-client-cert and --rpc-client-key must be supplied together")
    if args.rpc_client_key is not None:
        require_secret_file_permissions(args.rpc_client_key)
    return JsonRpcBitcoinCore(
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


def main() -> None:
    args = parser().parse_args()
    (
        activation,
        plan,
        participant,
        witness_policy,
        preauthorization,
        ledger,
        witnesses,
    ) = _load(args)
    rpc = _rpc(args) if args.phase == "phase-two" else None
    sidecar = TwoPhaseParticipantSidecar(
        activation=activation,
        plan=plan,
        witness_policy=witness_policy,
        participant=participant,
        ledger=ledger,
        rollback_witnesses=witnesses,
        bitcoin_core=rpc,
        minimum_confirmations=(args.minimum_confirmations if args.phase == "phase-two" else 1),
    )

    if args.phase == "phase-one":
        response, receipts, created = sidecar.issue_witness_shares(
            preauthorization=preauthorization,
            output_path=args.output,
        )
        result = {
            "schema": "ranklock-two-phase-sidecar-phase-one-result-v1",
            "phase": "phase-one",
            "slot_id": preauthorization.slot_id,
            "participant_index": response.participant_index,
            "preauthorization_digest": preauthorization.digest.hex(),
            "response_bytes": len(response.compact_bytes),
            "response_created": created,
            "ledger_state": ledger.use(preauthorization.slot_id).state,
        }
    else:
        confirmation = CommitteeAuthorizationRequest.parse_compact(
            args.confirmation_request.read_bytes()
        )
        response, observation, receipts, created = sidecar.issue_seed_share(
            preauthorization=preauthorization,
            confirmation_request=confirmation,
            raw_transaction=args.raw_transaction.read_bytes(),
            block_hash=args.block_hash,
            output_path=args.output,
        )
        result = {
            "schema": "ranklock-two-phase-sidecar-phase-two-result-v1",
            "phase": "phase-two",
            "slot_id": preauthorization.slot_id,
            "participant_index": response.participant_index,
            "confirmation_digest": confirmation.digest.hex(),
            "response_bytes": len(response.compact_bytes),
            "response_created": created,
            "txid": observation.txid,
            "wtxid": observation.wtxid,
            "block_hash": observation.block_hash,
            "confirmations": observation.confirmations,
            "block_height": observation.block_height,
            "ledger_state": ledger.use(preauthorization.slot_id).state,
        }
    result["ledger_audit_chain_valid"] = ledger.verify_audit_chain()
    result["rollback_witness_receipts"] = [
        {
            "witness_pubkey": receipt.witness_pubkey.hex(),
            "generation": receipt.generation,
            "checkpoint_digest": receipt.checkpoint_digest.hex(),
            "receipt_digest": receipt.digest.hex(),
        }
        for receipt in receipts
    ]
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
