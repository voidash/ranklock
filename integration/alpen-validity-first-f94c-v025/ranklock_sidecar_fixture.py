#!/usr/bin/env python3
"""Deterministic fixture producer for the Strata ↔ RankLock file handoff.

This is test/setup plumbing, not the positive-predicate evaluator.  Production
RankLock writes the same commitment and unlock files only after its proof
verification succeeds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Final

P: Final[int] = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
DOMAIN: Final[bytes] = b"strata-ranklock-validity-first-fixture-v1\x00"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def valid_xonly(encoded: bytes) -> bool:
    if len(encoded) != 32:
        return False
    x = int.from_bytes(encoded, "big")
    if x >= P:
        return False
    rhs = (pow(x, 3, P) + 7) % P
    return rhs == 0 or pow(rhs, (P - 1) // 2, P) == 1


def setup_stem(owner: int, deposit: int, game: int, watchtower: int) -> str:
    return f"owner{owner}-deposit{deposit}-game{game}-watchtower{watchtower}"


def unlock_stem(bridge_txid: str, counterproof_txid: str, ack_txid: str) -> str:
    return f"bridge{bridge_txid}-counterproof{counterproof_txid}-ack{ack_txid}"


def context_bytes(args: argparse.Namespace) -> bytes:
    return (
        args.owner.to_bytes(4, "little")
        + args.deposit.to_bytes(4, "little")
        + args.game.to_bytes(4, "little")
        + args.watchtower.to_bytes(4, "little")
    )


def derive_setup(args: argparse.Namespace) -> tuple[bytes, bytes, int]:
    seed = bytes.fromhex(args.seed) if args.seed else b"ranklock-fixture-seed"
    ctx = context_bytes(args)
    for counter in range(1 << 32):
        preimage = sha256(DOMAIN + seed + ctx + counter.to_bytes(4, "big"))
        commitment = sha256(preimage)
        if valid_xonly(commitment):
            return preimage, commitment, counter
    raise RuntimeError("failed to rejection-sample an x-only-compatible commitment")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def cmd_setup(args: argparse.Namespace) -> None:
    preimage, commitment, counter = derive_setup(args)
    stem = setup_stem(args.owner, args.deposit, args.game, args.watchtower)
    root = Path(args.root)
    commitment_path = root / "setup" / f"{stem}.commitment"
    secret_path = root / "fixture-secrets" / f"{stem}.preimage"
    manifest_path = root / "fixture-secrets" / f"{stem}.json"
    atomic_write(commitment_path, commitment)
    atomic_write(secret_path, preimage)
    atomic_write(
        manifest_path,
        json.dumps(
            {
                "schema": "strata-ranklock-sidecar-fixture-v1",
                "deposit_index": args.deposit,
                "graph_owner": args.owner,
                "game_index": args.game,
                "watchtower": args.watchtower,
                "counter": counter,
                "preimage_sha256": commitment.hex(),
                "commitment_is_valid_xonly": valid_xonly(commitment),
            },
            sort_keys=True,
            indent=2,
        ).encode()
        + b"\n",
    )
    print(commitment_path)


def cmd_unlock(args: argparse.Namespace) -> None:
    root = Path(args.root)
    setup = setup_stem(args.owner, args.deposit, args.game, args.watchtower)
    preimage = (root / "fixture-secrets" / f"{setup}.preimage").read_bytes()
    if len(preimage) != 32:
        raise ValueError("stored fixture preimage is malformed")
    stem = unlock_stem(args.bridge_txid, args.counterproof_txid, args.ack_txid)
    path = root / "unlock" / f"{stem}.preimage"
    if args.mode == "valid":
        data = preimage
    elif args.mode == "wrong":
        data = bytes([preimage[0] ^ 1]) + preimage[1:]
    elif args.mode == "malformed":
        data = preimage[:-1]
    else:  # pragma: no cover
        raise AssertionError(args.mode)
    atomic_write(path, data)
    print(path)


def add_setup_context(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", required=True)
    parser.add_argument("--deposit", required=True, type=_u32, help="graph deposit index")
    parser.add_argument("--owner", required=True, type=_u32)
    parser.add_argument("--game", required=True, type=_u32)
    parser.add_argument("--watchtower", required=True, type=_u32)


def _txid(value: str, label: str = "txid") -> str:
    if len(value) != 64:
        raise argparse.ArgumentTypeError(f"{label} txid must be 64 hex characters")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{label} txid is not hex") from exc
    return value.lower()


def _u32(value: str) -> int:
    parsed = int(value)
    if not 0 <= parsed < 2**32:
        raise argparse.ArgumentTypeError("value must fit u32")
    return parsed


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser()
    sub = top.add_subparsers(dest="command", required=True)

    setup = sub.add_parser("setup", help="write setup commitment and retained fixture secret")
    add_setup_context(setup)
    setup.add_argument("--seed", help="hex seed; deterministic default when omitted")
    setup.set_defaults(func=cmd_setup)

    unlock = sub.add_parser("unlock", help="write valid/wrong/malformed concrete unlock")
    add_setup_context(unlock)
    unlock.add_argument("--bridge-txid", required=True, type=lambda x: _txid(x, "bridge"))
    unlock.add_argument(
        "--counterproof-txid", required=True, type=lambda x: _txid(x, "counterproof")
    )
    unlock.add_argument("--ack-txid", required=True, type=lambda x: _txid(x, "ack"))
    unlock.add_argument("--mode", choices=("valid", "wrong", "malformed"), default="valid")
    unlock.set_defaults(func=cmd_unlock)
    return top


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
