from __future__ import annotations

"""Real Bitcoin Core regtest for the v0.25 authorization boundary.

The harness exercises two sequential Taproot script-path transactions.  Their
stripped serializations and txids are committed before either proof point is
selected; each 512-item witness is populated only after its point is known.
For every slot, three independent committee sidecars then:

* derive the point from the exact Bitcoin witness;
* cross-check raw bytes, txid, wtxid, block and confirmations with Core;
* burn a SQLite/WAL slot before preparing any share;
* anchor the transition at three rollback witnesses;
* re-read Core before atomically publishing the response.

This module is executable only when a pinned ``bitcoind`` is supplied.  Unit
tests cover its deterministic builders but are not a substitute for this run.
"""

from dataclasses import dataclass
from hashlib import sha256
import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Any
from urllib import request as urllib_request

from .adaptive_sealing import program_seed_commitment
from .authorization_transaction_plan import build_authorization_transaction_plan
from .bip340 import N, lift_x, public_key, tagged_hash, tapleaf_hash
from .bitcoin_authorization import BitcoinAuthorizationBinding, parse_bitcoin_transaction
from .bitcoin_witness_selection import (
    SignedBitcoinWitnessPolicy,
    UnsignedBitcoinWitnessPolicy,
    WitnessItemRule,
    derive_witness_selection,
    selector_validation_tapscript,
    sign_authorization_witness,
    witness_control_hash,
    witness_rules_from_label_pairs,
    witness_script_hash,
)
from .bn254_real import CURVE_ORDER, G1, affine, multiply
from .authorized_labels import LabelCommitmentTree
from .bounded_mpc_embryo import slot_descriptor_from_artifact
from .committee_authorization import (
    dealer_split_fixture,
    issue_committee_request,
)
from .dfb_real import CoordinateInputEncoding
from .durable_slot_ledger import DurableSlotLedger
from .predicate_locked_hashlock import NUMS_INTERNAL_KEY
from .rollback_witness import SqliteRollbackWitness
from .two_phase_authorization import (
    ParticipantSeedResponse,
    ParticipantWitnessShareResponse,
    issue_witness_preauthorization_request,
    reconstruct_program_seed,
    reconstruct_witness_labels,
)
from .two_phase_sidecar import TwoPhaseParticipantSidecar
from .real_secp import G as SECP_G, add as secp_add, multiply as secp_multiply


class BitcoinCoreRegtestError(RuntimeError):
    pass


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3
INPUT_BITS = 256
EXPECTED_CORE_VERSION = 310100
EXPECTED_CORE_RELEASE = "31.1"
# Structural stand-in used while the precommitted transaction is being built.
# BIP341 script-path sighashes exclude the spending input's own witness, so
# replacing this with the real signature leaves the txid unchanged.
_PLACEHOLDER_SIGNATURE = bytes(64)


def _compact(value: int) -> bytes:
    value = int(value)
    if value < 0:
        raise BitcoinCoreRegtestError("negative CompactSize")
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise BitcoinCoreRegtestError("CompactSize exceeds u64")


def _convertbits(data: bytes, from_bits: int, to_bits: int, *, pad: bool = True) -> list[int]:
    accumulator = 0
    bits = 0
    result: list[int] = []
    maximum = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise BitcoinCoreRegtestError("invalid bech32 data value")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & maximum)
    if pad:
        if bits:
            result.append((accumulator << (to_bits - bits)) & maximum)
    elif bits >= from_bits or ((accumulator << (to_bits - bits)) & maximum):
        raise BitcoinCoreRegtestError("invalid bech32 padding")
    return result


def _bech32_polymod(values: list[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _segwit_address(hrp: str, version: int, program: bytes) -> str:
    if not 0 <= version <= 16 or not 2 <= len(program) <= 40:
        raise BitcoinCoreRegtestError("invalid witness program")
    data = [version] + _convertbits(program, 8, 5)
    constant = BECH32_CONST if version == 0 else BECH32M_CONST
    values = _bech32_hrp_expand(hrp) + data + [0] * 6
    polymod = _bech32_polymod(values) ^ constant
    checksum = [(polymod >> (5 * (5 - index))) & 31 for index in range(6)]
    return hrp + "1" + "".join(BECH32_CHARSET[value] for value in data + checksum)


def _taproot_script_output(script: bytes) -> tuple[bytes, bytes, str]:
    """Commit ``script`` under an unspendable NUMS internal key.

    Earlier revisions derived the internal key from a hard-coded secret, which
    left a key-path spend that bypassed the authorization script entirely.
    Reusing the shared ``NUMS_INTERNAL_KEY`` (the same nothing-up-my-sleeve key
    the validity-first connector uses) makes the committed tapleaf the only
    way to spend the output.
    """

    internal_key = NUMS_INTERNAL_KEY
    merkle_root = tapleaf_hash(script)
    internal_point = lift_x(int.from_bytes(internal_key, "big"))
    tweak = int.from_bytes(tagged_hash("TapTweak", internal_key + merkle_root), "big")
    if tweak >= N:
        raise BitcoinCoreRegtestError("Taproot tweak exceeds curve order")
    output = secp_add(internal_point, secp_multiply(SECP_G, tweak))
    if output is None:
        raise BitcoinCoreRegtestError("Taproot tweak produced infinity")
    parity = output[1] & 1
    output_key = output[0].to_bytes(32, "big")
    control = bytes((0xC0 | parity,)) + internal_key
    return b"\x51\x20" + output_key, control, _segwit_address("bcrt", 1, output_key)


def _serialize_transaction(
    *,
    previous_txid: bytes,
    previous_vout: int,
    output_value_sat: int,
    output_script: bytes,
    witness_stack: tuple[bytes, ...],
) -> bytes:
    if len(previous_txid) != 32:
        raise BitcoinCoreRegtestError("previous txid must be 32 bytes in RPC order")
    if not 0 <= int(previous_vout) < 2**32:
        raise BitcoinCoreRegtestError("previous vout does not fit u32")
    if not 0 <= int(output_value_sat) < 2**64:
        raise BitcoinCoreRegtestError("output value does not fit u64")
    version = (2).to_bytes(4, "little")
    txin = (
        previous_txid[::-1]
        + int(previous_vout).to_bytes(4, "little")
        + b"\x00"
        + bytes.fromhex("fdffffff")
    )
    txout = (
        int(output_value_sat).to_bytes(8, "little")
        + _compact(len(output_script))
        + bytes(output_script)
    )
    witness = _compact(len(witness_stack)) + b"".join(
        _compact(len(item)) + bytes(item) for item in witness_stack
    )
    return version + b"\x00\x01\x01" + txin + b"\x01" + txout + witness + bytes(4)


def _selector_material(
    point: object,
    *,
    input_bits: int = INPUT_BITS,
    slot_id: int = 0,
) -> tuple[tuple[WitnessItemRule, ...], tuple[bytes, ...]]:
    coordinates = affine(point)  # type: ignore[arg-type]
    if coordinates is None:
        raise BitcoinCoreRegtestError("selector point is infinity")
    values = (int(coordinates[0].n), int(coordinates[1].n))
    rules: list[WitnessItemRule] = []
    selected: list[bytes] = []
    for coordinate in (0, 1):
        for bit in range(input_bits):
            header = int(slot_id).to_bytes(4, "big") + bytes((coordinate,)) + bit.to_bytes(2, "big")
            zero = b"RL0" + header + sha256(b"zero" + header).digest() + bytes(22)
            one = b"RL1" + header + sha256(b"one" + header).digest() + bytes(22)
            if len(zero) != 64 or len(one) != 64:  # pragma: no cover - invariant
                raise AssertionError("selector item width drift")
            rules.append(
                WitnessItemRule.selector(
                    coordinate=coordinate,
                    bit=bit,
                    zero_item=zero,
                    one_item=one,
                )
            )
            selected.append((zero, one)[(values[coordinate] >> bit) & 1])
    return tuple(rules), tuple(selected)


def _tree_selector_material(
    tree: LabelCommitmentTree,
    point: object,
) -> tuple[tuple[WitnessItemRule, ...], tuple[bytes, ...]]:
    """Return the real DFB-label policy and selected labels for ``point``.

    ``_selector_material`` above is retained only as a small deterministic
    transaction-builder fixture.  The actual regtest path must commit and
    spend the 16-byte labels from the activated ``LabelCommitmentTree`` so the
    Bitcoin witness is exactly the same object reconstructed by phase one.
    """

    coordinates = affine(point)  # type: ignore[arg-type]
    if coordinates is None:
        raise BitcoinCoreRegtestError("selector point is infinity")
    values = (int(coordinates[0].n), int(coordinates[1].n))
    rules = witness_rules_from_label_pairs(
        tree.label_pairs,
        input_bits=tree.input_bits,
    )
    selected = tuple(
        tree.label_pairs[coordinate * tree.input_bits + bit][
            (values[coordinate] >> bit) & 1
        ]
        for coordinate in (0, 1)
        for bit in range(tree.input_bits)
    )
    if any(len(item) != 16 for item in selected):  # pragma: no cover - tree invariant
        raise BitcoinCoreRegtestError("activated DFB labels are not 16 bytes")
    return tuple(rules), selected


def _encoding(bits: int, offset: int) -> CoordinateInputEncoding:
    import numpy as np

    words = (np.arange(bits * 2, dtype=np.uint64) + np.uint64(offset)).reshape(bits, 2)
    return CoordinateInputEncoding(
        masks=words.copy(),
        labels=words.copy(),
        delta=0xD6E8FEB86659FD93A5A3564E27F88691 ^ offset,
    )


class _Rpc:
    def __init__(self, url: str, user: str, password: str) -> None:
        self.url = url
        self.authorization = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self.counter = 0

    def call(self, method: str, *params: object) -> Any:
        self.counter += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": self.counter, "method": method, "params": list(params)},
            separators=(",", ":"),
        ).encode()
        req = urllib_request.Request(
            self.url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": self.authorization},
        )
        try:
            with urllib_request.urlopen(req, timeout=30) as response:
                payload = json.loads(response.read())
        except Exception as exc:
            raise BitcoinCoreRegtestError(f"Bitcoin Core RPC failed: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("error") is not None:
            raise BitcoinCoreRegtestError(f"Bitcoin Core RPC {method} failed: {payload!r}")
        return payload.get("result")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _binary_sha256(path: str | os.PathLike[str]) -> str:
    digest = sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class RegtestTransactionResult:
    slot_id: int
    txid: str
    wtxid: str
    block_hash: str
    confirmations: int
    selector_items: int
    point_encoding: str
    raw_transaction_sha256: str
    witness_policy_sha256: str
    mempool_policy_allowed: bool
    witness_share_responses: int
    seed_share_responses: int
    phase_one_response_bytes: int
    phase_two_response_bytes: int
    labels_released_before_broadcast: bool
    seed_released_only_after_confirmation: bool
    program_seed_commitment: str
    schema: str = "ranklock-v025-bitcoin-core-regtest-transaction-v3"

    def document(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class RegtestResult:
    bitcoin_core_version: str
    bitcoin_core_version_number: int
    bitcoind_sha256: str
    authorization_plan_digest: str
    authorization_plan_bytes: int
    transactions: tuple[RegtestTransactionResult, ...]
    exact_phase_one_replay_created_no_second_response: bool
    exact_phase_two_replay_created_no_second_response: bool
    reorg_never_reopened_consumed_slots: bool
    standard_policy_enabled: bool
    schema: str = "ranklock-v025-bitcoin-core-regtest-result-v3"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "bitcoin_core_version": self.bitcoin_core_version,
            "bitcoin_core_version_number": self.bitcoin_core_version_number,
            "bitcoind_sha256": self.bitcoind_sha256,
            "authorization_plan_digest": self.authorization_plan_digest,
            "authorization_plan_bytes": self.authorization_plan_bytes,
            "transactions": [row.document() for row in self.transactions],
            "exact_phase_one_replay_created_no_second_response": (
                self.exact_phase_one_replay_created_no_second_response
            ),
            "exact_phase_two_replay_created_no_second_response": (
                self.exact_phase_two_replay_created_no_second_response
            ),
            "reorg_never_reopened_consumed_slots": self.reorg_never_reopened_consumed_slots,
            "standard_policy_enabled": self.standard_policy_enabled,
        }


def _mempool_accepts(rpc: _Rpc, raw: bytes) -> bool:
    result = rpc.call("testmempoolaccept", [raw.hex()])
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise BitcoinCoreRegtestError("testmempoolaccept returned malformed data")
    if not bool(result[0].get("allowed")):
        raise BitcoinCoreRegtestError(
            "authorization transaction failed standard mempool policy: "
            + json.dumps(result[0], sort_keys=True)
        )
    return True


def run_bitcoin_core_regtest(
    *,
    bitcoind: str | os.PathLike[str] = "bitcoind",
    working_directory: str | os.PathLike[str] | None = None,
    expected_version: int | None = EXPECTED_CORE_VERSION,
    expected_bitcoind_sha256: str | None = None,
) -> RegtestResult:
    """Execute the exact v0.25 two-phase authorization protocol on regtest.

    Phase one burns the slot and releases only XOR shares of the 512 selected
    16-byte DFB labels.  The resulting witness transaction is then assembled,
    checked by standard mempool policy, broadcast and confirmed.  Phase two
    releases only the program-seed shares after every sidecar independently
    re-reads the exact txid, wtxid, witness digest, block and confirmation count
    from Bitcoin Core.
    """

    executable = shutil.which(str(bitcoind)) if not Path(str(bitcoind)).is_file() else str(bitcoind)
    if executable is None:
        raise BitcoinCoreRegtestError("bitcoind is not installed or was not supplied")
    binary_hash = _binary_sha256(executable)
    if expected_bitcoind_sha256 is not None and binary_hash != expected_bitcoind_sha256.lower():
        raise BitcoinCoreRegtestError("bitcoind binary hash differs from pinned release hash")

    temporary_root = working_directory is None
    root = (
        Path(tempfile.mkdtemp(prefix="ranklock-v025-regtest-"))
        if temporary_root
        else Path(working_directory)  # type: ignore[arg-type]
    )
    root.mkdir(parents=True, exist_ok=True)
    datadir = root / "node"
    datadir.mkdir(parents=True, exist_ok=True)
    rpc_port = _free_port()
    p2p_port = _free_port()
    user = "ranklock"
    password = secrets.token_hex(24)
    command = [
        executable,
        f"-datadir={datadir}",
        "-regtest=1",
        "-server=1",
        "-listen=0",
        "-discover=0",
        "-dnsseed=0",
        "-txindex=1",
        "-fallbackfee=0.0001",
        "-persistmempool=0",
        "-acceptnonstdtxn=0",
        f"-rpcport={rpc_port}",
        f"-port={p2p_port}",
        f"-rpcuser={user}",
        f"-rpcpassword={password}",
        "-printtoconsole=0",
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rpc = _Rpc(f"http://127.0.0.1:{rpc_port}", user, password)
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                info = rpc.call("getnetworkinfo")
                break
            except BitcoinCoreRegtestError:
                if process.poll() is not None:
                    stderr = process.stderr.read().decode(errors="replace") if process.stderr else ""
                    raise BitcoinCoreRegtestError(f"bitcoind exited during startup: {stderr}")
                if time.monotonic() >= deadline:
                    raise BitcoinCoreRegtestError("Bitcoin Core RPC startup timed out")
                time.sleep(0.2)
        if not isinstance(info, dict):
            raise BitcoinCoreRegtestError("getnetworkinfo returned malformed data")
        version_number = int(info.get("version", -1))
        version = str(info.get("subversion", version_number))
        if expected_version is not None and version_number != int(expected_version):
            raise BitcoinCoreRegtestError(
                f"Bitcoin Core version {version_number} differs from pinned {expected_version}"
            )
        try:
            rpc.call("createwallet", "ranklock-v025")
        except BitcoinCoreRegtestError:
            rpc.call("loadwallet", "ranklock-v025")
        mining_address = str(rpc.call("getnewaddress", "", "bech32m"))
        rpc.call("generatetoaddress", 101, mining_address)
        chain_genesis = bytes.fromhex(str(rpc.call("getblockhash", 0)))

        # This inner context is deliberately independent of the transaction
        # plan: Taproot outputs commit to labels, while the plan commits to
        # those outputs.  The outer activation, preauthorization and phase-two
        # confirmation bind the exact deposit, txids, wtxids and witnesses.
        context = sha256(
            b"ranklock/v025/core-regtest-inner-context/v3\x00" + chain_genesis
        ).digest()
        authorizer_secret = 211
        participant_secrets = (101, 103, 107)
        trees = tuple(
            LabelCommitmentTree.from_input_encodings(
                (
                    _encoding(INPUT_BITS, 100 + slot_id * 10_000),
                    _encoding(INPUT_BITS, 1000 + slot_id * 10_000),
                ),
                context_digest=context,
                slot_id=slot_id,
                input_bits=INPUT_BITS,
                program_seed=sha256(
                    b"ranklock/v025/core-regtest-program-seed/v3\x00"
                    + bytes((slot_id,))
                ).digest(),
            )
            for slot_id in range(2)
        )

        point0 = multiply(G1, 123456789, group="g1")
        rules0, selected0 = _tree_selector_material(trees[0], point0)
        rules1, placeholder_selected1 = _tree_selector_material(trees[1], G1)
        authorizer_pubkey = public_key(authorizer_secret)
        script0 = selector_validation_tapscript(rules0, authorizer_pubkey=authorizer_pubkey)
        script1 = selector_validation_tapscript(rules1, authorizer_pubkey=authorizer_pubkey)
        funding_script, control0, funding_address = _taproot_script_output(script0)
        continuation_script, control1, _continuation_address = _taproot_script_output(script1)
        funding_txid = str(rpc.call("sendtoaddress", funding_address, 0.02))
        rpc.call("generatetoaddress", 1, mining_address)
        funding = rpc.call("getrawtransaction", funding_txid, True)
        if not isinstance(funding, dict):
            raise BitcoinCoreRegtestError("funding transaction RPC result is malformed")
        vout = next(
            row
            for row in funding["vout"]
            if bytes.fromhex(str(row["scriptPubKey"]["hex"])) == funding_script
        )
        previous_vout = int(vout["n"])
        previous_value_sat = int(round(float(vout["value"]) * 100_000_000))
        if previous_value_sat <= 60_000:
            raise BitcoinCoreRegtestError("funding output cannot pay both authorization fees")
        destination = str(rpc.call("getnewaddress", "", "bech32m"))
        destination_info = rpc.call("getaddressinfo", destination)
        if not isinstance(destination_info, dict):
            raise BitcoinCoreRegtestError("destination address info is malformed")
        final_script = bytes.fromhex(str(destination_info["scriptPubKey"]))

        # The authorizer signature commits to the BIP341 sighash, which does
        # not include the spending input's own witness.  The plan therefore
        # commits to a transaction built with a placeholder signature and the
        # real signature is spliced in later without changing the txid.
        raw0 = _serialize_transaction(
            previous_txid=bytes.fromhex(funding_txid),
            previous_vout=previous_vout,
            output_value_sat=previous_value_sat - 30_000,
            output_script=continuation_script,
            witness_stack=selected0 + (_PLACEHOLDER_SIGNATURE, script0, control0),
        )
        txid0 = parse_bitcoin_transaction(raw0).txid
        placeholder1 = _serialize_transaction(
            previous_txid=txid0,
            previous_vout=0,
            output_value_sat=previous_value_sat - 60_000,
            output_script=final_script,
            witness_stack=placeholder_selected1
            + (_PLACEHOLDER_SIGNATURE, script1, control1),
        )
        # Value and scriptPubKey of the output each authorization spends; the
        # sighash commits to both, so the fee cannot be mutated silently.
        spent_values = (previous_value_sat, previous_value_sat - 30_000)
        spent_scripts = (funding_script, continuation_script)
        plan = build_authorization_transaction_plan(
            chain_genesis_hash=chain_genesis,
            deposit_outpoint=bytes.fromhex(funding_txid) + previous_vout.to_bytes(4, "little"),
            raw_transactions=(raw0, placeholder1),
            authorization_input_index=0,
            continuation_output_index=0,
        )

        descriptors = tuple(
            slot_descriptor_from_artifact(
                slot_id,
                b"ranklock-v025-core-regtest-sealed-slot-" + bytes((slot_id,)),
                input_label_commitment=trees[slot_id].root,
                independence_nonce=b"ranklock-v025-core-regtest-independence-"
                + bytes((slot_id,)),
            )
            for slot_id in range(2)
        )
        activations = []
        states_by_slot = []
        policies = []
        for slot_id, (rules, script, control) in enumerate(
            ((rules0, script0, control0), (rules1, script1, control1))
        ):
            activation, _guide, states = dealer_split_fixture(
                trees[slot_id],
                chain_genesis_hash=chain_genesis,
                counterproof_txid=plan.templates[slot_id].txid,
                artifact_root=descriptors[slot_id].artifact_root,
                participant_secrets=participant_secrets,
                request_authorizer_pubkey=public_key(authorizer_secret),
                rollback_witness_pubkeys=tuple(
                    public_key(307 + 2 * index) for index in range(3)
                ),
                deterministic_seed=b"ranklock-v025-core-regtest-dealer-v3-"
                + bytes((slot_id,)),
            )
            unsigned_policy = UnsignedBitcoinWitnessPolicy(
                context_digest=context,
                activation_digest=activation.digest,
                slot_id=slot_id,
                authorization_input_index=0,
                input_bits=INPUT_BITS,
                tapscript_hash=witness_script_hash(script),
                control_block_hash=witness_control_hash(control),
                authorizer_pubkey=authorizer_pubkey,
                rules=rules,
            )
            policy = SignedBitcoinWitnessPolicy.create(
                unsigned_policy,
                activation=activation,
                participant_secrets=participant_secrets,
            )
            activations.append(activation)
            states_by_slot.append(states)
            policies.append(policy)

        ledgers = tuple(
            DurableSlotLedger(
                root / f"participant-{index}.sqlite",
                context_digest=context,
                slot_count=2,
            )
            for index in range(3)
        )
        rollback_witnesses = tuple(
            SqliteRollbackWitness(
                root / f"rollback-witness-{index}.sqlite",
                witness_secret=307 + 2 * index,
            )
            for index in range(3)
        )

        transaction_results: list[RegtestTransactionResult] = []
        block_hashes: list[str] = []
        exact_phase_one_replay_no_second_output = False
        exact_phase_two_replay_no_second_output = False
        current_point = point0

        for slot_id in range(2):
            preauthorization = issue_witness_preauthorization_request(
                activations[slot_id],
                plan,
                point=current_point,
                request_authorizer_secret=authorizer_secret,
            )
            sidecars = tuple(
                TwoPhaseParticipantSidecar(
                    activation=activations[slot_id],
                    plan=plan,
                    witness_policy=policies[slot_id],
                    participant=states_by_slot[slot_id][participant_index],
                    ledger=ledgers[participant_index],
                    rollback_witnesses=rollback_witnesses,
                    bitcoin_core=rpc,
                    minimum_confirmations=6,
                )
                for participant_index in range(3)
            )

            witness_rows: list[ParticipantWitnessShareResponse] = []
            for participant_index, sidecar in enumerate(sidecars):
                output_path = root / (
                    f"slot-{slot_id}-participant-{participant_index}.witness-share"
                )
                response, _receipts, created = sidecar.issue_witness_shares(
                    preauthorization=preauthorization,
                    output_path=output_path,
                )
                if not created:
                    raise BitcoinCoreRegtestError(
                        "phase-one sidecar failed to publish its first response"
                    )
                witness_rows.append(response)
                if slot_id == 0 and participant_index == 0:
                    replay, _replay_receipts, replay_created = sidecar.issue_witness_shares(
                        preauthorization=preauthorization,
                        output_path=output_path,
                    )
                    exact_phase_one_replay_no_second_output = bool(
                        not replay_created
                        and replay.compact_bytes == response.compact_bytes
                    )

            reconstructed_witness = reconstruct_witness_labels(
                activation=activations[slot_id],
                preauthorization=preauthorization,
                plan=plan,
                policy=policies[slot_id],
                responses=tuple(witness_rows),
            )
            if slot_id == 0:
                previous_txid = bytes.fromhex(funding_txid)
                previous_index = previous_vout
                output_value = previous_value_sat - 30_000
                output_script = continuation_script
                script = script0
                control = control0
            else:
                previous_txid = plan.templates[0].txid
                previous_index = 0
                output_value = previous_value_sat - 60_000
                output_script = final_script
                script = script1
                control = control1
            # Build once with the placeholder so the sighash is taken over the
            # exact precommitted transaction, then splice in the real
            # signature.  The txid is identical either way.
            unsigned_raw = _serialize_transaction(
                previous_txid=previous_txid,
                previous_vout=previous_index,
                output_value_sat=output_value,
                output_script=output_script,
                witness_stack=reconstructed_witness.witness_stack_items
                + (_PLACEHOLDER_SIGNATURE, script, control),
            )
            authorization_signature = sign_authorization_witness(
                unsigned_raw,
                authorization_input_index=0,
                spent_values_sat=(spent_values[slot_id],),
                spent_scripts=(spent_scripts[slot_id],),
                tapscript=script,
                request_authorizer_secret=authorizer_secret,
            )
            raw = _serialize_transaction(
                previous_txid=previous_txid,
                previous_vout=previous_index,
                output_value_sat=output_value,
                output_script=output_script,
                witness_stack=reconstructed_witness.witness_stack_items
                + (authorization_signature, script, control),
            )
            if parse_bitcoin_transaction(raw).txid != parse_bitcoin_transaction(unsigned_raw).txid:
                raise BitcoinCoreRegtestError(
                    "authorization signature changed the precommitted txid"
                )
            if not plan.verify_raw_transaction(slot_id, raw):
                raise BitcoinCoreRegtestError(
                    "adaptive witness changed the precommitted stripped transaction"
                )
            selection = derive_witness_selection(
                raw,
                policy=policies[slot_id],
                activation=activations[slot_id],
            )
            if selection.point_encoding != preauthorization.point_encoding:
                raise BitcoinCoreRegtestError(
                    "reconstructed Bitcoin witness selected another point"
                )
            binding = BitcoinAuthorizationBinding.from_raw_transaction(
                raw,
                chain_genesis_hash=chain_genesis,
                authorization_input_index=0,
            )
            confirmation_request = issue_committee_request(
                activations[slot_id],
                point=current_point,
                bitcoin_binding=binding,
                request_authorizer_secret=authorizer_secret,
            )

            policy_allowed = _mempool_accepts(rpc, raw)
            release_txid = str(rpc.call("sendrawtransaction", raw.hex()))
            if release_txid != binding.counterproof_txid.hex():
                raise BitcoinCoreRegtestError("Bitcoin Core txid differs from local parser")
            rpc.call("generatetoaddress", 6, mining_address)
            confirmed = rpc.call("getrawtransaction", release_txid, True)
            if not isinstance(confirmed, dict):
                raise BitcoinCoreRegtestError("confirmed transaction RPC result is malformed")
            if bytes.fromhex(str(confirmed["hex"])) != raw:
                raise BitcoinCoreRegtestError("Bitcoin Core returned different transaction bytes")
            if str(confirmed["hash"]).lower() != binding.counterproof_wtxid.hex():
                raise BitcoinCoreRegtestError("Bitcoin Core wtxid differs from local parser")
            confirmations = int(confirmed["confirmations"])
            if confirmations < 6:
                raise BitcoinCoreRegtestError("authorization transaction did not reach six confirmations")
            block_hash = str(confirmed["blockhash"])

            seed_rows: list[ParticipantSeedResponse] = []
            for participant_index, sidecar in enumerate(sidecars):
                output_path = root / (
                    f"slot-{slot_id}-participant-{participant_index}.seed-share"
                )
                response, observation, _receipts, created = sidecar.issue_seed_share(
                    preauthorization=preauthorization,
                    confirmation_request=confirmation_request,
                    raw_transaction=raw,
                    block_hash=block_hash,
                    output_path=output_path,
                )
                if not created or observation.txid != release_txid:
                    raise BitcoinCoreRegtestError(
                        "phase-two sidecar did not publish exactly once"
                    )
                seed_rows.append(response)
                if slot_id == 0 and participant_index == 0:
                    replay, _observation, _replay_receipts, replay_created = (
                        sidecar.issue_seed_share(
                            preauthorization=preauthorization,
                            confirmation_request=confirmation_request,
                            raw_transaction=raw,
                            block_hash=block_hash,
                            output_path=output_path,
                        )
                    )
                    exact_phase_two_replay_no_second_output = bool(
                        not replay_created
                        and replay.compact_bytes == response.compact_bytes
                    )

            reconstructed_seed = reconstruct_program_seed(
                activation=activations[slot_id],
                preauthorization=preauthorization,
                confirmation_request=confirmation_request,
                responses=tuple(seed_rows),
            )
            if reconstructed_seed != trees[slot_id].program_seed:
                raise BitcoinCoreRegtestError("committee reconstructed the wrong program seed")

            parsed = parse_bitcoin_transaction(raw)
            previous_input_value = (
                previous_value_sat if slot_id == 0 else previous_value_sat - 30_000
            )
            if previous_input_value - output_value != 30_000:
                raise BitcoinCoreRegtestError("authorization transaction fee drifted")
            transaction_results.append(
                RegtestTransactionResult(
                    slot_id=slot_id,
                    txid=release_txid,
                    wtxid=binding.counterproof_wtxid.hex(),
                    block_hash=block_hash,
                    confirmations=confirmations,
                    selector_items=len(policies[slot_id].unsigned.rules),
                    point_encoding=selection.point_encoding.hex(),
                    raw_transaction_sha256=sha256(raw).hexdigest(),
                    witness_policy_sha256=sha256(
                        policies[slot_id].compact_bytes
                    ).hexdigest(),
                    mempool_policy_allowed=policy_allowed,
                    witness_share_responses=len(witness_rows),
                    seed_share_responses=len(seed_rows),
                    phase_one_response_bytes=sum(
                        len(response.compact_bytes) for response in witness_rows
                    ),
                    phase_two_response_bytes=sum(
                        len(response.compact_bytes) for response in seed_rows
                    ),
                    labels_released_before_broadcast=True,
                    seed_released_only_after_confirmation=True,
                    program_seed_commitment=program_seed_commitment(
                        reconstructed_seed
                    ).hex(),
                )
            )
            block_hashes.append(block_hash)
            if slot_id == 0:
                adaptive_scalar = int.from_bytes(
                    sha256(
                        b"ranklock/v025/core-regtest-adaptive-point/v3\x00"
                        + reconstructed_seed
                        + b"".join(reconstructed_witness.labels)
                    ).digest(),
                    "big",
                ) % CURVE_ORDER
                current_point = multiply(G1, adaptive_scalar or 1, group="g1")

        # Invalidate the first authorization block after both phase-two
        # responses are public.  A reorg may change chain observations, but it
        # can never make published labels or seed shares secret again.
        rpc.call("invalidateblock", block_hashes[0])
        for ledger in ledgers:
            for slot_id in range(2):
                ledger.record_chain_observation(
                    slot_id,
                    event_type="reorg-observed",
                    block_hash=bytes.fromhex(block_hashes[0]),
                    height=0,
                )
        reorg_never_reopened = all(
            ledger.use(slot_id).state == "success"
            for ledger in ledgers
            for slot_id in range(2)
        )

        return RegtestResult(
            bitcoin_core_version=version,
            bitcoin_core_version_number=version_number,
            bitcoind_sha256=binary_hash,
            authorization_plan_digest=plan.digest.hex(),
            authorization_plan_bytes=len(plan.encoded),
            transactions=tuple(transaction_results),
            exact_phase_one_replay_created_no_second_response=(
                exact_phase_one_replay_no_second_output
            ),
            exact_phase_two_replay_created_no_second_response=(
                exact_phase_two_replay_no_second_output
            ),
            reorg_never_reopened_consumed_slots=reorg_never_reopened,
            standard_policy_enabled=True,
        )
    finally:
        try:
            rpc.call("stop")
        except Exception:
            process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        if temporary_root:
            shutil.rmtree(root, ignore_errors=True)
