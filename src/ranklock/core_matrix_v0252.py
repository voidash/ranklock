from __future__ import annotations

"""Executable CORE-001..030 scenarios against a real Bitcoin Core regtest node.

Each scenario is an independent function returning one :class:`CaseResult`.
Cases that this build cannot yet execute return ``not_executed`` with an
explicit ``blocked_by`` -- they are never silently omitted and never reported
as passing.

The carrier-level cases here spend a funded Taproot output committed to the
selector tapscript.  They deliberately do *not* drive the full two-phase
sidecar protocol (that is what ``bitcoin_core_regtest.run_bitcoin_core_regtest``
does end to end); the cases that require it are marked accordingly so the
distinction stays visible in the evidence.
"""

from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Callable

from .acceptance_matrix_v0252 import CORE_CASE_IDS
from .bip340 import public_key
from .bitcoin_core_regtest import (
    EXPECTED_CORE_RELEASE,
    EXPECTED_CORE_VERSION,
    _serialize_transaction,
    _taproot_script_output,
)
from .bitcoin_tx import MAX_PARSE_TRANSACTION_BYTES, BitcoinTxError, parse_transaction
from .bitcoin_witness_selection import (
    WitnessItemRule,
    selector_validation_tapscript,
    sign_authorization_witness,
)
from .evidence_v0252 import CaseResult, MatrixReport
from .predicate_locked_hashlock import NUMS_INTERNAL_KEY
from .regtest_node import RegtestNode, RegtestRpc, binary_sha256

AUTHORIZER_SECRET = 0x2520A
SELECTOR_BITS = 8


class CoreMatrixError(RuntimeError):
    pass


def _selector_material(bits: int = SELECTOR_BITS):
    rules: list[WitnessItemRule] = []
    zero_items: list[bytes] = []
    one_items: list[bytes] = []
    for coordinate in (0, 1):
        for bit in range(bits):
            header = bytes((coordinate,)) + bit.to_bytes(2, "big")
            zero = b"Z" + header + sha256(b"zero" + header).digest()[:12]
            one = b"O" + header + sha256(b"one" + header).digest()[:12]
            rules.append(
                WitnessItemRule.selector(
                    coordinate=coordinate, bit=bit, zero_item=zero, one_item=one
                )
            )
            zero_items.append(zero)
            one_items.append(one)
    return tuple(rules), tuple(zero_items), tuple(one_items)


class CarrierScenario:
    """One funded carrier output plus helpers to build spends of it."""

    def __init__(self, rpc: RegtestRpc, node: RegtestNode) -> None:
        self.rpc = rpc
        self.node = node
        self.rules, self.zero_items, self.one_items = _selector_material()
        self.authorizer_pubkey = public_key(AUTHORIZER_SECRET)
        self.script = selector_validation_tapscript(
            self.rules, authorizer_pubkey=self.authorizer_pubkey
        )
        self.script_pubkey, self.control, self.address = _taproot_script_output(self.script)
        self.mining_address = str(rpc.call("getnewaddress", "", "bech32m"))

    def fund(self, amount_btc: float = 0.01) -> None:
        rpc = self.rpc
        txid = str(rpc.call("sendtoaddress", self.address, amount_btc))
        rpc.call("generatetoaddress", 1, self.mining_address)
        funding = rpc.call("getrawtransaction", txid, True)
        vout = next(
            row
            for row in funding["vout"]
            if bytes.fromhex(str(row["scriptPubKey"]["hex"])) == self.script_pubkey
        )
        self.funding_txid = txid
        self.vout_n = int(vout["n"])
        self.vout_value = int(round(float(vout["value"]) * 100_000_000))

    def destination(self) -> bytes:
        address = str(self.rpc.call("getnewaddress", "", "bech32m"))
        return bytes.fromhex(str(self.rpc.call("getaddressinfo", address)["scriptPubKey"]))

    def build(
        self,
        *,
        witness_items: tuple[bytes, ...],
        value: int,
        script_pubkey: bytes,
        signature: bytes | None,
        tapscript: bytes | None = None,
        control: bytes | None = None,
    ) -> bytes:
        stack = witness_items
        if signature is not None:
            stack = stack + (signature,)
        return _serialize_transaction(
            previous_txid=bytes.fromhex(self.funding_txid),
            previous_vout=self.vout_n,
            output_value_sat=value,
            output_script=script_pubkey,
            witness_stack=stack
            + (
                self.script if tapscript is None else tapscript,
                self.control if control is None else control,
            ),
        )

    def sign(self, *, witness_items: tuple[bytes, ...], value: int, script_pubkey: bytes) -> bytes:
        unsigned = self.build(
            witness_items=witness_items,
            value=value,
            script_pubkey=script_pubkey,
            signature=bytes(64),
        )
        return sign_authorization_witness(
            unsigned,
            authorization_input_index=0,
            spent_values_sat=(self.vout_value,),
            spent_scripts=(self.script_pubkey,),
            tapscript=self.script,
            request_authorizer_secret=AUTHORIZER_SECRET,
        )

    def honest(self, *, value: int | None = None, script_pubkey: bytes | None = None) -> bytes:
        value = self.vout_value - 5_000 if value is None else value
        script_pubkey = self.destination() if script_pubkey is None else script_pubkey
        signature = self.sign(
            witness_items=self.zero_items, value=value, script_pubkey=script_pubkey
        )
        return self.build(
            witness_items=self.zero_items,
            value=value,
            script_pubkey=script_pubkey,
            signature=signature,
        )

    def accept_result(self, raw: bytes) -> dict[str, Any]:
        result = self.rpc.call("testmempoolaccept", [raw.hex()])
        if not isinstance(result, list) or not result or not isinstance(result[0], dict):
            raise CoreMatrixError("testmempoolaccept returned malformed data")
        return result[0]


def _passed(case_id: str, description: str, evidence: dict[str, object], command) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        status="passed",
        description=description,
        commands=(command,),
        evidence=evidence,
    )


def _failed(case_id: str, description: str, evidence: dict[str, object], command) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        status="failed",
        description=description,
        commands=(command,),
        evidence=evidence,
    )


def _not_executed(case_id: str, description: str, blocked_by: str) -> CaseResult:
    return CaseResult(
        case_id=case_id,
        status="not_executed",
        description=description,
        blocked_by=blocked_by,
    )


def _rejection_case(
    scenario: CarrierScenario,
    *,
    case_id: str,
    description: str,
    raw: bytes,
    command,
    expect_substring: str | None = None,
) -> CaseResult:
    """A case that passes exactly when Core *rejects* the transaction."""

    result = scenario.accept_result(raw)
    allowed = bool(result.get("allowed"))
    reason = str(result.get("reject-reason", ""))
    evidence = {
        "raw_transaction_sha256": sha256(raw).hexdigest(),
        "txid": parse_transaction(raw).txid.hex(),
        "testmempoolaccept": result,
        "expected": "rejected",
    }
    ok = not allowed
    if ok and expect_substring is not None:
        ok = expect_substring in reason
        evidence["expected_reject_substring"] = expect_substring
    builder = _passed if ok else _failed
    return builder(case_id, description, evidence, command)


def _two_phase_protocol_cases(
    *,
    bitcoind: str,
    root: str | os.PathLike[str],
    command_record,
    expected_bitcoind_sha256: str | None,
) -> list[CaseResult]:
    """Drive the complete two-phase protocol once and map what it proves.

    ``run_bitcoin_core_regtest`` executes the real protocol end to end against
    Core: burn before any label release, broadcast, confirm, then release seed
    shares only after every sidecar independently re-reads the exact txid,
    wtxid, witness digest, block and confirmation depth.  Rather than
    reimplement that, this maps its observed results onto the matrix rows it
    actually establishes.

    A failure here is a real defect and is reported as ``failed``; an
    infrastructure problem (no usable node) is reported as ``unavailable``.
    """

    from .bitcoin_core_regtest import BitcoinCoreRegtestError, run_bitcoin_core_regtest

    protocol_root = Path(root) / "two-phase"
    protocol_root.mkdir(parents=True, exist_ok=True)
    try:
        result = run_bitcoin_core_regtest(
            bitcoind=bitcoind,
            working_directory=protocol_root,
            # Version pinning is enforced by CORE-001; this run must not
            # duplicate that gate, only exercise the protocol.
            expected_version=None,
            expected_bitcoind_sha256=expected_bitcoind_sha256,
        )
    except BitcoinCoreRegtestError as exc:
        blocked = f"two-phase protocol run did not complete: {exc}"
        return [
            CaseResult(
                case_id=case_id,
                status="unavailable",
                description=description,
                commands=(command_record,),
                evidence={"error": str(exc)},
                blocked_by=blocked,
            )
            for case_id, description in (
                ("CORE-002", "valid slot 0 authorization end to end"),
                ("CORE-003", "valid adaptive slot 1 chosen after slot-0 output"),
                ("CORE-013", "exact phase-one retry is byte-identical"),
                ("CORE-015", "exact phase-two retry releases no second seed"),
            )
        ]

    document = result.document()
    slots = document["transactions"]
    assert isinstance(slots, list)

    def _slot_case(case_id: str, slot_id: int, description: str) -> CaseResult:
        row = slots[slot_id]
        assert isinstance(row, dict)
        ok = bool(
            row["mempool_policy_allowed"]
            and int(row["confirmations"]) >= 6
            and row["labels_released_before_broadcast"]
            and row["seed_released_only_after_confirmation"]
        )
        evidence: dict[str, object] = {
            "txid": row["txid"],
            "wtxid": row["wtxid"],
            "block_hash": row["block_hash"],
            "confirmations": row["confirmations"],
            "selector_items": row["selector_items"],
            "raw_transaction_sha256": row["raw_transaction_sha256"],
            "witness_policy_sha256": row["witness_policy_sha256"],
            "mempool_policy_allowed": row["mempool_policy_allowed"],
            "labels_released_before_broadcast": row["labels_released_before_broadcast"],
            "seed_released_only_after_confirmation": row["seed_released_only_after_confirmation"],
            "program_seed_commitment": row["program_seed_commitment"],
            "standard_policy_enabled": document["standard_policy_enabled"],
        }
        if case_id == "CORE-003":
            # Recorded precisely rather than overclaimed: slot 1's point is
            # adaptive by dependency on slot-0's released material, not the
            # BN254 projective output of executing the retained DFB program
            # (the harness uses synthetic slot artifacts).
            evidence["adaptive_derivation"] = (
                "derived from slot-0 released seed and labels, which exist only "
                "after slot 0 confirmed"
            )
            evidence["scope_limitation"] = (
                "not the retained-program execution output; full retained-slot "
                "execution remains out of scope for this harness"
            )
        return (_passed if ok else _failed)(case_id, description, evidence, command_record)

    cases = [
        _slot_case("CORE-002", 0, "valid slot 0 authorization end to end"),
        _slot_case("CORE-003", 1, "valid adaptive slot 1 chosen after slot-0 output"),
    ]

    for case_id, key, description in (
        (
            "CORE-013",
            "exact_phase_one_replay_created_no_second_response",
            "exact phase-one retry is byte-identical and creates no second response",
        ),
        (
            "CORE-015",
            "exact_phase_two_replay_created_no_second_response",
            "exact phase-two retry releases no second seed",
        ),
    ):
        observed = bool(document[key])
        cases.append(
            (_passed if observed else _failed)(
                case_id,
                description,
                {key: observed, "authorization_plan_digest": document["authorization_plan_digest"]},
                command_record,
            )
        )

    return cases


def run_core_matrix(
    *,
    bitcoind: str | os.PathLike[str],
    root: str | os.PathLike[str],
    command_record,
    expected_bitcoind_sha256: str | None,
    enforce_pinned_release: bool = True,
) -> MatrixReport:
    """Execute every CORE case that this build can execute.

    ``command_record`` is the recorded command that produced this run; it is
    attached to each executed case so the evidence carries argv, exit code and
    raw-log hashes rather than a bare boolean.
    """

    executable = str(bitcoind)
    observed_hash = binary_sha256(executable)
    cases: list[CaseResult] = []

    node = RegtestNode.create(bitcoind=executable, root=root)
    rpc = node.start()
    try:
        version_number, version_string = node.version()

        # ---- CORE-001: pinned Core identity -------------------------------
        identity_evidence: dict[str, object] = {
            "expected_release": EXPECTED_CORE_RELEASE,
            "expected_numeric_version": EXPECTED_CORE_VERSION,
            "observed_numeric_version": version_number,
            "observed_subversion": version_string,
            "bitcoind_path": executable,
            "observed_bitcoind_sha256": observed_hash,
            "expected_bitcoind_sha256": expected_bitcoind_sha256,
        }
        version_matches = version_number == EXPECTED_CORE_VERSION
        hash_matches = (
            expected_bitcoind_sha256 is not None
            and observed_hash == expected_bitcoind_sha256.lower()
        )
        if version_matches and hash_matches:
            cases.append(
                _passed("CORE-001", "pinned Bitcoin Core identity", identity_evidence, command_record)
            )
        elif enforce_pinned_release:
            # Without an independently verified, hash-pinned release this is
            # not a failure of the implementation -- the qualifying input is
            # simply absent.  Record it as unavailable, never as a pass.
            identity_evidence["reason"] = (
                "qualification requires an independently verified, hash-pinned "
                f"Bitcoin Core {EXPECTED_CORE_RELEASE} release"
            )
            cases.append(
                CaseResult(
                    case_id="CORE-001",
                    status="unavailable",
                    description="pinned Bitcoin Core identity",
                    commands=(command_record,),
                    evidence=identity_evidence,
                    blocked_by="no independently verified Bitcoin Core 31.1 binary supplied",
                )
            )
        else:
            identity_evidence["reason"] = "development probe; not qualification evidence"
            cases.append(
                CaseResult(
                    case_id="CORE-001",
                    status="unavailable",
                    description="pinned Bitcoin Core identity",
                    commands=(command_record,),
                    evidence=identity_evidence,
                    blocked_by="development probe explicitly ran against an unpinned binary",
                )
            )

        rpc.call("createwallet", "ranklock-v0252-matrix")
        scenario = CarrierScenario(rpc, node)
        rpc.call("generatetoaddress", 101, scenario.mining_address)
        scenario.fund()

        # ---- CORE-025: intended fee is standard and relayable --------------
        honest_destination = scenario.destination()
        honest_value = scenario.vout_value - 5_000
        honest_raw = scenario.honest(value=honest_value, script_pubkey=honest_destination)
        honest_result = scenario.accept_result(honest_raw)
        honest_evidence = {
            "raw_transaction_sha256": sha256(honest_raw).hexdigest(),
            "txid": parse_transaction(honest_raw).txid.hex(),
            "wtxid": parse_transaction(honest_raw).wtxid.hex(),
            "vsize": parse_transaction(honest_raw).vsize,
            "fee_sat": scenario.vout_value - honest_value,
            "testmempoolaccept": honest_result,
            "expected": "accepted",
        }
        builder = _passed if honest_result.get("allowed") else _failed
        cases.append(
            builder(
                "CORE-025",
                "intended fee is standard and relayable",
                honest_evidence,
                command_record,
            )
        )

        # ---- CORE-004: modified selected label ----------------------------
        tampered = list(scenario.zero_items)
        tampered[0] = b"not-an-authorized-label"
        signature = scenario.sign(
            witness_items=scenario.zero_items,
            value=honest_value,
            script_pubkey=honest_destination,
        )
        cases.append(
            _rejection_case(
                scenario,
                case_id="CORE-004",
                description="modified selected label is rejected",
                expect_substring="OP_VERIFY",
                raw=scenario.build(
                    witness_items=tuple(tampered),
                    value=honest_value,
                    script_pubkey=honest_destination,
                    signature=signature,
                ),
                command=command_record,
            )
        )

        # ---- CORE-006: both labels offered for one bit --------------------
        both = scenario.zero_items + (scenario.one_items[0],)
        cases.append(
            _rejection_case(
                scenario,
                case_id="CORE-006",
                description="offering both labels for a bit is rejected",
                expect_substring="OP_VERIFY",
                raw=scenario.build(
                    witness_items=both,
                    value=honest_value,
                    script_pubkey=honest_destination,
                    signature=signature,
                ),
                command=command_record,
            )
        )

        # ---- CORE-007: missing label item ---------------------------------
        cases.append(
            _rejection_case(
                scenario,
                case_id="CORE-007",
                description="a missing label item is rejected",
                expect_substring="OP_VERIFY",
                raw=scenario.build(
                    witness_items=scenario.zero_items[:-1],
                    value=honest_value,
                    script_pubkey=honest_destination,
                    signature=signature,
                ),
                command=command_record,
            )
        )

        # ---- CORE-012: alternate tapscript / control block -----------------
        alternate_script = selector_validation_tapscript(
            scenario.rules, authorizer_pubkey=public_key(AUTHORIZER_SECRET + 1)
        )
        cases.append(
            _rejection_case(
                scenario,
                case_id="CORE-012",
                description="an alternate tapscript does not satisfy the committed output",
                expect_substring="Witness program hash mismatch",
                raw=scenario.build(
                    witness_items=scenario.zero_items,
                    value=honest_value,
                    script_pubkey=honest_destination,
                    signature=signature,
                    tapscript=alternate_script,
                ),
                command=command_record,
            )
        )

        # ---- CORE-028: mutation / RBF cannot redirect the carrier ----------
        attacker_script = scenario.destination()
        cases.append(
            _rejection_case(
                scenario,
                case_id="CORE-028",
                description=(
                    "revealed labels cannot be replayed into a mutated-output "
                    "transaction (previously exploitable)"
                ),
                raw=scenario.build(
                    witness_items=scenario.zero_items,
                    value=honest_value,
                    script_pubkey=attacker_script,
                    signature=signature,
                ),
                command=command_record,
                expect_substring="Invalid Schnorr signature",
            )
        )

        # ---- CORE-024: fee below the relay floor ---------------------------
        # Leave a dust-level fee so Core's minimum relay feerate rejects it.
        low_fee_value = scenario.vout_value - 1
        low_fee_raw = scenario.honest(value=low_fee_value, script_pubkey=honest_destination)
        cases.append(
            _rejection_case(
                scenario,
                case_id="CORE-024",
                description="a fee below the relay floor is predictably rejected",
                expect_substring="min relay fee not met",
                raw=low_fee_raw,
                command=command_record,
            )
        )

        # ---- CORE-030: malformed / oversize parser input -------------------
        oversize = b"\x02\x00\x00\x00" + b"\x00" * (MAX_PARSE_TRANSACTION_BYTES + 1)
        bounded_rejection = False
        parser_error = ""
        try:
            parse_transaction(oversize)
        except BitcoinTxError as exc:
            bounded_rejection = True
            parser_error = str(exc)
        truncated_rejection = False
        try:
            parse_transaction(b"\x02\x00")
        except BitcoinTxError:
            truncated_rejection = True
        core_ok, core_response = rpc.try_call("testmempoolaccept", [oversize.hex()])
        parser_evidence = {
            "oversize_input_bytes": len(oversize),
            "max_parse_transaction_bytes": MAX_PARSE_TRANSACTION_BYTES,
            "local_parser_bounded_rejection": bounded_rejection,
            "local_parser_error": parser_error,
            "truncated_input_rejected": truncated_rejection,
            "core_rejected_oversize": not core_ok,
            "core_response_digest": sha256(str(core_response).encode()).hexdigest(),
            "expected": "bounded rejection without crash or unbounded allocation",
        }
        builder = (
            _passed if (bounded_rejection and truncated_rejection and not core_ok) else _failed
        )
        cases.append(
            builder(
                "CORE-030",
                "malformed and oversize parser input is bounded-rejected",
                parser_evidence,
                command_record,
            )
        )

        # ---- CORE-029: Core restart preserves state ------------------------
        confirmed_txid = str(rpc.call("sendrawtransaction", honest_raw.hex()))
        rpc.call("generatetoaddress", 6, scenario.mining_address)
        before = rpc.call("getrawtransaction", confirmed_txid, True)
        before_confirmations = int(before["confirmations"])
        before_tip = str(rpc.call("getbestblockhash"))

        rpc = node.restart()
        scenario.rpc = rpc
        after = rpc.call("getrawtransaction", confirmed_txid, True)
        after_confirmations = int(after["confirmations"])
        after_tip = str(rpc.call("getbestblockhash"))
        # Re-broadcasting an already-confirmed transaction must not create a
        # second one.
        rebroadcast_ok, rebroadcast = rpc.try_call("sendrawtransaction", honest_raw.hex())
        restart_evidence = {
            "txid": confirmed_txid,
            "confirmations_before_restart": before_confirmations,
            "confirmations_after_restart": after_confirmations,
            "tip_before_restart": before_tip,
            "tip_after_restart": after_tip,
            "restarts": node.restarts,
            "rebroadcast_created_duplicate": bool(rebroadcast_ok),
            "rebroadcast_response_digest": sha256(str(rebroadcast).encode()).hexdigest(),
            "expected": "no duplicate release and no state regression",
        }
        restart_ok = (
            after_confirmations >= before_confirmations
            and after_tip == before_tip
            and not rebroadcast_ok
        )
        builder = _passed if restart_ok else _failed
        cases.append(
            builder(
                "CORE-029",
                "Core restart causes no duplicate release or state regression",
                restart_evidence,
                command_record,
            )
        )

        # ---- CORE-019: reorg after terminal release ------------------------
        # Invalidate the block containing the confirmed authorization, observe
        # that it loses its confirmations, then reconsider to restore the
        # chain.  Building a competing branch belongs to the two-phase reorg
        # scenario (CORE-018/CORE-020) where the sidecar ledger is live; here
        # the observable is that a confirmed authorization can be orphaned
        # while the released material stays public.
        reorg_tip = str(rpc.call("getbestblockhash"))
        containing_block = str(after["blockhash"])
        rpc.call("invalidateblock", containing_block)
        orphaned_tip = str(rpc.call("getbestblockhash"))
        orphaned_ok, orphaned = rpc.try_call("getrawtransaction", confirmed_txid, True)
        orphan_confirmations = (
            int(orphaned.get("confirmations", 0))
            if orphaned_ok and isinstance(orphaned, dict)
            else 0
        )
        rpc.call("reconsiderblock", containing_block)
        restored_tip = str(rpc.call("getbestblockhash"))
        restored = rpc.call("getrawtransaction", confirmed_txid, True)
        reorg_evidence = {
            "txid": confirmed_txid,
            "original_containing_block": containing_block,
            "tip_before_reorg": reorg_tip,
            "tip_while_orphaned": orphaned_tip,
            "tip_after_reconsider": restored_tip,
            "confirmations_while_orphaned": orphan_confirmations,
            "confirmations_after_reconsider": int(restored.get("confirmations", 0)),
            "expected": (
                "a reorg may orphan the authorization, but it can never make "
                "published material secret again or reopen a consumed slot"
            ),
            "slot_ledger_coverage": (
                "the no-reopen property of the slot ledger itself is covered by "
                "tests/test_durable_slot_ledger.py::"
                "test_reorg_is_recorded_but_never_reopens_slot"
            ),
        }
        reorg_ok = (
            orphaned_tip != reorg_tip
            and orphan_confirmations <= 0
            and restored_tip == reorg_tip
            and int(restored.get("confirmations", 0)) > 0
        )
        builder = _passed if reorg_ok else _failed
        cases.append(
            builder(
                "CORE-019",
                "a reorg after terminal release orphans the authorization without reopening it",
                reorg_evidence,
                command_record,
            )
        )
    finally:
        node.stop()

    # The complete two-phase protocol runs against its own node, so it happens
    # after the carrier scenarios have released theirs.
    cases.extend(
        _two_phase_protocol_cases(
            bitcoind=executable,
            root=root,
            command_record=command_record,
            expected_bitcoind_sha256=expected_bitcoind_sha256,
        )
    )

    # Cases this build does not yet execute.  They require driving the full
    # two-phase sidecar protocol (burn/anchor/release ordering, retained-slot
    # execution) or the Strata ACK/NACK graph per scenario, rather than the
    # carrier-level spends exercised above.
    deferred = {
        "CORE-005": ("wrong sibling/opening is rejected", "two-phase sidecar protocol scenario"),
        "CORE-008": ("noncanonical/wrong point is rejected", "two-phase sidecar protocol scenario"),
        "CORE-009": ("wrong slot is rejected", "two-phase sidecar protocol scenario"),
        "CORE-010": ("wrong game/deposit/operator/epoch is rejected", "two-phase sidecar protocol scenario"),
        "CORE-011": ("wrong txid/wtxid/witness releases no seed", "two-phase sidecar protocol scenario"),
        "CORE-014": ("conflicting phase-one retry is terminal", "two-phase sidecar protocol scenario"),
        "CORE-016": ("crash after burn before response", "process-level fault injection harness"),
        "CORE-017": ("crash after response write", "process-level fault injection harness"),
        "CORE-018": ("reorg before required depth withholds the seed", "two-phase sidecar protocol scenario"),
        "CORE-020": ("competing/stale fork observation fails closed", "two-phase sidecar protocol scenario"),
        "CORE-021": ("pre-CSV NACK is rejected", "Strata ACK/NACK graph (STRATA-012)"),
        "CORE-022": ("mature CSV NACK is accepted", "Strata ACK/NACK graph (STRATA-012)"),
        "CORE-023": ("timeout NACK remains reachable", "Strata ACK/NACK graph (STRATA-012)"),
        "CORE-026": ("CPFP before the allowed point", "Strata ACK/NACK graph (STRATA-012)"),
        "CORE-027": ("CPFP after the allowed point", "Strata ACK/NACK graph (STRATA-012)"),
    }
    covered = {case.case_id for case in cases}
    for case_id in CORE_CASE_IDS:
        if case_id in covered:
            continue
        description, blocker = deferred[case_id]
        cases.append(_not_executed(case_id, description, blocker))

    return MatrixReport(
        schema_name="ranklock-v0252-core-matrix-v1",
        required_case_ids=CORE_CASE_IDS,
        identity={
            "expected_release": EXPECTED_CORE_RELEASE,
            "expected_numeric_version": EXPECTED_CORE_VERSION,
            "bitcoind_path": executable,
            "bitcoind_sha256": observed_hash,
            "chain": "regtest",
        },
        cases=tuple(cases),
    )
