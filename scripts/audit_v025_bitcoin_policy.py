#!/usr/bin/env python3
from __future__ import annotations

"""Static Bitcoin policy/consensus envelope audit for v0.25 fixtures.

This is deliberately not labelled a Bitcoin Core execution.  It checks the
parts that are deterministically visible in the serialized witness against the
signed policy, an independent interpreter for RankLock's exact tapscript opcode
subset, and constants pinned to Bitcoin Core 31.1/BIP342.  The release gate
still requires ``run_v025_bitcoin_core_regtest.py`` against the pinned daemon.
"""

from hashlib import sha256
import json
from pathlib import Path

from ranklock.bitcoin_authorization import parse_bitcoin_transaction
from ranklock.bitcoin_witness_selection import (
    SignedBitcoinWitnessPolicy,
    execute_selector_tapscript_model,
    selector_validation_tapscript,
    witness_control_hash,
    witness_script_hash,
)
from generate_v025_committee_qualification import (
    DEPOSIT_INPUT_VALUE_SAT,
    SLOT_OUTPUT_VALUES_SAT,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "v025-committee-conformance"
OUTPUT = ROOT / "results" / "v025_bitcoin_policy_envelope.json"

# Pinned primary-source identities used for this static audit.  These SHA-1
# values are Git object blob identifiers for the named files at tag v31.1.
BITCOIN_CORE_RELEASE = "31.1"
BITCOIN_CORE_TAG = "v31.1"
BITCOIN_CORE_SOURCE_PINS = {
    "CMakeLists.txt": "6109639f00390e2bbd050d8cfed69320bf1ec159",
    "src/policy/policy.h": "0bc7b32770833211913b82204f1b8fc4bdb4dfd0",
    "src/policy/policy.cpp": "46ec238c3b18fd1c0a5ce35f25d1b619317dafda",
}
BIP342_SOURCE_BLOB = "d073b701ce785ab497d5d409640a16727af3a25b"

# Bitcoin Core 31.1 policy/consensus constants relevant to this exact witness.
MAX_STANDARD_TX_WEIGHT = 400_000
MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE = 80
MAX_TAPSCRIPT_INITIAL_STACK_ITEMS = 1_000
MAX_SCRIPT_ELEMENT_SIZE = 520
DEFAULT_MIN_RELAY_FEE_SAT_PER_KVB = 100
# RankLock intentionally requires a stricter local floor than Core's default.
RANKLOCK_MIN_RELAY_FEE_SAT_PER_KVB = 1_000


def transaction_weight(raw: bytes, stripped: bytes) -> int:
    # BIP141: base bytes count four times; witness bytes count once.
    return len(stripped) * 4 + (len(raw) - len(stripped))


def _minimum_fee(virtual_bytes: int, rate_sat_per_kvb: int) -> int:
    return (int(virtual_bytes) * int(rate_sat_per_kvb) + 999) // 1_000


def main() -> None:
    rows: list[dict[str, object]] = []
    all_pass = True
    previous_output_value = DEPOSIT_INPUT_VALUE_SAT
    for slot_id in range(2):
        raw = ARTIFACTS.joinpath(
            f"slot-{slot_id}-authorization-transaction.bin"
        ).read_bytes()
        policy = SignedBitcoinWitnessPolicy.parse_compact(
            ARTIFACTS.joinpath(f"slot-{slot_id}-witness-policy.bin").read_bytes()
        )
        parsed = parse_bitcoin_transaction(raw)
        input_index = policy.unsigned.authorization_input_index
        stack = parsed.witness_stacks[input_index]
        # Layout: selector items, authorizer signature, tapscript, control block.
        selector_items = stack[:-3]
        authorizer_signature = stack[-3]
        script, control = stack[-2:]
        expected_script = selector_validation_tapscript(
            policy.unsigned.rules,
            authorizer_pubkey=policy.unsigned.authorizer_pubkey,
        )
        weight = transaction_weight(raw, parsed.stripped)
        virtual_bytes = (weight + 3) // 4
        total_output_value = sum(parsed.output_values)
        fee_sat = previous_output_value - total_output_value
        core_default_minimum_fee_sat = _minimum_fee(
            virtual_bytes, DEFAULT_MIN_RELAY_FEE_SAT_PER_KVB
        )
        ranklock_minimum_fee_sat = _minimum_fee(
            virtual_bytes, RANKLOCK_MIN_RELAY_FEE_SAT_PER_KVB
        )
        checks = {
            "script_is_exact_hash_check_program": script == expected_script,
            "independent_tapscript_stack_model_accepts": execute_selector_tapscript_model(
                script, selector_items + (authorizer_signature,)
            ),
            # A witness without the authorizer signature is the pre-v0.25.2
            # shape, under which revealed labels were a reusable spending
            # capability. It must not satisfy the script.
            "unsigned_witness_is_rejected": not execute_selector_tapscript_model(
                script, selector_items
            ),
            "authorizer_signature_is_sighash_default_length": (
                len(authorizer_signature) == 64
            ),
            "script_matches_signed_policy": witness_script_hash(script)
            == policy.unsigned.tapscript_hash,
            "control_matches_signed_policy": witness_control_hash(control)
            == policy.unsigned.control_block_hash,
            "selector_count_matches_policy": len(selector_items)
            == len(policy.unsigned.rules),
            "initial_stack_within_consensus_limit": len(selector_items)
            <= MAX_TAPSCRIPT_INITIAL_STACK_ITEMS,
            "selector_items_within_standard_policy": max(map(len, selector_items), default=0)
            <= MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
            "selector_items_within_consensus_element_limit": max(
                map(len, selector_items), default=0
            )
            <= MAX_SCRIPT_ELEMENT_SIZE,
            "transaction_weight_within_standard_policy": weight
            <= MAX_STANDARD_TX_WEIGHT,
            "output_value_matches_precommitted_value_plan": (
                len(parsed.output_values) == 1
                and parsed.output_values[0] == SLOT_OUTPUT_VALUES_SAT[slot_id]
            ),
            "transaction_fee_is_positive": fee_sat > 0,
            "transaction_fee_meets_core_31_1_default_floor": fee_sat
            >= core_default_minimum_fee_sat,
            "transaction_fee_meets_ranklock_floor": fee_sat
            >= ranklock_minimum_fee_sat,
            "cleanstack_shape": script.endswith(b"\x51"),
        }
        passed = all(checks.values())
        all_pass &= passed
        rows.append(
            {
                "slot_id": slot_id,
                "passed": passed,
                "checks": checks,
                "txid": parsed.txid.hex(),
                "wtxid": parsed.wtxid.hex(),
                "raw_bytes": len(raw),
                "stripped_bytes": len(parsed.stripped),
                "weight": weight,
                "virtual_bytes_ceiling": virtual_bytes,
                "input_value_sat": previous_output_value,
                "total_output_value_sat": total_output_value,
                "fee_sat": fee_sat,
                "core_default_minimum_fee_sat": core_default_minimum_fee_sat,
                "ranklock_minimum_fee_sat": ranklock_minimum_fee_sat,
                "fee_rate_sat_per_vbyte": fee_sat / virtual_bytes,
                "selector_items": len(selector_items),
                "maximum_selector_item_bytes": max(map(len, selector_items), default=0),
                "tapscript_bytes": len(script),
                "tapscript_sha256": sha256(script).hexdigest(),
                "control_block_bytes": len(control),
            }
        )
        previous_output_value = parsed.output_values[0]
    document = {
        "schema": "ranklock-v025-bitcoin-policy-envelope-v2",
        "passed": all_pass,
        "bitcoin_core_executed": False,
        "scope": (
            "static serialized-witness, independent opcode-model, and resource-envelope "
            "audit only"
        ),
        "source_pins": {
            "bitcoin_core_release": BITCOIN_CORE_RELEASE,
            "bitcoin_core_tag": BITCOIN_CORE_TAG,
            "bitcoin_core_git_blobs": BITCOIN_CORE_SOURCE_PINS,
            "bip342_git_blob": BIP342_SOURCE_BLOB,
        },
        "constants": {
            "max_standard_tx_weight": MAX_STANDARD_TX_WEIGHT,
            "max_standard_tapscript_stack_item_size": MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE,
            "max_tapscript_initial_stack_items": MAX_TAPSCRIPT_INITIAL_STACK_ITEMS,
            "max_script_element_size": MAX_SCRIPT_ELEMENT_SIZE,
            "bitcoin_core_default_minimum_relay_fee_sat_per_kvb": (
                DEFAULT_MIN_RELAY_FEE_SAT_PER_KVB
            ),
            "ranklock_minimum_relay_fee_sat_per_kvb": (
                RANKLOCK_MIN_RELAY_FEE_SAT_PER_KVB
            ),
        },
        "transactions": rows,
    }
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))
    if not all_pass:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
