from __future__ import annotations

from pathlib import Path

from ranklock.bitcoin_authorization import parse_bitcoin_transaction

DEPOSIT_INPUT_VALUE_SAT = 160_000
SLOT_OUTPUT_VALUES_SAT = (130_000, 100_000)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "v025-committee-conformance"


def _weight(raw: bytes, stripped: bytes) -> int:
    return len(stripped) * 4 + len(raw) - len(stripped)


def test_precommitted_authorization_chain_has_positive_standard_fees():
    previous_value = DEPOSIT_INPUT_VALUE_SAT
    for slot_id in range(2):
        raw = ARTIFACTS.joinpath(
            f"slot-{slot_id}-authorization-transaction.bin"
        ).read_bytes()
        parsed = parse_bitcoin_transaction(raw)
        assert parsed.output_values == (SLOT_OUTPUT_VALUES_SAT[slot_id],)
        weight = _weight(raw, parsed.stripped)
        virtual_bytes = (weight + 3) // 4
        fee = previous_value - sum(parsed.output_values)
        assert fee > 0
        # The conformance floor is Bitcoin Core's default 1 sat/vB relay floor.
        assert fee >= virtual_bytes
        previous_value = parsed.output_values[0]
