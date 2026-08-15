# Test ledger

## Executed here

| Test | Result | What it establishes |
|---|---:|---|
| `pytest -q tests` in this bundle | 10 passed | setup/unlock encoding, context separation, installer pin/preflight, source polarity, exact fixed templates, byte formulas |
| RankLock `tests/test_validity_first_graph.py` | 6 passed | retained positive-preimage ACK / CSV NACK model and replay/context rules |
| `python -m py_compile` | passed | installer, fixture, and bundle tests parse |

## Rust/Core tests included but not executed in this environment

The connector module uses Alpen's existing `BitcoinNode`, which launches Bitcoin Core in regtest. It includes:

| Required branch | Included test/path |
|---|---|
| valid proof -> immediate ACK | `immediate_ack_spend`; modified `GameGraph` end-to-end branch removes the old CSV wait |
| invalid or absent positive unlock -> timeout NACK | `timeout_nack_spend`; modified graph test rejects NACK pre-maturity then accepts at CSV maturity |
| slash | existing graph end-to-end slash branch retained after exact ACK |
| payout | existing `AllNackd` / contested-payout branch retained after fixed NACKs |
| replay | `exact_message_signature_replay_is_rejected_by_core` |
| alternate game/deposit | fixture context-separation test plus `alternate_context_preimage_is_rejected_by_core` |
| malformed proof/unlock | executor decode tests, fixture malformed mode, and `malformed_positive_unlock_is_rejected_by_core` |
| fee/CPFP | NACK vsize pin plus Core package rejection before CSV and acceptance with wallet CPFP child at maturity |

## Commands for a real checkout

Prerequisites: project-pinned Rust nightly and Bitcoin Core 31.1 `bitcoind` in `PATH` (or the repository's normal test environment).

```bash
python /path/to/alpen-validity-first/apply_validity_first.py . --check
python /path/to/alpen-validity-first/apply_validity_first.py .

cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test -p strata-bridge-connectors validity_first_counterproof -- --nocapture
cargo test -p strata-bridge-tx-graph game_graph -- --nocapture
cargo test -p strata-bridge-sm counterproof -- --nocapture
cargo test --workspace
```

## Honest status

The code is apply-ready and the consensus test cases are present. It is not represented as compiled or Core-verified in the creation environment because that environment contained neither Rust nor Bitcoin Core and could not download them.
