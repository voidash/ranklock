# Test ledger

## Current v0.25.2 qualification

These results were reproduced from the imported v0.25.2 handoff on 2026-08-18.
The Strata matrix used a pristine checkout at the pinned
`f94c06d08ff29eee746f3e20bd63078d2949b304` base, Bitcoin Core 31.1, and
FoundationDB 7.3.43.

| Test | Result | What it establishes |
|---|---:|---|
| RankLock Python suite | 525 passed / 1 skipped | Complete source regression suite; the skip is reported, not hidden |
| Installer syntax and complete disposable preflight | passed | Anchor edits, formatting, ACK delta, and both NACK deltas apply before the target checkout is modified |
| Compose resolution | passed | All three bridges receive a read-only RankLock mount and Core resolves to the qualified 31.1 registry digest |
| `strata-bridge-sm` | 452 passed / 0 failed | State-machine behavior, including same-txid/different-witness rejection at classifier and transition boundaries |
| Complete serialized Strata workspace | 952 passed / 0 failed | All workspace tests pass against live FoundationDB; 7 doctests are ignored by upstream configuration |
| STRATA-001..009 build matrix | 9 passed / 0 failed | Clean installation, declared scope, format, focused bridge tests, full bridge tests, full workspace tests, Core version, and evidence capture |
| STRATA-010..020 E2E matrix | 0 passed / 11 not executed | The runner records the pinned environment and missing deployed producer; it does not promote modeled coverage |
| v0.25.2 evidence verifier | 88 checks / 0 failing | Canonical evidence is internally consistent, provenance-pinned, and remains fail-closed |

Canonical machine-readable evidence:

- `results/v0252_strata_build_matrix.json`
- `results/v0252_evidence_verification.json`
- `results/v0252_release_gate.json`
- `results/v0252_signet_readiness.json`

## Core-backed branches covered by the Rust suite

The connector module uses Alpen's existing `BitcoinNode`, which launches
Bitcoin Core in regtest.

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
| ACK witness substitution | same ACK txid without the committed preimage is rejected |
| NACK witness substitution | same NACK txid with a modified witness is rejected by both classification and direct transition processing |
| valid proof + one shared release withholder | typed graph analyzer derives exact ACK/NACK conflicts, owner NACK/payout receipts, canonical ACK/slash watchtower receipts, and returns `funds_safe_under_premise=false` |

## Reproduction commands

Prerequisites: the project-pinned Rust nightly, Bitcoin Core 31.1 `bitcoind`,
and FoundationDB 7.3.43.

```bash
python integration/alpen-validity-first-f94c-v025/apply_validity_first.py <clean-strata-checkout> --check
python integration/alpen-validity-first-f94c-v025/apply_validity_first.py <clean-strata-checkout>

cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo test -p strata-bridge-connectors validity_first_counterproof -- --nocapture
cargo test -p strata-bridge-tx-graph funds_safety -- --nocapture
cargo test -p strata-bridge-tx-graph game_graph -- --nocapture
cargo test -p strata-bridge-sm all_nackd_pov_contested_payout -- --nocapture
cargo test -p strata-bridge-sm counterproof -- --nocapture
cargo test --workspace
```

For the canonical serialized matrix, use
`scripts/run_v0252_strata_build_matrix.py`; do not run the database-backed
workspace cases in parallel.

## Honest status

Compilation and Core-backed tests are no longer an open claim. Funds safety is
categorically false for this graph: a semantically valid counterproof plus one
shared N-of-N release withholder can reach graph-owner NACK/contested-payout
receipts while avoiding the canonical slash. The typed detector is a kill
witness only; its `Ok(None)` threshold control is not a positive proof.
STRATA-010..020 are also all `not_executed`, no production service wires the
verified RankLock unlock into ACK export, and the independent suite, ceremony,
native constant-time, and rollback gates remain false. No current evidence may
authorize funds.
