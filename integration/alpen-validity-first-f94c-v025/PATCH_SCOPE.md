# Patch scope

## Added modules (5)

- `crates/connectors/src/validity_first_counterproof.rs`
- `crates/tx-graph/src/transactions/counterproof_nack.rs`
- `crates/tx-graph/src/funds_safety.rs`
- `crates/bridge-exec/src/graph/ranklock.rs`
- `scripts/ranklock_sidecar_fixture.py`

## Modified files (33)

- `compose.yml`;
- `crates/common/src/logging.rs`;
- `crates/connectors/src/lib.rs` and `prelude.rs`;
- `crates/p2p-service/src/tests/common.rs`;
- `crates/tx-graph/src/fee.rs`, `game_graph.rs`, `lib.rs`, `musig_functor.rs`;
- `crates/tx-graph/src/transactions/{counterproof.rs,counterproof_ack.rs,mod.rs,prelude.rs}`;
- `crates/bridge-exec/src/{errors.rs,graph/common.rs,graph/mod.rs}`;
- `crates/bridge-sm/src/graph/{duties.rs,events.rs,machine.rs,tx_classifier.rs}`;
- `crates/bridge-sm/src/graph/handlers/retry.rs`;
- `crates/bridge-sm/src/graph/transitions/{common.rs,contested.rs,counterproof.rs}`;
- `crates/bridge-sm/src/tx_classifier.rs`;
- `crates/bridge-sm/src/graph/tests/{mod.rs,notify_new_block.rs,tx_classifier.rs}`;
- `crates/bridge-sm/src/graph/tests/contested/{process_bridge_proof.rs,process_counterproof.rs,process_counterproof_ack.rs,process_counterproof_nackd.rs}`;
- `crates/bridge-sm/src/graph/tests/handlers/process_retry_tick.rs`.

This list is measured from a pristine install at the pinned base. The matrix
requires exactly 33 modified and 5 new paths and fails on any scope drift.

## Targeted behavior

- connector and transaction exports;
- ACK/NACK fee/vsize pinning;
- one extra N/N pre-signature per watchtower;
- `GameGraph` construction, summaries/inpoints/signing-info, and existing Core graph fixture;
- new validity-first duties and executor dispatch;
- exact full-transaction ACK/NACK classification and transition validation;
- a read-only typed economic kill witness for the valid-counterproof plus one
  shared N-of-N release-withholder trace; it is not an authorization input;
- new-block and retry polarity;
- setup commitment source and unlock resolution;
- read-only RankLock mounts plus digest-pinned Bitcoin Core 31.1 in Compose;
- two separately labeled base-test fixes: one-shot logging initialization and
  process-unique libp2p memory addresses.

## Explicitly unchanged

- deposit, stake, claim, contest, bridge-proof, slash, and contested-payout transaction templates;
- existing graph-state terminal meanings;
- P2P `GraphData` field layout;
- database schema;
- operator/watchtower ordering;
- Mosaic adaptor-key generation for the counterproof input itself.
