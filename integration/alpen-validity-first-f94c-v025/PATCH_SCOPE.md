# Patch scope

## Added/replaced modules

- `crates/connectors/src/validity_first_counterproof.rs`
- `crates/tx-graph/src/transactions/counterproof.rs`
- `crates/tx-graph/src/transactions/counterproof_ack.rs`
- `crates/tx-graph/src/transactions/counterproof_nack.rs`
- `crates/bridge-sm/src/graph/transitions/counterproof.rs`
- `crates/bridge-exec/src/graph/ranklock.rs`
- `scripts/ranklock_sidecar_fixture.py`

## Targeted edits

- connector and transaction exports;
- ACK/NACK fee/vsize pinning;
- one extra N/N pre-signature per watchtower;
- `GameGraph` construction, summaries/inpoints/signing-info, and existing Core graph fixture;
- new validity-first duties and executor dispatch;
- exact fixed-NACK classification;
- new-block and retry polarity;
- setup commitment source and unlock resolution.

## Explicitly unchanged

- deposit, stake, claim, contest, bridge-proof, slash, and contested-payout transaction templates;
- existing graph-state terminal meanings;
- P2P `GraphData` field layout;
- database schema;
- operator/watchtower ordering;
- Mosaic adaptor-key generation for the counterproof input itself.
