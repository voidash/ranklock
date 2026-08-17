# Pending Rust changes, not yet in the installer

Work verified against the patched tree but **not yet ported into
`apply_validity_first.py`**, so it is not part of the deliverable. Anything
here must be ported and re-verified from a pristine clone before it counts.

## `p4-complete.diff`

**Status: complete and green. 450 passed / 0 failed, including a negative
test that proves the check fires.**

Closes P4 in `V0252_THREAT_MODEL.md`. Under BIP141 a txid does not commit to
the witness, so comparing `event.counterproof_ack_txid` could not establish
that the ACK leaf was the leaf actually executed — a transaction carrying the
expected txid but spending via another path was accepted as an ACK.

Four parts:

1. **`events.rs`** — `CounterProofAckConfirmedEvent` gains
   `pub tx: bitcoin::Transaction`. Its sibling `CounterProofConfirmedEvent`
   always carried one; without it the check could not be written at the
   comparison site even in principle.
2. **`tx_classifier.rs`** — populates it.
3. **`machine.rs` / `contested.rs`** — threads `Arc<GraphSMCfg>` into
   `process_counterproof_ack` (one dispatch site), regenerates the graph for
   `counterproof_ack.ack_preimage_hash()`, and rejects unless some witness
   item hashes to it. The ACK leaf is
   `<N/N pubkey> OP_CHECKSIGVERIFY OP_SHA256 <hash> OP_EQUAL`, so a genuine
   ACK spend must reveal that preimage.
4. **`tests/mod.rs` + `process_counterproof_ack.rs`** — the fixture change
   that made the check satisfiable, described below.

### The finding this surfaced

Applying the check initially failed four tests, and they were right to fail.
`ack_preimage_hash` is sourced from `wt_fault_pubkeys` — the field the ACK
commitment was migrated into — and bridge-sm's `TEST_FAULT_PUBKEYS`
populated it with `generate_xonly_pubkey()`. **No preimage exists for a
random 32-byte value**, so no constructible witness could satisfy the check:
those fixtures had never modelled a real ACK spend, only a txid and a
commitment nobody held the preimage for.

Note the tx-graph signer (`game_graph.rs`) already did this correctly, as
`sha256(ack_preimage)`. The gap was specific to the bridge-sm test fixtures.

Fixed by deriving test commitments the same way: `test_ack_preimage(index)`
rejection-samples so `sha256(preimage)` is a valid x-only encoding — mirroring
`derive_setup_payload` on the RankLock side — and `test_ack_commitment` feeds
`TEST_FAULT_PUBKEYS`. Event fixtures then attach a transaction whose witness
reveals that preimage.

The negative test `an_ack_txid_without_the_committed_preimage_is_rejected`
strips the witness while keeping the txid and asserts rejection, so the check
is demonstrated to fire rather than merely to be present.

### Porting checklist

1. Add `patch_p4_ack_witness_check` to the installer, following
   `patch_base_logging_defect` as the model for a labelled delta.
2. Add the six touched files to `TOUCHED_RUST_FILES`.
3. Raise `EXPECTED_CHANGED_FILES` in `scripts/run_v0252_strata_build_matrix.py`
   (currently 29) and the matching description string.
4. Verify from a pristine clone: preflight, apply, scope count,
   `cargo fmt --all -- --check`, then the bridge-sm suite.
