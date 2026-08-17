# Pending Rust changes, not yet in the installer

Work verified against the patched tree but **not yet ported into
`apply_validity_first.py`**, so it is not part of the deliverable. Anything
here must be ported and re-verified from a pristine clone before it counts.

## `p4-ack-event-carries-tx.diff`

**Status: enabling half done, the check itself not implemented.**

Addresses P4 in `V0252_THREAT_MODEL.md`. Under BIP141 a txid does not commit
to the witness, so comparing `event.counterproof_ack_txid` cannot establish
that the ACK leaf was the leaf actually executed. Worse, the ACK event did
not carry the transaction at all — its sibling `CounterProofConfirmedEvent`
does — so the check could not be written at the comparison site even in
principle.

What this diff does:

- adds `pub tx: bitcoin::Transaction` to `CounterProofAckConfirmedEvent`
- populates it in `tx_classifier.rs`, next to the sibling event that already
  carried one
- updates the 8 test construction sites
- leaves a comment at the comparison site stating exactly what remains

Verified: `strata-bridge-sm` lib and tests compile, **449 passed / 0 failed**.

What it does **not** do, and why: the check needs the expected preimage hash,
which lives on the regenerated graph's `CounterproofAckTx`
(`ack_preimage_hash()` is public). `process_counterproof_ack` does not
receive `cfg`, unlike `process_counterproof_nackd`, so regenerating the graph
there requires threading `Arc<GraphSMCfg>` through the dispatcher and every
call site. That was deliberately not started rather than half-done in
consensus-adjacent code.

The intended check, once `cfg` is available: the ACK leaf is
`<N/N pubkey> OP_CHECKSIGVERIFY OP_SHA256 <hash> OP_EQUAL`, so a genuine ACK
spend must reveal a witness item whose SHA-256 equals the connector's
`ack_preimage_hash()`. Reject otherwise.

Note the test fixtures currently attach a placeholder transaction
(`generate_tx(1, 1)`). They type-check but carry no real ACK witness — when
the check lands, those fixtures must be rebuilt to spend the real ACK leaf,
or they will fail for the right reason.

### Porting checklist

1. Add a `patch_p4_ack_event_carries_tx` function to the installer, following
   `patch_base_logging_defect` as the model for a labelled delta.
2. Add the four touched files to `TOUCHED_RUST_FILES`.
3. Raise `EXPECTED_CHANGED_FILES` in `scripts/run_v0252_strata_build_matrix.py`
   (currently 29) and the matching description string.
4. Verify from a pristine clone: preflight, apply, scope count, `cargo fmt
   --all -- --check`, then the bridge-sm suite.
