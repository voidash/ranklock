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

## `p4-ack-witness-check.diff`

**Status: implemented and compiling; blocked on unrealistic test fixtures.**

Completes P4. Threads `Arc<GraphSMCfg>` into `process_counterproof_ack` (one
dispatch site in `machine.rs`), regenerates the game graph to obtain
`counterproof_ack.ack_preimage_hash()`, and rejects unless some witness item
in the confirmed transaction hashes to it.

The check is correct and the lib compiles. **Four tests fail with it applied,
and they are right to.**

### Why the fixtures cannot satisfy it — the finding

`ack_preimage_hash` is sourced from `wt_fault_pubkeys` (`game_graph.rs:626`),
the field the ACK commitment was migrated into. Test fixtures populate that
with **random x-only public keys**. No preimage exists for a random 32-byte
value, so no witness the tests can construct will ever hash to it.

That is not a fixture bug to paper over. It means **the existing tests never
modelled a real ACK spend** — they assert on a txid and a commitment for
which nobody holds the preimage. The check makes that visible, which is what
a real check should do.

### What has to happen before this lands

The test graph must be built with `wt_fault_pubkeys[i] = sha256(preimage_i)`,
rejection-sampled so the digest is a valid x-only encoding — exactly what
`derive_setup_payload` does on the Python side. Then fixtures can attach a
witness containing `preimage_i` and the four tests pass for the right reason.

Until then, applying this diff produces a red tree, so it is held here rather
than in the installer. Do not "fix" the four tests by weakening the check.
