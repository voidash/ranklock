# 48 — Validity-first counterproof graph

## Existing polarity

The current Strata counterproof connector has two mutually exclusive paths:

```text
immediate key path: wt_fault → Counterproof NACK
timeout script path: N/N     → Counterproof ACK
```

Mosaic releases `wt_fault` when the posted counterproof is invalid. If no NACK confirms before `nack_timelock`, the pre-signed N/N ACK consumes the connector and the contest-payout output, leading to slash.

## Proposed polarity inversion

```text
immediate key path: valid-proof key → Counterproof ACK
timeout script path: N/N            → Counterproof NACK
```

A valid counterproof lets any observer evaluate the public projective lock, derive the immediate ACK signature, consume the counterproof connector plus contest-payout connector, and proceed to slash. If no valid immediate spend confirms, a pre-signed N/N timeout NACK rejects the counterproof and the graph proceeds to contested payout.

## Required transaction rewiring

1. Replace `wt_fault_pubkey` with a valid-counterproof public key in `CounterproofConnector`.
2. Make input 0 of `CounterproofAckTx` use `TimelockedSpendPath::Normal` and the proof-conditioned signature.
3. Make `CounterproofNackTx` use `TimelockedSpendPath::Timeout` and a pre-signed N/N signature.
4. Remove Mosaic `evaluate_and_sign(INVALID)` from the NACK executor.
5. Add public evaluation/signing of `VALID(counterproof)` to the ACK executor.
6. Preserve the same connector outpoint, relative deadline, downstream contested-payout path, and slash path.

## Censorship symmetry

The current graph fails if an invalid-proof NACK is censored until timeout. The inverted graph fails if a valid-proof ACK is censored until timeout. Each graph therefore has one conditioned immediate-spend race under the same deadline assumption.

After the counterproof transaction confirms, the immediate transaction need not be published by a privileged party: any observer able to evaluate the public lock can publish it.

## Positive backend fit

BABE verifies positive Groth16 relations using witness encryption plus a small scalar-multiplication garbling component. Duty-Free Bits supplies Embryo, a projective drop-in for that component with a reported approximately 500 KiB encoding.

This is exactly the predicate polarity needed by the inverted graph. It does not prove that the complete Strata object is below one MiB, nor does it finish malicious distributed activation or Rust integration.

## Security caveat

Polarity inversion removes the complement-verifier requirement; it does not make an ordinary static WE ciphertext support arbitrary future proof bytes. The backend must be a real projective garbling/encoding construction such as BABE/Embryo, not the uninstantiated fixed-relation proxy.

## Decision

```text
PROMISING_PROTOCOL_PIVOT_NOT_YET_A_COMPLETE_REPLACEMENT
```

Evidence:

- `src/ranklock/validity_first_graph.py`
- `results/v018_validity_first_graph.json`
- upstream files audited in `alpenlabs/strata-bridge`:
  - `crates/connectors/src/timelocked.rs`
  - `crates/tx-graph/src/transactions/counterproof.rs`
  - `crates/tx-graph/src/transactions/counterproof_ack.rs`
  - `crates/bridge-exec/src/graph/counterproof_nack.rs`
  - `crates/bridge-sm/src/graph/transitions/counterproof.rs`
