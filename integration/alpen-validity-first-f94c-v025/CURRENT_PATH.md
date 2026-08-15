# Current Alpen counterproof path and exact replacement

## Current connector

`CounterproofConnector` is a two-way Taproot connector:

1. immediate key path controlled by the Mosaic fault key: dynamic NACK;
2. script path controlled by N/N after `nack_timelock`: delayed ACK.

The current `CounterproofTx` creates the ACK/NACK output plus its keyed anchor. The current ACK is a deterministic two-input pre-signed v3 transaction. The current NACK is deliberately not pre-signed: the executor appends a wallet input/output and uses the recovered/completed fault signatures.

## Current state-machine polarity

- A confirmed counterproof is decoded and recorded.
- On the graph owner's state machine, the current transition immediately emits `PublishCounterProofNack`.
- Retry re-creates/re-emits that mutable NACK.
- After `nack_timelock`, the counterprover emits the fixed ACK.
- Exact ACK txid moves the graph to `Acked`; later the existing slash transaction is published.
- Once every possible counterproof has a NACK, the graph moves to `AllNackd`; the existing contested payout remains the terminal payout path.
- The existing no-counterproof, bridge-proof-timeout, stake-spent, and payout-connector-spent logic is retained.

## Replacement boundary

Only the per-watchtower counterproof child pair is changed:

```text
ContestTx
  -> CounterproofTx                    unchanged parent/outpoint shape
       -> ACK (immediate positive lock) changed witness/leaf polarity
       -> NACK (CSV default)            new fixed pre-signed child

ACK -> existing contest-payout input -> existing ACK anchor -> existing slash semantics
NACK(s) -> existing AllNackd state -> existing contested-payout semantics
```

No outpoint in `ClaimTx`, `ContestTx`, `ContestedPayoutTx`, `SlashTx`, deposit graph, stake graph, or payout connector is renumbered.

## Pre-signing delta

Each watchtower functor grows from four N/N signatures to five:

```text
contest[1]
counterproof[1]
counterproof_ack[2]
counterproof_nack[1]   # new
```

This is the only packed signature-count change.

## Exact classification

The old NACK classifier accepted any transaction spending the expected ACK/NACK outpoint. The patch reconstructs the graph and accepts only the exact fixed NACK txid for the counterprover's slot. This rejects:

- alternate outputs;
- extra fee-wallet inputs;
- different deposit/game templates;
- a NACK copied from another watchtower slot;
- a mutated parent transaction.

ACK classification remains exact txid classification.
