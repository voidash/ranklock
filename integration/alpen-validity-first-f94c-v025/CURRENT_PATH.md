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

That preserved terminal meaning is now a confirmed funds-safety failure, not a
neutral compatibility property. With a semantically valid counterproof and one
shared N-of-N release withholder, every ACK can be suppressed, the owner can
collect fixed NACK outputs and contested payout, and the canonical slash does
not consume stake. `crates/tx-graph/src/funds_safety.rs` reconstructs the exact
conflicts, beneficiaries, transaction ids, and values and returns a typed kill
witness. It is deliberately read-only and disconnected from authorization.

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

## Exact classification and transition validation

The old NACK classifier accepted any transaction spending the expected ACK/NACK outpoint. An intermediate validity-first patch improved that to the fixed NACK `txid`, but BIP141 txids exclude witness data. The final patch unpacks the persisted N/N signatures, reconstructs the finalized fixed NACK for the counterprover's slot, and compares the complete transaction in both the classifier and the state transition. This rejects:

- alternate outputs;
- extra fee-wallet inputs;
- different deposit/game templates;
- a NACK copied from another watchtower slot;
- a mutated parent transaction.
- the same unsigned NACK body with any different witness.

ACK routing begins with the exact txid, but the transition also inspects the
complete transaction and requires the witness to reveal the slot's committed
preimage. Thus neither ACK nor NACK state resolution relies on txid alone.

## Deployment consumer boundary

The installer requires a host `STRATA_RANKLOCK_DIR`, mounts it read-only at
`/var/lib/strata/ranklock` in every bridge container, and configures the
executor to read that path. It pins `bitcoin/bitcoin:31.1` by the qualified
multi-architecture registry digest. This is deliberately only the consumer
boundary: no service in this bundle evaluates a RankLock proof or calls the
verified exporter, and the deterministic fixture is not a production
producer.
