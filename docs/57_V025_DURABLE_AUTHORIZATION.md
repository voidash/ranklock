# v0.25 durable one-shot authorization

## Security objective

For each one-shot slot, exactly one context-bound canonical point may cause the
committee to reveal enough shares to open the sealed program and reconstruct
one label per input bit. A crash, malformed authorized request, conflicting
witness, fork, timeout or reorg must never make a second point releasable.

## Release ordering

A participant sidecar performs the following order:

1. parse the signed committee activation and witness policy;
2. verify the exact raw transaction, authorization input, txid, wtxid and full
   witness digest against the signed request;
3. query Bitcoin Core for raw bytes, block, height and confirmations;
4. derive the canonical BN254 point from the 512 consensus witness choices;
5. execute `BEGIN IMMEDIATE` and bind the slot permanently to the input,
   request and chain-binding digests;
6. commit and fsync the burn in SQLite WAL/FULL mode;
7. anchor the new audit-chain head at every configured rollback witness;
8. query Bitcoin Core again and require an unchanged confirmed view;
9. prepare the participant seed and selected-label shares;
10. mark success, anchor the terminal state, and atomically create the response
    file with exclusive-create semantics.

Verification failures before step 5 do not consume the slot. Any failure after
step 5 leaves it burned. Exact replay returns the same response bytes and never
creates a second output file. A different point, wtxid or witness digest is a
permanent conflict.

## Reorg rule

Published witness data and participant shares cannot become secret again. A
reorg is therefore recorded as a tamper-evident observation but cannot return a
slot to `available`. This sacrifices liveness after a deep reorg to preserve
one-shot label safety.

## Rollback protection

SQLite durability does not prevent an operator from restoring an old disk
snapshot. Each ledger state is therefore signed and anchored at independent
rollback witnesses. A witness accepts only a monotonic extension of the exact
ledger identity and rejects stale generations or conflicting heads. Production
safety requires at least one required witness whose state and signing key are
outside the participant's rollback domain.

## Bitcoin witness program

Each of the 512 point bits has two independent 64-byte selector preimages. The
signed policy commits both SHA-256 hashes, the exact Tapscript and the control
block. Tapscript checks that every supplied item matches exactly one alternative
and leaves one true stack value. The current fixture has:

```text
selector items:                 512
maximum selector item:          64 bytes
Tapscript:                      37,889 bytes
transaction weight:             71,587 WU
virtual size:                    17,897 vB
fee:                             30,000 sat
fixture fee rate:                ~1.676 sat/vB
```

The static envelope is not a substitute for Bitcoin Core. The release gate
requires a pinned daemon hash and successful real-regtest evidence.

## Setup alternatives

The compact committee fixture uses a dealer and is only a semantic oracle for
an exact active-MPC backend. The split-scalar alternative removes the aggregate
scalar dealer: each participant independently generates a component artifact,
and ACK requires every component's locked preimage. One honest participant is
sufficient for safety, while any participant can block liveness. This path is
about twice the retained size.
