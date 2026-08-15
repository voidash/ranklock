# Malicious Activation Reduced to an Ordinary Public Proof

## Public relation

For each contributor, activation must prove knowledge of one setup scalar \(r\) such that:

1. the published base scale is \(r[1]_2\);
2. every scaled low-rank anchor is \(rU_j\);
3. the same \(r\) determines the fixed statement-side pairing session;
4. hashing that session with the relation digest, epoch, and signer identifier yields the published secp256k1 fault-share key.

Because the fault key is session-derived, no encrypted payload consistency relation remains.

## Why this proof may be ordinary

The activation proof is verified once **before the Bitcoin graph is funded**. It is not part of the later conditional computation. Therefore a conventional transparent proof, SNARK, or zkVM proof can instantiate the relation without being embedded in RankLock.

## Ceremony rule

The ceremony fails closed:

- every expected contributor must appear exactly once;
- all contributors must bind the same relation and epoch;
- every activation proof must verify;
- an abort or invalid proof burns the epoch and restarts with fresh setup scalars;
- the transaction graph is funded only after all receipts are accepted.

## Current state

The exact NP relation and ceremony state machine are executable. A zero-knowledge proof system and its concrete circuit are not implemented.
