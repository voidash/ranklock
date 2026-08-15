# RankLock v0.22.1 alignment

The integration follows `src/ranklock/predicate_locked_hashlock.py`, not the older proof-derived-private-key sketch.

The v0.22.1 construction states:

- a valid positive counterproof releases a 32-byte preimage;
- immediate ACK requires that preimage plus an N/N Schnorr signature bound to the exact ACK transaction;
- timeout NACK requires the exact-message N/N signature after CSV;
- the released value is not a reusable signing key;
- the RankLock research transaction format is not Bitcoin consensus serialization, so Bitcoin Core regtest is a separate gate.

This Rust patch supplies that missing consensus-side realization with rust-bitcoin transaction templates, Taproot witnesses, exact SIGHASH_DEFAULT pre-signing, and Core-backed tests.

The sidecar boundary deliberately does not import the RankLock prover into `strata-bridge`. RankLock owns proof evaluation and atomic release; the bridge owns transaction reconstruction, SHA256 verification, exact txid binding, and broadcasting.

## Compatibility slot

To avoid a P2P/DB schema migration, the existing 32-byte `fault_pubkeys` item carries the SHA256 preimage commitment. The existing type requires those bytes to parse as an x-only point. A setup producer therefore rejection-samples preimages until `SHA256(preimage)` is a valid x-only encoding. This affects only setup generation; the Bitcoin script still compares the full 32-byte SHA256 digest.

## Remaining cryptographic gates

This integration does not assert that RankLock's broader construction is production-ready. v0.22.1 still records open gates around active MPC execution, adaptive security, authenticated label release, complete Bitcoin/BABE bytes, selective privacy, and the final storage theorem. Those are backend gates, not transaction-graph integration bugs.
