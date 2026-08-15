# 49 — RankLock v0.18 decision

## Breakthrough target

**Not met.**

## Gates that passed

```text
BN254 cofactor-one point binding:       267 rows / G1
old point ceiling:                      325 rows / G1
one-sided scalar verifier:              161 nonlinear rows
Poseidon2 transcript:                   32 permutations
Poseidon2 nonlinear rows:               7,680
arithmetic/transcript envelope:         862,693 bytes
margin to one MiB:                      185,883 bytes
```

The official BN256 Poseidon2 known-answer test passes, and the same typed proof object drives both transcript hashing and pairing verification.

## Hidden assumptions removed

1. The old outer-curve subgroup strategy is too expensive.
2. Identity-normalized pairing verification does not itself create a hidden session.
3. Public affine target shifts leak through scaled anchors.
4. The 66-byte scalar inner-product slope does not cover unknown-discrete-log G1 proof elements.
5. Ordinary NO-instance WE does not protect the fixed invalidity relation because that relation is already YES.
6. The 862,693-byte figure is a coordinate envelope, not an instantiated conditional key.

## Active routes

### Primary: validity-first graph + positive projective backend

Invert the immediate/timeout meanings of the existing counterproof connector and use BABE/Embryo-class positive Groth16 verification. This removes complement verification and appears mechanically compatible with the current graph structure.

Immediate next gates:

1. build a Rust transaction-graph prototype with immediate ACK and timeout NACK;
2. instantiate the exact BABE/Embryo object for Strata's 36-byte public values and 128-byte proof;
3. measure total retained material, setup, evaluation, and peak RAM;
4. prove equivalence of economic outcomes and timelock/censorship assumptions;
5. add malicious setup and replay/session binding;
6. execute ACK/NACK/slash/contested-payout scenarios on Bitcoin Core regtest.

Kill the route if it requires a stronger censorship assumption than the current graph, cannot preserve pre-signing, or the complete retained object is not materially better than Mosaic/Argo/BABE baselines.

### Fallback: hard-YES RankVM WPRF

Construct a standard-assumption, extractable, one-honest-contributor witness PRF for the fixed projective invalidity relation. This remains a major open primitive and should not be represented as implemented.

## Current decision

```text
CONTINUE_WITH_VALIDITY_FIRST_POSITIVE_BACKEND
KEEP_HARD_YES_WPRF_AS_THE_CRYPTOGRAPHIC_FALLBACK
DO_NOT_ANNOUNCE_BREAKTHROUGH_YET
```
