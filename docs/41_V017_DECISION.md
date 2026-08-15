# v0.17 Research Decision

**Date:** 2026-08-07

## Breakthrough target

**Not met.**

## Main correction

The v0.16 requirement “nonidentity target with no decomposition” was too narrow. Standard KZG-opening witness encryption shows that an identity-normalized PPE may still support conditional disclosure. The correct criterion is:

> The setup-scaled witness bases must not give the public evaluator an algebraic route to the statement-side accepting session without the witness.

This is called **split-basis/session separation**.

## Positive results

1. A real BN254 split-basis PPE lock works and compresses witness evaluation according to fixed-G2 coefficient rank.
2. The low-rank KZG leakage attack is reproduced: publishing both \(r[\tau]\) and \(r[1]\) exposes the statement session.
3. A basis-separated KZG variant avoids that immediate leak but still needs a post-statement encapsulator, so it does not solve static timing.
4. A real one-sided final pairing equation has only future G1 terms and rank-two fixed G2 bases.
5. The naïve hidden-Fiat–Shamir route is killed by an exact nonlinear-dependency audit.
6. A public-transcript wrapper remains below one MiB only if canonical G1 binding costs no more than roughly 325 constraints per proof element under the current proxy model.
7. One shared parsed proof object eliminates a concrete transcript/pairing split-brain interface.
8. Deriving the Bitcoin fault key from the accepting pairing session removes encrypted-payload substitution.
9. Malicious activation is reduced to an ordinary public ZK proof checked before funding.

## Surviving architecture

```text
132 future Strata bytes
        │
        ▼
noninteractive malicious projective authentication
        │
        ▼
fixed statement: authenticated bytes feed RankVM and output INVALID
        │
        ▼
one-sided proof: 10 future G1 + 20 scalars, no future G2
        │
        ▼
shared canonical proof object + public transcript mini-lock
        │
        ▼
rank-two fixed-G2 pairing session
        │
        ▼
hash session into secp256k1 fault scalar
        │
        ▼
Bitcoin NACK path
```

## Current practical envelope

Under explicit planning assumptions:

```text
projective static input material:      112,746 B
fixed wrapper relation key:            918,850 B
derived fault-share object:              1,547 B
manifest/domain allowance:               2,048 B
activation static total:             1,035,191 B
future proof:                             1,280 B
static + future proof:                1,036,471 B
margin below one MiB:                    12,105 B
```

The envelope is **tight** and relies on proxies, especially 66 bytes per fixed relation coordinate and 64-byte G1 planning encodings. These are not production measurements.

## Reusable CRS

The reference one-sided proof has a universal but circuit-linear reusable CRS. Under the 64-byte G1 planning assumption, the prover-time-optimized dominant CRS is approximately:

- 1.66 MB for 25,889 assumed gates;
- 8.28 MB for 129,445 assumed gates;
- 162.38 MB for the deliberately conservative 2,537,122-event upper envelope.

This does not count as per-deposit material, but it prevents claiming the original polylog-total-artifact theorem.

## New primary target

### P0-CDS-6 — instantiate the fixed-statement one-sided conditional wrapper

Build the complete outer-curve circuit and real conditional compiler for:

```text
projective input authentication
+ canonical counterproof parsing
+ complete RankVM/SP1 invalidity
+ public transcript verification
+ rank-two final PPE
+ session-derived secp fault key.
```

Required evidence:

- real proof generation and verification;
- real point encoding/subgroup gadget below the measured size threshold;
- exact CRS, relation key, proof, setup, and runtime bytes;
- knowledge-soundness/extraction argument;
- malformed proof, replay, split-brain, and selective-failure tests.

### P0-SETUP-3 — instantiate activation proof and n−1-corrupt ceremony

Implement the fixed activation circuit, public proof verification, epoch burn/restart, contributor receipts, and aggregate Bitcoin-key binding.

### P0-PROJ-3 — remove the online OT baseline

Replace the current 1,056-OT measurement path with a faithful noninteractive malicious-receiver projectivization.

## Claim policy

Allowed:

> v0.17 identifies and implements the correct split-basis conditional-session criterion, a real one-sided rank-two final equation, ciphertext-free Bitcoin-key derivation, and a tight fixed-statement byte envelope.

Not allowed:

> RankLock has replaced Mosaic, achieved the full theorem, or is production-ready.
