# Target-Separated Low-Rank Wrapper Frontier

**Date:** 2026-08-07
**Evidence:** **EXACT interface classification**; proof-system instantiation remains open
**Code:** `src/ranklock/verifier_shape_frontier.py`

## Required final verifier shape

The low-rank PPE lock needs a proof whose final verification equation has all of the following:

1. future/dynamic proof elements only in G1;
2. all G2 verifier elements fixed at setup;
3. public coefficient rank `k = polylog(R)` or constant;
4. a fixed nonidentity GT target;
5. no public target decomposition over the scaled G2 anchors;
6. every future scalar coefficient bound to the proof transcript and statement;
7. a knowledge-sound proof backend;
8. a universal/reusable or otherwise acceptably small verifier-specific setup.

Call this interface a **target-separated low-rank fixed-G2 wrapper**.

## Why familiar pairing equations miss the interface

### KZG opening equations

After expanding `[tau-z]G2` over fixed anchors `[tau]G2` and `G2`, the G2 rank is two and all
future terms can be placed in G1. This is excellent for correlation storage. However, the
normalized verification target is the identity:

```text
product pairings = 1.
```

Scaling the fixed bases gives session `1^r = 1`, which contains no conditional entropy.

### PLONK/KZG-style aggregated opening equations

The same structural issue remains. Universal/updatable KZG-based SNARKs can have a small
fixed-G2 verifier basis and modern knowledge-soundness analyses, but their normalized pairing
check is normally identity-valued. Low G2 rank alone does not create a conditional lock.

### Groth16 normalized PPE

Groth16 naturally has a nonidentity constant target, but the proof contains a future/dynamic G2
component `B`. A static lock cannot pre-scale an element that does not exist at setup. The
nonidentity target therefore does not fix the cold-start interface.

## Exact missing object

The surviving proof target is:

> A knowledge-sound, transcript-bound proof with only future G1 terms, a constant/polylog fixed
> G2 anchor basis, and a nonidentity target whose scaled value is unavailable without a valid
> proof.

This is sharper than “find a compact PCG.” The generic PCG route is unnecessary for a low-rank
verifier and impossible in the current algebraic model for independent bases. The real open
cryptographic problem is **target separation** together with knowledge soundness and malicious
activation.

## Candidate research directions

The following remain hypotheses, not constructions:

- modify a universal KZG/PLONK-style wrapper so one affine target term is reachable by valid
  proofs but has no public decomposition over the scaled anchors;
- instantiate an LVA-WE gadget whose verification key has low coefficient rank and whose target
  decomposition is witness-dependent;
- compile a transparent RankFold/sumcheck proof into such a target-separated wrapper without a
  circuit-linear verifier-specific CRS;
- prove ciphertext/share consistency during a distributed setup ceremony without restoring
  trace-linear material or an online secret holder.

The 2025/1364 LVA-WE framework confirms that small linearly verifiable relations can induce WE
gadgets, but RankLock still needs an exact target-separated wrapper, projective future inputs,
malicious n-1-corrupt activation, and complete cost accounting.
