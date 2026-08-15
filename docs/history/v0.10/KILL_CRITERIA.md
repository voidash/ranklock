# Kill criteria and decision gates

The project should be stopped, narrowed, or reframed if any of the following is established.

## Prior-art kill criteria

1. OHMG already gives projective, publicly evaluable, malicious-generator-secure, width-independent
   evaluation for large-prime-field circuits at comparable or lower concrete cost.
2. Existing aHMAC/HSS garbling plus a known malicious compiler already yields the target theorem
   without a new primitive.
3. Argo/BABE supports the same general RankIR class and not merely specialized verifier structure.
4. A known “garbled SNARK/IOP” construction already gives near-native prover/evaluator cost and
   sub-megabyte conditional release under the same assumptions.

## Technical kill criteria

1. Vector authentication still requires one exponentiation/HSS restricted multiplication per rank
   term. That would make 645,221 terms too slow and collapse the main novelty.
2. The trace-binding/sumcheck layer requires a general SNARK whose prover or verifier dominates the
   original computation without a compensating storage benefit.
3. Malicious-generator soundness requires per-instance proofs or cut-and-choose, restoring linear
   setup material.
4. Projective input translation restores `Omega(lambda)` bits per field bit or permits cross-session
   label synthesis.
5. The final construction needs one honest online signer. That returns to v0.8's trust model.

## Concrete performance kill criteria

After a native implementation:

- retained material >= 16 MB without a strong generality advantage over Argo;
- evaluator runtime > 10× native;
- setup bandwidth reduction < 10× versus security-normalized Mosaic;
- peak RAM remains in the multi-hundred-gigabyte range;
- proof/input overhead dominates the verifier-specific material.

## Milestones

### M0 — algebraic core — PASS

Exact low-rank compiler and transcript-bound folding.

### M1 — vector-authentication microprotocol — OPEN

A real cryptographic protocol for a batch of rank terms, with attacks and a reduction.

### M2 — malicious distributed setup — OPEN

No trusted generator, active security, public activation proof.

### M3 — projective 132-byte input — OPEN

One active value per byte with security under reuse and malicious selection.

### M4 — full SP1 artifact — OPEN

Serialized artifact, measured setup/evaluation/storage.

### M5 — Strata regtest and paper theorem — OPEN

Drop-in bridge test, Bitcoin NACK execution, proof, prior-art separation, independent review.

## RankFold-specific kill criteria

Kill the breakthrough claim if any of the following remains true after the PCS experiment:

- verifier/opening work requires Ω(R) group or HSS operations;
- the only viable lock is a generic SNARK/WE or generic garbled verifier with no concrete win over
  Argo, BABE, aHMAC, or BitVMX-GC;
- the prover exceeds 10× native field work without a credible SIMD/GPU path below 2×;
- multilinear openings or distributed commitment generation introduce more than 1 MiB retained
  material for the SP1 relation;
- malicious distributed activation requires an honest online signer rather than one honest setup
  contributor.
