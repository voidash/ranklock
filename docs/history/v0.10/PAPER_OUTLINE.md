# Paper outline

## Working title

**RankLock: Width-Free Conditional Disclosure for Algebraic Programs**

## Abstract structure

1. Problem: Bitcoin garbled locks obtain compact on-chain fraud proofs but require enormous
   off-chain material or expensive per-gate succinct evaluation.
2. Primitive: rank-folded, distributed, projective CDS for algebraic programs.
3. Theorem: artifact and expensive evaluation depend on unique templates/depth rather than gate
   count, with malicious `n-1`-corrupt setup security.
4. Compiler: exact low-rank extraction and machine-checkable certificates.
5. Evaluation: real SP1 Groth16/Strata replacement with measured setup, storage, RAM and runtime.

## Contributions section

### C1. Width-free conditional disclosure

Formal definition and construction.

### C2. Rank-folded vector authentication

Proof that committed nonlinear residuals can be authenticated with expensive cost independent of
width/instance count.

### C3. Publicly auditable distributed activation

Dishonest-majority setup protocol and proof that accepted artifacts implement the canonical program.

### C4. Certified RankIR compiler

Automatic template extraction, exact algebraic certificates, trace generation, and projective input
binding.

### C5. Strata evaluation

Drop-in Mosaic API, real counterproof fixture, Bitcoin Core regtest NACK execution.

## Main technical sections

1. Definitions and adversarial model
2. RankIR and low-rank template certificates
3. Committed native traces and the RankFold sumcheck
4. Binding multilinear openings and RankFold-native conditional disclosure
5. Distributed setup and malicious security
6. Projective input composition
7. Bitcoin conditional-output binding
8. Formal reductions
9. Implementation
10. Evaluation and limitations

## Required baselines

- Mosaic at its configured malicious-security parameters
- ordinary half-gates/authenticity-only Boolean garbling
- OHMG
- authenticated tensor gates
- HSS succinct garbling
- Argo MAC
- BABE
- Duty-Free Bits applied to relevant baselines
- dishonest-majority arithmetic garbling

## Required measurements

- total setup bytes, not only retained tables
- retained bytes per operator pair
- circuit/program bytes
- CPU-hours and wall-clock setup
- evaluator latency and throughput
- peak and steady-state RAM
- projective input material
- proof/activation material
- cold-start download and evaluation
- failure/restart behavior
- security parameter normalized to at least 128 bits

## Venue bar

The target is a top cryptography/security venue, not an application note. Without a new primitive
and reduction, the work should be framed as systems/compiler research rather than submitted with a
cryptographic-breakthrough claim.
