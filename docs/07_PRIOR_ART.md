# Prior-Art Collision Matrix

Checked against official IACR ePrint metadata and classical multiplication references through 2026-08-07. Abstract-level comparison is not sufficient for a novelty claim; full theorem/proof review remains required.

| Work | What it already establishes | Collision with RankLock | Remaining possible distinction |
|---|---|---|---|
| Toom-Cook evaluation/interpolation multiplication (classical) | Multiplication of two degree-`n-1` polynomials from `2n-1` fixed point products and linear interpolation | The 3×85 rank-5 convolution is a direct application, not novel | Only its complete RankLock trace/conditional-lock composition and measured system effect may contribute |
| Mosaic, ePrint 2026/812 | Malicious cut-and-choose for Bitcoin garbled circuits; on-chain labels independent of copy count via polynomial correlation and adaptor signatures | “Remove 181× on-chain labels” is not novel | Reduce off-chain storage/setup under the same malicious model |
| Argo MAC, ePrint 2026/049 | EC homomorphic-MAC translation and >1000× more efficient garbled SNARK verifier primitive | “Use EC MACs to shrink verifier garbling” is known | General RankVM trace/conditional-lock compiler or lower complete cost |
| BABE, ePrint 2026/065 | Witness encryption for linear pairing relations plus small garbled EC scalar multiplication; ~1000× cheaper off-chain than 42 GiB BitVM3 | “Specialize Groth16 into WE + small GC” is known | Eliminate remaining source-group garbling or support general programs with comparable cost |
| Duty-Free Bits, ePrint 2026/476 | Projectivizes large-field garbling; 45× BABE and 20× Argo encoding improvements | “Efficient projective large-field inputs” is known | Compose projectivity with succinct trace lock and malicious activation |
| OHMG, ePrint 2025/2338 (rev. 2026-07-22) | UC authenticity-only arithmetic/tensor/EC garbling, at most one ciphertext per arithmetic gate | Authenticity-only arithmetic/tensor garbling is known | Retained material and expensive work sublinear/polylog in trace length |
| Succinct HSS garbling, ePrint 2025/442 | 1 bit/gate Boolean garbling and removal of typical lambda overhead for arithmetic; slower evaluation | Succinct garbling is known | Near-native evaluator plus fully succinct conditional disclosure |
| WARPfold, ePrint 2024/354 | Folding/IVC with multiple non-native fields and range-checked interfaces between them | “Use multiple proof fields and range-check the interface” is known | Determine whether dual-field CRT helps the conditional-lock setting concretely |
| KZG witness encryption, ePrint 2024/264 | One-group-element WE ciphertext for one KZG opening; one pairing for encryption/decryption | “Use a KZG opening as a decryption witness” is known | Dynamic conjunction of trace/PPE equations with projective inputs and malicious setup |
| Row-reduced n-party garbling, ePrint 2025/829 | 25% row reduction and improved preprocessing with arbitrary corruptions | 3n*kappa rows per AND are known | Avoid one authenticated row per scalar gate entirely |
| AuthOr, ePrint 2025/775 | Authenticity-only Boolean garbling with up to ~98% circuit-dependent savings | Dropping privacy for bandwidth is known | Algebraic trace folding and static conditional lock |
| Arithmetic Garbling from Bilinear Maps, ePrint 2019/082 | Inner-product predicates over exponentially large fields and generic arithmetic garbling | Large-field/bilinear arithmetic garbling is known | Concrete symmetric/projective public evaluation with width-free material |
| Silent NISC / OT extension, ePrint 2019/1159 | Short setup plus party-local expansion of OT/correlation views | Short-seed correlation expansion is known | RankLock requires one public cold-start artifact with no party-private seed after activation |
| FOLEAGE PCG, ePrint 2024/429 | Parties stretch short PCG seeds into large MPC preprocessing correlations | Efficient PCG preprocessing is known | Public verifier-key expansion is a different interface; private setup seeds may still help the ceremony |
| Noninteractive inner product, ePrint 2023/072 | Public input encodings plus retained party secret state; malicious upgrade with sublinear ZK | NISC inner-product and malicious state validation are known | Eliminate retained secret state and make the artifact universally publicly evaluable |
| LVA-SNARK WE framework, ePrint 2025/1364 (rev. 2026-02-18) | Modular WE gadgets induced by linearly verifiable arguments; constant-size keys/ciphertexts in applications | Small targeted LVA-WE gadgets are known | Complete target-separated RankVM wrapper, projective Bitcoin input, malicious activation, and concrete advantage |
| PLONK knowledge soundness, ePrint 2024/994 | KZG/PLONK variants with ROM knowledge-soundness from falsifiable assumptions | Knowledge-sound universal KZG wrappers are known | Their usual identity-valued pairing equation has no direct conditional entropy |
| Universal zkSNARK non-malleability, ePrint 2024/721 | Simulation extractability for optimized universal PLONK/Marlin-style systems | Real-world universal wrapper security is known | Compile to target-separated low-rank conditional disclosure rather than ordinary verification |

## Official references

- https://www.lirmm.fr/arith18/papers/Chung-Squaring.pdf
- https://eprint.iacr.org/2026/812
- https://eprint.iacr.org/2026/049
- https://eprint.iacr.org/2026/065
- https://eprint.iacr.org/2026/476
- https://eprint.iacr.org/2025/2338
- https://eprint.iacr.org/2025/442
- https://eprint.iacr.org/2024/354
- https://eprint.iacr.org/2024/264
- https://eprint.iacr.org/2025/829
- https://eprint.iacr.org/2025/775
- https://eprint.iacr.org/2019/082
- https://eprint.iacr.org/2019/1159
- https://eprint.iacr.org/2024/429
- https://eprint.iacr.org/2023/072
- https://eprint.iacr.org/2025/1364
- https://eprint.iacr.org/2024/994
- https://eprint.iacr.org/2024/721

## Current novelty hypothesis

No cited work is presently known to provide the full intersection:

```text
fully succinct static conditional disclosure
+ near-linear native large-field evaluation
+ polylog expensive cryptography
+ future projective Bitcoin inputs
+ public cold-start evaluation
+ malicious n-1-corrupt setup
+ no online authority
+ production verifier compiler
```

This is a hypothesis, not a novelty claim.

## v0.17 one-sided wrapper collision check

### A Flexible SNARK via the Monomial Basis (ePrint 2023/1255)

The paper already supplies the proof-system shape motivating the current wrapper profile: universal/updateable monomial-basis CRS, 10 G1 plus 20 scalar proof elements, two-pairing verification, no prover-defined G2 proof element in the final interface, and prover work dominated by circuit-linear MSMs.

Therefore RankLock cannot claim novelty for the one-sided SNARK itself. A possible contribution must instead be the complete fixed-statement conditional composition:

```text
projective future inputs
+ complete RankVM invalidity
+ shared transcript/final-PPE proof object
+ split-basis conditional session
+ session-derived Bitcoin key
+ n−1-corrupt activation.
```

### KZG-opening witness encryption

KZG-opening WE demonstrates that an identity-normalized pairing relation can still yield conditional disclosure. The v0.16 “nonidentity target” requirement was therefore not a general cryptographic criterion. v0.17 reframes the requirement as statement-session separation from the scaled witness-anchor span.

### Novelty warning

Generic “SNARK verifier plus witness encryption” and LVA-gadget composition are prior art. The paper-level claim survives only if the complete RankLock compiler or security theorem materially improves generality, setup, retained material, or evaluation over existing constructions such as BABE/Argo while retaining Mosaic-level malicious security.
