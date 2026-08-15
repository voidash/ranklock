# Research Backlog and Kill Criteria

## v0.22 current P0 lane

### P0-MASK-FUSION-1 — final-output-mask fusion or impossibility

Construct an Embryo evaluator that consumes the masked DFB outputs without retaining the current 228,083-byte CRT output-mask state, with a complete correctness and privacy proof. Measure every replacement byte.

Kill the two-slot sub-MiB route if no sound fusion/compression exists; the current standalone total is 1,356,472 bytes including the historical 748-byte manifest.

### P0-ADAPT-1 — adaptive two-instance theorem or attack

Prove or break adaptive, auxiliary-input and same-scalar two-instance security for the exact switch system, including any mask-fusion layer.

### P0-MPC-1 — real active ceremony

Compile the exact generator into an active `n-1`-corrupt MPC backend and measure communication, runtime, memory, abort and output binding.

### P0-GRAPH-2 — Bitcoin completion

Authenticate exactly one future label per bit, bind all contexts, serialize BABE/validity-first graph data, and execute every branch on Bitcoin Core regtest.

> Older backlog entries below are historical or parallel lanes unless explicitly referenced by the v0.22 handoff.


## P0-FIELD-1 — Compare limb and dual-field CRT bridges

**Native-model phase: complete in v0.13.2.**

Delivered:

- canonical-bound 3×85 multiplication;
- rank-5 evaluation/interpolation convolution replacing nine schoolbook products;
- exact 2×127 split-product challenger;
- dual-field CRT model with canonical outputs, a maximal 254-bit quotient range under the current residual theorem, and an executable split-brain barrier;
- packed 16-bit logical range/carry inventories and sensitivity analysis;
- elimination of the redundant quotient canonical-slack proof, with adversarial regressions;
- backend-independent executable constraint ledgers that reproduce the route estimates;
- native witness benchmarks and adversarial tests.

Current decision: 3×85 rank-5 is the provisional single-field baseline; 2×127 remains a real-backend challenger; CRT is blocked on cross-PCS equality.

Remaining evidence upgrade: compile the two selectable routes into the same real cryptographic proof backend, preserving `constraint_backend.py` semantics, and measure physical rows, prover/verifier time, memory, proof size and SRS/fixed-table degree.

Kill a route if its complete proof/lock cost is dominated or it cannot compose with the conditional backend.

## P0-PCS-1 — Real non-native commitment route

**Question:** Can the 3×85 rank-5 representation be integrated into a real proof/PCS over BLS12-381 Fr without destroying the concrete advantage?

Deliverables:

- real proof-system constraints for rank-5 multiplication, squaring, reduction, equality and inversion witnesses;
- an automated comparison against the transparent event labels and counts in `constraint_backend.py`;
- canonical ranges for inputs/outputs, a 254-bit internal quotient bound, and signed carries;
- side-by-side 3×85 rank-5 and 2×127 split-product benchmark;
- row/column counts, fixed table size, prover memory/time, proof size and verifier work;
- complete verifier schedule including canonical parsing and SHA-256.

Kill criteria:

- more than 2 million native nonlinear constraints for the known verifier subtotal before parsing/SHA;
- prover overhead clearly worse than 5× native verification without a compensating storage theorem;
- PCS/conditional backend cannot consume the field representation compactly.

## P0-CRT-BIND-1 — Cross-field common-table binding

**Question:** Can two PCS traces over BN254 Fr and BLS12-381 Fr be bound to one canonical value table more cheaply than the single-field route?

Required construction:

- one binding commitment/digest to canonical chunks;
- verified equality of every value used by both residue traces;
- degree, setup and challenge-timing specification;
- conjunction with the eventual conditional lock;
- complete proof and verifier cost.

Kill criteria:

- requires hashing the full table independently in both circuits at a cost exceeding rank-5 3×85;
- introduces a third generic proof/recursion layer with no end-to-end advantage;
- equality depends on an honest coordinator or shared prover memory rather than cryptography.

## P0-CDS-1 — Conditional disclosure for conjunction of opening/PPE equations

**Question:** Can the complete phased proof relation release one static secret without a generic garbled verifier?

Investigate:

- composition of KZG-opening witness encryption for many openings;
- witness encryption from linearly verifiable arguments/PPE systems;
- batching only after value publication;
- dynamic statements and projective inputs;
- extractability and malicious setup.

Kill criteria:

- ciphertext/artifact grows linearly with trace rows;
- runtime requires an online secret holder;
- construction reduces to generic iO/FHE-scale machinery with no practical route;
- security assumes the coordinator/signers are honest rather than cryptographic enforcement.

## P0-PROJ-1 — Sub-megabyte projective input layer

Integrate a Duty-Free-Bits-class translation for:

- 132 existing Strata bytes;
- any exposed terminal/opening scalars;
- beacon and session binding.

Kill criterion: complete per-game public input material remains above 1 MiB without a stronger theorem-level advantage.

## P0-BATCH-1 — Reduce verifier equations without unsound challenge reuse

Current result: same-point KZG batching needs values bound before `rho`, adding a phase/beacon.

Explore:

- native multi-opening PCS;
- deterministic commitment-derived coefficients with a proof of no cancellation;
- accumulator/folding schemes whose values are intrinsically bound;
- whether one blockchain beacon can safely supply multiple sequential challenges across block heights.

## P0-COMP-1 — Full RankVM-to-phased-AIR compiler

Compile:

- sparse pairing verifier;
- dynamic MSM and subgroup/curve checks;
- canonical compressed proof parsing;
- SHA-256/Blake3 public-value policy;
- byte/range constraints;
- memory layout and output predicate.

Every table shared across proof components must reuse commitments.

## P1-SETUP-1 — Malicious distributed activation

Define and implement:

- canonical artifact digest;
- n-party contribution protocol;
- one-honest-party secrecy;
- proof of correct artifact generation;
- abort/restart and erasure semantics.

## P1-BEACON-1 — Concrete Bitcoin beacon schedule

Specify block-height commitments, burial depth, grinding model, reorg behavior, poles/retries and liveness impact for two or three sequential challenges.

## P2-INTEGRATION-1 — Strata and Bitcoin execution

Only after the primitive survives P0:

- Rust bridge adapter;
- real counterproof fixture;
- regtest NACK Tapscript spend;
- comparison with Mosaic/Argo/BABE.

## P0-CDS-2 — Fixed authenticated-input LVA-WE instantiation

**Question:** Does the 2025 linearly-verifiable-SNARK WE framework instantiate the complete RankLock relation with acceptable CRS, witness generation, and decryption work?

Required accounting:

- fixed statement: program/VK, deposit/session context, transport public keys;
- witness: 132 completed signatures, selected bytes, invalidity trace/proof;
- authentication gadget cost;
- trace-proof gadget cost;
- encryption key/CRS bytes;
- ciphertext bytes;
- prover field and group operations;
- decryption group operations/pairings;
- extractability and setup assumptions.

Kill criteria:

- decryption performs `O(R)` group operations rather than native field work;
- CRS/activation material is linear with an unacceptable constant;
- BIP340/adaptor authentication requires a generic garbled EC verifier comparable to BABE's residual component;
- assumptions or malicious setup are weaker than the target model.

## P0-CDS-3 — Commitment-oblivious projective opening lock

Construct or rule out a primitive supporting public updates to future arbitrary KZG commitments without revealing the KZG-WE session.

The standard one-randomizer affine updater is ruled out by A-012. A surviving construction must not expose two reusable standard headers under the same hidden randomizer.

### P0-CDS-2A — Algebraic input-authentication gadget mapping

The current candidate authenticates all 132 byte witnesses with:

```text
1 aggregate BLS signature gadget
1 inner-product gadget binding apk = sum_i(A_i + v_i B_i)
```

Required next deliverables:

- exact LVA-WE encryption key/CRS elements for both gadgets and their conjunction;
- proof that witness variables `v_i` are shared with every trace constraint;
- one-time projective token-delivery construction under malicious abort/retry;
- distributed generation/audit of affine token shares with one honest contributor;
- direct cost comparison with verifying the 132 BIP340 adaptor signatures through Argo/BABE machinery.

Kill criteria:

- token delivery requires publishing two affine tokens for any `(session, coordinate)`;
- encryption key/CRS or decryption work scales with the trace width at an unacceptable constant;
- the added pairing-friendly token catalog remains above 1 MiB after the best applicable projectivization;
- malicious setup needs an honest online issuer.

## P0-PROJ-2 — Instantiate Duty-Free-Bits vector OLE for 132 authenticated bytes

Deliverables:

- real vector-OLE implementation/configuration over the chosen LVA-WE scalar field;
- mapping from the existing 132 selected bytes or their bit labels into receiver inputs;
- exact base-OT, extension, malicious-check, framing and authentication bytes;
- fresh-state and burn semantics across abort/retry;
- distributed additive affine sender shares with one honest contributor;
- benchmarked selected-token derivation and aggregate BLS witness generation;
- complete retained/runtime material compared with the 1.62 MiB naïve catalog.

Kill criteria:

- concrete projective material exceeds one MiB before the trace lock;
- the protocol permits two affine evaluations under one sender state;
- setup requires an honest online sender after the counterproof is known;
- the scalar-field or authentication relation cannot compose with the selected LVA-WE backend.

## P0-CDS-4 — Complete fixed RankVM-invalidity relation

**Question:** can the future authenticated bytes and a proof of RankVM invalidity be witness variables of one fixed relation whose verifier-specific key/CRS stays below the remaining 935,830-byte envelope?

Required deliverables:

- complete relation, including parsing, SHA-256/Blake3 policy, memory, and invalid result;
- knowledge/soundness theorem and exact challenge schedule;
- exact LVA/PPE gadget inventory;
- encryption key, CRS, ciphertext, decryption, proof-generation, and setup costs;
- malformed proof, statement substitution, replay, and selective-failure tests;
- comparison against BABE/Argo and generic recursive-proof alternatives.

Kill if direct material exceeds the cap and recursion/gadgets provide no complete cost or generality advantage.

## P0-PROJ-3 — Final noninteractive projectivization

Replace `co_ot.py` with the exact malicious-receiver-secure projectivization required by Duty-Free Bits. Define distributed sender generation, public cold-start delivery, transcript commitment, burn-on-abort semantics, and communication constants—not only asymptotic leading terms.

Kill if an honest online sender remains necessary after activation.

## P0-SETUP-1 — Malicious distributed fixed-relation setup

Generate the protected secret sharing, projective affine states, relation bases, scaled bases, and setup proofs with security against all but one malicious contributor. Produce a public activation transcript and specify restart/blame semantics.

Kill if correctness needs 181-copy cut-and-choose or trace-linear retained proofs.

## P0-CDS-5 — Historical v0.16 target; superseded by P0-CDS-6

The nonidentity-target requirement below is retained as history and is not normative after the split-basis KZG result.


**Question:** Can complete RankVM invalidity be proven by a knowledge-sound wrapper whose final
verification equation has only future G1 terms, a constant/polylog fixed-G2 anchor basis, and a
nonidentity target with no public decomposition over the scaled anchors?

Required deliverables:

- exact proof relation and extractor statement;
- canonical transcript/challenge schedule and context binding;
- concrete wrapper prover and verifier;
- fixed-G2 coefficient matrix and exact rank;
- proof, universal CRS, verifier-specific key, lock, ciphertext, and runtime sizes;
- target-separation argument and regression tests;
- comparison against KZG/PLONK identity-target and Groth16 dynamic-G2 blockers;
- complete RankVM-invalidity fixture, not a synthesized target relation.

Kill criteria:

- identity-valued final equation with no conditional entropy;
- a future/dynamic G2 proof element;
- public target preimage over the scaled anchors;
- circuit-linear verifier-specific CRS without a major theorem or concrete advantage;
- generic recursion + known LVA/PPE-WE with no new result over BABE/Argo/HSS garbling.

## P0-SETUP-2 — Historical ciphertext route; superseded by P0-SETUP-3

The ciphertext payload is removed in v0.17. The normative activation task is the session-derived-key relation in P0-SETUP-3.


Extend P0-SETUP-1 beyond common-scalar anchor correctness. Every contributor's encrypted
fault-secret/adaptor share must be publicly proven consistent with:

- its public share commitment;
- the same low-rank lock scalar used on its anchors;
- the aggregate Bitcoin fault/adaptor public point;
- the deployment/session transcript;
- one-shot abort and retry semantics.

The current executable attack shows that a valid anchor proof plus arbitrary ciphertext is
undetectable before the future witness. Reject any activation protocol that relies on eventual
witness availability for correctness checking.

## P0-CDS-6 — Real fixed-statement one-sided wrapper

Implement the full one-sided proof/circuit for authenticated future inputs and complete RankVM invalidity. Replace every proxy in `fixed_statement_wrapper_candidate.py` with measured proof-system objects.

Required deliverables:

- outer-curve implementation and exact encodings;
- complete canonical parsing, SHA/transcript, range, and subgroup constraints;
- real public-transcript verifier;
- rank-two final PPE and knowledge-soundness theorem;
- real conditional/LVA key generation and unlock;
- proof, CRS, key, runtime, RAM, and network accounting;
- end-to-end valid/invalid and attack fixtures.

Kill if the point/transcript wrapper exceeds the one-MiB envelope with no major generality advantage.

## P0-SETUP-3 — Activation NIZK and ceremony

Instantiate the NP relation in `activation_nizk_frontier.py`. Verify every proof before funding, bind the proof-system/program digest into the manifest, and implement epoch burn/restart and contributor receipts.

Required theorem: all but one contributor may be malicious; no accepted contributor can substitute an unlock-dead secp key without breaking proof soundness.

## P0-CDS-7 — Purpose-built LVA alternative

In parallel with public-transcript verification, investigate whether a new one-sided linear interactive proof can make challenge-dependent prover responses projectively computable. Do not reuse the existing prover with hidden challenges; that path is killed.
