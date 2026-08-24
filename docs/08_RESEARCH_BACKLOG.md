# Research Backlog and Kill Criteria

## v0.25.2 current funds-safety lane

### P0-STRATA-E2E-1 — production proof-to-ACK wiring and live matrix

The library function `export_ack_from_verified_unlock` binds a verified
RankLock unlock to ACK export, but no production service or CLI invokes it.
The consumer side is now present: compose requires a host RankLock export
root, mounts it read-only into all three bridges, and pins Bitcoin Core 31.1
by registry digest. No deployed producer invokes the verified exporter, and
STRATA-010..020 remain `not_executed`.

Required deliverables:

- wire the deployed proof-verification result to
  `export_ack_from_verified_unlock` without exposing the direct exporter;
- provision the positive lock with `ack_proof_session_context` so the verified
  statement and complete ACK destination are one identity;
- bind the one-shot RankLock directory, context, deposit, graph, committee,
  chain observation, and durable burn/authorization state across restart;
- remove or make operationally unavailable every setup-entropy path that can
  recreate the ACK preimage;
- pin and attest Bitcoin Core 31.1 plus the exact Strata revision in deployment;
- execute STRATA-010..020 against the real service boundary, including crash,
  restart, reorg, malformed proof, alternate context, timeout, fee/CPFP,
  rollback witness, and concurrent-use cases;
- retain logs, exact commands, versions, hashes, and failure evidence in the
  canonical result files.

Funding is killed—not merely downgraded—if an unverified caller can export the
ACK, setup entropy remains a live release capability, any E2E case is absent or
modeled-only, rollback witnesses are not independently deployed, or the
release gate does not remain fail-closed on missing evidence.

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

## P0-GRAPH-3 — Shared-selection timeout and two-world economic closure

Replace the broken per-slot NACK/`AllNackd` owner-payout path with a side-by-side
graph version in which every counterproof and owner payout consume the shared
contest-payout outpoint. The selected counterproof creates one resolution
connector and consumes the deposit, allocating its exact amount immediately to
the committed recovery-policy script. ACK and CSV timeout spend the resolution
connector exclusively; ACK creates a slash-only authorization output, and
timeout conflicts with slash while omitting claim-payout. Descriptor control
remains a separate acceptance gate.

Required deliverables:

- Rust `CounterproofV2`, resolution connector, slash-authorization connector,
  `ACKV2`, `SlashV2`, and timeout-settlement parents with fresh full-transaction
  presignatures;
- exact ordered watchtower/counterproof roster, one CP/ACK CPFP descriptor per
  alternative, and no reuse of the two RankLock query-slot ids for that roster;
- a typed resolution connector with exact value, Taproot policy, control block,
  ACK path and CSV timeout path verified from consensus bytes;
- exact ordered output/principal map, value conservation, fee/CPFP bounds and
  bounded cleanup or explicit accounting for every unselected counterproof
  funding output;
- Bitcoin Core tests for shared-`P` double-spend exclusion, CSV boundaries,
  ACK/timeout and timeout/slash conflicts, parent/witness mutation, fee
  pressure, reorg and recovery;
- an ACK-created slash authorization outpoint so Slash cannot race timeout
  before ACK, omission of claim-payout from timeout, and exclusive reservation
  of the stake input through the ACK/slash horizon;
- an exhaustive subject-unique signing allowlist and verified destruction of at
  least one deposit-signing share/nonces/backups before funding, or a confirmed
  cutover of legacy deposit into a fresh script-only state, so a hidden
  CooperativePayout signature cannot preempt counterproof selection;
- a fresh versioned counterproof input/ContestV2 outpoint and categorical
  exclusion of every v1 counterproof, ACK, NACK, Slash signature, partial
  signature, adaptor value and runtime parent;
- global exclusive reservation of stake against Unstaking and every other
  game's Slash through the ACK/slash finality and reorg horizon;
- exhaustive maximal-compatible-terminal enumeration proving every declared
  principal obligation is paid or remains spendable, rather than inferring
  priority from pairwise conflicts;
- an explicit resolution of the indistinguishable `valid + withheld` versus
  `invalid + absent` timeout worlds using consensus validity, audited threshold
  availability, or fully reserved two-world insurance.

The Python model is EXACT abstract conflict/value evidence only. Kill any claim
that it proves Bitcoin acceptance or universal funds safety, any graph where
two counterproofs confirm, any timeout that can resurrect owner payout, and any
policy that calls stranded or indefinitely locked value preserved.

The local terminal enumerator now satisfies the finite-roster portion of this
task: it produces five maximal traces and seven semantic mappings for the
two-alternative reference, requires a disposition for every positive terminal
outpoint, binds declared principals to committed beneficiaries, and proves the
two no-ACK semantic worlds share one timeout trace. Atomic all-reserve selection
now assigns every reserve exactly and the reference satisfies its declared
local policy with zero abandoned reserve value. This does **not** discharge the
deliverable above or establish protected value. Protected-baseline authority,
per-principal loss allowances, the service-fee schedule/baseline, and exact
by-horizon CSV/reorg/fee execution remain explicit blockers, and the Python
fixture is not a canonical projection of the Rust graph.

Current executable progress is **REPRODUCED research evidence**: typed v0.26
NUMS connectors, six exact transaction templates, a private-field
`V026Graph` assembler, an independently reconstructed transaction projection,
and an exact spender matrix pass 97 tx-graph and 54 connector tests. Six
real-Core cases independently validate both counterproof alternatives, the
mature owner path, ACK, first-valid CSV timeout, ACK-created Slash ancestry,
the intended shared-input conflicts, and the confirmed-Contest relay boundary
for the measured 10,690-WU v3 counterproof. The Slash case also proves that a
separate valid live-key spend can consume `K` and defeat Slash. Therefore this
progress discharges neither global stake reservation nor any activation gate.
Remaining P0-GRAPH-3 work includes authenticated terminal economics,
runtime/state serialization, the upstream
Slash-v2 ASM activation, exact presign/erasure and legacy-material evidence,
fee/package/reorg qualification, terminal wealth enumeration, and the
validity/withholding economic theorem.

The first runtime-adjacent slice is intentionally negative-only. The frozen
`StructurallyVerifiedFundingBlockedV1`/fifteen-code namespace remains
byte-compatible and fails closed for the current graph; bridge-sm derives the
current sixteen-code `StructurallyVerifiedFundingBlockedV2`, and DB persists it
in a separate versioned namespace with first-writer-wins replay/conflict
detection. Live write capabilities are not deserializable. Neither version
exposes admission or action and therefore neither discharges
`RuntimeAdmissionUnimplemented`.
Before any active state-machine work, freeze the canonical v0.26 plan/wire
schema and supply authenticated external Claim/D/Q/K, controller, fee,
presign/erasure, and legacy-material evidence. The live FoundationDB CAS test
must also execute in a qualified environment; its local harness currently
hangs.

## P0-GRAPH-4 — Consume a confirmed subject receipt in the versioned threshold runtime

The subject-bound counterproof slice now verifies the receipt's exact
BridgeProof transaction id and can combine the unforgeable receipt with exact
Bitcoin Core transaction bytes, Merkle-valid inclusion, active-chain identity,
minimum confirmation depth, and a repeated reorg check. That capability is
point-in-time evidence only. A fail-closed executor helper now additionally
checks every ACK-subject field, rechecks Bitcoin before and after immutable
witness CAS, and rejects a conflicting first writer. No valid receipt executes
that composed path, no duty requires it, and the lower-level witness store
remains independently callable.

Required deliverables:

- generate and positively verify a valid receipt with a qualified prover, or
  bind an authorized network prover to explicit capacity, latency, quota, and
  transcript evidence;
- define a new versioned duty carrying the exact threshold-v3 selected subject,
  verify the receipt, and create the live canonical-confirmation capability;
- bind released signatures to the selected commitment, exact `R` outpoint,
  ACK template, and BIP341 sighash before publication;
- repeat the active-chain check immediately before irreversible publication,
  and define reorg rollback, stale-capability invalidation, and retry behavior;
- atomically adopt the exact ACK witness through the selected-commitment
  first-writer-wins store; and
- keep the legacy preimage ACK profile and threshold-v3 receipt profile in
  distinct wire, state, persistence, and activation namespaces.

The two current Core regressions qualify only the confirmation mechanics, and
two pure regressions qualify only subject/CAS classification. They do not
provide a valid receipt, enforced runtime consumption, atomic Bitcoin/FDB
finality, or funding authority.

## P0-CDS-7 — Purpose-built LVA alternative

In parallel with public-transcript verification, investigate whether a new one-sided linear interactive proof can make challenge-dependent prover responses projectively computable. Do not reuse the existing prover with hidden challenges; that path is killed.
