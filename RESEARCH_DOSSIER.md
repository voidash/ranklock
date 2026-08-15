# RankLock Research Dossier

**Current snapshot:** v0.22.0  
**Date:** 2026-08-11  
**Decision:** real full-dimension DFB/Embryo execution is complete, but two standalone slots exceed one MiB under the implemented output-mask interface. The primary gate is now secure output-mask fusion or a decisive impossibility result.

## v0.22 decisive update

The exact switch-system gate is no longer hypothetical. v0.22 emits a 449,779-byte canonical DFB join program, a 228,083-byte standalone final-mask state and a 677,862-byte standalone bundle. The bundle is reparsed with future input-label files and reproduces all 3,077 Embryo field outputs, 256 conditional Jacobian maps and final BN254 `[r]A`.

The execution corrects the v0.21 construction envelope:

```text
q=2 join-only + historical manifest:       900,306 B
q=2 standalone + historical manifest:    1,356,472 B
standalone over one MiB:                    307,896 B
```

Thus the former 1,023,186-byte figure is historical paper-derived accounting. A sub-MiB two-slot route now requires a proved application-level fusion that consumes the final masked outputs without retaining one CRT mask residue per affine output. Adaptive two-instance security, active MPC generation, authenticated Bitcoin labels and regtest remain open.

> The remainder of this dossier preserves earlier snapshot analysis. Where it conflicts with the v0.22 update above, the v0.22 checkpoint and `STATUS.json` are normative.

**Snapshot:** v0.18.0
**Date:** 2026-08-08
**Decision:** breakthrough target not met. The arithmetic, canonical-point, scalar-verifier, and typed-transcript gates pass under an executable BN254-direct model, but the previous sub-megabyte figure is only a coordinate envelope—not an instantiated conditional key. The primary route is now a validity-first transaction-graph inversion paired with a real positive projective Groth16 backend; the fallback is a hard-YES-secure RankVM witness PRF.

## Executive thesis

RankLock is not an incremental Boolean-garbling optimization. It seeks a new static cryptographic object:

> a projective conditional lock for large-field programs whose retained material and expensive cryptographic verification are polylogarithmic in trace length, while public evaluators execute the computation with near-linear native work and no online secret holder.

The Strata application is a maliciously secure replacement for Mosaic's off-chain garbled-circuit infrastructure without weakening its adversarial model.


## v0.18 decisive update

v0.18 replaced the two largest remaining wrapper estimates with executable models:

```text
BN254 cofactor-one G1 binding:       267 logical nonlinear/range rows per point
one-sided scalar verifier:          161 nonlinear rows
official BN256 Poseidon2 transcript: 32 permutations / 7,680 nonlinear rows
arithmetic/transcript envelope:     862,693 bytes
margin to one MiB:                  185,883 bytes
```

The official Poseidon2 BN256 known-answer test is reproduced. Each G1 proof object is parsed once and the same typed object drives transcript hashing and final pairing verification.

That size result is **not** a complete conditional-disclosure construction. The audit exposed two semantic blockers:

1. the identity-normalized final pairing equation does not automatically provide a hidden accepting session; and
2. the fixed per-deposit invalidity relation is already a YES instance before the future counterproof is selected, so ordinary NO-instance witness-encryption secrecy is insufficient.

The old 66-byte-per-coordinate slope only applies to scalar-witness gadgets; it does not cover future G1 proof elements with unknown discrete logarithms. Therefore the 862,693-byte value is classified only as an arithmetic/transcript coordinate envelope.

The strongest protocol pivot is **validity-first counterproof resolution**. Strata's existing counterproof connector already has one immediate key path and one N/N relative-timeout path. The candidate swaps their meanings:

```text
current:   INVALID proof -> immediate NACK; otherwise timeout ACK
candidate: VALID proof   -> immediate ACK; otherwise timeout NACK
```

This removes complement verification and aligns the conditioned branch with positive Groth16 projective systems. It still requires a real projective backend, complete size/setup measurements, malicious distributed activation, Rust transaction-graph integration, and Bitcoin Core regtest execution. The hard-YES RankVM witness-PRF target remains the cryptographic fallback.

## v0.17 decisive update

The old rule “the PPE target must be nonidentity” is rejected. The correct condition is whether the statement-side accepting session is algebraically obtainable from the scaled witness-anchor span. The real split-basis implementation and KZG attack make this distinction executable.

A one-sided proof shape is now the leading wrapper candidate: all prover-defined group elements are in G1 and the final fixed G2 coefficient rank is two. Hiding its raw Fiat–Shamir challenges is not viable because every challenge enters nonlinear prover work, so the current candidate verifies the public transcript in a fixed mini-lock.

The current envelope survives only narrowly: under the explicit 300-constraint-per-G1 and 66-byte-per-coordinate proxies, static plus future proof material is 1,036,471 bytes. A 400-constraint-per-G1 point-binding gadget exceeds the cap.

The encrypted fault-secret payload has been removed. The accepting pairing session deterministically derives a secp256k1 fault scalar. This converts malicious activation into a one-time ordinary public proof of anchor/session/public-key consistency before funding.

## Current construction candidate

The proof-side candidate is a phased polynomial trace argument:

1. compile the canonical verifier into sparse large-field obligations;
2. execute a fixed-width trace with sorted memory accesses;
3. commit trace, quotient, and access-table columns;
4. derive AIR and tuple-compression challenges from external beacons;
5. commit memory grand products and quotients;
6. derive permutation evaluation points from a later beacon;
7. bind opening values before any KZG batching challenge;
8. reduce verification to a small set of opening/PPE equations;
9. compile those equations into a static conditional-disclosure lock.

Steps 1–7 have exact or formal executable models. Step 8 has both formal batching and an actual BN254 KZG-opening-WE microimplementation. A direct hybrid still requires an online encapsulator. Step 9 now works for a fixed linear predicate, but the complete RankVM-invalidity relation and malicious setup remain open.

## v0.16 conditional-lock frontier

### Real projective input path

A 132-byte execution runs 1,056 binary OTs over secp256k1 and uses 257,418 public and interactive bytes. This is an online measurement backend, not the final noninteractive Duty-Free-Bits construction.

### Real KZG-opening witness encryption

Actual BN254 pairing arithmetic verifies openings and decrypts a 112-byte KZG-WE ciphertext. The concrete XOR hybrid demonstrates that statement-bound KZG-WE still needs an online holder when the future commitment does not yet exist.

### Fixed-relation lift

Moving future byte/trace data into the witness of one setup-time relation removes the post-statement holder. The concrete fixed-linear prototype uses a 48-byte ciphertext and has an exact 134,604-byte retained model for 132 future bytes plus 64 trace scalars. The trace relation is not RankVM invalidity.

### Setup-proof batching and direct-route kill

One aggregate DLEQ proof lowers the reference key slope from 130 to 66 bytes per relation scalar and raises the one-MiB trace-width envelope to 13,912. The current multiplication-only verifier inventory would still require 8.27 MiB, while all logical events require 159.82 MiB. Direct one-coordinate-per-event compilation is therefore killed.

### Public correlation rank dichotomy

An exact algebraic model now separates arbitrary independent verifier bases from structured
low-rank bases. A public group-linear expander needs at least the desired coefficient rank;
standard silent PCGs keep party-private seeds and do not directly satisfy public cold start.

### Real low-rank fixed-G2 PPE lock

For fixed G2 bases of rank `k`, the real BN254 lock retains only `k` scaled anchors and decrypts
with `k` pairings. The 11-term / 2-anchor envelope is 1,719 bytes. This is not a complete
RankVM relation or a WE theorem.

### Target separation and malicious activation

The target must be nonidentity and have no public decomposition over the scaled anchors. KZG/
PLONK identity checks and Groth16 dynamic-G2 proofs miss different parts of the interface. The
common-scalar setup proof also permits undetectable ciphertext replacement, so share-consistency
activation remains open.

### Formal recursive candidate

A transparent/folding proof followed by a Groth16 wrapper could reduce the fixed lock relation to one PPE and a replay-bound context. The repository contains only an exponent-space model and size envelope. The parallel checkpoint proposing this route had two failing R1CS/IPA tests and was rejected as a release baseline.

## Reproducibility

```text
261 tests across 71 files passing in reproducible per-file batches
```

The archive manifest, test suite, generated result documents, and transparent field-bridge constraint traces reproduce from a clean checkout.

## Positive results

### Sparse verifier arithmetic

The current known arithmetic schedule is:

```text
12,997 Fq products in sparse pairing work
25,889 Fq products in the known verifier subtotal
```

The subtotal excludes complete canonical parsing, SHA-256/Blake3, and byte-binding policy.

### Rank-5 3×85 foreign-field bridge

Three 85-bit limbs form degree-two polynomials. Five fixed point products determine the full convolution; all remaining evaluation and interpolation is native-field linear.

```text
5 native nonlinear products per generic Fq multiplication
76 logical tuple/range lookups per product under 16-bit chunks
17 linear relation events per product
129,445 native products for the known subtotal
```

This removes 103,556 multiplication gates from the old nine-product schoolbook model. Canonical byte/limb binding, signed carry ranges, and the full modeled relation are executable and tamper-tested. A second optimization removes the quotient's redundant canonical-slack proof: canonical `x,y,z`, exact integer equality, and a 254-bit nonnegative bound already force the unique quotient. This saves 20 lookup events and six linear relations per product relative to the canonical-quotient reference.

The current known-subtotal inventory is:

```text
1,967,564 logical lookup events
440,113 linear relation events
```

A real proof backend is still missing; these are not physical row counts.

### 2×127 split-product challenger

BLS12-381 Fr is large enough for exact 127×127-bit limb products. Four variable products plus explicit low/high chunks and normalization enforce the integer multiplication relation.

```text
4 native products + 206 logical lookups + 26 linear relations
```

It saves one multiplication but adds 130 logical lookup events relative to rank-5 3×85. In the symbolic `lookups + w*multiplications` model, it wins only for `w > 130`. Real lookup packing could still change the outcome.

### Dual-field CRT

BN254 Fr and BLS12-381 Fr are coprime and their product is approximately `2.3956*q^2`. Two congruences prove exact multiplication only after both traces are bound to the same canonical values.

```text
2 native products + 63 owner-side logical lookups + 20 linear relations
```

The arithmetic theorem and transparent constraint traces are exact/reproduced. The canonical output remains `< q`, while the internal quotient is only constrained to 254 bits. This is the largest quotient range certified by the present CRT residual bound: the safety ratio is about 1.811 at 254 bits and below one at 255 bits. However, the two native ledgers only consume host-equal words; a cryptographic common-table commitment/equality proof and dual conditional-lock conjunction are absent. CRT therefore remains non-selectable. The optimistic free-shared-table lower bound is 49 logical lookups and is not a construction.

### Backend-independent constraint ledger

`constraint_backend.py` emits and executes the same multiplication, linear, boundary, and logical tuple/range relations used by the cost inventory. It detects tampering and asserts exact agreement with the route estimators.

This upgrades the cost models from disconnected formulas to executable constraint traces. It does **not** upgrade them to cryptographic proofs: there is no lookup argument, PCS, degree bound, zero knowledge, or proof byte measurement.

### Explicit protocol phases

Commitment-before-beacon wrappers and shared commitments close executable late-binding and split-brain attacks in the formal exponent-space model.

### Conditional-disclosure conjunction

The AIR and permutation arguments now share a second-beacon evaluation point. After opening values are published and a third beacon derives safe batching coefficients:

```text
72 individual KZG openings
4 distinct evaluation points
4 aggregate opening statements
384 bytes of KZG-WE headers in the 96-byte formal cost model
4 decryption pairings
```

This proves that opening-equation count is not the dominant CDS blocker. The aggregate statements are future objects, so standard KZG-WE cannot encapsulate the fault secret during static setup.

### Static KZG-WE barrier and authenticated lift

Two reusable standard headers under one randomizer reveal `r[1]_2`; this makes every future KZG-WE session public. A fixed commitment can support one-time projective point/value selection, but an arbitrary future commitment remains unsupported.

An alternative is to keep the WE statement fixed and place future bytes, transport authentication, and invalidity proof in the witness. The package demonstrates the substitution attack without authentication and a one-time-signature relation model that prevents retargeting. The generic transformation is prior-art-adjacent to the 2025 LVA-WE gadget framework; novelty must come from complete cost/security and Strata specialization.

## Why this is not the breakthrough

The project still lacks:

- a real binding/extractable PCS and degree bounds;
- a real range-lookup implementation and physical benchmark;
- a static conditional-disclosure construction for future arbitrary commitments or a complete fixed authenticated-input LVA-WE instantiation;
- sub-megabyte projective future inputs;
- malicious distributed activation;
- a complete verifier compiler and Strata/Bitcoin execution;
- a formal end-to-end security proof.

## Current research fork

### P0-PCS-1 — real single-field backend

Compile 3×85 rank-5 and 2×127 into one backend, preserving the transparent ledger semantics, then compare physical rows, lookup packing, fixed-table degree, prover memory/time, proof size, and verifier work.

### P0-CRT-BIND-1 — common-table equality

Construct or rule out a compact commitment/equality proof binding two field-specific PCS traces to one canonical chunk table. Shared prover memory or host-equal Python values are not sufficient.

### P0-CDS-2 — fixed authenticated-input LVA-WE

Map the complete 132-signature authenticated invalidity relation into the 2025 gadget framework and measure CRS, prover group work, ciphertext, decryption work, and malicious-setup assumptions.

### P0-CDS-3 — commitment-oblivious projective WE

Only pursue a new direct primitive if the fixed-relation route misses the cost/security target. Standard reusable affine KZG-WE updates are ruled out in their one-randomizer form.

## Novelty bar

Evaluation/interpolation multiplication, non-native arithmetic, and multi-field proof interfaces are known ingredients. A paper-worthy result must be the complete intersection:

```text
fully succinct static conditional disclosure
+ near-native large-field trace execution
+ polylog expensive cryptography
+ projective future Bitcoin inputs
+ public cold-start evaluation
+ n-1-corrupt malicious setup
+ no online authority
+ production verifier compiler
```

## Navigation

- `README.md` — repository entry point.
- `HANDOFF.md` — next-agent instructions.
- `AGENTS.md` — research rules.
- `STATUS.json` — machine-readable truth ledger.
- `docs/05_ATTACK_LEDGER.md` — breaks and fixes.
- `docs/08_RESEARCH_BACKLOG.md` — next experiments.
- `docs/12_FIELD_BRIDGES.md` — complete route comparison.
- `docs/13_LOW_RANK_FIELD_BRIDGE.md` — rank-5 construction and proof sketch.
- `docs/14_CONSTRAINT_BACKEND.md` — executable constraint ledger and limitations.
- `docs/15_CDS_CONJUNCTION.md` — dynamic conjunction compression.
- `docs/16_STATIC_KZG_WE_BARRIER.md` — static timing/lower-bound scope.
- `docs/17_AUTHENTICATED_WITNESS_LIFT.md` — fixed-relation alternative.
- `docs/18_PARALLEL_COORDINATION.md` — other-agent coordination.

- `docs/19_ALGEBRAIC_INPUT_AUTH.md` — fixed-relation algebraic input authentication and one-time-token attack.

- `docs/20_VOLE_PROJECTIVE_INPUT.md` — Duty-Free-Bits vector-OLE delivery candidate and one-shot-state attack.

- `docs/32_SPLIT_BASIS_PPE_WE.md` — corrected conditional-session criterion.
- `docs/35_ONE_SIDED_SNARK_WRAPPER.md` — future-G1/rank-two fixed-G2 wrapper frontier.
- `docs/37_TRANSCRIPT_MINI_LOCK.md` — tight transcript/point-binding budget.
- `docs/38_CIPHERTEXT_FREE_FAULT_KEY.md` — session-derived secp key.
- `docs/39_ACTIVATION_NIZK.md` — public activation relation.
- `docs/41_V017_DECISION.md` — current decision and next gates.
