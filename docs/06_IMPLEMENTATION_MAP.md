# Implementation Map

## v0.22 real DFB/Embryo modules

| Module/file | Evidence | Role |
|---|---|---|
| `dfb_real.py` | REPRODUCED full-dimension execution | fixed-key AES CCRH, chunk/extract/fold/body switch, canonical program/decode serializers and parsers |
| `embryo_real.py` | REPRODUCED real BN254 application | 3,077 affine outputs, curve-secret check, 256 conditional Jacobian maps, final `[r]A` |
| `generate_v022_results.py` | DETERMINISTIC ARTIFACT GENERATOR | emits program, decoder, standalone bundle, future labels and machine report; replays from bytes |
| `test_real_dfb_embryo.py` | 8 REPRODUCED TESTS | golden vector, exact accounting, late binding, byte replay, parser mutation, polynomial/group correctness |
| `v022_real_dfb_embryo_execution.json` | GENERATED EVIDENCE | hashes, sizes, timings, memory, execution and claim boundary |

Critical distinction: `DfbProgram` is the 449,779-byte join payload; `DfbDecodeState` is the 228,083-byte final-mask state required for standalone decoding. No fusion theorem exists in v0.22.


## Safe protocol wrappers

| Module | Purpose | Evidence class |
|---|---|---|
| `beacon.py` | Domain-separated, rejection-sampled field challenges | REPRODUCED utility |
| `phased_air.py` | Commit-before-beacon local AIR | FORMAL MODEL |
| `phased_permutation.py` | Two-beacon tuple permutation | FORMAL MODEL |
| `phased_memory.py` | Shared-commitment memory composition | FORMAL MODEL |
| `batched_opening.py` | Value-before-`rho` KZG batching schedule | FORMAL MODEL |

## Exact arithmetic/compiler modules

| Module | Purpose | Evidence class |
|---|---|---|
| `rank_ir.py` | Certified bilinear-rank IR | EXACT model |
| `tower_compiler.py` | BN254 Fq12 rank-54/rank-48 kernels | EXACT model |
| `pairing_rank.py` | Sparse/residue-witness pairing schedule | EXACT identities + ESTIMATE schedule |
| `nonnative_field.py` | Schoolbook limb/carry foreign multiplication | EXACT integer model + legacy ESTIMATE |
| `field_bridge.py` | Canonical output binding, bounded internal quotient, and complete 3×85 logical cost | EXACT witness + ESTIMATE |
| `low_rank_convolution.py` | Generic fixed-point rank-`2n-1` convolution | EXACT algebraic model |
| `low_rank_field_bridge.py` | Rank-5 3×85 foreign multiplication with reduced-quotient schedule | EXACT witness + ESTIMATE |
| `split_limb_field.py` | Exact 2×127 split-product challenger | EXACT witness + ESTIMATE |
| `crt_field.py` | Exact dual-field CRT lemmas, 254-bit quotient bound, and split-brain attack | EXACT model / BROKEN unbound variant |
| `crt_bridge.py` | Owner-side canonical binding and CRT cost lower bounds | EXACT witness + ESTIMATE |
| `bridge_comparison.py` | Route ranking, geometry sweep and break-even analysis | ESTIMATE + REPRODUCED benchmark |
| `constraint_backend.py` | Executable multiplication/linear/tuple-lookup ledgers for bridge routes | REPRODUCED transparent constraint trace |

## Formal cryptographic backends

| Module | Warning |
|---|---|
| `kzg_we_model.py` | Exponents are public; no computational security |
| `ppe_normal_form.py` | Algebra/PPE shape only |
| `projective_kzg_we.py` | Cost model only |
| `ipa_pcs.py` | Reference PCS/negative verifier-cost result, not deployment |

## Legacy broken helpers retained for regression attacks

- `generic_air.py`
- `one_beacon_air.py`
- `tuple_permutation.py`
- `memory_air.py`

Do not use their one-shot proving APIs in new protocol code.

## Tests by research claim

- `test_rank_compiler.py` — rank decomposition correctness.
- `test_pairing_rank.py` — sparse kernel identities/schedule.
- `test_nonnative_field.py` — exact schoolbook limb/carry multiplication.
- `test_field_bridge.py` — canonical output, bounded quotient, and complete 3×85 logical inventories.
- `test_low_rank_convolution.py` — rank-`2n-1` convolution and tamper rejection.
- `test_low_rank_field_bridge.py` — complete rank-5 3×85 composition.
- `test_split_limb_field.py` — exact 2×127 challenger.
- `test_crt_bridge.py` — canonical-output/bounded-quotient CRT linkage and missing-cross-PCS warning.
- `test_bridge_comparison.py` — break-even and geometry decisions.
- `test_constraint_backend.py` — emitted constraint counts and adversarial tamper rejection.
- `test_phased_air.py` — AIR forgery and phase fix.
- `test_phased_permutation.py` — permutation forgery and phase fix.
- `test_phased_memory.py` — split-brain composition and shared commitment fix.
- `test_batched_opening.py` — batching cancellation and safe phase.

## v0.14 conditional-disclosure lane

- `kzg_we_conjunction.py` — formal single/multi-opening KZG-WE and same-point aggregation.
- `static_kzg_we.py` — fixed-commitment projective positive model and public-update leakage.
- `commitment_oblivious_lower_bound.py` — two-header randomizer-base recovery.
- `authenticated_witness_lift.py` — fixed-relation input-authentication model.
- `unified_memory_opening.py` — shared second-beacon `zeta`, value publication, and 72-to-4 batching.
- `tests/test_kzg_we_conjunction.py` — correctness, linear cost and cancellation attack.
- `tests/test_static_kzg_we.py` — fixed-commitment selection and dynamic-commitment barrier.
- `tests/test_commitment_oblivious_lower_bound.py` — reusable-update session recovery.
- `tests/test_authenticated_witness_lift.py` — substitution and authenticated lift.
- `tests/test_unified_memory_opening.py` — unified schedule, four-opening conjunction and tampering.
- `results/cds_research.json` — machine-readable CDS inventory/decision.

## v0.15 concrete conditional-lock modules

| Module | Evidence | Purpose |
|---|---|---|
| `real_secp.py` | REPRODUCED | strict secp256k1 arithmetic, DLEQ, ECDH helpers |
| `co_ot.py` | REPRODUCED / scoped baseline | real online binary OT transcript |
| `projective_vole_lock.py` | REPRODUCED | 132-byte OT-to-affine selected-witness path |
| `bn254_real.py` | REPRODUCED | actual dependency-free BN254 pairing arithmetic |
| `real_kzg_we.py` | REPRODUCED | KZG commitments/openings and opening WE |
| `hybrid_conditional_lock.py` | REPRODUCED failure certificate | concrete online-encapsulator barrier |
| `inner_product_we.py` | REPRODUCED | fixed linear relation WE reference |
| `batched_inner_product_we.py` | REPRODUCED / ROM | one aggregate DLEQ setup proof |
| `static_linear_conjunction.py` | REPRODUCED | no-online-holder fixed linear input+trace lock |
| `fixed_relation_budget.py` | EXACT accounting | one-MiB relation envelope |
| `direct_relation_barrier.py` | EXACT accounting | direct full-trace route kill |
| `groth16_projective_lock.py` | FORMAL MODEL / ESTIMATE | recursive PPE/context candidate |

## v0.16 public-correlation and low-rank PPE lane

| Module | Evidence | Purpose |
|---|---|---|
| `public_correlation_rank.py` | EXACT algebraic model | coefficient-rank lower bound and low-rank escape |
| `low_rank_ppe_lock.py` | REPRODUCED real BN254 + EXACT bytes | rank-k fixed-G2 PPE conditional lock |
| `verifier_shape_frontier.py` | EXACT interface classification | identity-target, dynamic-G2, and target-preimage blockers |
| `correlation_seed_experiment.py` | REPRODUCED checkpoint generator | consolidated v0.16 result JSON |
| `tests/test_public_correlation_rank.py` | EXACT regression | independent and structured rank cases |
| `tests/test_low_rank_ppe_lock.py` | REPRODUCED adversarial tests | correctness, tampering, target leak, setup selective failure |
| `tests/test_verifier_shape_frontier.py` | EXACT regression | wrapper-interface blocker classification |
| `results/public_correlation_checkpoint.json` | GENERATED EVIDENCE | rank, real PPE, cost, and decision checkpoint |

## v0.17 fixed-statement wrapper modules

| File | Evidence | Role |
|---|---|---|
| `split_basis_ppe_we.py` | REAL BN254 | generalized split-basis PPE session, same-scalar key, statement-span attack |
| `basis_separated_kzg.py` | REAL BN254 | rho-separated KZG experiment and static-timing failure |
| `one_sided_wrapper_frontier.py` | REAL final equation + PROFILE | future-G1/rank-two fixed-G2 target and CRS/proof envelope |
| `hidden_challenge_audit.py` | EXACT protocol-shape audit | kills unchanged-prover hidden-Fiat–Shamir shortcut |
| `transcript_mini_lock.py` | ESTIMATE | public transcript/point-binding relation budget |
| `shared_proof_binding.py` | REAL BN254 interface regression | one canonical object shared by transcript and pairings |
| `ciphertext_free_fault_key.py` | REAL BN254 + secp256k1 | derives Bitcoin key from accepting pairing session |
| `activation_nizk_frontier.py` | EXECUTABLE NP RELATION | pre-funding malicious activation statement and ceremony |
| `fixed_statement_wrapper_candidate.py` | COMPOSED ESTIMATE | per-deposit and reusable-CRS envelope |
