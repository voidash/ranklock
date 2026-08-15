# Attack Ledger

Every item in this ledger either has an executable regression test or is explicitly marked as a model-only barrier.

## A-001 — reusable affine-label forgery

**Status:** inherited negative result.

Seeing the zero label and basis labels reveals the affine deltas, allowing arbitrary label synthesis. This killed the naïve reusable register-label design.

## A-002 — unbound RankFold terminal opening

**Status:** inherited executable attack.

If an opening oracle does not cryptographically bind terminal values to the committed tables, a prover can choose terminal values after challenges and make the final relation pass.

Evidence: `tests/test_rankfold.py`.

## A-003 — IPA proof is small but verifier remains linear

**Status:** inherited measured/model result.

The Grumpkin IPA opening is logarithmic in bytes but its verifier still performs an `O(R)` generator MSM, moving rather than removing the expensive work.

Evidence: `tests/test_ipa_pcs.py` and historical v0.10 docs.

## A-004 — one-beacon Sumcheck message-tree explosion

**Status:** inherited cost barrier.

Precommitting every adaptive degree-three Sumcheck message function creates an exponential tree. At 15 rounds the dense commitment model is tens of gigabytes.

Evidence: `tests/test_beacon_sumcheck.py`.

## A-005 — hidden source-group scalar barrier

**Status:** algebraic-model barrier.

Pairings can expose the mixed term in `GT`, but ordinary generic bilinear operations do not map it back to `[r]P` in the source group. This explains the remaining hidden-scalar garbling in BABE/Argo-style designs.

Evidence: `tests/test_hidden_scalar_lower_bound.py`.

## A-006 — AIR late-binding quotient forgery

**Status:** executable break; fixed by `phased_air.py`.

Legacy `prove_generic_air` accepted `zeta` before committing the quotient. An invalid trace can choose a constant quotient tailored only to that point and pass.

Evidence: `test_legacy_helper_has_a_real_late_binding_attack` in `tests/test_phased_air.py`.

## A-007 — tuple-permutation late-binding quotient forgery

**Status:** executable break; fixed by `phased_permutation.py`.

Legacy `respond_tuple_permutation` committed `Z/Q` after `zeta` was known. A non-permutation with `Z=1` and point-tailored constant `Q` passes all legacy checks.

Evidence: `test_legacy_tuple_permutation_has_late_binding_forgery`.

## A-008 — split-brain memory composition

**Status:** executable break; fixed by `phased_memory.py`.

The legacy bundle independently proved:

- an invalid access table is a permutation of itself; and
- an unrelated table is a valid sorted-memory AIR.

No commitment equality linked the tables, so the combined verifier accepted.

Evidence: `test_legacy_memory_bundle_accepts_unrelated_permutation_and_air_tables`.

## A-009 — known batching coefficient permits false-value cancellation

**Status:** executable break; safe schedule modeled by `batched_opening.py`.

For two claimed values and known `rho`, choose errors `(-rho*d, d)`. The weighted aggregate is unchanged, so one KZG batch equation accepts although both individual values are wrong.

Evidence: `test_known_batching_scalar_allows_false_values_to_cancel`.

## A-010 — incomplete handoff / irreproducible status

**Status:** fixed in v0.13.

The visible v0.12 handoff omitted `field.py`, `kzg_we_model.py`, and `projective_kzg_we.py`; the historical “76 tests” claim could not be reproduced. v0.13 reconstructs the minimum foundations, clearly marks formal models, and has a clean 61-test baseline.

## A-011 — unbound dual-field CRT split brain

**Status:** executable barrier; safe CRT witness requires shared canonical bytes.

Two independent native-field proofs can each satisfy their multiplication congruence while encoding completely different integers. CRT exactness applies only after both residues are bound to the same canonical `x,y,z` and the same 254-bit bounded quotient.

Evidence: `test_unbound_dual_proofs_can_describe_two_unrelated_multiplications`.

## Open attack lanes

- polynomial degree-bound substitution;
- beacon grinding/selective abort;
- non-native carry/range wrap attacks once encoded in AIR;
- multi-point opening batching;
- projective input equivocation;
- malicious setup generator substitution;
- conjunction/composition attacks in the future conditional lock;
- cross-session replay and beacon reuse.

## A-012 — reusable KZG-WE public-update session recovery

**Status:** executable algebraic-family barrier.

If one fixed randomizer is reused to publicly produce standard KZG-WE headers at two distinct points, their difference reveals `r[1]_2`. The KZG-WE session for every future commitment/value is then publicly computable without an opening.

Evidence: `tests/test_commitment_oblivious_lower_bound.py`.

Scope: this does not rule out one-time selected projective delivery or stronger functional/witness encryption.

## A-013 — unauthenticated future-input witness substitution

**Status:** executable break; authentication requirement modeled.

Moving a future proof/input from the WE statement into an existential witness makes a static relation possible, but without a session-bound authentication token the adversary substitutes any convenient invalid input.

Evidence: `tests/test_authenticated_witness_lift.py`.

## A-014 — statement-specific KZG-WE cannot by itself provide static activation

**Status:** construction-timing barrier.

After safe batching, the current memory proof needs only four KZG opening statements. Those statements are generated after trace commitments, openings, and the value-binding beacon. Standard KZG-WE encapsulation requires the protected secret at that later time.

Evidence: `tests/test_unified_memory_opening.py` and `tests/test_static_kzg_we.py`.

## A-013 — Repeated affine input-token release

**Broken idea:** issue pairing-friendly authentication tokens affine in a byte value and allow retries to reveal more than one token for the same `(session, coordinate)`.

**Attack:** from tokens at values `v0 != v1`, compute the signature slope

```text
(H*b_i) = (sigma_{i,v1} - sigma_{i,v0}) / (v1-v0)
```

and derive a valid token for every value at that coordinate.

**Executable evidence:** `tests/test_algebraic_input_auth.py::test_two_values_for_one_coordinate_reveal_every_token_for_that_session`.

**Decision:** token delivery must be one-time per session and coordinate. Abort/retry burns the selection state or refreshes the session tag/key material. A public full token catalog is not an authentication mechanism.

## A-014 — Reuse of affine VOLE sender state

**Broken idea:** use one affine sender state `(a_i,b_i)` for multiple input-vector evaluations or retries.

**Attack:** two outputs at distinct inputs recover

```text
b_i = (t_i' - t_i)/(v_i' - v_i)
a_i = t_i - v_i b_i,
```

allowing every value key/token for that coordinate to be generated.

**Executable evidence:** `tests/test_vole_input_auth.py::test_two_receiver_vectors_recover_affine_sender_secret_and_all_values`.

**Decision:** affine VOLE state is strictly one-shot per deposit/session and is burned on every terminal or retry path. Fresh session material is mandatory for retry.

## 2026-08-05 — Future-statement KZG hybrid requires an online secret holder

**Attack / failure:** standard KZG-opening WE binds its ciphertext to the future commitment, point, and value. Static setup cannot encrypt the trace share before those objects exist.

**Executable evidence:** `hybrid_conditional_lock.py` succeeds only through one-shot `OnlineTraceEncapsulator`, which retains the trace share until the future statement exists.

**Decision:** direct KZG-WE hybrid is a failure certificate, not the target construction. Move future commitments/openings into the witness of one fixed relation.

## 2026-08-05 — Per-coordinate DLEQ setup proofs are unnecessary overhead

**Shortcut tested:** verify all scaled relation bases with one Fiat–Shamir random linear combination and one aggregate DLEQ proof.

**Attack surface:** a malicious setup could alter scaled bases. The aggregate error cancels only when the derived polynomial in `rho` vanishes; random-oracle soundness is bounded by approximately `(n-1)/q`.

**Decision:** use `batched_inner_product_we.py` as the reference fixed-linear setup proof. It is not a malicious distributed-setup protocol.

## 2026-08-05 — Direct fixed-linear full-trace compilation exceeds target

**Result:** even after DLEQ batching, one coordinate per known multiplication consumes 8.27 MiB; one per current logical event consumes 159.82 MiB.

**Decision:** kill direct one-coordinate-per-event compilation. Require folding/recursion or a structured relation gadget. Scope: concrete gadget cost barrier, not a universal lower bound.

## 2026-08-05 — Parallel “breakthrough” checkpoint fails clean-room validation

**Evidence:** extracted checkpoint produced 109 passes and two failures in its new R1CS/IPA backend.

**Decision:** reject the archive as a release baseline and reject its breakthrough label. Retain only independently passing formal context/PPE components, clearly marked FORMAL MODEL.

## A-015 — Public target decomposition destroys low-rank PPE secrecy

**Broken idea:** treat any fixed nonidentity GT target as sufficient conditional entropy.

**Attack:** if public G1 points `X_j` satisfy

```text
product_j e(X_j, U_j) = T,
```

then the public scaled anchors reveal

```text
product_j e(X_j, r U_j) = T^r.
```

The attacker derives the AEAD key without the future proof.

**Executable evidence:**
`tests/test_low_rank_ppe_lock.py::test_public_target_preimage_is_a_complete_break`.

**Decision:** the wrapper target must be nonidentity **and target-separated**: no satisfying
decomposition over the scaled anchors may be public before a valid future proof.

## A-016 — Same-scalar setup proof does not certify the encrypted fault share

**Broken idea:** accept a valid common-scalar proof for all scaled anchors as a complete malicious
activation proof.

**Attack:** a corrupt generator keeps the valid key/proof and replaces the 48-byte ciphertext.
Public activation still accepts the anchor proof, but every future satisfying witness fails AEAD
authentication. The failure is undetectable until the future proof exists.

**Executable evidence:**
`tests/test_low_rank_ppe_lock.py::test_same_scalar_proof_does_not_certify_ciphertext_correctness`.

**Decision:** P0-SETUP-1 must prove ciphertext/plaintext-share consistency and binding to the
activated Bitcoin fault/adaptor condition, not merely common-scalar anchor generation.

## 2026-08-07 — Statement-span decomposition breaks low-rank PPE secrecy

**Broken idea:** compress all witness bases into scaled anchors without checking whether the public statement bases lie in the same span.

**Attack:** decompose every statement-side G2 base over the witness anchors, aggregate the public statement G1 terms by anchor, and pair them with the published scaled anchors. This reconstructs the accepting session without a witness.

**Executable evidence:** `tests/test_split_basis_ppe_we.py::test_low_rank_kzg_anchor_expansion_leaks_session`.

**Decision:** replace the old nonidentity-target criterion with split-basis/session separation.

## 2026-08-07 — Publishing scaled rho breaks basis-separated KZG

**Broken idea:** publish the setup-scaled statement basis to remove the post-statement encapsulator.

**Attack:** pair the public `C-y` statement element with the published `r[rho]` base and derive the payload session directly.

**Executable evidence:** `tests/test_basis_separated_kzg.py::test_publishing_scaled_rho_breaks_the_ciphertext_after_statement_exists`.

**Decision:** basis separation alone does not solve static timing; move future objects into a fixed relation witness.

## 2026-08-07 — Raw hidden Fiat–Shamir challenges are incompatible with the existing prover

**Broken idea:** hide all verifier challenges in the conditional key and otherwise run the published one-sided prover unchanged.

**Attack/failure:** every audited challenge enters nonlinear prover work such as grand products, hidden-point evaluations, inversions, shifts, or quotient commitments.

**Executable evidence:** `hidden_challenge_audit.py` and `tests/test_hidden_challenge_audit.py`.

**Decision:** verify the public transcript inside the fixed wrapper or design a new purpose-built LVA protocol.

## 2026-08-07 — Transcript/pairing split brain

**Broken interface:** hash one set of proof encodings while pairing another set of points.

**Attack:** the transcript remains bound to the honest proof while the final PPE consumes substituted elements.

**Executable evidence:** `tests/test_shared_proof_binding.py::test_split_brain_view_can_hash_one_proof_and_pair_another`.

**Decision:** canonically parse each proof element once and share the typed object across all gadgets.
