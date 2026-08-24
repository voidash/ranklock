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

## A-017 — Witness-blind fixed-NACK recognition

**Status:** closed in the local v0.25.2 installer; live STRATA-010..020
qualification remains open.

**Broken interface:** the NACK classifier and `process_counterproof_nackd`
transition compared only the expected BIP141 `txid`. A `txid` excludes SegWit
witness data, so this did not establish that the exact pre-signed NACK witness
was the transaction being classified or accepted by the state machine.

**Executable attack:** start from a correctly finalized NACK, flip one witness
byte, and preserve the unsigned transaction. The malicious transaction keeps
the same `txid` while its `wtxid` changes.

**Regression evidence:**

- `classify_tx_rejects_counterproof_nack_with_modified_witness`;
- `event_rejected_same_txid_with_modified_witness`;
- `integration/alpen-validity-first-f94c-v025/pending/p4-nack-classifier.diff`;
- `integration/alpen-validity-first-f94c-v025/pending/p4-nack-witness.diff`.

**Decision:** reconstruct the finalized fixed NACK from the persisted state
signatures and compare the complete `bitcoin::Transaction` independently at
both the classifier and transition boundaries. A txid-only match is never
sufficient evidence for a fixed witness path.

## A-018 — Unmanifested executable integration deltas

**Status:** closed locally.

**Broken interface:** `run_bundle_checks.sh` verified hashes only for paths
already named in the standalone bundle manifest. All post-format P4 diffs were
absent from that list, including the code that enforces ACK and NACK witness
binding. Modifying or replacing an unlisted executable delta did not affect
the manifest check.

**Regression evidence:** the bundle check now compares the sorted manifest
paths with every distributable file before hashing, and
`test_manifest_covers_every_distributable_bundle_file` requires exact coverage
plus explicit inclusion of all three P4 diffs. The current 27-entry bundle
passes this check.

**Decision:** checksum verification without a complete-file-set assertion is
not accepted as bundle-integrity evidence. Both omission and hash drift must
fail closed.

## A-019 — Overwritable and path-unsafe ACK export state

**Status:** closed in the local exporter; deployed producer and rollback
witness qualification remain open.

**Broken interface:** setup commitments were written with a predictable
`.partial` file followed by replacement, so a second publication could replace
the commitment used to build a graph. The unlock exporter opened SQLite at an
unchecked caller path and used the same overwrite-shaped file publication.
Two contexts whose full bindings differed but whose bridge/counterproof/ACK
txids produced the same filename could race after both ledger commits. The
proof-gated entry point also accepted an expected commitment without requiring
that the same bytes had already been published for graph setup.

**Regression evidence:**

- `test_commitment_publication_is_write_once`;
- `test_commitment_publication_rejects_insecure_existing_file`;
- `test_exporter_rejects_world_writable_root`;
- `test_exporter_rejects_symlinked_ledger`;
- `test_concurrent_unlock_publishers_cannot_overwrite_each_other`;
- `test_proof_gated_export_requires_the_published_graph_commitment`;
- `test_visible_unlock_after_directory_sync_failure_requires_exact_retry`.

**Decision:** require a private real directory and owner-only inode-checked
SQLite ledger; publish commitments and unlocks by write-once hard-link; verify
private ownership, mode and exact bytes after publication; bind proof export to
the already-published setup commitment; and permanently conflict a commitment
after an ordinary publication collision. If the exact authorized bytes are
already visible but directory durability reporting fails, retain the durable
context binding and require an exact retry—do not pretend an observable secret
was never published.

## A-020 — Silent two-phase abort-witness failure

**Status:** closed locally.

**Broken interface:** when phase-two authorization failed, the recovery path
attempted to finalize the slot as aborted and anchor that state at the rollback
witnesses. A broad nested `except Exception: pass` discarded any failure of
that recovery. The caller saw only the original phase-two error and could not
distinguish a durably witnessed abort from an unanchored local transition.

**Regression evidence:**
`tests/test_two_phase_authorization.py::test_two_phase_sidecar_reports_abort_anchor_failure`.

**Decision:** preserve both the primary failure and recovery failure in an
`ExceptionGroup`, raise a typed `TwoPhaseSidecarError`, and never report the
primary rejection as if fail-closed recovery had completed successfully.

## A-021 — Integer-to-zero-byte setup entropy coercion

**Status:** closed locally; production setup remains prohibited.

**Broken interface:** `derive_setup_payload` began with `bytes(entropy)`.
Python defines `bytes(32)` as thirty-two zero bytes, so a caller that violated
the type hint by supplying integer `32` silently received a syntactically valid
but public setup secret instead of an error. Context indices similarly used
`int(value)`, accepting booleans and numeric strings, while `AckContext`
coerced mutable and non-byte transaction identifiers on demand.

**Regression evidence:**

- `test_setup_refuses_integer_bytes_coercion`;
- `test_setup_refuses_noncanonical_indices`;
- `test_ack_context_requires_immutable_exact_bytes`.

**Decision:** secret-bearing APIs accept only explicit byte containers, stored
context identifiers require immutable exact bytes, u32 fields require real
integers rather than coercible values, and the variable-length entropy input
is length-prefixed under a bumped v2 derivation domain. No runtime coercion may
turn an input-type error into valid key material, and v1 setup material is not
silently reinterpreted.

## A-022 — Optional provenance in passing matrix evidence

**Status:** closed locally.

**Broken interface:** the evidence verifier compared the Core and Strata E2E
bitcoind hashes only when both report identities supplied a hash. It used the
same optional pattern for the build/E2E Strata commit. A future report with
passed commands could omit the identity field and skip the cross-report check
instead of failing closed.

**Regression evidence:**
`tests/test_verify_v0252_evidence.py::test_verifier_rejects_passing_core_report_without_binary_identity`.
The E2E runner now records the resolved executable, SHA-256 and version in its
environment probe and report identity.

**Decision:** any phase containing passed cases must identify the pinned
Bitcoin Core executable and, for Strata, the exact pinned commit. Missing
execution may remain honestly unavailable or not executed; passing evidence
may never omit provenance to bypass a comparison.

## A-023 — Stale deterministic artifacts accepted as release inputs

**Status:** closed locally.

**Broken interface:** generator-critical source changed after the public
committee and split-scalar conformance artifacts were produced. The committed
artifacts therefore embedded obsolete generator-code commitments, while a
previous clean-archive report described a different archive and could not
establish reproducibility for the current tree.

**Executable evidence:** two independent clean extractions regenerated the
same bytes, but ten packaged artifacts differed from those fresh results. The
first current-tree clean-archive run consequently failed only
`packaged_fixtures_match_clean_generation`. After regenerating the public
fixtures and their evidence, a new clean extraction passed all 15 checks and
519 tests; the final regression count is updated with this continuation's
archive-boundary test.

**Decision:** source changes covered by a generator-code commitment require
regenerating every dependent conformance artifact and evidence report. A green
report for another archive digest is historical evidence, never permission to
reuse stale binaries.

## A-024 — Post-build evidence packaged into the archive it attests

**Status:** closed locally.

**Broken interface:** the source builder included both
`clean_archive_verification_v0252.json`, which records the archive digest, and
`v0252_release_gate.json`, which records the clean-report digest. Rebuilding
after either companion changed invalidated the subject archive, so no final
archive could simultaneously contain and match its post-build evidence.
Once the clean report was correctly removed, the gate generator also crashed
while hashing the missing default path even though its optional loader had
already returned `None`, preventing clean-extraction tests from failing closed.

**Regression evidence:**
`test_post_build_companion_evidence_is_not_packaged_into_its_subject` requires
the clean report and v0.25.2 release gate to remain outside the source archive
while retaining pre-build matrix verification evidence.
`test_missing_clean_archive_companion_is_absent_not_an_io_error` proves an
absent companion yields a closed fact rather than an I/O exception.

**Decision:** post-build qualification is companion evidence. Exclude it from
the source archive and its manifest; verify it by detached digest after the
archive is fixed. Never solve a checksum cycle by accepting a stale report.

## A-025 — Proof-session and ACK-destination split brain

**Status:** closed at the local library boundary; the deployed producer and
live STRATA-010..020 qualification remain open.

**Broken interface:** `export_ack_from_verified_unlock` accepted both an
authenticated positive-lock `session_context` and an independent `AckContext`.
The former selected the statement that could unlock the payload; the latter
selected the output filename and durable one-shot ledger identity. The setup
commitment path binds only graph owner, deposit, game and watchtower indices,
so two contexts differing in slot, epoch or transaction identifiers can share
that path.

**Executable attack:** construct a valid proof, lock and `[r]A` for the
original session, publish its commitment, then invoke the exporter with the
original session bytes and a substituted ACK transaction identifier. Before
the fix, proof verification succeeded and the commitment could be consumed
under the substituted destination.

**Regression evidence:**
`tests/test_strata_exporter.py::test_a_valid_unlock_cannot_be_redirected_to_another_ack_context`
proves that two contexts share the old partial commitment path, but the
substituted destination now fails statement verification, publishes no
preimage and consumes no ledger entry. The API-shape test also requires that
the proof-gated function expose neither `payload` nor `session_context`.

**Decision:** derive the positive-lock session from the complete canonical
`AckContext` at setup and derive it again internally at proof-gated release.
Never accept separately caller-controlled statement and publication contexts
at a funds-releasing boundary.

## A-026 — Verified Core execution rejected by the hardening generator

**Status:** closed locally.

**Broken evidence predicate:** the v0.25.1 security-hardening generator treated
only `executed=false, passed=false` as a valid Core state. Running the official
reproduction workflow with the qualified Core 31.1 binary produced successful
evidence and then failed the hardening stage because execution had occurred.
This was fail-closed, but it made the claimed pinned-Core reproduction path
internally inconsistent.

**Regression evidence:**
`tests/test_generate_v0251_security_hardening.py` covers the unavailable
fail-closed state, the exact Core 31.1 version and binary hash, and rejection of
missing, wrong-version, or wrong-binary success evidence.

**Decision:** accept exactly two Core evidence states: honest unavailability
with a recorded error, or successful execution of version 310100 with SHA-256
`d55c12b0b02001cc16b1481c4075361dcba193100a8143924abda911174c09ec`.
Do not equate “a node ran” with “the qualified node ran.”

## A-027 — Valid counterproof plus release withholding redirects timeout value

**Status:** current graph broken; shared-selection deposit-recovery model added,
universal funds safety still open.

**Executable counterexample:** in the applied validity-first graph, assume the
counterproof is semantically valid and one participant required by every
N-of-N ACK withholds. Every ACK is unavailable. After CSV, exact NACK parents
pay the graph owner and `AllNackd` enables the existing contested payout, while
the canonical ACK/slash branch never executes. The Rust
`detect_correlated_ack_withholder_loss` analyzer derives that trace from the
generated graph and returns a negative funds-safety verdict.

**Narrow repair model:** `ranklock.v026.timeout_economics` makes every
`CounterproofV2_i` and owner payout atomically consume the complete ordered
counterproof-reserve roster plus one shared contest-payout outpoint, so at most
one selector confirms and any confirmation consensus-conflicts with every
sibling. Each counterproof also consumes the deposit, immediately allocates its
exact amount to a distinct plan-committed P2TR recovery descriptor, and returns
each non-selected reserve exactly to its setup-bound beneficiary. Owner payout
returns every reserve. Selected ACK and timeout parents conflict on resolution. ACK
alone creates a slash-authorization outpoint; timeout consumes contest-slash
and deliberately omits the independently burnable claim-payout output.
Sixty-four regressions cover graph resurrection, multi-counterproof selection,
CPFP/control-domain separation, beneficiary/value diversion, exact ordered
Slash distribution and zero-value header, separate CPFP/payout descriptors,
safe timeout change, and residual reserve accounting.

The alternative index in this model is the ordered Strata watchtower index,
not either of the two RankLock query slots. Each counterproof/ACK alternative
has its own ordered CPFP descriptor. Every selected resolution output must also
match one plan-level value/script/policy commitment; exact connector Script
semantics remain a categorical blocker until Rust/Core verification.

**Remaining attack:** Bitcoin cannot distinguish `valid counterproof + withheld
release` from `invalid counterproof + no release` at the timeout. Counterproof
selection allocates the deposit to the declared recovery script, but actual
descriptor control is not yet proven; an invalid first counterproof may also
deny reimbursement to an honest fronting operator. The abstract model therefore hard-codes
`funding_eligible=false`. Universal protection requires consensus-valid
adjudication, threshold availability under a new theorem, or fully reserved
coverage for both indistinguishable worlds.

The model does not yet establish a qualified terminal recovery theorem. Its
abstract v2 parents remove the current post-selection deposit, ungated-Slash,
claim-payout-burn, and abandoned-reserve dependencies. Before counterproof confirmation, however, the
existing CooperativePayout can spend the deposit alone. Funding therefore
requires an exhaustive presign allowlist plus verified destruction of at least
one subject-unique signing share and every backup, or a confirmed cutover into a
fresh script-only deposit state; erasure cannot prove a hidden signature never
existed. The complete applied parent set and principal disposition are not yet
enumerated. Accordingly the only positive field is
`counterproof_selection_allocates_exact_deposit`, not “principal preserved,” and
`terminal-principal-disposition-unmodeled` remains a categorical blocker.
Stake exclusivity and complete exact-presign/legacy-template exclusion are
separate categorical blockers: current stake also feeds Unstaking and other
games, and any surviving v1 counterproof/ACK/NACK/Slash material bypasses the v2
consumer roster.
Slash payout scripts are distinct from every other committed plan script, and their
declared control domains are disjoint from graph-owner, recovery, and timeout-
broadcaster controls. Actual key possession/control remains an explicit funding
blocker.

**Terminal-enumeration delta:** the abstract model walks live UTXO states
to every maximal local terminal rather than treating pairwise conflicts as a
terminal theorem. For two alternatives it deterministically produces five
traces (`Owner`, two `CP -> ACK -> Slash`, and two `CP -> Timeout`) and maps
seven semantic worlds. Each `valid + withheld` world and its corresponding
`invalid + absent` world name the exact same timeout trace. Atomic selection
eliminates the prior six locked-reserve witnesses: the committed policy now
returns `AbstractDeclaredPolicySatisfiedV1` with zero abandoned reserve value.
Output dispositions must match committed non-null beneficiaries and the policy
digest is content-derived. That result is deliberately named
`AbstractDeclaredPolicySatisfiedV1`; it hard-codes `funding_eligible=false`,
`protected_value_theorem_established=false`, and retains blockers for baseline
authority, per-principal allowances, service-fee authority, and by-horizon
CSV/reorg/fee execution.

**Reproduced Rust/Core delta:** a side-by-side research `V026Graph` assembler
now derives every internal `C/P/S/R/L` edge from parent transaction bytes,
reconstructs an exact spender matrix, and retains sixteen unconditional
activation blockers. Six real Bitcoin Core cases independently accept both
counterproof siblings, the mature owner branch, ACK, the first-valid CSV
timeout, and the ACK-descended Slash. They also reproduce both directions of
the shared-input conflicts only after the losing branch is independently
mature, execute a competing live-key stake spend that prevents Slash, and show
that the signed 10,690-WU counterproof is accepted only after Contest confirms
under the tested version-3 policy.
This closes the earlier “Rust graph absent” and “no Core execution” evidence
gaps only for the isolated research graph. It does not close A-027: the stake
counterexample is positive evidence that global exclusivity is absent, the
runtime does not consume the graph type, the Slash-v2 ASM profile is not
activated, and the validity/withholding economic ambiguity remains.

The frozen `StructurallyVerifiedFundingBlockedV1` observation preserves its
exact fifteen-code bytes and subspace but fails closed for the current graph.
A separate `StructurallyVerifiedFundingBlockedV2` envelope/subspace records the
current sixteen-code set. Both reject non-canonical encodings and distinguish
atomic creation, exact replay, and conflict without overwrite; their live write
capabilities are not publicly deserializable. No runtime, P2P, funding, signing,
duty, or broadcast path consumes either record. This improves crash-visible
negative evidence; it is not admission. The live FoundationDB replay test did
not complete locally, so only codec/classification behavior is reproduced.

## A-028 — Receipt txid equality is not canonical-chain confirmation

**Status:** exact transaction, active-chain observation, ACK-subject binding,
and witness-CAS classification are composed; a positive receipt and an enforced
runtime consumer remain open.

**Attack:** a valid subject-bound receipt authenticates the non-witness
BridgeProof transaction id, but txid equality alone does not prove which witness
was mined, whether the transaction is only in the mempool, whether the reported
block remains on the active chain, or whether a reorganization occurred while
the runtime checked it. Treating receipt verification as confirmation could
therefore expose threshold release for an off-chain, alternate-witness, or
stale-chain observation.

**Regression evidence:** the bridge executor now creates a non-serializable,
non-cloneable live capability only after Bitcoin Core returns the exact full
transaction bytes, a minimum confirmation count, a Merkle-valid containing
block, and the same active block hash at the reported height. It repeats the
transaction and active-height lookups before returning. Real-Core regressions
reject a mempool transaction, insufficient depth, an invalidated block, and a
same-txid/different-witness transaction.

The executor can then consume that live capability with one independently
verified threshold-v3 ACK witness, compare every receipt-authenticated subject
field and the witness-stripped transaction template, recheck Bitcoin on both
sides of selected-commitment CAS, accept only exact create/replay, and reject a
conflicting first writer. Two pure regressions cover the subject and CAS
decision table. There is no positive receipt execution of this composed path,
and the lower-level witness-store API is not yet hidden behind it.

**Decision:** classify this capability as reorg-sensitive point-in-time
evidence. Recreate it immediately before any irreversible action. Keep funding
disabled because no valid production receipt exists and no runtime duty
requires the composition before threshold release.
