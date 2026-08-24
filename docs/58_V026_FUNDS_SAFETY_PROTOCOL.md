# RankLock v0.26 funds-safety protocol

**Status:** design draft; not an implementation, audit, or funding approval.  
**Funding state:** prohibited.  
**Target:** a loss-safe, versioned RankLock/Strata protocol whose enforcement
decision is derived from verified runtime evidence rather than a local report.

This document deliberately makes a breaking protocol change. The v0.25.2
pieces cannot be made safe for funds by wiring the existing exporter into the
existing bridge. The selected setup mode, on-chain connector, runtime context,
proof suite, and operational gate currently describe different systems.

Normative words `MUST`, `MUST NOT`, `SHOULD`, and `MAY` describe the proposed
v0.26 protocol. They do not describe current implementation status.

---

## 1. Executive decision

v0.26 SHALL use the following architecture:

1. **One canonical runtime root, built as a DAG.** A final `FundingSubjectV1`
   binds an acyclic chain from setup intent through contributions, graph
   presigning, ceremony, and immutable execution policy. Runtime bindings are
   derived children; no object hashes itself through a certificate or policy.
2. **Split-scalar safety topology.** Each setup participant independently owns
   one scalar and one random ACK preimage. The Bitcoin ACK requires the ordered
   preimage vector. No coordinator learns an aggregate scalar or aggregate
   release secret. The release mechanism is a separately versioned profile:
   the existing DFB evaluator and the proposed direct-scalar custodian are not
   interchangeable implementations of one suite.
3. **A new vector-hash connector.** The current Strata single-preimage connector
   is not reused. v0.26 carries 2..64 raw SHA-256 commitments in a correctly
   typed field and checks all preimages on chain.
4. **A complete proof-suite migration.** BN254/Python remains research-only.
   The baseline security floor is 128 bits and the strict engineering target is
   an end-to-end BN462 suite. BLS12-381 remains a separately identified
   compatibility candidate and is not fundable under that floor. Neither suite
   is implemented or qualified today.
5. **No entropy-derived ACK.** Production preimages are sampled independently
   inside participant trust boundaries. Under the DFB profile, both the
   preimage and scalar are erased before activation. Under the direct-custody
   candidate, plaintext `k_j` is erased but the retained `r_j` remains an
   equivalent ACK-recovery capability and MUST live only in the qualified
   non-exportable one-shot boundary. The v0.25
   entropy derivation and public unverified-export capability MUST NOT be linked
   into an enforce-mode binary.
6. **A staged coordinator boundary.** An authenticated `EvaluationIntentV1` is
   globally locked before any burn. Each participant independently validates,
   burns, and commits nonsecret readiness. A subject-wide reservation must win
   atomically against NACK and the alternate slot before any honest participant
   evaluates or emits a result. A signed, write-once `AckReleaseCapsuleV1`
   leaves the coordinator. The bridge never consumes a bare preimage or treats
   a filename as authority.
7. **Loss safety before liveness claims.** N-of-N prevents an invalid ACK when
   one participant is honest, but one participant can block a valid ACK. The
   timeout outcome MUST be economically fund-preserving under that failure, or
   the protocol must explicitly adopt a weaker `t-of-n` corruption model.
8. **No in-place migration.** v0.25 graphs, fixtures, subjects, and release files
   never become v0.26 by reinterpretation. New protocol or proof-suite versions
   require a new graph and new deposits.
9. **One-subject graph signing keys.** Every fund-moving ACK/NACK parent is
   completely presigned before funding by the pinned N-of-N graph roster. At
   least one honest signer verifies the graph and destroys its one-use share;
   otherwise exposed preimages plus a surviving quorum can authorize a
   different transaction.
10. **No implicit release-profile choice.** `Profile S-DFB` removes the raw
    scalar but still lacks its adaptive/output-mask theorem. `Profile
    C-DIRECT` removes DFB but retains the scalar in an online conditional-
    release custodian. Governance must ratify one exact trust model and new
    suite id; neither is fundable today.

The sub-MiB retained-object target is an optimization, not a security
requirement. It MUST NOT select a weaker curve, incomplete proof, or unsafe
setup.

---

## 2. Why v0.25.2 cannot be promoted in place

These are implementation facts, not speculative threats.

| Boundary | Current fact | v0.26 consequence |
|---|---|---|
| Setup mode vs Bitcoin | The release gate selects `split-scalar-n-of-n`, and `split_hashlock_ack_leaf_script` requires 2..64 ordered preimages. The Strata connector, ACK finalizer, and executor accept exactly one `[u8; 32]`. | Introduce a new graph and vector-hash connector. The current path is not the selected safety mode. |
| Context identity | `EvaluationContext` and `AckContext` overlap but bind different fields. The lower split-scalar API accepts an independent `session_context` and `context_digest`. | Replace them as authorities with an acyclic `FundingSubjectV1`; per-participant setup contexts and runtime evaluation bindings are domain-separated children only. |
| Producer handoff | The bridge reads a single raw-or-hex preimage from a filename based on three txids and checks SHA-256. | Replace it with a canonical signed release capsule keyed by full subject identity. |
| Alternate release capability | `derive_setup_payload` recreates the ACK preimage from retained entropy, and `export_unlock(... allow_unverified_payload=True)` is a public boolean-gated path. | Remove both from enforce-mode dependency closure. A boolean is not a capability boundary. |
| Crypto level | `PositiveLock` publishes `[r]delta` and masks under a BN254 GT session. Current analysis places the target near 100-bit security, and Python operations are variable-time. | No v0.25 proof suite is fundable. Migrate proof, VK, projectivizer, lock, scale proof, and certificates together. |
| Deployment gate | `evaluate_deployment` is called only from tests. Generic attestations validate signatures and a digest, not the referenced evidence schema. Runtime value at risk is caller-supplied. | Enforce typed policy in every capable service; reserve risk atomically in the safety registry and reconcile it with Core. |
| Durability | The exporter has no externally witnessed monotonic journal, and two release sidecars still suppress abort-anchor recovery errors. | Use an externally anchored outbox state machine. Surface primary and recovery failures together. |
| E2E | STRATA-010..020 are 0 passed / 11 not executed. The source file they claim to quote, `03_ACCEPTANCE_MATRIX.md`, is absent from this worktree. | Restore a canonical matrix, add executable commands, and require every row to record a zero-exit execution. |

Key source locations:

- `src/ranklock/split_scalar_lock.py:676-697, 773-819, 823-923`
- `src/ranklock/authorized_labels.py:72-117`
- `src/ranklock/strata_exporter.py:134-276, 507-550, 641-696`
- `src/ranklock/deployment_policy.py:182-307, 349-421, 426-594`
- `src/ranklock/split_scalar_authorization.py:676-688`
- `src/ranklock/release_sidecar.py:592-603`
- `integration/alpen-validity-first-f94c-v025/new_files/crates/connectors/src/validity_first_counterproof.rs:17-86`
- `integration/alpen-validity-first-f94c-v025/new_files/crates/tx-graph/src/transactions/counterproof_ack.rs:117-147`
- `integration/alpen-validity-first-f94c-v025/new_files/crates/bridge-exec/src/graph/ranklock.rs:40-178`
- `results/v0252_release_gate.json`
- `results/v0252_strata_e2e_matrix.json`

---

## 3. Security objective and adversary model

### 3.1 Loss-safety objective

For one exact funded subject, the protocol MUST ensure, except with the
computational and consensus failure probability defined in section 3.3:

- an ACK branch spend is possible only for a canonically valid, context-bound
  proof and one of the exact fully presigned ACK parents;
- the absence, crash, withholding, rollback, reorg, or equivocation of any
  single actor cannot produce an unauthorized value transfer;
- after any release-bearing byte becomes visible, the slot never returns to an
  unreleased state;
- every accepted retry is byte-identical and every conflicting retry is
  terminal;
- missing or stale evidence disables new activation/admission. For an already
  admitted subject, runtime verifies the exact frozen evidence was valid at its
  admission height; later expiry cannot strand resolution;
- a timeout can reduce availability, but cannot become a profitable attack by a
  party capable of causing the timeout.

“Exactly one outcome” is scoped to one deposit/game/counterproof outpoint. It
does not mean every independent watchtower output magically shares one database
transaction.

### 3.2 Adversary capabilities

The design assumes an adversary may:

- observe, delay, reorder, replay, or replace network messages;
- control the prover, coordinator caller, bridge operator, or up to `N-1` setup
  participants;
- supply malformed, noncanonical, oversized, mixed-suite, or context-substituted
  encodings;
- crash a process at every durable-write boundary;
- race multiple coordinators and multiple watchtowers;
- restore local disk snapshots and consistently rewrite a local database;
- cause Bitcoin reorganizations within the configured operating bound;
- manipulate fee pressure and race the ACK against a mature NACK;
- compromise any one administrative failure domain.

The design does not protect against a break of any assumption enumerated in
section 3.3, a governance quorum deliberately authorizing a malicious subject
before funding, or corruption of all members of a required honest set during
its protected epoch. Those assumptions must be explicit in the signed policy
and external reviews.

### 3.3 Computational funds-safety game

The phrase “one-honest split-scalar safety” is conditional, not absolute. For
one admitted `FundingSubjectV1`, the adversary may control the caller,
coordinator, bridge, up to `N-1` split-scalar participants, and up to `f` of the
`3f+1` safety-registry replicas. The following independent conditions are
required:

- at least one enrolled split-scalar contribution was generated honestly and
  that participant's release-profile boundary remains uncompromised for the
  profile-specific protected epoch defined below;
- the adversary obtains only the outputs permitted by the selected release
  profile, while one subject-wide release reservation selects at most one
  slot/preimage vector for exposure;
- at least one member of the N-of-N graph-signing roster signs only the exact
  accepted graph parents and honestly destroys its one-subject share before
  funding;
- registry commit certificates require `2f+1` signatures and honest replicas
  never certify divergent successors for the same key and sequence;
- the approved proof system is knowledge-sound for the exact statement;
- the selected release mechanism satisfies its profile-specific theorem;
- the positive-lock KDF/encoding, SHA-256, BIP340/secp256k1, canonical parsers,
  and native implementation satisfy their stated security properties; and
- Bitcoin's consensus and common-prefix behavior stay within the signed reorg
  and timing model.

For `Profile S-DFB`, the honest participant's two per-slot retained states must
remain uncompromised until both slots are `RELEASED`/cryptographically retired
or the subject reaches ACK/NACK chain resolution. The adversary obtains at most
one result from each of the exactly two committed DFB query slots, and the DFB
construction must satisfy its reviewed adaptive, auxiliary-input, same-scalar,
and multi-target privacy definitions.

For `Profile C-DIRECT`, `r_j` is a subject-level ACK-recovery capability. The
honest participant's non-exportable scalar boundary, every clone, and its
monotonic state must remain uncompromised until an exact result is durably
staged and `r_j` is destroyed, or until terminal no-result destruction. The
boundary may answer zero unauthorized scalar-multiplication queries and at most
one distinct authorized query. Two logical retry slots share one handle; they
do not own scalar copies. The exact accepted `A` is extracted from canonical
proof bytes, locally verified, and irreversibly bound by the subject-wide
reservation. Knowledge of `r_j` immediately recovers `k_j` from the public
positive lock without a proof, so plaintext-preimage erasure alone establishes
no confidentiality claim. Scalar exposure is an honest-boundary failure; it is
not side information under which the positive lock is expected to hide.

The C-DIRECT release-mechanism game begins after an honest module has generated
the exact subject contribution. The adversary receives the complete public
subject/CRS/VK/lock transcript and all corrupt-participant state, may submit
arbitrarily many rejected requests, and receives no honest scalar output before
the unique certified reservation and complete custody-bound barrier. Its post-
reservation, pre-erasure view includes the exact result-body digest,
authenticated ciphertext/envelope, durability-receipt digest, conditional-key
envelope, replica acknowledgements/availability receipt, and body-commit
certificate. The suite pins the AEAD, nonce generation/uniqueness rule,
associated-data domain, subject/release/body binding, threshold result-key
service, and conditional release game. The adversary receives no result key or
plaintext before finalized matching scalar erasure. Fewer than the threshold
number of independently controlled result-key-service shares may be corrupt
through normal erasure finalization or the no-result child-key-share erasure
finalization. Subject-specific forward-secure shares held by honest domains
must be unrecoverably erased on the no-result branch, so compromising those
domains later cannot reconstruct the old result key. The signed availability
model on the normal-release branch MUST retain enough honest shares and
ciphertext replicas to reconstruct the exact result after erasure. The
no-result branch instead requires certified unrecoverability. Threshold
confidentiality failure, normal-branch post-erasure availability failure, and
no-result erasure failure are explicit terms in `Adv_C-DIRECT-release`; none is
hidden inside a generic service assumption. It wins
the pre-release game if it obtains the honest `k_j`, causes an output for an
unreserved or differently bound `A`, or obtains outputs for two distinct `A`
values. The secrecy epoch ends only at the finalized `RESULT_KEY_RELEASED`
event—not at reservation, body commitment, or scalar erasure alone. At that
event the challenger returns exactly one `X_j = [r_j]A`; afterward no secrecy
of `k_j` is claimed. The concrete
report names and bounds this probability as `Adv_C-DIRECT-release` under the
exact module, registry, AEAD/result-key, positive-lock, and implementation
assumptions.

The adversary wins if it confirms an ACK-branch spend for an invalid proof or
changes any committed fund-moving economics. Its advantage MUST be bounded by
the sum of the proof knowledge-soundness error, selected release-mechanism
advantage, positive-lock/KDF advantage under the exact CRS/VK and public side
information, AEAD/conditional-result-key advantage where applicable, SHA-256
preimage advantage, BIP340 forgery advantage, registry safety failure, honest-
boundary failure, implementation failure, and Bitcoin consensus/common-prefix
failure. The concrete-security report must instantiate that bound for the
selected suite and deployment lifetime.

In this game, `terminally retired` is a cryptographic lifecycle fact, not a
registry label. Under S-DFB, a participant slot requires destruction of its
envelope key and every recoverable backup plus a durable signed erasure record
and registry certificate. Under C-DIRECT, an alternate slot is only logically
retired once the one subject handle is release-bound to the selected slot; final
subject retirement requires destruction of that handle, every admitted clone,
and every scalar backup plus a durable device receipt and registry envelope.
The honest-participant protection epoch cannot end while registry state says
retired but recoverable secret material remains.

This game does not establish availability. Participant, registry, signer, Core,
or fee-path unavailability is acceptable only after the timeout/NACK path is
independently proved economically loss-safe.

---

## 4. Canonical protocol identity

### 4.1 Acyclic identity DAG

A single final digest is still the runtime authority, but it cannot be an input
to objects from which it is constructed. v0.26 uses this dependency order:

```text
GraphKeyDescriptorV1
  -> SetupIntentV1
  -> ParticipantContributionV1[N]
  -> GraphBundleV1
  -> ParticipantBundleApprovalV1[N]
  -> GraphPresignTranscriptV1
  -> CeremonyCertificateV1
  -> ExecutionPolicyV1
  -> FundingSubjectV1
  -> AuditManifestV1[*]
  -> ActivationCertificateV1

AdmissionPolicyEpochV1 + ActivationCertificateV1
  -> AdmissionCertificateV1
  -> EvaluationBindingV1
```

An object may contain only predecessor digests. No signature, certificate,
receipt, or policy is hashed into an ancestor that it also signs. Validators
reconstruct and validate the entire predecessor chain rather than trusting a
digest merely because it is nonzero.

`SetupIntentV1` selects one exact integrated `proof_suite_id`. The compiled
suite registry maps that id to exactly one release mechanism; callers cannot
mix a proof backend with another profile. Every contribution, graph object,
ceremony certificate, funding subject, and runtime message repeats and must
exactly match that id. Profile-specific bodies are tagged unions; missing
fields, extra fields from the other profile, and dummy artifact/custody
placeholders are noncanonical.

| Object | Required content |
|---|---|
| `GraphKeyDescriptorV1` | fresh setup nonce; safety-registry cluster/generation and uniqueness namespace; key-generation/aggregation profile and transcript; ordered signer keys/control domains; N-of-N aggregate x-only key; proof-of-possession set; certified registry uniqueness claim |
| `SetupIntentV1` | graph-key-descriptor and exact matching registry-profile digests; protocol/graph/wire/signature ids and integrated proof-suite id; network and genesis; complete unsigned funding transaction and planned outpoint/amount; program, VK, exact canonical public-input bytes and digest; result tag; exactly two ordered logical query-slot descriptors and aggregate query budget; S-DFB slot roots/nonce namespace or C-DIRECT subject-handle/counter policy; ordered split-participant roster; governance/control-domain registries; confirmation/reorg/CSV bounds |
| `ParticipantContributionV1` | setup-intent digest; participant index/key/control domain; exact integrated proof-suite id; positive lock; scale proof; `[r_j]delta`; ACK hash; participant signature; for S-DFB, retained-artifact/public-manifest digests; for C-DIRECT, custody-handle policy, device attestation, monotonic namespace, firmware/build identity, and complete clone/replica inventory |
| `GraphBundleV1` | setup-intent digest; ordered contribution digests and ACK hashes; transaction-plan and witness-policy digests; bridge-proof and unsigned counterproof txids/templates; exact typed shared-selection `CounterproofV2`, `ACKV2`, timeout-settlement, owner-payout and slash parent templates; every Taproot internal key, leaf, root, output key and control block; graph signer roster/public key; CPFP authorization policy |
| `ParticipantBundleApprovalV1` | graph-bundle digest, participant identity, and signature after full common-bundle verification |
| `GraphPresignTranscriptV1` | graph-bundle digest; every committed prevout, amount, script, control block, sighash type and message; complete ACK/NACK parent signatures; signer roster; one-subject key-erasure receipt set |
| `CeremonyCertificateV1` | predecessor digests; exact integrated proof-suite id; contribution and approval sets; public anchor; S-DFB artifact/transcript/generator-erasure inventory or C-DIRECT device-attestation/handle/clone inventory and plaintext-preimage erasure statement; verifier roster and signatures |
| `ExecutionPolicyV1` | predecessor digests; immutable funded-deposit resolution rules; ordered economic-principal map; `RecoveryVaultDescriptorV1` and exact neutral-refund allocation; authorized requester/coordinator/bridge keys; registry/finalization/retention-key parameters; independent Core-node/control-domain and observation rules; role quorums; release/reorg, ACK/refund finality, timing and fee rules; graph lifetime plus reorg tail; governance signature |
| `FundingSubjectV1` | canonical embedding of the exact predecessor objects/digests plus one integrated proof-suite discriminant, complete txid-stable funding transaction, deposit/game/operator/watchtower/epoch indices and ordered two-slot set; no runtime-only witness or block data |
| `AuditManifestV1` | funding-subject/source/binary scope; finding ids, severity taxonomy and disposition; auditor role/control domain; admission-time validity interval; signature |
| `ActivationCertificateV1` | final funding-subject digest; typed audit manifests; no-value-before-activation assertion; exact subject-lifetime days deterministically rounded up from the immutable policy's maximum resolution, retention, and reorg-tail interval; activation Core checkpoint height/hash/median-time-past; `activation_time_unix` derived exactly from that MTP; signed security-floor report digest; governance activation quorum |
| `AdmissionPolicyEpochV1` | latest registry-backed admission sequence; allowed profiles; value/count caps; validity heights; cooldown/revocation; funding custody keys; governance quorum |
| `AdmissionCertificateV1` | funding-subject, activation-certificate and exact admission-policy digests; governance checkpoint; immutable risk-namespace id; registry cluster/generation; atomic value/count reservation; safety-registry commit certificate |
| `EvaluationBindingV1` | funding-subject and admission-certificate digests; exact committed slot id; semantic-request id; accepted signed-intent digest; exact raw counterproof transaction; txid, wtxid, witness digest, authorization outpoint and selector; exact canonical proof digest; canonical `A` digest serialized as a derived checked field and recomputed from the proof on every parse; no caller-authoritative block location |

The graph-key uniqueness claim certifies a predecessor tuple—registry
cluster/generation, uniqueness namespace, setup nonce, aggregate key, and
ordered roster—not the digest of the descriptor that embeds it. This keeps the
first DAG node acyclic while making reuse globally rejectable.

For baseline v0.26, the admission certificate's registry cluster/generation
MUST exactly equal the setup intent and execution policy. A cluster change
before admission retires the unfunded subject and requires a new setup intent;
runtime state for an already admitted subject remains on its pinned cluster.

`SetupIntentV1` commits the exact public statement because `PositiveLock` is
statement-specific. A runtime-selected public-input vector is forbidden. If an
application needs derived inputs, the setup intent must pin one deterministic,
canonical derivation algorithm and all its inputs; that derivation must produce
the committed bytes before any contribution is accepted.

`FundingSubjectV1` is the sole runtime lookup root:

```text
funding_subject_digest = SHA256(
    "ranklock/v026/funding-subject\0" || canonical_funding_subject_bytes
)
```

Setup locks use a predecessor-only participant context:

```text
participant_lock_context_j = SHA256(
    "ranklock/v026/participant-lock-context\0" ||
    setup_intent_digest || u16(j) || participant_pubkey_j
)
```

Participant contributions and approvals sign their exact predecessor bodies.
Runtime requests, slot keys, results, journals, release ids, capsules, consumer
receipts, and runtime attestations bind `funding_subject_digest`. The final
digest is never fed backward into setup or activation ancestors.

`EvaluationContext`, `AckContext`, and `SafetySubject.context_digest` MAY remain
only as non-authoritative compatibility views constructed from the validated
DAG. Enforce-mode APIs MUST NOT accept them independently.

### 4.2 Canonical encoding rules

- The allowlisted `WireProfileV1` defines every magic value, field width,
  section maximum, vector maximum, and total-message maximum before setup.
- Framing uses an 8-byte magic, `u16` schema version, `u16` protocol version,
  and `u32` total length. Variable byte strings use a `u32` byte length;
  vectors use a `u16` count followed by canonical elements.
- Parsers MUST check total and section lengths before allocation.
- All fixed-width unsigned integers use network byte order (big-endian).
- Hashes and keys are fixed 32-byte fields. Bitcoin txids/wtxids use the raw
  32-byte consensus hash order, never display-reversed text.
- The wire profile pins the BIP341 NUMS base point and exact public derivation
  for every script-only Taproot internal key; arbitrary internal keys fail.
- Integer coercion, trimmed text, hex fallbacks, and Unicode identifiers are
  forbidden at the binary boundary.
- Curve encodings MUST be canonical, on curve, in the correct subgroup, and
  nonidentity where required.
- Duplicate, reordered, omitted, unknown, or mixed-version sections fail.
- Decoding followed by encoding MUST reproduce the original bytes exactly.
- Python and Rust implementations MUST share golden vectors and differential
  fuzz tests.
- No codec implementation may begin while any field width or bound remains an
  owner-selected default; changing the wire profile creates a new subject.

### 4.3 Signature and quorum profile

`SetupIntentV1` pins a separate `SignatureProfileV1`; the proof-suite id does
not implicitly select operational signatures. The v0.26 baseline is BIP340:
32-byte x-only secp256k1 keys, 64-byte signatures, and a 32-byte SHA-256
domain-separated message. Every signed object defines its unsigned canonical
body and exact domain tag.

- contributions and graph-bundle approvals require every ordered split
  participant;
- graph parents require every one-subject graph signer and use only the exact
  committed Taproot sighash mode;
- ceremony activation requires every named ceremony verifier, with a minimum
  of two independent control domains;
- governance uses the exact `q-of-m` roster pinned in the setup intent;
- each required audit role supplies its own typed signed manifest;
- safety-registry commit certificates require `2f+1` of `3f+1` replicas,
  `f >= 1`, with unique control domains; and
- requester, coordinator, bridge, registry, audit, and governance key lifecycles
  are explicit policy fields. Graph-signing shares are unique per subject and
  MUST be destroyed before funding.

Alternative signature or quorum rules require a new signature-profile id,
golden vectors, security review, and funding subject.

---

## 5. Cryptographic profile

### 5.1 Suite registry

The setup intent and final funding subject pin an allowlisted `proof_suite_id`.
The suite definition includes:

- exact curve and field parameters;
- canonical G1, G2, GT, scalar, proof, and VK encodings;
- proof-system version and verification equation;
- exact release mechanism and implementation version;
- positive-lock construction and KDF;
- split-scalar scale proof and pairing certificates;
- for S-DFB, label width, generator, nonce schedule, CRT profile, and
  statistical bound;
- for C-DIRECT, custody-module policy, attestation roots, monotonic-state,
  anti-clone, one-shot, fault, erasure, conditional-result-key, and AEAD
  profiles;
- hash functions and every domain tag;
- native implementation and build digests;
- claimed concrete-security level and deployment lifetime.

The request cannot provide public inputs, a verifier, or a substitute VK. The
coordinator and participants resolve them from the validated funding-subject
DAG.

### 5.2 Current suite decision

No current suite is eligible for enforce mode.

- BN254 is disqualified from the funds path. The CFRG pairing-curve draft says
  a 254-bit BN curve provides no more than about 100-bit security after exTNFS.
- Split-scalar does not multiply that into `100*N` bits. Breaking the one
  honest target costs approximately one BN254 target attack; multiple targets
  add only a small multi-target factor.
- Migrating only `PositiveLock` is invalid. The proof, VK, A/B/C elements,
  projectivizer, scale proof, and pairing certificates share the same security
  assumption and must migrate together.
- BLS12-381 remains an interoperability candidate, not an enforce candidate.
  Current estimates are close to but below the baseline's strict conservative
  128-bit target.
- The repository has no production BLS12-381 group/pairing backend. Existing
  BLS12-381 material is field-cost or exponent-space modeling.

The baseline security floor is 128 bits. The strict curve target is BN462. The
DFB candidate is `RL26-BN462-DFB-SPLIT-N`; the separately versioned direct-custody
candidate is `RL26-BN462-DIRECT-CUSTODY-N`. The current CFRG pairing-curve draft
publishes parameters and pairing test vectors for BN462 and recommends it at
the 128-bit level. Its
separate statement that BLS12 curves generally need a characteristic of at
least 461 bits is not enough to qualify an arbitrary BLS12-461 parameter set or
backend.
`RL26-BLS381-DFB-SPLIT-N` and `RL26-BLS461-DFB-SPLIT-N` therefore remain separately
named, non-fundable research candidates. None of these suites is eligible
today: the repository has no audited end-to-end BN462 backend, the DFB theorem
remains open, and no qualified scalar-custody module exists. A primitive
library, HSM marketing claim, or small unaudited crate is not a production
dependency merely because it claims constant-time or non-exportable
operations. The one-MiB artifact target is subordinate to the security floor.
The registry records known attack upper bounds separately from an independently
approved conservative suite floor; a curve recommendation or attack upper
bound can never satisfy a minimum-security gate by itself.
Every approved floor resolves to a typed, signed security report with an exact
profile digest, approver roster, approval time, expiry time, and maximum
deployment lifetime. Activation supplies its intended lifetime, and the
registry rejects a suite unless the report is already valid and remains valid
through the entire subject lifetime. An untyped 32-byte digest or integer floor
is not approval evidence.
The funding gate accepts these values only from a fully validated
`ActivationCertificateV1`: it recomputes the certificate digest, verifies the
Core checkpoint and MTP through the configured independent quorum, resolves and
verifies the signed security-floor report, and passes the committed lifetime.
Raw caller timestamps or shortened lifetimes are not authoritative. Until this
evidence verifier and the canonical activation codec exist, the compiled suite
registry carries an unconditional implementation blocker even if every suite
fact is otherwise set to qualified.

The same draft explicitly does **not** define a BN462 point serialization: a
58-byte field coordinate leaves only two spare high bits, while its generic
compressed format needs three metadata bits. `WireProfileV1` must therefore
freeze a RankLock-owned leading-byte encoding, sign convention, identity rule,
subgroup validation, exact lengths, and independently reproduced vectors before
any suite codec or setup artifact exists. A backend-native encoding is not an
implicit protocol default.

A reproduced planning calculation that applies the current compact DFB formulas
to 381-bit coordinates selects 118 CRT primes and projects 709,616 program
bytes plus 36,576 mask bytes per slot: 1,493,132 bytes for two slots and the old
748-byte manifest. This is not a measured BLS artifact—the lane counts, compact
CRT proof, and manifest would all need revalidation—but it is enough to prohibit
assuming that a curve swap preserves the one-MiB target. The formulas are in
`dfb_real.py:475-541` and `embryo_mask_fusion.py:642-658`.

### 5.3 Split-scalar release profiles

The two profiles below produce the same public algebraic object but have
different retained secrets, failure modes, and security theorems. Their suite
ids, contribution schemas, ceremonies, state machines, and audit evidence MUST
remain distinct.

#### 5.3.1 Profile S-DFB

For participant `j`:

1. sample independent nonzero scalar `r_j`;
2. sample independent 32-byte preimage `k_j` directly from an approved RNG;
3. generate an independent two-slot artifact with a disjoint nonce namespace;
4. create a positive lock for `k_j` under
   `participant_lock_context_j` and the exact setup-committed statement;
5. publish `R_j = [r_j]delta`, a proof of knowledge of `r_j`, the artifact
   digest, and `h_j = SHA256(k_j)`;
6. sign the complete common bundle only after verifying every participant row
   and the final Bitcoin graph;
7. before funding, erase `r_j`, `k_j`, free-XOR deltas, generator random tapes,
   graph-building intermediates, and every seed not required by the one-shot
   evaluator.

Each participant MUST retain, inside its own encrypted and access-controlled
boundary, two independently compartmentalized slot states. Each slot has its
own label-pair tree, program opening seed, ledger recovery material, and
envelope key; common public/sealed artifact bytes and the release authorization
key are explicitly inventoried. Those values are not “temporary setup state.”
They MUST be excluded from ordinary snapshots and logs. Before subject-wide
release reservation, either slot may independently burn and become ready. The
reservation selects one slot and atomically marks the alternate slot
`SUPERSEDED_ERASURE_REQUIRED` unless it is already cryptographically terminal.
Before evaluating the selected slot, each participant either (a) destroys a
nonterminal alternate envelope key and every backup, durably signs
`ParticipantSupersededErasureV1`, and commits
`RETIRED_SUPERSEDED(erasure_record_digest)`, or (b) validates an already-terminal
alternate's exact prior physical-erasure record and commits a finalized,
release-bound `SupersessionReferenceV1` without changing its state. The complete
ordered evidence set is the erasure barrier. The selected slot is retired only
after its signed result wrapper is durable and certified.
`ACK_FINAL`/`NACK_FINAL` before reservation requires equivalent terminal erasure
of both slots.
Destroying one slot envelope key must not destroy or expose the other, and
destroying both retires every backup. A restored copy must query the safety
registry, complete every pending erasure first, and may resume only the request
locked to that exact slot.

The participant evaluates locally only after both burn and certified release
reservation, then exports only the signed projective output/result described in
section 7. It never exports raw program seeds or both label branches to the
coordinator.

The ACK leaf verifies an exact Taproot/BIP340 signature and all ordered
preimages. The hash vector is an ordinary `[u8; 32]` vector; it is not smuggled
through an `XOnlyPublicKey` compatibility field.

No honest participant gives a coordinator its scalar, setup preimage, random
tape, label-pair tree, reconstructing seed, or projective output before the
reservation and erasure barrier. Corrupt participants may leak their own
components at any time; the claim is that no complete vector is available until
the honest component is authorized and a complete valid result set unlocks the
positive locks.

#### 5.3.2 Profile C-DIRECT — online conditional-release custody candidate

This is a new incompatible candidate, not an optimization flag on S-DFB. It
removes the garbled projectivizer by retaining `r_j` inside a subject-unique,
non-exportable, rollback-resistant custody module. That trade is explicit:
while `r_j` survives, the module can compute the positive-lock session `Y^r_j`
and recover `k_j` without a proof. Erasing plaintext `k_j` is duplicate-secret
hygiene; it does not remove the ACK capability. A software-owned ciphertext,
ordinary sealed file, or restorable backup does not qualify this profile.

The custody module MUST:

1. generate nonzero `r_j` and independent `k_j` internally; create `R_j =
   [r_j]delta`, the scale proof, `h_j`, and the positive lock without ever
   exporting either secret; make the contribution bytes durable and
   independently verified before erasing plaintext `k_j`;
2. retain exactly one subject-level `r_j` handle shared by the two logical
   retry slots, with no per-slot scalar copies, reusable export, general GT-
   exponentiation API, or caller-selected scalar-multiplication API;
3. validate the final reservation certificate, subject, suite, statement, Core
   observations, canonical proof, and proof validity internally; extract `A`
   from those exact proof bytes rather than accepting an independent point;
4. reject identity, noncanonical, wrong-subgroup, wrong-suite, wrong-subject,
   wrong-proof, wrong-release, stale-counter, clone, and firmware-rollback
   inputs before loading `r_j`;
5. irreversibly bind its monotonic handle to
   `(release_id, slot_id, proof_digest, canonical_A)` and wait for a complete
   ordered `CUSTODY_BOUND` barrier before any participant performs the secret
   operation;
6. durably consume the handle's sole invocation as
   `OUTPUT_INTENT_DURABLE(counter = 1)` before entering scalar code. It then
   computes exactly one distinct `X_j = [r_j]A` using constant-time,
   adversarial-input-safe code and self-check
   `e(X_j, delta) = e(A, R_j)` before signing the result; the coordinator and
   bridge independently recompute that equation from canonical points and never
   trust a boolean self-check claim. The module persists `OUTPUT_CACHED_DURABLE`
   before exposing the output internally; power loss after the intent but before
   that cache is terminal no-result and never authorizes recomputation;
7. generate and seal a result key that is unavailable outside the boundary
   before scalar erasure, privately stage and fsync the exact signed result
   body, encrypt it under that key, and create
   `ConditionalResultKeyEnvelopeV1` under the pinned threshold recovery service
   using subject-specific forward-secure child-key shares with an exact
   inventory and backup-erasure policy. Before activating any child share or
   accepting any envelope byte, the service validates a durable signed
   `RESULT_KEY_SEALED` receipt plus the exact proposed envelope/activation-
   attempt digest for the subject/release/body tuple. Any partially started
   activation is durably recorded under that attempt digest and forces the same
   no-result tombstone/share-erasure path as an active envelope. The envelope's
   release predicate contains only
   predecessor fields: suite/profile, subject, release id, body digest, handle
   inventory/counter, and registry profile. A later finalized scalar-erasure
   envelope satisfies it only when those decoded fields match exactly and that
   erasure record independently commits this conditional-envelope digest; the
   predicate never embeds a future erasure-record or finalization-envelope
   digest. It replicates both envelopes, obtains the
   exact quorum acknowledgements, reads back and internally authenticates/
   decrypts the replicated result ciphertext, and obtains a
   `ParticipantResultBodyCommitCertificateV1` that commits the body,
   ciphertext, conditional-key envelope, durability receipt, replica-
   acknowledgement set, and availability-receipt digests; the module validates
   that exact certificate before permitting erasure;
8. make every admitted scalar copy irrecoverable under one of exactly two
   profile-pinned models: either one attested replicated-handle device consumes
   a shared monotonic state and issues one receipt covering the exact inventory,
   or every physically distinct clone issues an ordered signed erasure receipt.
   Then destroy the primary `r_j`, its envelope key, and live buffers while
   persisting a signed device tombstone plus the independently generated
   result-key release-state digest; finalize a
   `ParticipantScalarErasureV1` bound to that exact body/certificate/envelope,
   then validate the exact erasure finalization inside the module or threshold
   recovery service before transitioning to `RESULT_KEY_RELEASED`;
9. decrypt/reconstruct, construct, and replicate the final byte-identical result
   wrapper without invoking scalar code; and
10. only after final-wrapper durability emit those exact bytes. After terminal
   erasure, answer retries only from staged result bytes and
   never recompute. Before reservation, ACK/NACK finality or ceremony abort
   takes a separate certified no-result erasure path.

The cross-authority crash chronology is monotonic. Every state below is tagged
with its owner; it is not one fictitiously atomic machine:

```text
module: ACTIVE
  -> RELEASE_BOUND(release_id, slot_id, proof_digest, A_digest)
  -> OUTPUT_INTENT_DURABLE(counter = 1)
  -> OUTPUT_CACHED_DURABLE
  -> RESULT_KEY_SEALED
outbox: RESULT_BODY_DURABLE
threshold service: KEY_ABSENT
  -> KEY_ACTIVATION_STARTED -> KEY_ENVELOPE_ACTIVE
outbox: RESULT_BODY_CIPHERTEXT_QUORUM_AVAILABLE
registry: RESULT_BODY_COMMITTED
  (issues ParticipantResultBodyCommitCertificateV1)
outbox: RESULT_BODY_COMMIT_CERTIFIED
module: RESULT_BODY_COMMIT_VALIDATED
  -> SCALAR_ERASED_WITH_DEVICE_RECEIPT
registry: ERASURE_FINALIZED
module: ERASURE_FINALIZED_CERT_VALIDATED
threshold service: KEY_ENVELOPE_ACTIVE -> RESULT_KEY_RELEASED
module: RESULT_KEY_RELEASED
outbox: FINAL_WRAPPER_DURABLE_REPLICATED -> EMITTED
module: OUTPUT_INTENT_DURABLE -> OUTPUT_LOST
  -> SCALAR_ERASED_NO_RESULT_TERMINAL
    (if no durable cache exists; never retries the multiplication)
module: RELEASE_BOUND -> SCALAR_ERASED_NO_RESULT_TERMINAL
module: OUTPUT_CACHED_DURABLE -> SCALAR_ERASED_NO_RESULT_TERMINAL
    (only with a threshold-service KEY_ABSENT certificate)
module: RESULT_KEY_SEALED
  -> SCALAR_ERASED_NO_RESULT_PENDING_KEY_TOMBSTONE
threshold service: KEY_ABSENT | KEY_ACTIVATION_STARTED | KEY_ENVELOPE_ACTIVE
  -> NO_RESULT_TOMBSTONED -> CHILD_KEY_SHARES_ERASED_FINAL
module: SCALAR_ERASED_NO_RESULT_PENDING_KEY_TOMBSTONE
  -> SCALAR_ERASED_NO_RESULT_TERMINAL
    (only after validating the exact registry teardown certificate and ordered
     threshold-service child-key-share erasure receipts)
```

Recovery before `OUTPUT_INTENT_DURABLE` may resume only the exact bound input.
After that intent is durable, the module may return only
`OUTPUT_CACHED_DURABLE`; if the one physical invocation was interrupted before
the cache commit, it records terminal no-result and never re-enters scalar
code. An external retry never invokes scalar multiplication. A crash after scalar
destruction replays the durable device tombstone/result-key state, finalizes
erasure, reconstructs the final wrapper from separately durable components, and
never restores `r_j`. A failure that cannot prove byte-identical recovery is
terminal and emits nothing. Backups must be absent, synchronously consume the
same nonrollback state, or be an independently specified threshold-custody
protocol; an inventory of ordinary restorable scalar ciphertexts is a kill
condition.
Before registry body-commit certification, a permanent failure uses the exact
`CustodyNoResultTeardownCertificateV1` and complete clone-erasure evidence from
section 8.3. The registry atomically selects either that teardown certificate
or `ParticipantResultBodyCommitCertificateV1`; the two certificates cannot both
exist. After body-commit certification, no no-result transition exists, even if
the module has not yet validated the certificate. Recovery retrieves and
validates the committed bytes, then finishes ordinary erasure and key release.
If `RESULT_KEY_SEALED` was reached, local deletion is not terminal. The
threshold service first validates the exact mutually exclusive registry
`CustodyNoResultTeardownCertificateV1`, including proof that no body-commit
certificate won the CAS. It then commits `NO_RESULT_TOMBSTONED` for the exact
envelope or activation-attempt digest and permanently rejects both normal-
release and replay predicates. Every
admitted child-key share and backup then produces an ordered forward-secure
erasure receipt. Only `CHILD_KEY_SHARES_ERASED_FINAL` and destruction of the
module's local result key/cached output permit
`SCALAR_ERASED_NO_RESULT_TERMINAL`. Ciphertext/envelope copies may remain public
only under the theorem that fewer than the threshold old shares were corrupt
before this certified erasure and honest erased shares are not recoverable by
later compromise.

For canonical nonidentity points in prime-order Type-3 groups, `R_j =
[r_j]delta` and pairing nondegeneracy make the public certificate equation
uniquely imply `X_j = [r_j]A`. For a valid Groth16 proof:

```text
e([r_j]A, B) / e(C, [r_j]delta)
    = (e(A, B) / e(C, delta))^r_j
    = Y^r_j
```

That algebra is not the hiding theorem. Pre-release secrecy requires a reviewed
positive-lock/hashed target-exponent assumption for the exact CRS, VK,
statement, and public leakage, `Y != 1`, nonzero `delta`, canonical subgroup
parsing, and toxic-waste erasure. In particular, no known point `Q` or known CRS
trapdoor relation may satisfy `Y = e(Q, delta)`, because then
`Y^r_j = e(Q, R_j)` is public. `[r_j]delta` plus guarded `A -> [r_j]A` is a one-shot
co-CDH oracle. Two unauthorized structured outputs can reconstruct `Y^r_j`, so
the acceptable property is zero unauthorized queries and one distinct
authorized query—not an optimistic `q = 2` hardness claim.

This profile is fund-ineligible until governance ratifies online scalar custody
as the honest-boundary assumption and independent reviews validate module
non-exportability, anti-clone/rollback state, setup/runtime constant-time and
fault behavior, scalar/result-key separation, crash recovery, terminal erasure,
and the full one-shot theorem. Removing DFB does not waive those gates.

### 5.4 Graph-signing key theorem

The Taproot N-of-N public key is not a covenant. If its signing quorum survives,
that quorum can sign a different parent after the preimages are exposed.
Therefore every graph uses a fresh, one-subject signing roster and key:

1. `GraphKeyDescriptorV1` pins the fresh setup nonce, ordered signer roster,
   control domains, threshold `N-of-N`, aggregate public key, key-aggregation
   transcript, and exact signature profile;
2. `GraphBundleV1` commits every fund-moving ACK/NACK parent field and every
   permitted witness hole;
3. each signer independently reconstructs the graph and signs only the exact
   BIP341 sighash messages recorded in `GraphPresignTranscriptV1`;
4. independent verifiers assemble and validate every complete parent witness;
5. before activation, at least one honest signer destroys its secret share,
   nonce state, backups, and any general-purpose derivation parent; and
6. the certificate rejects a graph key used by another subject or any signer
   capable of deriving the share again.

This assumes at least one honest signer through verified erasure. Mere
possession of a signature with `SIGHASH_DEFAULT` does not prevent a still-live
key from creating another signature.

### 5.5 Taproot key-path elimination

Every protocol output whose authorized conditions exist only in script leaves
MUST have no usable Taproot key path. v0.26 pins the BIP341 example NUMS point:

```text
H = lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
r_i = int(tagged_hash("RankLock/v026/TaprootNUMS",
    setup_intent_digest || output_role || u32(output_index)
)) mod n
P_i = H + r_i*G
```

`tagged_hash` is the BIP340-style tagged SHA-256 function and the tag is the
exact ASCII byte string shown above; `output_role` is a fixed one-byte enum, not
text. Because the discrete logarithm of `H` is not known and `r_i` is public,
no setup actor knows the discrete logarithm of `P_i`.

`GraphBundleV1` carries `P_i`, the exact script tree/root, tweaked output key,
and every control block. Participants, graph signers, ceremony verifiers,
funding custody, coordinator, and bridge independently reconstruct all four.
They MUST reject an arbitrary internal key, a mismatched tweak/control block,
an unrecognized script leaf, or a one-element key-path witness for a
script-only output. Outputs intentionally controlled by a key, such as a
bounded CPFP anchor, use a different explicit connector type and are not
silently exempted.

### 5.6 DKG and VSS boundary

Split-scalar does not require a DKG because no aggregate secret is constructed.
That is the main reason to prefer it for v0.26.

`setup_ceremony.py` is public commit/reveal randomness, not MPC. The current
Feldman VSS is dealer-generated, and `reshare()` reconstructs plaintext before
splitting it again. Neither may be described as DKG or used to weaken the N-of-N
assumption.

A real active DKG/MPC is required only for a future profile that collapses the
independent components into one aggregate lock or implements threshold release
of one shared preimage. That profile receives a different suite and ceremony
identifier.

### 5.7 Liveness boundary

All-preimage ACK provides one-honest safety and N-of-N liveness. There is no
cryptographic setting that simultaneously means “one honest participant blocks
an invalid release” and “one malicious participant cannot withhold” at the same
decision layer.

Before any funds deployment, one of these MUST be true:

- timeout/NACK is economically fund-preserving for the protected party, so
  withholding causes delay or refund rather than theft; or
- the design adopts a `t-of-n`/BFT threshold, rewrites its corruption theorem,
  and obtains new cryptographic and economic audits.

The current contested-payout semantics have not established the first property.
Therefore both S-DFB and C-DIRECT remain blocked even after a correct vector
connector.

The applied `f94c06d` validity-first graph supplies a concrete counterexample,
not merely a missing proof. Assume a semantically valid counterproof and one
participant shared by every N-of-N release withholds. No ACK preimage becomes
available. Each exact CSV-mature NACK spends its slot's ACK/NACK outpoint to
the graph owner, and `AllNackd` reaches the existing contested payout, whose
only output also belongs to the graph owner. The canonical valid-ACK branch
instead consumes the shared contest-payout connector and makes the existing
slash transaction consume the stake plus contest-slash connector for the
watchtower beneficiary set. The timeout trace therefore redirects principal
and avoids the canonical slash. A larger CSV or working CPFP can improve an
honest ACK's inclusion probability; neither repairs intentional withholding.

For a fixed signed execution policy and horizon `H`, let `W_p(T,H)` be the
spendable on-chain value controlled by principal `p` after terminal trace `T`,
plus policy-enforceable compensation, minus that principal's wallet inputs and
fees. Indefinitely locked outputs do not count as preserved. The policy MUST
commit the complete graph/templates, every input amount, a role-to-economic-
principal map, the selected valid-ACK baseline, the exact neutral-principal
baseline, all CSV/finality bounds, and the fee/CPFP authorization. Let
`P_p(T,H)` be the portion of `W_p` attributable to pre-existing principal,
excluding a newly earned bounty or penalty. For a valid counterproof, every
allowed one-fault terminal trace MUST be either the exact ACK/slash baseline or
a separately signed refund/insurance trace satisfying both:

```text
sum_p in protected [P_p(neutral_baseline,H) - P_p(T,H)]_+
    <= explicit_fee_and_delay_allowance

W_timeout_coalition(T,H) - W_timeout_coalition(neutral_baseline,H)
    <= explicit_service_fee
```

The mandatory protected-principal set includes every depositor/user/insurer and
service principal whose pre-existing value is represented by a consumed
protocol UTXO. The graph owner/refuted operator is adversarial in this
valid-counterproof game. ACK-anchor bounties and slash rewards are protected
only when the signed policy makes them unconditional or they contain the
beneficiary's contributed principal; the neutral-refund profile instead makes
new rewards and penalties conditional on a confirmed ACK. A stronger
incentive-parity claim, including “the refuted operator cannot avoid the
baseline slash,” requires independently locked insurance or a validity signal
and is a separate mandatory gate if governance relies on that deterrent. The
dual invalid-or-absent-proof game protects the honest operator's principal and
forbids wrongful ACK/slash. Both games quantify exact Core CSV boundary
behavior, miner inclusion/censorship assumptions, reorg depth, package
feerates, fee reserves, CPFP ownership, and every residual UTXO. A
caller-supplied `funds_preserved` boolean or an unspendable residual output is
not evidence.

The integration bundle ships a typed, read-only
`detect_correlated_ack_withholder_loss` analyzer. It reconstructs transaction
ids, conflicts, scripts, and values from a generated `GameGraph` and emits
`funds_safe_under_premise = false` for the current N-of-N trace. It is a kill
witness only: `Ok(None)` for a weaker threshold is not a safety proof, and the
analyzer is intentionally disconnected from funding authorization. Production
qualification additionally requires a validity certificate bound to exact
subject/proof/txid/wtxid bytes and Core-backed terminal enumeration.

### 5.8 Selected timeout direction: prove neutral principal recovery first

The v0.26 baseline keeps N-of-N cryptographic release and requires an on-chain
economically neutral terminal. The current abstract candidate does not yet
establish that property: it proves only a narrow conflict and deposit-allocation
condition. Threshold release is not the baseline and cannot be used to excuse
an unsafe terminal.

This follows from an indistinguishability limit. Before an ACK witness appears,
Bitcoin sees the same fact in both of these worlds:

1. the same selected, syntactically authorized counterproof is semantically
   invalid and therefore has no ACK preimage; and
2. that selected counterproof is semantically valid but one required release
   participant withholds the ACK preimage.

A deterministic presigned timeout cannot condition its outputs on which world
occurred. Because the current ACK/slash and NACK/payout baselines allocate the
same scarce connectors to different principals, no rearrangement of those
UTXOs can reproduce both exact baselines. A claimed solution MUST therefore do
at least one of the following: return principal to a neutral recovery policy
and make semantic rewards/penalties conditional on a confirmed ACK; add fully reserved
collateral sufficient to dominate both baselines; or introduce a separately
audited validity signal. CPFP anchors and other precommitted service fees are
not semantic rewards and MUST remain inside the explicit fee allowance. The
first option is the required v0.26 foundation.

The graph-v2 candidate has these exact conflict requirements; its byte layout
is not frozen until the Rust/Core prototype passes:

1. For a roster of `n` counterproof reserves, every `CounterproofV2_i` spends
   all `C_0..C_(n-1)` in canonical order, followed by the shared
   `ContestPayoutConnector` and the deposit state output. `C_i` uses its exact
   graph-plus-operator counterproof leaf; every `C_j, j != i` uses the separate
   graph-only reserve-recovery leaf. Outputs are the exact deposit value to
   `RecoveryVaultDescriptorV1`, one `CounterproofResolutionConnectorV1`, one
   selected-watchtower CPFP anchor, and one exact-value return `U_j` to each
   non-selected reserve beneficiary in increasing roster order. Owner payout
   spends `D,Q,P,S,C_0..C_(n-1)` and returns every `C_j` exactly to `U_j`.
   Consequently every selecting branch atomically consumes every reserve;
   confirmation selects at most one counterproof, makes every legacy deposit
   spender and owner payout consensus-invalid, and leaves no unselected `C_j`.
2. `ACKV2_i` spends the resolution connector through the immediate positive
   lock and emits exactly one `SlashAuthorizationConnectorV1_i` plus a separate
   ACK CPFP anchor. The slash-authorization output is a standard dust-valued,
   script-only Taproot output with the approved NUMS internal key and exactly
   one presigned Slash path. It MUST NOT double as the CPFP anchor.
3. `CounterproofTimeoutSettlementV1_i` spends the same resolution through its
   exact CSV path plus contest-slash through its presigned normal path. It MUST
   NOT spend deposit or the independently burnable claim-payout output. It pays
   exactly one bounded, independently controlled CPFP anchor; any required
   excess change goes only to the recovery descriptor.
4. `SlashV2_i` spends the ACK-created authorization, contest-slash through the
   delayed Slash path, and an exclusively reserved stake output. It pays the
   exact zero-value protocol header followed by the exact committed ordered
   watchtower distribution. The ordered penalty-payout descriptors are bound
   separately from CP/ACK CPFP descriptors even when both rosters identify the
   same economic watchtowers. Every v1 counterproof, ACK,
   NACK, Slash, completed or partial signature, adaptor value, and runtime
   parent is different protocol material and MUST NOT survive in a v2 signing
   roster. In particular, v2 MUST NOT reuse a `C_i` for which a v1
   counterproof signature or adaptor path may exist.
5. Owner payout and all counterproof siblings conflict on the shared
   contest-payout connector, the deposit, and every `C_j`; counterproof and every
   legacy deposit spender conflict on deposit; ACK and timeout conflict on
   resolution; timeout and Slash conflict on contest-slash. ACK-to-Slash is an
   ancestry relation through the authorization output, not a conflict. The
   reserve-recovery leaf is CHECKSIG, not a covenant: its safety depends on an
   exhaustive exact-template presign transcript plus one-honest key, nonce,
   derivation, and backup erasure. Bitcoin conflict establishes exclusion, not
   priority; inclusion, CSV, CPFP and reorg bounds remain explicit assumptions.
6. The recovery vault and every reserve-return beneficiary are typed,
   setup-time committed economic principals with their own liveness, threshold,
   rotation, and fee policies. They are never inferred from the graph owner and
   never supplied at runtime. A naked delayed sweep is forbidden because it
   would race a still-valid counterproof after CSV maturity; reserve cleanup is
   atomic inside the selecting parent instead.

Here `i` is the ordered Strata watchtower/counterproof alternative index. It is
not either of the exactly two RankLock query slots. The abstract plan binds an
ordered CP/ACK CPFP descriptor per alternative and one common resolution-
connector value/script/policy commitment. The two-alternative reference fixture
is only a deterministic evidence fixture; it is not a protocol roster limit.

For exact values, with fees measured from the finalized signed transactions:

```text
sum_j(C_j) + P + D
    = D_recovery + R_i + anchor_CP + sum_(j != i)(U_j) + fee_CP
D + Q + P + S + sum_j(C_j) = owner + sum_j(U_j) + fee_owner
R_i = L_i + anchor_ACK + fee_ACK
R_i + S = anchor_timeout + recovery_change + fee_timeout
L_i + S + K = sum(watchtower_outputs) + fee_slash
```

`D_recovery` MUST equal `D`, each emitted `U_j` MUST equal its corresponding
`C_j`, and `recovery_change` MUST be nonnegative and pay only the recovery
descriptor. Cancelling those exact returns leaves the original selected-reserve
equation `C_i + P = R_i + anchor_CP + fee_CP`. Reserve values and roster size
MUST be bounded from finalized signed weight; connector-level consensus maxima
are not production fee or policy limits.

The prototype MUST reject the candidate if one confirmed counterproof does not
make owner payout and every legacy deposit spender invalid at consensus, if two
counterproofs can both confirm, if any fund-moving parent needs a surviving
graph signing key, if the party able to force timeout controls its beneficiary
or CPFP path, if slash can exist without the ACK-created authorization, if
claim-payout is required for recovery, if stake is not exclusively reserved, if
unselected outputs create an unbounded stranded-value case, or if the exact
packages cannot enter the common prefix under the signed inclusion assumptions.

`ranklock.v026.timeout_economics` now implements the finite abstract check for
this candidate. It requires every counterproof and owner payout to consume the
complete ordered counterproof-reserve roster as well as the shared selection
outpoint and deposit, requires exact beneficiary-bound returns for every
non-selected reserve, checks the per-alternative resolution/ACK/timeout and
timeout/Slash conflicts, requires ACK to create the committed slash-
authorization output, conserves every integer satoshi amount, allocates exactly
the deposit amount to the committed recovery descriptor at counterproof
selection, checks the exact Slash header and ordered beneficiary/value roster
under separate penalty-payout descriptors, permits at
most one exact recovery change output on timeout, requires exact independent
CPFP outputs, rejects claim-payout as a timeout input, and requires the
worst-case abandoned counterproof reserve to be zero.
The focused suite includes missing-shared-gate,
owner-payout resurrection, deposit diversion, recovery-beneficiary
substitution, pre-ACK Slash, claim-payout dependency, missing Slash conflict,
value-creation, reserve-overrun and noncanonical-object regressions.

The same artifact now contains a deterministic live-UTXO terminal enumerator.
For the two-alternative reference it enumerates exactly five maximal local
traces and seven semantic worlds. Both `VALID_RELEASE_WITHHELD_i` and
`INVALID_RELEASE_ABSENT_i` map to the identical `CP_i -> Timeout_i` trace.
Every positive terminal outpoint requires a declared disposition, non-null
beneficiaries cannot be economically relabeled, locked value receives zero
credit, and the policy digest is derived from canonical policy content. The
committed atomic-reserve policy returns
`AbstractDeclaredPolicySatisfiedV1` with no locked-reserve witness. This means
only that every caller-declared terminal disposition satisfies the declared
local policy; it does not authenticate the policy or establish protected value.

This does not establish the terminal wealth theorem. Every satisfied engine
case returns only `AbstractDeclaredPolicySatisfiedV1`, with
`protected_value_theorem_established = false` and `funding_eligible = false`.
It always retains four qualification blockers: protected-baseline authority,
per-principal allowance authority, service-fee schedule/baseline authority, and
by-horizon CSV/reorg/fee execution. The Python fixture is not a canonical
projection of the Rust graph and cannot discharge those authorities.

That result is **EXACT abstract graph evidence**, not Bitcoin consensus
evidence. Even when its narrow
`counterproof_selection_allocates_exact_deposit` result is true, the assessment
returns `funding_eligible = false` and its artifact retains thirteen categorical
blockers:
recovery-descriptor control is unverified; CPFP control is unverified;
resolution-connector Script policy is unverified; slash-authorization Script
policy is unverified; Slash-beneficiary control is unverified; alternate deposit signatures have not been excluded;
stake exclusivity is unverified; the complete exact-presign, legacy-template,
and signing-share erasure inventory is unverified; the atomic roster
weight/confirmed-parent policy is unqualified; terminal principal disposition
is not enumerated; the validity/withholding ambiguity is unresolved; the Python
policy has not been proven to be a canonical projection of the Rust graph; and
the executed Core cases have not been cryptographically bound to that model.

The Rust implementation and Core cases are a separate **REPRODUCED research**
slice. Side-by-side
Rust types implement research NUMS `C/P/S/R/L` connectors, exact
Contest/Counterproof/ACK/Timeout/Slash/Owner parents, and a private-field
`V026Graph` assembler. The assembler derives every internal outpoint from its
actual parent txid, independently reconstructs the expected unsigned
transactions and exact spender matrix, and always returns
`funding_eligible = false` with sixteen activation blockers.

Six real Bitcoin Core cases independently accept both counterproof siblings,
the mature owner payout, ACK, timeout at the first valid resolution CSV
height, and Slash after its ACK-created authorization and contest-slash CSV.
The losing owner and timeout transactions are retried only after their own
CSV has matured, so rejection is attributable to the shared spent input rather
than a timelock. A separate valid N-of-N key spend of the stake output is also
accepted and then prevents the otherwise-valid Slash. That is reproduced
evidence for the `K` conflict and positive evidence that stake exclusivity has
not been established. It is not evidence for runtime admission, canonical
wire identity, complete presigning/erasure, legacy-material exclusion, ASM
activation, fee-package/reorg liveness, terminal wealth preservation, or the
validity/withholding theorem. The exact signed two-alternative,
`n_data=128` fixture measures 10,690 WU for CounterproofV2 and 2,345 WU for
OwnerPayoutV2. Core accepts that counterproof after Contest confirms but rejects
the identical signed transaction while Contest is an unconfirmed version-3
parent because the child exceeds the tested 4,000-WU v3-child limit. The
confirmed-parent requirement and a joint roster/`n_data` activation bound
therefore remain explicit evidence gates. The source-bound report is
`results/v026_rust_graph_core.json`.

The only durable runtime-adjacent integration is a negative observation lane.
The frozen `StructurallyVerifiedFundingBlockedV1` format retains its exact
fifteen-code array, `RL26ADM || u16_le(1) || body` envelope, and
`v026_admissions_v1` subspace. It fails closed for the current sixteen-blocker
graph. Current observations use a separate
`StructurallyVerifiedFundingBlockedV2`, `RL26ADM || u16_le(2) || body`, and
`v026_admissions_v2` subspace. Both have a constant false funding predicate and
store only a local txid manifest—not a canonical graph digest. Decoding rejects unknown versions,
unknown blockers, truncation, trailing bytes, malformed shapes, row/body key
mismatch, and any byte string that differs from canonical re-encoding. The
atomic outcomes are `Created`, `ExactReplay`, and a non-overwriting
`Conflict`. No P2P, GraphSM, duty, executor, funding, signing, or broadcast path
consumes either record, so `RuntimeAdmissionUnimplemented` remains mandatory.
Neither live observation capability is deserializable by downstream callers;
private persisted read models preserve strict decoding without minting a write
capability. The live FDB CAS test compiled but did not complete because the local FDB
harness hung; codec and pure classification tests are reproduced in
`results/v026_runtime_observation.json`.

The alternate-signature blocker is not discharged merely by consuming deposit
inside `CounterproofV2`. Before counterproof confirmation, current
`CooperativePayout` can spend deposit alone and may already have a hidden valid
signature. Activation MUST either (a) verify an exhaustive, subject-unique
deposit-spend signing transcript and irreversible destruction of at least one
honest participant's share, nonce material, derivation path, and every backup
before funding, or (b) confirm and finalize a cutover into a fresh deposit state
whose complete spender set is consensus-enforced by the selected Script
semantics. A merely script-only CHECKSIG output is not a covenant: if its key is
live, it needs the same exhaustive exact-presign, no-off-transcript-signature,
non-derivability, and one-honest share-erasure proof. Erasure proves that a new
signature cannot be created; it does not prove an old signature never existed.

The abstract candidate closes the known post-selection deposit, current-Slash,
claim-payout burn, and unselected-reserve disposition races by topology, but it
still is not a complete terminal graph. Stake can be shared with unstaking or
another game's Slash; descriptor possession and every Script path are
caller-declared; and pairwise conflicts do not establish
priority or whole-graph wealth preservation. Refunding the bridge deposit can
also leave an honest fronting operator unreimbursed after an invalid first
counterproof. Universal all-party funds safety still needs consensus-verifiable
validity, threshold availability under a separately audited corruption theorem,
or independently funded two-world coverage.

The complete-graph presign blocker covers every live-key or legacy escape, not
only deposit: all intended P/S/K/C/R/L parents and witnesses MUST be enumerated,
fully committed, independently verified, and presigned before funding; every
v1 parent and signature MUST be rejected; and at least one subject-specific
signing share, nonce source, derivation path, and backup set MUST then be
irreversibly destroyed. The stake-exclusivity blocker separately requires a
global reservation/consumer proof against Unstaking and every concurrent game,
not merely a local graph assertion.

A future threshold profile may use `n = 3f + 1` participants and a `2f + 1`
release/decision certificate to tolerate `f` withholding faults. It is a new
protocol requiring active malicious-secure DKG/MPC and a new corruption
theorem. Even then, the neutral refund remains mandatory for `f + 1` faults,
pre-GST partition, fee starvation, or service failure.

---

## 6. Setup ceremony and activation

The policy selects exactly one incompatible ceremony profile.

### 6.1 Profile S-DFB — split-scalar N-of-N

This is one candidate, not an approved implementation target.

1. The one-subject graph roster creates `GraphKeyDescriptorV1`; the registry
   rejects reuse of its setup nonce, aggregate key, or member key derivation.
2. Governance publishes and signs `SetupIntentV1`. It contains no descendant
   digest and no mutable admission decision.
3. Participants independently generate and sign their contributions under the
   intent-derived lock context.
4. The graph builder creates `GraphBundleV1`; every participant verifies the
   same ordered contribution set and graph before issuing its bundle approval.
5. The one-subject graph roster presigns every exact fund-moving parent,
   verifies the complete witnesses, and destroys its signing shares and backup
   derivation paths.
6. Contributions, approvals, presign transcript, and erasure inventories are
   published to independent append-only stores and anchored before
   certification.
7. Every named ceremony verifier, at least two independent control domains,
   reproduces all public outputs and signs `CeremonyCertificateV1`.
8. Governance signs immutable `ExecutionPolicyV1`, constructs
   `FundingSubjectV1`, and signs `ActivationCertificateV1` over the final
   funding-subject digest, typed audit manifests, exact subject lifetime,
   Core-MTP-derived activation time, and verified signed security-floor report.
9. The BFT safety registry atomically admits and reserves value/count capacity,
   producing `AdmissionCertificateV1` under the current admission policy.
10. Only the custody-gated funding service may add signatures or broadcast the
    exact funding transaction, and only after steps 1–9 succeed.

An abort at any point produces a signed `CeremonyAbortV1` and a monotonic
registry retirement record for the setup-intent digest, epoch, deposit
identifier, graph key, nonce namespaces, and every contribution. Retired bytes
can never appear in another subject.

`CeremonyCertificateV1` contains predecessor digests, participant identities,
ordered contribution/artifact/approval digests, graph and connector digests,
the complete graph-presign transcript, exact setup-secret and retained-secret
inventories, public anchor observation, verifier identities, report schema ids,
and signatures. It does not contain or sign its descendant funding-subject
digest.

The complete unsigned funding transaction is fixed in `SetupIntentV1`. Every
input MUST be native SegWit or Taproot with an empty `scriptSig`, so adding only
witness signatures cannot change its txid. Version, locktime, inputs, sequences,
outputs, fees, and planned deposit outpoint are exact; baseline v0.26 forbids
RBF and alternate funding transactions. Ceremony and funding custody recompute
the txid before and after signing.

No funding-transaction input may be signed and no value may be broadcast into
the graph before the final activation certificate, audit set, admission
reservation, erasure checks, and recovery paths all validate. This prohibition
does not apply to the required unfunded ACK/NACK descendant presigning in step
5. A green local JSON report is not activation.

### 6.2 Profile C-DIRECT — online conditional-release custody

Profile C follows the same identity DAG, contribution review, graph presigning,
external anchoring, activation, admission, and funding-custody order. It changes
the participant ceremony in these mandatory ways:

- the attested custody module generates `r_j` and `k_j`, constructs the exact
  positive lock and scale proof internally, and never exposes either secret;
- the contribution commits the subject-unique custody handle, module policy,
  firmware/build and attestation roots, monotonic counter namespace, physical
  control domain, and complete replica/clone inventory instead of an artifact
  root;
- independent verifiers challenge the exact module policy and reproduce every
  public contribution, proof, graph, and attestation chain before activation;
- the certificate records that plaintext `k_j` was erased but `r_j` remains the
  live ACK-recovery capability. It MUST NOT claim the participant has erased
  every setup secret;
- a subject has one scalar handle, not one scalar per logical retry slot;
- ordinary backups are forbidden. Any replicated or threshold handle needs an
  exact protocol whose members share the same irreversible reservation and
  consumed state; and
- the threshold conditional-result-key roster, encryption/availability
  protocol, control domains, and erasure-certificate release predicate are
  fixed before contributions; and
- abort before funding destroys the handle and every admitted clone before the
  setup intent may become terminal.

No existing HSM or enclave is implicitly approved. Profile C remains disabled
until the exact device, firmware, attestation, side-channel/fault analysis,
anti-rollback/clone mechanism, and recovery behavior are pinned and audited.

### 6.3 Profile M — active MPC

Profile M is disabled until an audited backend executes the exact generator
with active security against `N-1` corruptions. The existing MPC evidence types
are a useful envelope, not the missing backend.

Activation additionally requires:

- backend protocol, implementation, circuit, parameter, and parser versions;
- authenticated-channel identities and network topology;
- private-view commitments before an anchored post-cutoff beacon;
- complete participant receipts and two independent transcript replays;
- evidence that no party learns the aggregate scalar, label pairs, ACK payload,
  or reconstructing entropy;
- machine-verification of every referenced evidence schema.

The public entropy commit/reveal ceremony cannot qualify Profile M by itself.

---

## 7. Runtime messages

Sections 7.1, 7.3, and 7.4 are common. Section 7.2 first gives the S-DFB
participant branch and then the incompatible C-DIRECT branch. A deployment
MUST parse the integrated `proof_suite_id` from the validated funding subject
and resolve its one compiled release mechanism; it cannot infer the branch from
which fields happen to be present.

### 7.1 `EvaluationIntentV1` and semantic identity

The external caller may submit only:

```text
framing
funding_subject_digest
slot_id
transport_nonce
exact_raw_counterproof_transaction
canonical_future_proof
requester_xonly_pubkey || requester_bip340_signature
```

It cannot submit public inputs, a VK, a verifier, participant outputs, burn
receipts, release records, policy objects, or an authoritative block location.
The signature is exactly 64-byte BIP340 over:

```text
SHA256("ranklock/v026/evaluation-intent\0" || unsigned_intent_bytes)
```

The immutable execution policy pins the requester keys. `transport_nonce` is
anti-replay metadata but is deliberately excluded from semantic equivalence.
After strict parsing, the coordinator constructs:

```text
semantic_request_id = SHA256(
    "ranklock/v026/semantic-request\0" ||
    funding_subject_digest ||
    u16(slot_id) ||
    SHA256(exact_raw_counterproof_transaction) ||
    SHA256(canonical_future_proof)
)
```

`slot_id` MUST be one of the subject's two ordered query slots. It then derives
canonical `EvaluationBindingV1`: funding-subject and admission-certificate
digests, slot id, semantic id, exact raw transaction, txid, wtxid, witness
digest, authorization outpoint, selector digest, and proof digest.
Block hash, height, and confirmation depth are signed `CoreObservationV1`
records, not caller authority and not part of semantic identity.
Each observation contains node/control-domain identity, chain genesis, raw
transaction digest, txid, wtxid, witness digest, target block hash/height,
best-block hash/height, cumulative chainwork, median-time-past, observation
height, and signature. The execution policy requires agreement from at least
two independently operated fully validating nodes and prevents the coordinator,
all participants, and bridge from sharing one RPC/control failure domain.

The exact signed-envelope digest is:

```text
evaluation_intent_digest = SHA256(
    "ranklock/v026/evaluation-intent-envelope\0" || canonical_signed_intent
)
```

The first successful slot CAS records that digest as the accepted authorization
envelope. A later envelope with the same semantic id but another nonce/signature
receives the existing lock and cannot change downstream bytes.

### 7.2 Participant command and result

For Profile S-DFB, after the global registry accepts the semantic request, the
following state machine applies.

After the global registry accepts the semantic request, the coordinator sends
each participant an authenticated `ParticipantEvaluationCommandV1` containing
the exact intent and evaluation binding, the global intent-lock certificate,
and the coordinator key. Each participant independently:

1. validates the complete funding-subject DAG and immutable execution policy;
2. canonical-parses the transaction and proof and derives the committed public
   inputs from `SetupIntentV1`;
3. independently queries pinned Core and validates txid, wtxid, witness,
   selector, active-chain depth, unspent ACK/NACK outpoint, and
   `chain_guard == OPEN`;
4. compare-and-sets its participant slot to this exact semantic id in the
   safety registry, obtains a `BURNED` certificate, and can never reuse that
   slot for another semantic request;
5. fully verifies the exact proof/statement and rechecks Core, but does not yet
   evaluate the retained artifact or emit any projective output;
6. creates and signs a nonsecret `ParticipantReadyV1` containing the subject,
   slot, semantic-request and binding digests; participant index/key; `BURNED`
   certificate; exact proof-verification result; Core observations; artifact
   identity; and next participant-journal position. It stores those exact bytes
   durably and commits `READY(ready_digest)` in the registry;
7. waits for and validates a subject-wide `ReleaseReservationCertificateV1`
   selecting this exact slot, semantic request, binding, and complete ordered
   ready-set digest. An honest participant never computes or transmits
   `[r_j]A` before this certificate;
8. handles the alternate slot by its exact registry state: if nonterminal, it
   destroys the envelope key and every recoverable backup, fsyncs a signed
   `ParticipantSupersededErasureV1`, and commits
   `RETIRED_SUPERSEDED(erasure_record_digest)`; if already cryptographically
   terminal, it validates the prior physical-erasure record and commits a
   finalized release-bound `SupersessionReferenceV1` without changing state. A
   crash in either branch resumes/validates that evidence, never evaluation;
9. waits for `ERASURE_BARRIER_COMPLETE`, validates the complete ordered erasure
   set including its own record, then rechecks the reservation and evaluates its
   selected retained artifact locally to produce the exact `[r_j]A` projective
   output;
10. creates and signs exact `ParticipantResultBodyV1` bytes once, stores them in
   a private durable result outbox, and fsyncs the object and directory;
11. compare-and-sets `RELEASED(result_body_digest, outbox_predecessor_head,
    release_sequence)` and receives a separate
    `ParticipantReleaseCertificateV1`; and
12. durably stores the secret-bearing `signed_body || release_certificate`
    wrapper under a result-retention key distinct from the evaluator envelope
    key, then retires the selected slot's evaluator secrets and emits those exact
    bytes only to authorized post-reservation handlers.

The signed body contains the funding-subject, slot, semantic-request and
evaluation-binding digests; participant index/key; projective output;
before/after Core observations; the pre-existing `BURNED`, `READY`, and release-
reservation certificates; the selected erasure-or-supersession evidence; the
complete ordered erasure-set digest; and the outbox predecessor head/next
sequence. It
cannot contain its descendant
`RELEASED` certificate or resulting journal head. Its BIP340 signature is over:

```text
SHA256("ranklock/v026/participant-result-body\0" || unsigned_result_body_bytes)
```

`ParticipantSupersededErasureV1` contains the funding subject, release id,
participant id, losing slot id, envelope-key id, complete backup/wrapping-key
inventory digest, destruction method/evidence references, predecessor/next
participant-journal positions, and participant signature. It is an auditable
honest-party attestation, not a magical proof of deletion; section 3.3 relies on
at least one participant actually following it. An erasure record for the wrong
reservation, participant, slot, or inventory cannot satisfy the barrier.
`SupersessionReferenceV1` contains the same subject/release/participant/slot
identity plus the exact prior terminal state, erasure-record digest, inventory
digest, and finalization-envelope digest. It cannot substitute a tombstone that
lacks physical-erasure evidence.

The returned `ParticipantEvaluationResultV1` wrapper is the exact signed body
followed by the release certificate, which commits that body digest. It is
secret-bearing authorized post-reservation data because its `[r_j]A` component
can unlock that participant's preimage; it is never a general log/audit object.
Exact replay returns the staged wrapper even after evaluator-secret erasure.
Caller-supplied or coordinator-invented participant results are never accepted.
A participant exports neither its label pairs nor its program seed.

The coordinator may request readiness for either committed query slot, but it
cannot obtain an honest projective result merely by collecting `READY` records.
Only after all ordered participants are ready, a fresh independent Core quorum
still observes the bound wtxid in the required common prefix, and no NACK is
terminal may the registry atomically reserve one subject-wide release. That
reservation requires physical retirement of the other slot before selected
evaluation. It is the protocol's cryptographic point of no return, although an
honest result is still withheld until superseded erasure completes: the
selected vector may be exposed after those barriers even if a later NACK
prevents ACK broadcast.

#### Profile C-DIRECT participant branch

Profile C reuses steps 1–7 only with `artifact identity` replaced by the exact
custody-handle policy/attestation/counter identity. Proof verification completes
before readiness. `READY` is a signed, attested claim that the module has
performed zero scalar operations; its truth is part of the honest-module
assumption. It does not load or expose `r_j`.

After the subject-wide reservation selects one slot and exact proof, each
module validates the reservation and independently derives canonical `A` from
the bound proof. It then irreversibly changes its handle from `ACTIVE` to
`RELEASE_BOUND(release_id, slot_id, proof_digest, A_digest, counter)` and signs
`ParticipantCustodyBoundV1`. The registry accepts the complete ordered bound set
as an exact `CustodyBoundCompleteCertificateV1` containing the subject,
release id, proof/`A` digests, ordered participant/handle/counter set,
predecessor/new roots, signer bitmap, and `2f+1` signatures. The module itself,
not host software, validates those exact bytes before it durably consumes the
one allowed operation as `OUTPUT_INTENT_DURABLE(counter = 1)`. The
alternate slot becomes
`RETIRED_SUPERSEDED_LOGICAL`; there is no alternate scalar or fake per-slot
physical-erasure claim. No participant may multiply before the complete bound
barrier. After reservation, the module validates the reservation's certified
`OPEN` Core observation snapshot; a later NACK does not select another request
or unwind binding, while the common chain guard still suppresses new
publication and broadcast.

After that barrier and durable output intent, each module computes and
self-certifies the single exact `[r_j]A` and atomically persists
`OUTPUT_CACHED_DURABLE`. A crash after intent but before that cache terminally
erases without a result; it never repeats scalar code. From the cached output,
the module seals the distinct result key, then the participant signs and
privately fsyncs `ParticipantResultBodyV1` and obtains a separate
`ParticipantResultBodyDurabilityReceiptV1`. It submits only the body
digest, durability-receipt digest, body ciphertext, and exact
`ConditionalResultKeyEnvelopeV1`/replica-availability evidence. The result key
is unavailable until a matching erasure envelope is final; registry replicas
and the coordinator receive no plaintext output. The module reads the exact
quorum-replicated ciphertext back, authenticates/decrypts it internally, and
compares it with the durable body before allowing erasure. The registry returns
`ParticipantResultBodyCommitCertificateV1`. The quorum-available encrypted body
and exact registry certificate make `ResultCoreV1 = signed_body ||
body_commit_certificate` deterministically reconstructible after key release.
The participant executes the selected `CloneErasureEvidenceV1` branch: a shared
monotonic-domain device may issue one inventory-covering atomic receipt, while
physically distinct clones must each issue an ordered erasure receipt. It then
persists the primary device tombstone/result-key release state under an
attestation key independent of `r_j` and produces
`ParticipantScalarErasureV1` binding the complete evidence. The registry
finalizes that erasure. The surviving module or pinned threshold recovery
service validates that exact envelope, releases the result key, and only then
the participant constructs and durably
replicates `ParticipantEvaluationResultV1 = ResultCoreV1 ||
ParticipantScalarErasureV1 || erasure_finalization_envelope`. Only then may the
plaintext wrapper leave the participant boundary. Exact replay reads that final
wrapper; it never invokes scalar multiplication again.

The Profile C result body replaces artifact/alternate-erasure fields with the
custody-bound certificate, operation counter, canonical `A` digest, output
self-check inputs, outbox predecessor/next sequence, target result-retention-key
id/inventory, and the precommitted scalar-erasure policy/inventory digest. It
contains no result-durability receipt, body-commit certificate, or erasure
record, because each is a descendant of the signed body. The body-commit CAS
binds the body and durability-receipt digests. `ParticipantScalarErasureV1` and
its registry envelope bind the subject, release id, body digest, body-commit-
certificate digest, ciphertext/AEAD/conditional-result-key envelope and
availability-receipt digests, handle/clone inventory, operation counter,
result-key release-state digest, and terminal module-state/device-receipt
digest. It also binds `CloneErasureEvidenceV1`, a tagged union of
`SHARED_MONOTONIC_DOMAIN(exact_inventory_digest, shared_device_receipt)` or
`ORDERED_PHYSICAL_ERASURE_SET(exact_inventory_digest,
ordered_clone_receipts)`. A singular receipt cannot silently stand for
physically independent clones. The release-profile codec fixes the final
wrapper ordering and rejects S-DFB fields.

Crash recovery follows the exact monotonic sequence in section 5.3.2. Before
reservation it may retry the same logical slot. After reservation it may bind
only the selected proof. After `OUTPUT_INTENT_DURABLE`, it either reaches
`OUTPUT_CACHED_DURABLE` from the sole invocation or terminally erases without a
result; no recovery path multiplies again. After result-body durability it
finishes ciphertext/key-envelope availability, readback, and commit
certification before erasure. A crash immediately after erasure recovers the
durable device tombstone or conditional key envelope, finalizes/validates
erasure, releases the result key, and assembles the final wrapper without the
scalar. After final-wrapper durability it replays bytes only. It never selects
the alternate slot. Terminal chain resolution before reservation invokes
certified no-result scalar destruction.

### 7.3 `VerifiedReleaseSnapshotV1`

After receiving all ordered results, the coordinator durably stores a canonical
snapshot containing the canonical semantic payload/binding, accepted
authorization-envelope digest, proof, Core observations, ordered signed
participant result wrappers, canonical registry certificates, verified
graph/policy versions, certified projective outputs, unlock checks, coordinator
authorization-policy digest, and every deterministic unsigned-capsule input. It
excludes a chosen coordinator key, transport nonce, and other equivalent-retry
metadata. The snapshot also excludes plaintext preimages; they are
deterministically re-derived from the proof, positive locks, and certified
outputs.

The complete result set is secret-bearing even though it contains no literal
preimage: a holder can run the public unlock algorithm. The coordinator and
registry replicas therefore receive projective result bodies only after the
subject-wide reservation has authorized that exact vector. They are treated as
potentially able to recover it from the first complete valid result set onward.

The snapshot digest and exact `VERIFIED_SNAPSHOT` finalization-envelope digest
become immutable before any publish intent. Registry CAS selects the first valid
snapshot. A racing coordinator with newer but compatible Core observations
validates and adopts that registry-selected snapshot; no local coordinator
journal identity is authoritative. Only a different security-relevant binding
is a terminal conflict.

Any coordinator key authorized by the snapshot's immutable execution policy may
adopt the winning snapshot and sign a capsule. Before `PUBLISH_INTENT`, racing
authorized keys may produce different signature bytes over the same reserved
vector and transaction economics. The first successful publish CAS selects the
exact capsule and signer; after that transition every retry is byte-identical
and no coordinator may freshly sign.

### 7.4 `AckReleaseCapsuleV1`

The coordinator publishes:

```text
framing
funding_subject_digest
slot_id || semantic_request_id || evaluation_binding_digest || release_id
ack_template_digest || connector_digest
ordered_preimage_count || ordered_preimages
verified_snapshot_digest || verified_snapshot_transition_digest
participant_certificate_set_digest
coordinator_xonly_pubkey || coordinator_bip340_signature
```

`verified_snapshot_transition_digest` identifies the finalization envelope
immediately before `PUBLISH_INTENT`; the separately finalized publish transition
binds that predecessor, slot key, semantic id, release id, snapshot digest,
exact capsule digest, transition sequence, and predecessor state root. This
avoids a digest cycle. The 64-byte coordinator signature is BIP340 over:

```text
SHA256("ranklock/v026/ack-release-capsule\0" || unsigned_capsule_bytes)
```

The content-addressed path is:

```text
release/<funding_subject_digest>/<release_id>.ack
```

Capsule/preimage bytes are restricted to the coordinator, authorized
safety-registry replicas, and bridge readers. Outside the canonical secret
`PUBLISH_INTENT` record and final capsule they MUST never appear in logs,
metrics, exception strings, audit manifests, or attestations.

The bridge MUST independently:

1. open without following symlinks and require a private, bounded regular file;
2. canonical-parse the capsule and validate the funding-subject DAG, activation
   and admission certificates, immutable execution policy, and coordinator key;
3. validate every participant result and registry commit certificate;
4. require the BFT registry's exact `PUBLISH_INTENT` for these capsule bytes;
5. reconstruct the graph, connector, complete ACK parent and presigned witness;
6. verify preimage count/order/uniqueness and every SHA-256 commitment;
7. query pinned Core immediately before submission and require the exact parent
   txid and wtxid at depth, the ACK/NACK outpoint unspent, and derived
   `chain_guard == OPEN`;
8. run consensus, policy, and package acceptance for the exact ACK parent and
   permitted CPFP child; and
9. broadcast only those bytes and return a signed idempotent consumer receipt.

Mutable admission-policy revocation cannot strand an admitted subject. Before
the global intent lock it may stop new admissions only. After certified
`ProfileReleaseReservedV1`, governance cannot authorize a different slot or vector even
if a coordinator key is later revoked. After certified `PUBLISH_INTENT`, the
bridge accepts only the exact capsule selected by that reservation. Exposed
preimages cannot be retracted. Any stronger
emergency rule must already exist as an independently audited on-chain branch.

---

## 8. Safety registry and distributed state machines

### 8.1 Externally monotonic registry

Local SQLite uniqueness is not an election mechanism. v0.26 requires an
authenticated, totally ordered BFT safety registry with `3f+1` replicas and
`2f+1`-signature finalization envelopes. The baseline is `f >= 1`. Replica keys,
control domains, cluster id, generation, state-machine version, receipt schema,
and reconfiguration prohibition for active subjects are pinned by
`ExecutionPolicyV1`.

The registry provides linearizable compare-and-set for:

- governance sequence, graph-key/setup-intent/contribution-set successor
  selection, and ceremony retirement;
- admission reservations and global active value/count;
- one semantic request per subject/slot;
- each participant's burn/readiness/release state;
- one subject-wide release reservation, coordinator snapshot, and publish
  intent; and
- terminal chain resolution.

Each finalized registry entry has one byte-exact, nonrecursive
`FinalizedTransitionV1` envelope containing the transition body, key, old/new
values, sequence, predecessor and new state roots, command digest, signer
bitmap/order, and `2f+1` signatures under the pinned registry signature profile.
Intersecting quorums contain at least one honest replica, which never certifies
divergent successors. The BFT finalization protocol fixes and reliably
broadcasts one exact envelope; at least `2f+1` replicas persist it in immutable
log storage before reporting the transition committed.

The envelope is the consensus evidence for that entry, not another state-
machine command or CAS, and therefore does not require a certificate of its own.
Its digest is the stable transition-certificate identity used by descendants.
Exact replay returns that stored envelope rather than assembling another valid
signer subset/order. If the selected BFT engine cannot make exact envelope bytes
convergent and quorum-available without recursive certification, it is
ineligible; an audited unique threshold-signature profile is the alternative.
Every later reference to a registry commit/release certificate means the exact
applicable `FinalizedTransitionV1` envelope.

Digest durability is insufficient if exact bytes can disappear. Every
authoritative object needed to validate, recover, or retire an active subject
is retained as bounded canonical content inline in the BFT log or CAS value:

- graph-key descriptor, setup intent, ordered contributions, graph bundle,
  approvals, graph-presign transcript, ceremony certificate, immutable
  execution policy, funding subject, audit manifests, activation certificate,
  admission policy/certificate, governance checkpoints, admission-authority
  handoff, ceremony-retirement record, and terminal Core evidence;
- `INTENT_LOCKED` stores the accepted signed evaluation-intent bytes;
- every `READY` stores its exact signed readiness bytes and every tagged
  `ProfileReleaseReservedV1` stores the exact ordered ready set, fresh Core-quorum
  observations, selected slot/binding, and release identity;
- every S-DFB superseded-erasure transition stores the exact signed erasure
  record and `ERASURE_BARRIER_COMPLETE` stores the ordered record/envelope set;
  every C-DIRECT custody-bound transition stores its signed module evidence and
  `CUSTODY_BOUND_COMPLETE` stores the exact ordered certificate;
- S-DFB `RELEASED` stores an exact encrypted envelope for the signed participant
  result body, while its exact finalization envelope completes that profile's
  byte-identical result wrapper; C-DIRECT `RESULT_BODY_COMMITTED` stores only
  the module-gated ciphertext plus exact body/durability digests, then stores
  the scalar-erasure envelope and final wrapper as separately ordered
  descendants;
- `VERIFIED_SNAPSHOT` stores an exact encrypted envelope for the snapshot; and
- `PUBLISH_INTENT` stores an exact encrypted envelope for the signed capsule,
  not only its digest.

Retention has three distinct classes:

- permanent tombstones retain graph-key/nonce reuse, ceremony retirement,
  admission-authority cutover, subject terminal state, and content commitments;
- active-lifetime validation bytes retain the exact DAG, policies, audits,
  observations, readiness/erasure/reservation evidence, and finalization
  envelopes through subject `RETIRED` plus the signed reorg tail; and
- secret-bearing result bodies, snapshots, and capsules are stored inline only
  as ciphertext under independent subject/object retention keys, with exact
  plaintext digest and framing committed by consensus.

Registry workers may inspect S-DFB secret-bearing plaintext only after release
reservation. For C-DIRECT they receive only ciphertext/digests until the exact
scalar-erasure envelope is final; the pre-erasure result key remains unavailable
outside the qualified module boundary. Every profile encrypts secret material
before durable log, WAL, snapshot, or backup write.
`SecretPayloadEnvelopeV1` pins the AEAD/profile id, one sampled-once
nonce, object type, subject/release id, plaintext digest/length, ciphertext,
tag, retention-key id, authorized recovery roster, and associated data; exact
bytes are produced once and bounded by `WireProfileV1`. The retention-key
service is a separately controlled threshold-HSM roster whose exact `t-of-m`
profile and control domains are pinned by `ExecutionPolicyV1`. Key shares never
enter registry WALs, snapshots, ordinary memory dumps, or backups; those contain
ciphertext only. The service must remain recoverable under the signed fault
threshold without giving pre-reservation result access. After terminal finality
plus the reorg tail, the registry first records `RETENTION_ERASURE_REQUIRED`
with the complete managed HSM-share/storage inventory. The required independent
honest domains destroy enough managed shares to leave fewer than `t`, attest
their exact inventories, and permit `RETENTION_EXPIRED`; registry state alone
never claims to erase a key. Tombstones, ciphertext, and commitments remain.
This guarantees deletion only for honest policy-managed recoverable copies. A
Byzantine handler may have remembered post-reservation plaintext, which is
already outside the confidentiality claim. A secret participant artifact
is never copied into the registry; its independent per-slot recovery lifecycle
is defined by the ceremony. An external blob-store profile would require an
audited quorum-availability certificate, immutable independent stores, and a
conditional secret-release construction; it is not baseline v0.26.

The registry's wire profile bounds each object before consensus. Replicas use
encrypted storage, access control, redaction, and secure deletion. Encryption
at rest does not make a Byzantine replica confidential, so projective result
bodies cannot enter a proposal before a subject-wide release reservation.
For C-DIRECT, ordinary encryption at rest is additionally insufficient before
scalar erasure: the decryption key itself remains module-gated until the durable
erasure receipt exists.
`ProfileReleaseReservedV1`, not `PUBLISH_INTENT`, is the protocol point of no
return.
After reservation, an adversarial coordinator or registry replica may derive
or leak the one selected valid vector as results arrive. `PUBLISH_INTENT` is the
later exact-capsule durability/publication point; it is not a secrecy boundary.

The one-shot key and release identity are:

```text
slot_key = SHA256(
    "ranklock/v026/slot-key\0" || funding_subject_digest || u16(slot_id)
)

release_key = SHA256(
    "ranklock/v026/release-key\0" || funding_subject_digest
)

release_id = SHA256(
    "ranklock/v026/release-id\0" || slot_key || semantic_request_id ||
    evaluation_binding_digest || ack_template_digest
)
```

For Profile S-DFB, the following slot and erasure-barrier branch applies.
Before the first participant burn, the registry atomically changes
`slot_key: ABSENT -> INTENT_LOCKED(semantic_request_id,
evaluation_binding_digest, accepted_evaluation_intent_digest)` only while
`release_key == ABSENT` and `chain_guard == OPEN`.
A competing semantic request can never acquire that slot. Partial burns may
resume only the identical locked request. A slot abort moves every participant
copy of that query slot through its required physical erasure to one terminal
abort; the subject's other committed query slot remains available until chain
finality or release reservation. Every
participant `BURNED` and `READY` CAS jointly requires
`release_key == ABSENT`, the exact matching `INTENT_LOCKED` slot value, and the
current derived `chain_guard == OPEN`. A delayed losing-slot command therefore
cannot burn or become ready after another slot reserves release.

Once every ordered participant has committed `READY` for one slot, the
coordinator obtains fresh signed observations from the independent Core quorum
and proposes this atomic command:

```text
release_key: ABSENT -> RELEASE_RESERVED(
    slot_id, semantic_request_id, evaluation_binding_digest,
    ordered_ready_set_digest, core_observation_set_digest, release_id
)
every alternate participant slot:
    if nonterminal:
        current_state -> SUPERSEDED_ERASURE_REQUIRED(release_id)
    if already terminally erased:
        state unchanged; add SUPERSESSION_REFERENCE(
            release_id, prior_erasure_record_digest
        )
alternate slot_key:
    if nonterminal: current_state -> SLOT_SUPERSEDED(release_id)
    if terminal: state unchanged; bind terminal digest into reservation
condition: chain_guard == OPEN
```

This nonsecret CAS races both NACK resolution and the other slot. If NACK or
another slot commits first, it fails without an honest projective output. If
reservation commits first, only its exact slot/binding/vector may proceed. Each
participant then changes its alternate slot from
`SUPERSEDED_ERASURE_REQUIRED(release_id)` to
`RETIRED_SUPERSEDED(erasure_record_digest)` only after physical key/backup
destruction. Once every ordered erasure record is exact and certified, the
registry changes `release_key` from `RELEASE_RESERVED` to
`ERASURE_BARRIER_COMPLETE(ordered_erasure_set_digest)`. No selected participant
may evaluate before that complete barrier. A later NACK can suppress
publication/broadcast but cannot authorize another release or restore
confidentiality. `release_key` then advances monotonically through
`PUBLISH_INTENT(exact_capsule_digest)` and `PUBLISHED`, always bound to the same
reservation.

If a losing participant slot was already cryptographically terminal after an
earlier burned abort, the reservation atomically creates a release-bound
`SupersessionReferenceV1` over the exact prior signed erasure record/inventory
without changing or reopening that terminal state. The ordered erasure barrier
accepts either a post-reservation erasure record or this finalized prior-erasure
reference for each participant, never an absent or registry-only tombstone.
This permits the second slot to serve as the bounded fallback while keeping the
losing state physically unavailable.

For Profile C-DIRECT, the intent/burn/readiness guards are the same, but the
reservation uses a different state-machine variant:

```text
release_key: ABSENT -> RELEASE_RESERVED_CUSTODY(
    slot_id, semantic_request_id, evaluation_binding_digest,
    proof_digest, canonical_A_digest, ordered_ready_set_digest,
    core_observation_set_digest, release_id
)
every selected participant slot:
    READY -> RELEASE_RESERVED_CUSTODY(release_id)
every alternate participant slot:
    current_nonreleased_state -> RETIRED_SUPERSEDED_LOGICAL(release_id)
alternate slot_key:
    current_nonterminal_state -> SLOT_SUPERSEDED_LOGICAL(release_id)
condition: chain_guard == OPEN
```

That single CAS races NACK and both slots. Logical retirement is safe only
because each subject has one nonrollback scalar handle rather than a scalar per
slot. Next, every custody module performs its own irreversible
`ACTIVE -> RELEASE_BOUND` transition and the registry stores each exact signed
`ParticipantCustodyBoundV1`. Only the complete ordered set advances
`release_key` to `CUSTODY_BOUND_COMPLETE`; a registry flag cannot substitute for
module state. No module may multiply before that barrier. Every released result
then advances through result-body ciphertext and conditional-key-envelope quorum
availability, body-commit certification, scalar erasure, erasure finalization
and result-key release, final-wrapper replication, and emission. The registry
never reopens a handle or selects another slot after reservation.

If a module or clone cannot prove it shares the consumed monotonic state, the
profile fails closed before funding. If recovery cannot complete the exact
bound result, the subject remains reserved; it does not fall back to another
proof or slot. Funding remains prohibited until a loss-safe timeout path is
independently qualified for this terminal.

The common coordinator consumes the exact tagged reservation:

```text
ProfileReleaseReservedV1 =
    S_DFB(RELEASE_RESERVED, release_reservation_certificate_digest)
  | C_DIRECT(RELEASE_RESERVED_CUSTODY,
             custody_release_reservation_certificate_digest)
```

The common coordinator and publication logic then consumes a separate tagged
barrier union, never an untyped alias:

```text
ProfileReleaseBarrierCompleteV1 =
    S_DFB(ERASURE_BARRIER_COMPLETE, ordered_erasure_set_digest)
  | C_DIRECT(CUSTODY_BOUND_COMPLETE, custody_bound_certificate_digest)
```

The integrated `proof_suite_id` in `FundingSubjectV1` selects exactly one
variant through the closed suite registry. Cross-variant certificates and state
names fail parsing.

Successful setup also uses CAS: one graph-key descriptor selects one setup
intent; one intent selects one contribution set/graph bundle; and that chain
selects one funding subject. A concurrent fork cannot reuse the graph key, ACK
hashes, or the selected profile's artifact/nonce or custody-handle/counter
namespaces even when neither fork aborts.

### 8.2 Coordinator and chain state

Coordinator phase is monotonic. Chain observations live in a separate
append-only event log because nonfinal confirmations can reorg:

```text
RECEIVED -> STRUCTURAL_VALID -> INTENT_LOCKED -> COLLECTING_READY
         -> READY_SET -> PROFILE_RELEASE_RESERVED
         -> PROFILE_RELEASE_BARRIER_COMPLETE
         -> COLLECTING_RESULTS -> COMPLETE_RESULTS -> VERIFIED_SNAPSHOT
         -> CAPSULE_STAGED
         -> PUBLISH_INTENT -> PUBLISHED -> CONSUMER_ACCEPTED
PROFILE_RELEASE_RESERVED -> ABORTED_RESERVED_NO_RESULT
PROFILE_RELEASE_BARRIER_COMPLETE -> ABORTED_RESERVED_NO_RESULT
ABORTED_RESERVED_NO_RESULT -> WAITING_LOSS_SAFE_TIMEOUT

derived chain_guard: OPEN | ACK_SEEN | NACK_SEEN | ACK_FINAL | NACK_FINAL
append-only events: SEEN(block) | REMOVED_BY_REORG(block) | FINAL(depth)
```

Independent Core-quorum observations append `SEEN` and `REMOVED_BY_REORG`
events; no registry entry is deleted or rewritten. `ACK_FINAL`/`NACK_FINAL` are
allowed only after the observed resolution transaction is deeper than the
signed maximum resolution-removing reorg bound. A deeper removal is an explicit
assumption failure, not an ordinary rollback.

Every burn, readiness, release-reservation, and publish-intent CAS requires
derived `chain_guard == OPEN`. `ACK_SEEN` or `NACK_SEEN` blocks those new
authorizations while present; a certified reorg event may derive `OPEN` again
and resume only the exact locked/reserved path. Before
`ProfileReleaseReservedV1`, a
final chain outcome retires the subject and no honest participant emits a
projective output. After reservation, the exact selected participant-result
durability pipeline may finish, but `NACK_SEEN`/`NACK_FINAL` forbids a new
publish intent and bridge broadcast. An already certified publish intent
remains byte-recoverable. If a nonfinal NACK is removed, only the exact reserved
ACK may resume. A pre-burn parse/authentication rejection consumes nothing.
After the global intent lock, only the same semantic request may continue. A
different transport nonce with identical semantics is an idempotent retry; a
different semantic id is a conflict. After `ProfileReleaseReservedV1`, governance/key
revocation or a conflicting request cannot replace the selected slot or vector.
`NACK_SEEN` before reservation suppresses honest result exposure. After reservation,
the vector is potentially exposed even if no capsule has yet been staged.
`ABORTED_RESERVED_NO_RESULT` is terminal for the selected release identity: it
preserves the reservation, accepts only its exact no-result erasure evidence,
and waits for the policy's timeout resolution. It never returns to readiness,
chooses an alternate slot, or authorizes a new scalar/projectivizer execution.
No subject may fund until that timeout resolution is independently proven
loss-safe for this terminal.

### 8.3 Participant state

For Profile S-DFB, each participant owns its artifact, local crash journal, and
registry-backed state machine:

```text
AVAILABLE -> INTENT_BOUND -> BURNED -> READY
BURNED -> ABORTED_BURNED | RETIRED_CHAIN
READY[selected] -> RELEASE_RESERVED -> ERASURE_BARRIER_COMPLETE
READY[alternate] -> SUPERSEDED_ERASURE_REQUIRED -> RETIRED_SUPERSEDED
TERMINAL_ERASED[alternate] -> SUPERSESSION_REFERENCE (state unchanged)
ERASURE_BARRIER_COMPLETE -> EVALUATING -> RELEASED
EVALUATING -> ABORTED_RESERVED
```

Registry CAS, not the coordinator's database, binds every transition to the
global semantic id. A crash after `BURNED` may resume only that exact command.
A proof/readiness failure records `ABORTED_BURNED`; an evaluation failure after
reservation records `ABORTED_RESERVED`. Exact replay returns the same terminal
result. Neither abort state is terminal until the affected slot's envelope key
and backups are destroyed and its exact signed erasure record is finalized.
`RELEASED` is valid only after the exact signed-body outbox is durable
and the separate release certificate commits its digest. Every selected
`RELEASED` CAS requires the exact matching reservation and complete ordered
erasure-set digest. Exact replay returns the staged wrapper. Reservation marks
the alternate slot erasure-required; only physical erasure plus its signed
record makes it `RETIRED_SUPERSEDED`. An already-terminal alternate remains
terminal and contributes only its finalized `SupersessionReferenceV1`. Chain
finality before reservation moves
every nonreleased slot through required erasure to `RETIRED_CHAIN`. After
reservation, the selected participant finishes only that exact result despite
later chain observations, and the bridge separately enforces NACK. No
transition can make a slot available again.

Profile C-DIRECT keeps four authorities separate.

Registry participant-slot state:

```text
AVAILABLE -> INTENT_BOUND -> BURNED -> READY
BURNED -> ABORTED_BURNED | RETIRED_CHAIN
READY[selected] -> RELEASE_RESERVED_CUSTODY -> RESULT_BODY_COMMITTED
RESULT_BODY_COMMITTED -> SCALAR_ERASURE_FINALIZED -> RESULT_EMITTED
RELEASE_RESERVED_CUSTODY -> ABORTED_RESERVED_NO_RESULT(reason)
ABORTED_RESERVED_NO_RESULT -> SCALAR_ERASURE_NO_RESULT_FINALIZED
READY[alternate] -> RETIRED_SUPERSEDED_LOGICAL
```

Module-handle state:

```text
ACTIVE -> RELEASE_BOUND -> OUTPUT_INTENT_DURABLE -> OUTPUT_CACHED_DURABLE
OUTPUT_CACHED_DURABLE -> RESULT_KEY_SEALED -> RESULT_BODY_COMMIT_VALIDATED
RESULT_BODY_COMMIT_VALIDATED -> SCALAR_ERASED_WITH_DEVICE_RECEIPT
SCALAR_ERASED_WITH_DEVICE_RECEIPT -> ERASURE_FINALIZED_CERT_VALIDATED
ERASURE_FINALIZED_CERT_VALIDATED -> RESULT_KEY_RELEASED
OUTPUT_INTENT_DURABLE -> OUTPUT_LOST -> SCALAR_ERASED_NO_RESULT_TERMINAL
RELEASE_BOUND -> SCALAR_ERASED_NO_RESULT_TERMINAL
OUTPUT_CACHED_DURABLE -> SCALAR_ERASED_NO_RESULT_TERMINAL
RESULT_KEY_SEALED -> SCALAR_ERASED_NO_RESULT_PENDING_KEY_TOMBSTONE
SCALAR_ERASED_NO_RESULT_PENDING_KEY_TOMBSTONE
    -> SCALAR_ERASED_NO_RESULT_TERMINAL
ACTIVE -> SCALAR_ERASED_NO_RESULT
```

Threshold result-key service state:

```text
KEY_ABSENT -> KEY_ACTIVATION_STARTED -> KEY_ENVELOPE_ACTIVE
KEY_ENVELOPE_ACTIVE -> RESULT_KEY_RELEASED
KEY_ABSENT | KEY_ACTIVATION_STARTED | KEY_ENVELOPE_ACTIVE
    -> NO_RESULT_TOMBSTONED
NO_RESULT_TOMBSTONED -> CHILD_KEY_SHARES_ERASED_FINAL
```

`KEY_ABSENT -> KEY_ACTIVATION_STARTED` requires the exact durable module
`RESULT_KEY_SEALED` receipt. A no-result transition directly from
`OUTPUT_CACHED_DURABLE` requires an authenticated `KEY_ABSENT` certificate; any
partial activation instead takes the tombstone/share-erasure path.
After `RESULT_KEY_SEALED`, even a still-absent service state must CAS to
`NO_RESULT_TOMBSTONED` using the sealed receipt, activation-attempt digest, and
registry teardown certificate; this is an irreversible never-activate record,
not the earlier read-only absence certificate.

Participant result-outbox state:

```text
EMPTY -> RESULT_BODY_DURABLE -> RESULT_BODY_CIPHERTEXT_QUORUM_AVAILABLE
RESULT_BODY_CIPHERTEXT_QUORUM_AVAILABLE -> RESULT_BODY_COMMIT_CERTIFIED
RESULT_BODY_COMMIT_CERTIFIED -> ERASURE_FINALIZED
ERASURE_FINALIZED -> FINAL_WRAPPER_DURABLE_REPLICATED -> EMITTED
```

The reservation CAS and module bind are necessarily separate operations. Exact
signed reservation/bound/barrier/body/erasure digests correlate them; no text
claims atomicity across the registry and device. A bind failure after
reservation is terminal availability loss and never permits rollback or an
alternate slot. The module's monotonic state, not merely the participant
journal or registry, enforces `RELEASE_BOUND`, `OUTPUT_INTENT_DURABLE`, and
`OUTPUT_CACHED_DURABLE`. A crash resumes only the exact selected tuple and never
repeats a consumed output intent. `SCALAR_ERASED_WITH_DEVICE_RECEIPT` requires
every admitted clone and backup to be unrecoverable; otherwise no erasure
certificate is valid and no result may be emitted. The result key remains
unavailable until the module or pinned threshold recovery service validates the
exact finalized erasure certificate; its conditional key envelope and
availability receipt must already be quorum-recoverable. `ACK_FINAL`/
`NACK_FINAL` before reservation takes the distinct no-result path.
Issuing `ParticipantResultBodyCommitCertificateV1` is the single registry CAS
that moves the participant slot to `RESULT_BODY_COMMITTED`; storing those exact
certificate bytes moves the participant outbox to
`RESULT_BODY_COMMIT_CERTIFIED`; module verification then moves only the module
to `RESULT_BODY_COMMIT_VALIDATED`. The registry CAS—not later module
verification—is the irreversible no-result cutoff. A crash between issuance and
module verification replays that exact certificate and continues the normal
path.
`OUTPUT_LOST` commits the module tombstone and device receipt through
`ABORTED_RESERVED_NO_RESULT(OUTPUT_LOST) ->
SCALAR_ERASURE_NO_RESULT_FINALIZED`; the
subject-wide reservation remains selected and the coordinator may only wait
for the independently proved loss-safe timeout. It cannot retry the scalar,
reopen the handle, or select the alternate slot.
A permanent bind or pre-body-commit failure causes the registry to issue one
`CustodyNoResultTeardownCertificateV1` bound to the exact reservation, failure
reason, participant/handle inventory, and any cached-output/result-key state.
Modules accept it from `RELEASE_BOUND`, `OUTPUT_CACHED_DURABLE`, or
`RESULT_KEY_SEALED`, destroy the scalar plus cached output/result key as
applicable, and emit no result. The body-commit CAS and teardown CAS are
mutually exclusive; teardown is forbidden once the registry enters
`RESULT_BODY_COMMITTED`, even if exact certificate storage in the outbox and
module validation have not yet completed. The committed normal path must
complete ordinary erasure, key release, and wrapper construction. Every
no-result finalization binds the same
complete `CloneErasureEvidenceV1` required by normal erasure, so a primary
tombstone cannot leave a separately recoverable clone.
For `RESULT_KEY_SEALED`, the no-result finalization additionally binds the exact
`NO_RESULT_TOMBSTONED` record and ordered child-key-share/backup erasure receipt
set. The threshold service creates that tombstone only after validating the
exact teardown certificate and permanently rejects the ordinary release
predicate for that envelope. The registry cannot certify
`SCALAR_ERASURE_NO_RESULT_FINALIZED` until both participant clone erasure and
`CHILD_KEY_SHARES_ERASED_FINAL` are present.

### 8.4 Secret-bearing outbox

Publication is:

1. require the exact subject-wide release-reservation and selected tagged
   profile-barrier envelopes and commit `VerifiedReleaseSnapshotV1` plus its
   exact finalization envelope;
2. an authorized coordinator derives the already-reserved preimages,
   creates/signs one candidate capsule, and writes it to a
   private encrypted staging object, fsync it, and record its digest;
3. compare-and-set subject-wide `release_key` from the exact matching tagged
   `ProfileReleaseBarrierCompleteV1` to `PUBLISH_INTENT` while
   `chain_guard == OPEN`, replicating the exact `SecretPayloadEnvelopeV1`
   ciphertext and plaintext capsule digest inline;
4. atomically install the bounded final file with no-replace semantics, fsync
   it and its directory;
5. commit `PUBLISHED`; and
6. accept only a signed, idempotent bridge consumer receipt.

Before publish intent, another policy-authorized coordinator may adopt the
snapshot and propose a capsule over the same reserved vector. Recovery after
intent retrieves the exact selected capsule bytes, never a fresh randomized
signature. A missing final file installs those bytes; an
identical final file completes publication; different bytes freeze the subject
while preserving the certified intended capsule. Directory-sync ambiguity
assumes exact visible bytes may have been consumed. If `NACK_SEEN`/`NACK_FINAL`
blocks the path before `ProfileReleaseReservedV1`, no honest result or preimage vector
is exposed while blocked. After reservation, confidentiality is already
considered spent and exact selected results remain recoverable. If a NACK blocks
the path before `PUBLISH_INTENT`, recovery discards that private capsule stage
and creates no publication record; a later reorg to `OPEN` may resume only the
same reserved vector. If publish intent commits first, its exact capsule remains
recoverable, but the bridge will
not broadcast while `chain_guard` is `NACK_SEEN` or `NACK_FINAL`. No retry may
derive another slot/vector.

No exception is silently discarded. If primary processing and fail-closed
recovery both fail, a typed compound incident preserves both causes and freezes
new admissions without invalidating an already certified publish intent.

---

## 9. Validation and release order

The distributed protocol executes this order:

1. The coordinator checks framing, profile ids, lengths, canonical proof/point
   encoding, and request signature before any state change.
2. It loads and fully validates the funding-subject DAG, activation certificate,
   admission certificate, immutable execution policy, exact public statement,
   and the byte-exact audit evidence frozen as valid at admission. Present-time
   admission/audit expiry affects new funding, not this subject's resolution.
3. It reconstructs and compares every graph input, value, prevout, connector,
   control block, ACK/NACK template, presignature, sighash type, CSV rule, and
   CPFP authorization.
4. It canonical-parses the exact counterproof transaction and derives the
   evaluation binding, txid, wtxid, witness digest, authorization outpoint, and
   selector. The request cannot supply these as independent claims.
5. It verifies ordered contributions, bundle approvals, scale proofs, presign
   transcript, certificate, policy, evidence schemas, and the selected profile's
   exact artifact/nonce/erasure or custody/attestation/counter evidence.
6. It authenticates the semantic request and obtains agreeing observations from
   the execution policy's independent Core-node quorum at the required release
   depth. Unauthorized or structurally invalid garbage MUST NOT consume a slot.
7. It acquires the registry's global intent lock before contacting any
   participant. A competing semantic request fails without partial selection.
8. Every participant independently repeats the relevant DAG, parser, policy,
   Core, chain-terminal, canonical proof framing, and exact-statement binding
   checks; CAS-burns its own slot; only then performs full proof verification
   and commits exact nonsecret `READY` bytes without evaluating or returning
   `[r_j]A`.
9. The coordinator accepts only the complete ordered ready set for one slot,
   re-reads the independent Core quorum, and atomically CAS-reserves that
   subject-wide release against NACK and the alternate slot.
10. The selected release-profile state machine runs. S-DFB destroys and
    certifies every alternate-slot key, waits for the ordered erasure barrier,
    evaluates the selected artifact, and retires its evaluator secrets only
    after the exact result is replayable. C-DIRECT logically retires the
    alternate, obtains the complete custody-bound barrier, performs the single
    bound multiplication, makes the exact result replayable, destroys every
    scalar handle/clone, and emits only after finalized erasure evidence.
11. The coordinator accepts only the complete ordered result set for the same
    binding and validates every registry certificate and participant signature.
12. It re-reads the independent Core quorum and requires identical raw
    transaction, txid, wtxid, witness, target block hash/height, active-chain
    status, unspent outpoint, and `chain_guard == OPEN`. Confirmation depth may
    increase and MUST remain at or above the minimum; a decrease or changed
    target block follows the explicit reorg path.
13. It verifies the future proof, certifies every `[r_j]A`, unlocks every
    preimage, and compares the ordered hash vector.
14. It reconstructs the complete presigned ACK witness and runs pinned Core
    consensus/policy/package checks under the bounded CPFP authorization.
15. It commits `VerifiedReleaseSnapshotV1` and executes the secret-bearing
    publication outbox.
16. The bridge independently repeats its section 7.4 validation immediately
    before broadcasting and returns a signed consumer receipt.

Burn-before-ready and release-reservation-before-evaluate prevent a valid
authorizer from using malformed semantic inputs as a retry oracle or obtaining
two honest output vectors. Authentication and structural bounds still occur
before the global intent lock so arbitrary network garbage cannot consume
slots. Because an authorized actor can still intentionally burn a bad semantic
request, the timeout path MUST be loss-safe; authentication is not a liveness
proof.

---

## 10. Failure, retry, reorg, and fee semantics

An ACK outpoint commits the counterproof txid, not its wtxid. Once preimages are
visible, policy cannot stop a third party from using the same ACK after a
same-txid/different-witness replacement. Therefore the execution policy MUST
enforce and the concrete theorem MUST assume:

```text
release_confirmation_depth > maximum_parent_removing_reorg_depth
resolution_finality_depth > maximum_resolution_removing_reorg_depth
```

At release, the exact bound wtxid must be inside that assumed immutable common
prefix. A reorg capable of replacing it is outside the funds-safety assumption,
not a recoverable software incident. If that assumption is unacceptable, the
selector/witness commitment must move into txid-committed or on-chain state and
the graph must be redesigned before funding.

ACK/NACK observations are different from final outcomes. A seen resolution
transaction blocks new release/publication immediately, but it becomes
`ACK_FINAL` or `NACK_FINAL` only after `resolution_finality_depth`. A shallower
reorg appends `REMOVED_BY_REORG` and may derive `OPEN` again; a reorg of a final
outcome is outside the signed common-prefix assumption and freezes the subject.

| Event | Required result |
|---|---|
| Parse/authentication failure before global lock | Reject without consuming the slot. |
| Same semantics, different transport nonce | Idempotent retry; nonce does not create another slot. |
| Different semantics before global lock | May replace a merely local pending request. |
| Different semantics after global lock | Registry rejects it; record conflict and continue/fail only the locked request. |
| Crash after any participant burn | Slot never becomes available; exact locked request may resume. |
| Partial participant burn | Unburned participants accept only the same global intent; global abort/NACK retires all. |
| Safety-registry outage | No new lock, burn, readiness, release reservation, result, or publish intent. Availability loss is acceptable only with loss-safe timeout. |
| Target block/raw tx/wtxid changes between observations | Terminal burned abort; publish no capsule. Increasing depth for the same target is valid. |
| Parent-chain reorg after capsule publication within the assumed bound | Exact bound parent wtxid remains in the common prefix; only append the new observation and never select another vector/capsule. |
| Reorg deep enough to replace the bound wtxid | Funds-safety assumption failure and incident; software cannot make exposed preimages secret again. |
| `ACK_SEEN` removed before finality | Append the reorg event; consumer returns to broadcast-pending and may rebroadcast only the exact selected ACK. |
| `NACK_SEEN` before release reservation | Blocks burn/readiness/reservation. If removed before finality, only the exact locked request may resume; `NACK_FINAL` erases/retires both slots. |
| `NACK_SEEN` after release reservation | Stops new publish intent and bridge broadcast. If removed before finality, only the exact reserved ACK may resume; `NACK_FINAL` leaves confidentiality spent and forbids ACK broadcast permanently. |
| ACK/NACK finality reorg | Assumption failure: freeze subject/new funding and execute the incident path; never silently rewrite terminal state. |
| Reorg deeper than policy bound | Freeze subject and new funding; governance incident process. |
| Two coordinators or two slots | Registry CAS selects one semantic request per slot and one subject-wide release reservation; exact retries converge on one selected vector/snapshot/capsule. |
| Two bridges | Both reconstruct the same transaction; broadcast is idempotent. |
| Revocation after release reservation | New admissions freeze; it cannot select another vector or mutate the reserved subject. `NACK_SEEN`/`NACK_FINAL` still suppress bridge broadcast. |

The accepted Taproot `SIGHASH_DEFAULT` signatures commit the relevant
non-witness transaction data, prevouts, amounts, scripts, sequences, outputs,
and script path; they do not commit every other input's witness bytes and they
do not stop a surviving signing key from signing another parent. Exact witness
templates plus the presign-and-erasure ceremony provide the remaining binding.

CPFP does not mutate the ACK parent. A fixed presigned child has a fixed fee, so
v0.26 instead pins a bounded `CpfpAuthorizationV1` for the anchor spend. It MUST
define:

- responsible fee-bump operator;
- exact anchor outpoint/script and child sighash/signature profile;
- whether wallet inputs may be added and the allowlisted change scripts;
- available anchor value, wallet reserve, absolute fee/value caps;
- maximum child/package weight and minimum fee headroom;
- latest safe broadcast height before CSV maturity;
- halt threshold when fee estimates exceed the signed budget.

The child authorization cannot spend or redirect any other protocol output.
ACK/NACK template digests commit complete typed templates, prevouts, amounts,
scripts, control blocks, sighash types, versions, sequences, outputs, and the
explicitly permitted witness holes—not merely transaction ids.

The ACK/NACK race MUST be tested under forced fee pressure at, before, and after
CSV maturity. A hand-waved “D-block head start” is not an economic safety proof.

---

## 11. Policy, roles, and operational independence

### 11.1 Policy requirements

v0.26 separates two policies that must not be conflated.

`AdmissionPolicyEpochV1` is mutable and applies only before funding. It has:

- monotonically increasing sequence;
- activation/expiry heights and revocation reference;
- proof and ceremony profile ids;
- per-deposit, aggregate-value, and active-deposit caps;
- immutable `risk_namespace_id`, registry cluster/generation, and certified
  governance checkpoint;
- allowed control-domain, participant, graph-signer, and registry profiles;
- typed audit schemas and authorized signers;
- funding custody keys, cooldown, and admission freeze behavior; and
- coordinator, participant, bridge, and funding binary/configuration digests.

`ExecutionPolicyV1` is immutable for an admitted subject through its graph
lifetime plus signed reorg tail. It contains:

- exact participant, graph signer, requester, coordinator, bridge, and registry
  identities and quorum rules;
- confirmation, reorg, CSV, and fee/CPFP limits;
- exact resolution/retry/point-of-no-return rules;
- custody, backup, erasure, incident, and terminal-retirement rules; and
- a stable height/MTP clock basis.

Admission expiry or revocation stops new reservations and funding broadcasts;
it does not revoke an admitted subject's resolution authority. Cap increases
apply only to subjects admitted under the new sequence.

Audit validity/freshness is evaluated at the admission height and frozen by the
activation/admission certificates. Runtime must reproduce exact bytes, scope,
signatures, finding dispositions, and historical validity; it MUST NOT require
the manifest to remain currently unexpired. Later audit expiry freezes new
admission only.

Governance sequences and revocations are committed to the safety registry.
Processes require the latest certified checkpoint; a rolled-back host cannot
accept an older sequence. Registry partition is fail-closed for admission. Key
rotation creates a new admission epoch and never rewrites an active execution
policy.

All admission clusters for one economic deployment share one immutable risk
namespace. A new cluster/generation may admit value only after a joint old/new
consensus handoff carries every active reservation and latest governance state.
If the old cluster cannot certify that handoff, new admissions remain frozen
until its namespace has no active or reorg-tail reservation. Starting a fresh
cluster with an empty view is prohibited.

The handoff is one exclusive CAS at a named sequence/height:

```text
ADMISSION_AUTHORITY(risk_namespace_id):
    OLD(cluster_id, generation) -> NEW(cluster_id, generation)
```

The old and new quorums jointly certify it. After cutover, the old cluster MUST
reject new admission certificates but MAY continue runtime transitions for
subjects that immutably pin it. New admissions require subjects built for the
new cluster; a prebuilt old-cluster subject cannot cross the cutover.

### 11.2 Atomic admission and risk accounting

Core is necessary but cannot atomically enforce fleet-wide caps. Before any
funding signature or broadcast, the safety registry reserves the exact subject,
deposit outpoint, amount, and count in one ordered transaction. The reservation
states are:

```text
RESERVED -> MEMPOOL -> CONFIRMED -> SPENT_REORG_TAIL -> RETIRED
```

`RESERVED`, mempool, confirmed, and reorg-tail value all count against caps.
The registry reconciles exact funding tx bytes and active UTXOs with pinned
Core. Baseline v0.26 forbids funding RBF/replacement; mempool disappearance
retains the reservation and permits only byte-identical rebroadcast.
Abandonment, spend, and reorg-tail exit rules are signed. Two funding services
therefore cannot each observe spare capacity and oversubscribe it.

Funding keys are custody-gated behind a valid activation and admission
certificate. Any wallet, RPC, pre-signed file, or broadcast path that bypasses
the reservation is a release blocker.

The deployment evaluator runs inside every process capable of admission,
funding, burning, publishing, or consuming. It validates evidence content, not
only digests. Chain value comes from the reservation registry reconciled with
Core, never a caller.

### 11.3 Roles and control domains

- offline governance quorum;
- independent setup participants;
- one-subject graph-signing operators;
- ceremony verifiers;
- cryptography auditors;
- implementation and supply-chain auditors;
- Bitcoin/fee/reorg auditors;
- operations and disaster-recovery auditors;
- safety-registry operators;
- admission and funding-custody operators;
- proof coordinator operators;
- bridge/watchtower operators.

Distinct public keys are insufficient evidence of independence. Policy and
audit must bind legal/administrative control, cloud accounts, HSM custody,
network, and geographic failure domains.

A signed, versioned `ControlDomainRegistryV1` supplies canonical organization
and infrastructure identities plus evidence schemas. No control domain may
occupy multiple split-participant slots, graph-signer positions, registry
replicas, governance roster positions, or supposedly independent auditor roles.
Governance quorum is counted by distinct control domains, never merely keys.

The governance quorum and an independent operations auditor co-sign the
control-domain registry. It has a registry sequence, activation/expiry heights,
parent-control evidence, update rules, and a monotonic safety-registry
checkpoint. Merger, acquisition, common-cloud migration, or custody transfer
freezes new admission until a new registry/audit. If consolidation breaks a
funded subject's participant, graph-signer, registry, governance, or audit
corruption threshold, that subject enters `ASSUMPTION_FAILURE`: the funds-safety
claim is suspended and operators follow only its precommitted on-chain
loss-safe resolution/incident path. Off-chain governance cannot repair the old
execution policy.

Hard separations:

- registry operators are disjoint from setup, governance, coordinator, bridge,
  and every attestation authority;
- cryptography, implementation, Bitcoin, and operations auditors are mutually
  disjoint;
- setup participants are disjoint from the governance quorum;
- graph signers are disjoint from setup participants, governance, registry,
  funding custody, coordinator, and bridge control domains;
- funding custody is disjoint from governance, registry, coordinator, and
  bridge control domains;
- coordinator authorization keys are disjoint from bridge transaction keys;
- one organization or common parent cannot satisfy multiple independent roles.

---

## 12. Acceptance gates

Every gate is mandatory for enforce mode.

| Gate | Required evidence |
|---|---|
| Protocol identity | Machine-checked acyclic dependency graph; no activation object contains future witness/block data; Rust/Python golden vectors; every predecessor/final-subject mutation rejected. |
| Statement binding | Exact canonical public-input bytes or reviewed deterministic derivation committed before contributions; request substitution rejected. |
| Signature profile | Exact domains, encodings, rosters and quorums for every signed object; cross-profile and cross-role negatives. |
| Suite | Exact allowlisted suite; no production `bn254_real.py`; mixed-suite, malformed, subgroup, infinity, and noncanonical negatives. |
| Concrete security | Independent report covering source groups, GT, proof soundness, multi-target attacks, statistical bounds, and intended lifetime; registry stores the approved conservative floor separately from attack ceilings and pins the report/profile digest plus lifetime. |
| Native implementation | Audited constant-time secret operations, explicit zeroization, denial-of-service bounds, and differential implementation evidence. |
| Release mechanism | Exact separately versioned profile. S-DFB requires measured production artifacts plus reviewed selective/adaptive, auxiliary-input, same-scalar, and multi-participant security. C-DIRECT requires the one-shot positive-lock theorem plus audited non-exportable, anti-clone/rollback, constant-time/fault-resistant custody and erasure. |
| Setup | Typed DAG/profile certificate; independent unique contributions; exact artifact or custody-handle/clone secret-retention inventory; anchor before activation; monotonic abort/nonce/key reuse rejection. |
| Graph signing | Every ACK/NACK parent fully presigned and witness-verified before funding; unique N-of-N roster/key; at least one honest-share erasure and non-derivability audited. |
| Funding transaction | Complete unsigned bytes fixed pre-graph; native SegWit/Taproot inputs with empty scriptSigs; txid unchanged after signing; RBF/alternate funding rejected. |
| Bitcoin connector | Real Core accepts complete vector ACK; missing, duplicated, reordered, wrong-slot, and wrong-context vectors fail. Fixed NUMS derivation, tweak/output-key/control-block reconstruction, and key-path bypass negatives for every script-only output. |
| Safety registry | `3f+1` independent replicas/`2f+1` finalization envelopes; total-order/CAS, nonrecursive exact-envelope convergence, quorum-intersection, rollback, equivocation, partition and restored-snapshot tests. |
| Exact-byte availability | Every active validation object/finalization envelope recoverable byte-identically through reorg tail; per-object secret ciphertext; `RETENTION_ERASURE_REQUIRED` plus complete physical-erasure receipts before `RETENTION_EXPIRED`; tombstones persist. |
| Admission | Certificate binds exact policy/checkpoint/risk namespace/cluster; atomic fleet-wide value/count reservation before custody signing; joint cluster handoff, Core/reorg-tail lifecycle, and bypass tests. |
| One shot | Global intent lock before first burn; complete nonsecret ready set and subject-wide reservation before output; S-DFB physically erases every losing-slot key/backup before selected evaluation; C-DIRECT irreversibly binds the single subject handle and completes the custody-bound barrier before one multiplication, then erases all scalar copies before emission; no second vector. |
| Coordinator | Strict intent/readiness/reservation/erasure/snapshot/capsule parsing; authorized-key failover before publish CAS and byte identity after; no caller post-burn data or swallowed recovery errors. |
| Bridge | New graph reconstructed from subject; live txid+wtxid/outpoint/derived-chain-guard checks; certified intent; exact ACK and bounded CPFP only. |
| Chain finality | Independent Core quorum proves exact wtxid and ACK/NACK finality deeper than their signed removal bounds; append-only seen/reorg/final events; same-txid/different-witness, resolution-reorg and eclipse tests. |
| Liveness/economics | Participant withholding and ACK fee starvation cannot cause an unauthorized economic outcome. CSV and contested-payout semantics independently audited. |
| Runtime policy | Mutable admission vs immutable execution semantics; certified latest governance sequence; gates on every admission/funding/burn/release/consume path. |
| E2E | Every restored STRATA-010..020 row and added v0.26 row records a real zero-exit command against pinned binaries. |
| External review | Typed scope/source/binary/subject manifests, finding ids, severity/disposition, signer/control-domain, expiry; no unresolved critical/high finding. |

Required v0.26 additions to the E2E matrix include:

- truncation, trailing bytes, unknown sections, oversize, and noncanonical
  proof/capsule inputs;
- mutation of each canonical subject field;
- unauthenticated request cannot burn;
- runtime public-input, VK, verifier, wtxid-at-activation, and dependency-cycle
  substitution;
- omitted, reordered, duplicated, and incorrect participants/preimages;
- out-of-range slot ids, inconsistent slot widths, both-slot races, third-query
  attempts, and competing subject-wide release reservations/publish intents;
- for S-DFB, burning/aborting slot 0 cannot destroy or expose slot 1; reserving slot 0
  marks slot 1 erasure-required and selected evaluation waits for physical
  erasure of every losing copy; chain finality retires both; stale backup cannot
  reopen either slot;
- for C-DIRECT, two logical slots share one subject handle; two handle copies,
  caller-selected `A`, pre-barrier multiplication, second distinct queries,
  clone/firmware rollback, result emission before scalar erasure, and post-
  erasure recomputation all fail;
- for C-DIRECT, crash at every body-fsync/ciphertext-availability/body-commit/
  scalar-destruction/device-receipt/erasure-finalization/final-wrapper boundary;
  read back the exact quorum ciphertext and conditional-key envelope before
  erasure; pre-erasure replicas cannot decrypt, and post-erasure recovery
  constructs the exact final wrapper without scalar code;
- crash injection before/after every journal commit, external anchor, file link,
  file fsync, and directory fsync;
- for S-DFB, participant crash before/after `READY` fsync/CAS, release reservation,
  alternate-slot tombstone/key-and-backup erasure, erasure-record fsync/CAS,
  complete erasure barrier, selected evaluation, result-body fsync, `RELEASED`
  CAS, wrapper fsync, selected-secret retirement, and coordinator delivery;
- exact, semantic-equivalent, and conflicting retries across coordinators;
- global intent CAS, disjoint partial-burn races, complete-ready-set
  reservation, NACK/reservation race, alternate-slot reservation race,
  registry partition, equivocation, quorum loss, and restored-replica rollback;
- delete every coordinator/participant local copy after each irreversible CAS
  and recover every subject object plus exact intent/readiness/reservation/
  erasure/result/snapshot/capsule and finalization-envelope bytes from the
  registry;
- after final resolution plus reorg tail, crash-test
  `RETENTION_ERASURE_REQUIRED`; prove shares never entered ordinary replicas,
  WALs, snapshots, or backups; destroy the required threshold-HSM shares; and
  certify `RETENTION_EXPIRED` while permanent reuse/terminal tombstones remain
  enforceable;
- malicious coordinator and Byzantine replica cannot obtain, derive, propose,
  or leak an honest participant output before `ProfileReleaseReservedV1`;
  leakage of a
  losing post-reservation proposal cannot select a second vector;
- Core reorg before burn, between burn and recheck, after publication, and for
  ACK/NACK observations before finality; removal after signed finality is an
  assumption-failure test;
- participant local-ledger rewind and subject-specific backup restore;
- admission cap races, mempool disappearance, forbidden replacement, spent
  reorg-tail accounting, and funding-custody bypass;
- legacy/scriptSig funding inputs, post-signature txid mutation, RBF signalling,
  alternate funding transaction, and graph child outpoint mismatch;
- ACK/NACK race and CPFP under forced fee pressure;
- coordinator, participant, registry, and bridge independent restart;
- graph signer retained-key attack and alternate-parent signature attempt;
- arbitrary Taproot internal key, mismatched NUMS derivation/tweak/control block,
  and one-element key-path witness attempt;
- admission expiry/revocation before funding, after burn, after release
  reservation, after publish intent, and during bridge consumption;
- v0.25/v0.26 cross-version rejection;
- complete slash, timeout, refund, and contested-payout downstream behavior.

---

## 13. Deployment stages and migration

### 13.1 Stages

1. **Regtest:** deterministic fixtures permitted; zero economic value.
2. **Signet:** production binaries, topology, policy, and ceremony path; zero
   economic value.
3. **Mainnet shadow:** observe-only; no RankLock-funded outputs.
4. **Bounded activation:** one reserved-or-active graph, explicit nonzero caps,
   admission-policy expiry, governance cooldown, all hard gates satisfied.
5. **Cap review:** any increase requires a new policy sequence, fresh
   attestations, an incident-free observation period, and a repeated recovery
   exercise. There are no automatic cap increases.

The protocol does not invent a satoshi cap. Governance chooses a loss budget;
the registry reserves it atomically and reconciles it with Core. A graph becomes
active at `RESERVED` and leaves the cap only at `RETIRED` after the signed reorg
tail. Every observation period, recovery exercise, and cap review names exact
start/end heights, test ids, binaries, pass criteria, and signed evidence.

### 13.2 Migration

- v0.25 single-hash and v0.26 vector-hash connectors are explicit enum variants.
- Enforce-mode binaries do not include the v0.25 raw-preimage compatibility
  reader or deterministic fixture generators.
- Existing unfunded v0.25 material remains test-only.
- A funded legacy graph, if one exists, resolves under its original script. It
  is never upgraded in place.
- Participant rotation, proof-suite change, immutable execution-policy change,
  or graph change creates a new epoch, subject, graph, and deposit. A mutable
  admission-policy sequence never rewrites an already admitted subject.
- Feldman resharing cannot mutate an active v0.26 subject.

---

## 14. Hard kill criteria

`safe_for_funds` remains false if any item below is true:

1. selected setup mode and on-chain connector disagree on preimage cardinality;
2. more than one independently authoritative runtime context remains;
3. any subject/evidence dependency is cyclic or hashes a descendant into its
   ancestor;
4. an activation object depends on future witness, wtxid, or block data;
5. exact public inputs are neither committed nor deterministically derived
   before contribution generation;
6. any signed object lacks an exact signature profile, message, roster, quorum,
   or key lifecycle;
7. a live graph-signing quorum can authorize an alternate parent after funding;
8. BN254 remains in the proof or conditional-lock trust path;
9. a new lock wraps a still-authoritative weaker proof suite;
10. the selected curve is below the signed security floor, the signed report is
    not valid through the complete canonically committed subject lifetime, or
    activation time/lifetime comes from caller input instead of the validated
    activation certificate and Core-MTP rule;
11. storage or performance targets justify weaker parameters;
12. production preimages are reconstructible from retained entropy or any
    secret outside the selected profile's exact qualified one-shot boundary;
13. retained runtime secrets lack an exact custody, backup, restore, and
    terminal-erasure policy;
14. an unverified API or development override can publish an ACK;
15. the selected release mechanism's security remains conditional or unaudited;
16. production point parsing is not canonical and subgroup safe;
17. secret operations are not native, constant-time, and explicitly zeroized;
18. a participant, registry outage, or authorized bad request can cause wrongful
    fund loss merely by withholding or consuming availability;
19. the initial caller request contains participant releases, projective
    outputs, burn receipts, public inputs, a verifier, or a VK;
20. the coordinator can impersonate a participant burn or evaluation;
21. no globally exclusive semantic-request lock exists before the first burn;
22. registry quorum intersection, CAS, receipt semantics, or control-domain
    independence is unspecified;
23. current chain guard is not derived from append-only ACK/NACK seen, reorg,
    and final events; a seen NACK cannot block burn/reservation/publication; or
    bridge broadcast is not suppressed while NACK is seen/final;
24. mutable expiry or revocation can alter an already admitted subject's exact
    resolution or strand a certified publish intent;
25. active value/count lacks an atomic reservation outside Core, or any funding
    signer/broadcast path can bypass admission;
26. ceremony aborts, graph keys, epochs, contributions, or nonce namespaces can
    be reused without monotonic rejection;
27. the bridge consumes bare preimages, trusts path names, or omits live
    txid/wtxid/outpoint/NACK checks;
28. required capsule recomputation inputs and exact staged bytes are not durably
    committed before publish intent, or a certified publish cannot replay exact
    bytes;
29. any primary or recovery error is suppressed;
30. ACK/CPFP authorization or fee delivery has no quantified safe margin before
    NACK maturity;
31. any required E2E row is absent, modeled-only, or lacks a zero-exit command;
32. deterministic fixtures or compatibility readers are reachable in enforce
    mode;
33. v0.25 bytes are silently interpreted as v0.26;
34. audit evidence lacks typed scope/finding/disposition semantics; or
35. any critical/high external audit finding remains open; or
36. any script-only protocol output has an arbitrary/spendable Taproot internal
    key or lacks key-path bypass rejection evidence; or
37. the exact two-slot logical budget, uniform `u16` slot encoding, per-slot
    intent lock, subject-wide single-release CAS, or selected profile's required
    superseded-erasure/custody-bound barrier is absent; or
38. participant evaluator secrets can be retired before exact certified result
    bytes are durably replayable; or
39. the funding transaction is not txid-stable before descendant presigning or
    permits RBF/alternate funding in the baseline;
40. an admission certificate omits the exact policy, governance checkpoint,
    risk namespace or registry generation, or a new cluster can reset caps;
41. current audit/policy expiry can strand an already admitted resolution;
42. successful setup descendants can fork/reuse one graph key, contribution
    set, artifact, ACK hash, or nonce namespace;
43. release depth or ACK/NACK finality depth is not strictly greater than its
    corresponding removal-reorg bound, or coordinator/participants/bridge rely
    on one Core control domain; or
44. under S-DFB, the two retained slot states lack separate
    trees/seeds/envelope keys, one slot's retirement destroys/exposes the other,
    physical losing-slot erasure is not certified before selected evaluation,
    or the honest-boundary assumption ends before both slots are
    cryptographically terminal; or
45. any irreversible CAS, exact nonrecursive finalization envelope, or secret
    erasure can outlive the only retrievable copy of its required accepted
    bytes; or
46. governance quorum counts multiple keys from one control domain, or active
    control-domain consolidation breaks a corruption threshold without
    suspending the funds-safety claim; or
47. subject-wide `ProfileReleaseReservedV1` is absent, secret-bearing, not atomic against
    NACK and the alternate slot, or occurs after any honest participant computes
    or transmits its projective output; or
48. a caller, coordinator, registry proposal/replica, or losing slot can obtain
    or derive more than the one vector selected by the reservation; or
49. implementation or operations treat `PUBLISH_INTENT` as the first possible
    exposure point and permit pre-reservation result leakage; or
50. a nonfinal ACK/NACK reorg rewrites registry history, resumes anything except
    the exact locked/reserved path, or a final resolution can be removed within
    the signed operating bound; or
51. coordinator failover can change the reserved vector/economics, or any retry
    can change capsule bytes after `PUBLISH_INTENT`; or
52. under C-DIRECT, `r_j` exists outside the exact non-exportable,
    rollback-resistant subject handle or any scalar clone/backup can escape the
    same consumed monotonic state; or
53. under C-DIRECT, a module accepts caller-supplied `A`, emits any
    pre-reservation output, or can evaluate more than one distinct bound input;
    or
54. under C-DIRECT, setup/runtime secret operations are not constant-time and
    fault hardened, result plaintext/decryption capability can leave before
    scalar erasure, ciphertext and conditional result-key envelopes lack
    quorum readback/availability, exact erasure cannot recover from its durable
    device tombstone, or a consumed output intent or exact retry can invoke the
    scalar again, or any pre-body-commit terminal failure lacks exact no-result
    teardown with the complete clone-erasure evidence, or a sealed conditional
    result-key envelope can survive no-result teardown without an irreversible
    service tombstone and certified forward-secure child-share erasure, a
    partial key-service activation can bypass that teardown, or no-result can
    race a certified body-commit CAS; or
55. under C-DIRECT, positive-lock hiding is not proved for the exact CRS/VK,
    public leakage, guarded one-shot service access, and toxic-waste model while
    `r_j` remains secret in the honest boundary, or `Y`, `delta`, subgroup,
    nonidentity, and canonical-encoding checks are incomplete; or
56. the signed security-floor report and canonical activation-window evidence
    verifier is absent, bypassable, or accepts a bare digest without resolving
    and verifying the typed report.

---

## 15. Work programme

The build should proceed in this order:

1. **Kill decisions:** set the security floor, ratify S-DFB versus C-DIRECT and
   its honest-boundary assumption, and prove timeout fund preservation or
   explicitly change the corruption/liveness model. Stop if any cannot be made
   safe.
2. **Identity DAG and profiles:** implement the acyclic setup-to-funding object
   graph, exact wire/signature profiles, strict Rust/Python codecs, golden
   vectors, dependency-cycle checks, and field-mutation tests.
3. **Graph v2 and presigning:** implement the ordered vector-hash connector,
   exact ACK/NACK templates, one-subject signing ceremony/key erasure, and Core
   tests before touching the coordinator.
4. **Safety registry and admission:** implement BFT total order/CAS, ceremony
   retirement, global intent locks, nonsecret readiness and subject-wide release
   reservation, selected release-profile barrier, atomic risk reservations,
   nonrecursive exact-envelope availability, retention-key lifecycle,
   append-only Core observations, and custody-gated funding.
5. **Proof-suite spike:** implement and measure the complete selected candidate
   suite. For S-DFB this includes the new DFB profile; for C-DIRECT it includes
   the exact custody module and positive-lock theorem. Drop the one-MiB target
   if necessary.
6. **Selected ceremony and participant:** add typed profile certificates, local
   burn-then-ready and release-barrier services, exact retained-secret
   lifecycle, and evidence parsers; remove entropy-derived ACKs and fixtures
   from production linkage.
7. **Coordinator and bridge:** implement intent/binding/result/snapshot/capsule,
   secret outbox, live Core checks, recovery, and embedded execution gates.
8. **Live matrix:** restore the canonical acceptance specification and execute
   the complete multi-service Core/Strata matrix with crash, reorg, concurrency,
   and fee-pressure injection.
9. **Independent review:** cryptography, implementation, Bitcoin economics, and
   operations audits over the exact source, artifact, subject, and binaries.
10. **Staged activation:** signet, mainnet shadow, then a governance-capped
    activation only after all gates are externally satisfied.

The first implementation milestone is therefore not a proof coordinator. It is
the acyclic identity/profile codec plus graph-v2 connector and presign theorem.
Until those exist, coordinator work would automate an ambiguous protocol.

---

## 16. Open decisions requiring owners

| Decision | Owner | Must be fixed before |
|---|---|---|
| Ratify the 128-bit floor and BN462 target; select, harden, audit, and pin a native backend | cryptography + governance | suite implementation commitment |
| Select S-DFB or the separately versioned C-DIRECT custody model; for C-DIRECT pin the exact device/firmware/attestation/clone/backup and conditional-result-key service policy | cryptography + protocol + governance + operations | contribution schema or participant implementation |
| Timeout/NACK economic semantics; N-of-N vs weaker threshold model | protocol + Bitcoin economics | graph-v2 finalization |
| Exact wire maxima/widths and operational signature profile | protocol + implementation + crypto | codec implementation |
| Participant and graph-signer counts/control domains | governance + operations | selected profile setup intent |
| Parent-release and ACK/NACK-finality depths plus their removal bounds | Bitcoin economics + operations | signet deployment |
| CSV delay, fee reserve, CPFP responsibility, and halt threshold | Bitcoin economics | E2E matrix |
| Registry `f`, BFT engine/exact-envelope protocol, replica roster, retention-key service, cluster lifetime, and failure domains | operations + security | registry deployment |
| Initial per-deposit, aggregate, and active-count caps | governance | bounded activation |
| Admission expiry, revocation distribution, and cooldown | governance + operations | admission service |
| Exact evidence schemas and external signer rosters | auditors + governance | release gate integration |

Open decisions are not permission to use defaults. Each one changes the
security theorem or economic loss bound.

---

## 17. External references

- IRTF CFRG, [Pairing-Friendly Curves](https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/) — current curve-security guidance; records the exTNFS downgrade for 254-bit BN curves and the security considerations for BLS12-381.
- zkcrypto, [BLS12-381 implementation](https://github.com/zkcrypto/bls12_381) — a constant-time engineering candidate whose own README says it is not audited; it cannot substitute for RankLock's implementation audit.
- Bitcoin, [BIP340 Schnorr signatures](https://bips.dev/340/) and [BIP341 Taproot](https://bips.dev/341/) — canonical operational signatures plus exact script-path and `SIGHASH_DEFAULT` transaction binding.
- Bitcoin, [BIP68 relative lock-time](https://bips.dev/68/) and [BIP112 CHECKSEQUENCEVERIFY](https://bips.dev/112/) — consensus basis for the delayed NACK branch.

These references support parameter and consensus decisions. They do not
validate RankLock's construction.
