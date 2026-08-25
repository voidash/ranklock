# v0.26 §16 decision 4 — exact wire maxima/widths and operational signature profile

**Status: PROPOSED. NOT RATIFIED. NOT AUTHORITATIVE.**

This document is decision *input* for the fourth open decision in
`58_V026_FUNDS_SAFETY_PROTOCOL.md` §16:

| Decision | Owner | Must be fixed before |
|---|---|---|
| Exact wire maxima/widths and operational signature profile | protocol + implementation + crypto | codec implementation |

It does not make that decision. §16 states plainly that *"Open decisions are not
permission to use defaults. Each one changes the security theorem or economic
loss bound."* Every numeric value below is a starting proposal whose purpose is
to be argued down by its owners, not a default to be inherited.

**Until the ratification block in §8 is signed, §4.2's last rule still binds:**

> No codec implementation may begin while any field width or bound remains an
> owner-selected default; changing the wire profile creates a new subject.

Publishing this draft therefore moves **no** blocker. Obligation 24
(`canonical-wire-identity-unimplemented`) and obligation 1
(`research-nums-profile`) in `59_V026_CRITICAL_PATH_GAP_MAP.md` remain open.
`safe_for_funds` remains `false`. No `funding_eligible` flag changes. No
evidence artifact under `results/` was written or edited to produce this
document.

---

## 1. Why this decision was drafted first

From the gap map's §16 inversion table, decision 4 is the cheapest high-leverage
decision on the critical path:

- Its owners (protocol + implementation + crypto) are **all internal**. Checked
  against the full §16 table, it is the only one of the eleven open decisions
  whose owner set contains no governance, operations, Bitcoin-economics or
  auditor role. Every other decision needs a counterparty outside engineering.
- It gates obligations 1 (NUMS role/index semantics) and 24 (canonical
  graph/wire identity) directly, and obligation 27 (Rust graph projection
  unverified against the Python model) transitively, through §4.2's shared
  golden-vector requirement — see defect D-5. It also gates the §15 step-2
  milestone that §15 names as the *first* implementation milestone:

  > The first implementation milestone is therefore not a proof coordinator. It
  > is the acyclic identity/profile codec plus graph-v2 connector and presign
  > theorem.

The finding in §6 below is that decision 4 is not one decision. It is two, and
only one of them is genuinely blocked on upstream decisions.

---

## 2. Method and provenance

Every statement below carries one of three tags. Nothing is asserted without one.

| Tag | Meaning |
|---|---|
| **FIXED** | Already stated in `58_V026_FUNDS_SAFETY_PROTOCOL.md` §4.2 or §4.3. Restated here for completeness. Not a decision this document makes or may change. |
| **OBSERVED** | Read out of existing source at a cited `file:line`. Records what the tree already does. Existing practice is evidence, not authority — an observed value can still be wrong. |
| **PROPOSED** | New. Owner must accept, amend, or reject. |

Source trees read for this draft:

```text
/Users/cdjk/github/llm/ranklock/worktree-v0.25.2          (docs, Python model)
/Users/cdjk/github/llm/ranklock/tmp/strata-v026-f94c      (active Rust checkout)
```

No existing file in either tree was modified to produce this draft. The Rust
checkout is a dirty worktree containing unrelated user changes and was read
only. This document was first written 2026-08-22 and has been revised since;
its companion decision drafts are `62_V026_DECISION1_SECURITY_FLOOR_PROPOSAL.md`
(§16.1) and the gap map `59_V026_CRITICAL_PATH_GAP_MAP.md`.

---

## 3. Already fixed by §4.2 and §4.3 — restate, do not decide

These are **FIXED**. They are listed so the owner review can confirm the
proposal in §4 is additive rather than a silent amendment to the protocol.

**Framing (§4.2):**

- 8-byte magic.
- `u16` schema version.
- `u16` protocol version.
- `u32` total length.
- Variable byte strings: `u32` byte length prefix.
- Vectors: `u16` count, then canonical elements.
- All fixed-width unsigned integers in network byte order (big-endian).
- Hashes and keys are fixed 32-byte fields.
- Bitcoin txids/wtxids use raw 32-byte consensus hash order, never
  display-reversed text.
- Parsers check total and section lengths **before** allocation.
- Integer coercion, trimmed text, hex fallbacks and Unicode identifiers are
  forbidden at the binary boundary.
- Curve encodings canonical, on curve, correct subgroup, nonidentity where
  required.
- Duplicate, reordered, omitted, unknown or mixed-version sections fail.
- Decode-then-encode reproduces the original bytes exactly.
- Python and Rust share golden vectors and differential fuzz tests.

**Signature baseline (§4.3):**

- BIP340: 32-byte x-only secp256k1 keys, 64-byte signatures, 32-byte
  SHA-256 domain-separated message.
- `SetupIntentV1` pins a `SignatureProfileV1` **separate** from the proof-suite
  id; the suite id does not implicitly select operational signatures.
- Every signed object defines its unsigned canonical body and exact domain tag.
- Quorums: contributions and bundle approvals need every ordered split
  participant; graph parents need every one-subject graph signer and use only
  the exact committed Taproot sighash mode; ceremony activation needs every
  named verifier across at least two independent control domains; governance
  uses the exact `q-of-m` roster pinned in the setup intent; each audit role
  supplies its own typed signed manifest; registry commit certificates need
  `2f+1` of `3f+1` replicas with `f >= 1` and unique control domains.
- Alternative signature or quorum rules require a new signature-profile id,
  golden vectors, security review, and funding subject.

Note the consequence of the graph-parent rule, because it is easy to get wrong
in a codec: **graph parent signatures have no RankLock domain tag.** Their
message is the BIP341 sighash over the exact committed prevouts, amounts,
scripts, control blocks and sighash type. A RankLock tag on that path would be a
protocol violation, not a hardening measure.

---

## 4. What decision 4 must actually fix

### 4.1 The 8-byte magic registry

Convention **OBSERVED** across the Rust tree: 8 bytes, ASCII, `RL26` + a
three-character object code + a one-digit object version.

Already allocated (do not reuse):

| Magic | Object | Source |
|---|---|---|
| `RL26TBP3` | threshold bond policy v3 | `crates/connectors/src/counterproof_bond_v3.rs:59` |
| `RL26TFS3` | threshold funded settlement v3 | `crates/connectors/src/counterproof_bond_v3.rs:61` |
| `RL26TKR3` | threshold key registry v3 | `crates/connectors/src/threshold_registry_v3.rs:28` |
| `RL26TPC3` | threshold participant contribution v3 | `crates/connectors/src/threshold_registry_v3.rs:31` |
| `RL26SBS1` | subject-bound subject | `crates/proofs/bridge-counterproof/src/subject_bound.rs:43` |
| `RL26SBM1` | subject-bound manifest | `crates/proofs/bridge-counterproof/src/subject_bound.rs:44` |
| `RL26SBG1` | subject-bound commitment | `crates/proofs/bridge-counterproof/src/subject_bound.rs:45` |
| `RL26ADM` (**7 bytes**) | persisted admission observation envelope | `crates/db/src/fdb/row_spec/v026_admissions_v2.rs:17` |

**PROPOSED** allocation for the fourteen §4.1 DAG objects plus
`RecoveryVaultDescriptorV1`, which §4.1 references inside `ExecutionPolicyV1`
rather than listing as its own row — fifteen in total, all at object version `1`:

| Object | Magic |
|---|---|
| `GraphKeyDescriptorV1` | `RL26GKD1` |
| `SetupIntentV1` | `RL26SIN1` |
| `ParticipantContributionV1` | `RL26PCN1` |
| `GraphBundleV1` | `RL26GBN1` |
| `ParticipantBundleApprovalV1` | `RL26PBA1` |
| `GraphPresignTranscriptV1` | `RL26GPT1` |
| `CeremonyCertificateV1` | `RL26CCT1` |
| `ExecutionPolicyV1` | `RL26EXP1` |
| `RecoveryVaultDescriptorV1` | `RL26RVD1` |
| `FundingSubjectV1` | `RL26FSJ1` |
| `AuditManifestV1` | `RL26AMF1` |
| `ActivationCertificateV1` | `RL26ACT1` |
| `AdmissionPolicyEpochV1` | `RL26APE1` |
| `AdmissionCertificateV1` | `RL26ACR1` |
| `EvaluationBindingV1` | `RL26EVB1` |

**PROPOSED** registry invariants:

1. The magic registry is allowlist-only. A parser rejects any 8-byte prefix not
   in the allowlist before reading a single further byte.
2. No allocated 8-byte magic may have `RL26ADM` as its first seven bytes. The
   fifteen above satisfy this; it must be re-checked on every future allocation.
   (See defect D-1 in §7 for why this constraint exists at all.)
3. A magic identifies exactly one object type at exactly one object version.
   Bumping the trailing digit is a new magic, never a reinterpretation.
4. The three-character code is unique across the whole registry independent of
   the trailing digit, so `RL26XYZ1` and `RL26XYZ2` are the same object at two
   versions and nothing else may claim `XYZ`.

### 4.2 Version fields

| Field | Value | Tag |
|---|---|---|
| `protocol_version: u16` | `26` | **OBSERVED** — `threshold_registry_v3.rs:32`, `counterproof_bond_v3.rs:63` |
| `schema_version: u16` | `1` for every object in §4.1 at first freeze | **PROPOSED** |

**PROPOSED:** the schema version is *not* redundant with the magic's trailing
digit. The trailing digit is the object's identity; the `u16` is the encoding
revision within that identity. §4.2 forbids mixed-version sections, so every
section of one message carries the same pair, and a mismatch fails the parse
rather than triggering any compatibility path.

### 4.3 Total-message and per-object section maxima

The dominant-term column shows what actually sets each bound, so the owner can
argue the arithmetic rather than the round number.

| Object | Dominant term | Proposed section max (bytes) | Blocked on |
|---|---|---|---|
| `GraphKeyDescriptorV1` | ordered signer keys + PoP set | 262,144 | §16.5 signer count |
| `SetupIntentV1` | unsigned funding tx + canonical public-input bytes + VK | 1,048,576 | §16.1 suite, §16.5 roster |
| `ParticipantContributionV1` | positive lock + scale proof + `[r_j]delta` | 262,144 | §16.1 suite, §16.2 custody arm |
| `GraphBundleV1` | every parent template + control blocks | 4,194,304 | §16.3 template set, §16.5 |
| `ParticipantBundleApprovalV1` | three fixed fields | 512 | — |
| `GraphPresignTranscriptV1` | per-parent sighash + parent signatures | 2,097,152 | §16.3, §16.5 |
| `CeremonyCertificateV1` | contribution + approval sets, clone inventory | 1,048,576 | §16.2, §16.5 |
| `ExecutionPolicyV1` | economic-principal map + role quorums | 262,144 | §16.5, §16.7, §16.8 |
| `RecoveryVaultDescriptorV1` | script + allocation | 16,384 | §16.7 |
| `FundingSubjectV1` | embedded predecessor digests + funding tx | 1,048,576 | §16.1 |
| `AuditManifestV1` | finding set | 262,144 | §16.11 |
| `ActivationCertificateV1` | typed audit manifests | 1,048,576 | §16.11 |
| `AdmissionPolicyEpochV1` | allowed-profile list + caps | 65,536 | §16.9, §16.10 |
| `AdmissionCertificateV1` | fixed digests + registry commit certificate | 65,536 | §16.8 |
| `EvaluationBindingV1` | raw counterproof transaction | 524,288 | §16.1 |

**PROPOSED** `WIRE_TOTAL_MAX = 4_194_304` (2^22), set by the largest object
(`GraphBundleV1`). Every object's own section maximum is additionally enforced;
the total is a ceiling, never a substitute for the per-object bound.

**Explicitly not inherited.** Two transaction-size ceilings already coexist in
the Python tree and neither is the wire profile's:

- `src/ranklock/bitcoin_tx.py:31` — `MAX_PARSE_TRANSACTION_BYTES = 400_000`
- `src/ranklock/bitcoin_authorization.py:31` — `_MAX_TRANSACTION_BYTES = 4_000_000`

They serve different modules and are not in conflict with each other, but a
codec that silently reaches for either is exactly the "owner-selected default"
§4.2 forbids. The wire profile's transaction-bearing byte-string maximum must be
stated in this document and referenced by both implementations.

### 4.4 Vector maxima (`u16` counts)

| Vector | Proposed max | Tag / basis |
|---|---|---|
| ordered logical query slots | exactly **2** | **FIXED** — §4.1 "exactly two ordered logical query-slot descriptors"; kill criterion 37 pins the uniform `u16` slot encoding |
| ACK preimage commitments per connector | **2..64** declared; **2..44** operationally relayable | **OBSERVED** — `split_scalar_lock.py:946`, `:982` and Rust `counterproof_resolution_v2.rs` (`MIN/MAX_ACK_PREIMAGES`) both enforce 2..64. **MEASURED against real Bitcoin Core 2026-08-25** (`vector_ack_truc_child_crossover_is_measured_against_core`): ACK weight grows ~72 WU per preimage — n=2 → 912 WU, n=44 → 3,938 WU, **n=45 → 4,009 WU**, n=64 → 5,378 WU. The v3 relay path caps children of an *unconfirmed* v3 parent at 4,000 WU, so **45..64 are valid and Core-acceptable only against a confirmed parent.** Owners must decide whether the profile maximum stays 64 with a documented confirmed-parent requirement above 44, or is lowered to 44. |
| ordered split participants | 256 | **PROPOSED** — blocked on §16.5 |
| one-subject graph signers | 256 | **PROPOSED** — blocked on §16.5 |
| control domains | 64 | **PROPOSED** — blocked on §16.5 |
| registry replicas | 256 | **PROPOSED** — must be `3f+1`; blocked on §16.8 `f` |
| ceremony verifiers | 64 | **PROPOSED**; §4.3 sets the *minimum* at two independent control domains |
| audit manifests per activation certificate | 64 | **PROPOSED** — blocked on §16.11 |
| findings per audit manifest | 4,096 | **PROPOSED** — blocked on §16.11 severity taxonomy |
| governance `q-of-m` roster | 256 | **PROPOSED** — blocked on §16.5 |
| economic principals | 256 | **PROPOSED** — blocked on §16.3 |
| C-DIRECT clone/replica inventory entries | 256 | **PROPOSED** — blocked on §16.2; absent entirely under S-DFB |

Every `u16` count is additionally bounded by its own maximum; `u16` is the wire
width, never the semantic bound. A count of 65,535 must fail on the semantic
bound, not on allocation.

### 4.5 Byte-string maxima (`u32` length prefixes)

| Byte string | Proposed max | Basis |
|---|---|---|
| Groth16 on-chain proof bytes | 65,536 | **PROPOSED**. Observed today: 356 bytes (4-byte selector + 352-byte encoded proof, BN254). BN462 roughly doubles element width; the headroom is deliberate and must be re-derived once §16.1 pins the curve. |
| canonical public-input bytes | 65,536 | **PROPOSED**. Observed today: 488 bytes for the subject-bound statement. |
| verification key | 1,048,576 | **PROPOSED** — blocked on §16.1 |
| raw Bitcoin transaction | 400,000 | **PROPOSED**, matching `bitcoin_tx.py:31`, adopted *explicitly* rather than inherited |
| Bitcoin script (leaf or scriptPubKey) | 10,000 | **OBSERVED** — `bitcoin_tx.py:34`, `timeout_economics.py:31`; equals Bitcoin's consensus script limit |
| Taproot control block | 4,129 | **PROPOSED** — BIP341 maximum: 33 + 32×128 |
| witness item | 100,000 | **OBSERVED** — `bitcoin_tx.py:36` |
| total witness | 400,000 | **OBSERVED** — `bitcoin_tx.py:37` |

### 4.6 The NUMS pin

§4.2 requires the wire profile to pin *"the BIP341 NUMS base point and exact
public derivation for every script-only Taproot internal key; arbitrary internal
keys fail."* Kill criterion 36 makes a violation fatal.

**OBSERVED** in `crates/connectors/src/ranklock_nums.rs`, and its own module
doc calls itself a research profile that MUST NOT authorize funding:

- base point: BIP341's example NUMS point, x-only (`:21`)
- tagged hash: `RankLock/v026/TaprootNUMS` (`:15`)
- message: exactly 37 bytes — 32-byte `setup_intent_digest` ‖ `u8` role ‖ `u32`
  big-endian `output_index` (`:95`–`:98`)
- tweak: digest reduced mod the secp256k1 order, then `base.add_tweak` (`:101`–
  `:105`)
- derivation failure is explicit and typed: invalid pinned base point, scalar
  reduction failure, point at infinity (`:113`–`:119`)

**PROPOSED:** promote the construction — base point, tag, 37-byte message
layout, big-endian index, reduce-then-tweak, and the three typed failures —
unchanged into `WireProfileV1`. It already satisfies §4.2's structural
requirements and its failure handling is explicit rather than silent.

**Not promotable as-is.** The module's own doc comment states the two genuinely
open questions, and they are obligation 1:

> The v0.26 protocol document has not yet assigned authoritative byte values to
> its `output_role` enum or defined whether `output_index` is a vout, role-local
> ordinal, or global graph ordinal.

Both must be answered here:

1. **Role registry.** The six research roles at `:37`–`:49`
   (`CounterproofResolution` = `0x01` through `CounterproofResolutionThreshold`
   = `0x06`) are prototyping bytes. **PROPOSED:** the authoritative registry
   starts at `0x10` so that no research byte can ever be mistaken for an
   authoritative one, and `0x00`–`0x0F` are permanently reserved-invalid. This
   costs nothing and makes the research/authoritative boundary a parse failure
   rather than a code review.
2. **`output_index` semantics.** **PROPOSED: global graph ordinal**, assigned
   once in `GraphBundleV1` in canonical order over the full parent-template set.
   Rationale: a vout is not unique across the graph, so two outputs in different
   transactions with the same role and vout would derive the same internal key —
   the exact per-output uniqueness the module explicitly declines to claim. A
   role-local ordinal is unique but makes the derivation depend on template
   ordering *within* a role, which is not itself committed anywhere. A global
   ordinal is committed by the bundle that already commits every template.

   This is the single highest-value line in this document and the one most
   deserving of an owner's disagreement.

### 4.7 Signature domain tags and unsigned canonical bodies

**OBSERVED** namespace convention: `ranklock/v026/<kebab-case>` with a trailing
`\0`, per the §4.1 worked examples (`funding_subject_digest`,
`participant_lock_context_j`) and twelve tags already allocated in the trees:

```text
ranklock/v026/ack-threshold
ranklock/v026/deterministic-wrapper-statement
ranklock/v026/imported-counterproof-artifacts
ranklock/v026/known-toxic-vk-points
ranklock/v026/participant-lock-context
ranklock/v026/subject-bound-ack
ranklock/v026/subject-bound-manifest
ranklock/v026/threshold-release-static-evidence
ranklock/v026/threshold-release-static-game
ranklock/v026/wrapper-ack-subject
ranklock/v026/wrapper-binding-manifest
ranklock/v026/wrapper-inner-sp1-statement
```

**PROPOSED**: ten tags across eleven signed objects — graph parents take none —
none colliding with the twelve above:

| Signed object | Domain tag | Signer set (§4.3) |
|---|---|---|
| `ParticipantContributionV1` | `ranklock/v026/participant-contribution\0` | every ordered split participant |
| `ParticipantBundleApprovalV1` | `ranklock/v026/bundle-approval\0` | every ordered split participant |
| graph parent | **none — BIP341 sighash** | every one-subject graph signer |
| `CeremonyCertificateV1` | `ranklock/v026/ceremony-certificate\0` | every named verifier, ≥2 control domains |
| `ExecutionPolicyV1` | `ranklock/v026/execution-policy\0` | governance `q-of-m` |
| `AuditManifestV1` | `ranklock/v026/audit-manifest\0` | one per required audit role |
| `ActivationCertificateV1` | `ranklock/v026/activation-certificate\0` | governance activation quorum |
| `AdmissionPolicyEpochV1` | `ranklock/v026/admission-policy-epoch\0` | governance quorum |
| `AdmissionCertificateV1` | `ranklock/v026/admission-certificate\0` | governance + registry commit |
| registry commit certificate | `ranklock/v026/registry-commit\0` | `2f+1` of `3f+1`, unique control domains |
| signed security-floor report | `ranklock/v026/security-floor-report\0` | per §14 criterion 56 |

**PROPOSED** unsigned-canonical-body rule, uniform across every tagged object:

```text
message = SHA256( domain_tag_with_nul || canonical_object_bytes_without_signature_section )
```

where the signature section is the final section of the object and is absent —
not zeroed, not placeholder-filled — from the bytes being hashed. Zero-filling
would make a signature section of the wrong length hash identically to a valid
one; absence makes it a length mismatch and a parse failure. The signed object
and its unsigned body therefore have different total lengths, and both lengths
are checked.

---

## 5. What decision 4 must **not** decide

Each row below is a value a codec author will want and must not take from this
document. Where §4 proposes a number for one of these, that number is an upper
bound chosen so that any plausible answer to the upstream decision fits inside
it — it is not a proposed answer to the upstream decision.

| Value | Belongs to | Consequence of deciding it here |
|---|---|---|
| participant and graph-signer counts, control domains | §16 decision 5 (governance + operations) | pre-empts the selected profile setup intent |
| N-of-N vs weaker threshold; timeout/NACK economics | §16 decision 3 (protocol + Bitcoin economics) | changes which parent templates exist, hence the `GraphBundleV1` bound — and the loss bound |
| registry `f`, replica roster, failure domains | §16 decision 8 (operations + security) | `3f+1` sets the replica vector max |
| curve, field, proof/VK element widths | §16 decision 1 (cryptography + governance) — drafted in `62_V026_DECISION1_SECURITY_FLOOR_PROPOSAL.md` | every suite-bearing byte string; BN254 is disqualified from the funds path, so today's observed 356/488 are **not** the target. That draft's §9 records the reverse dependency: `canonical_subgroup_checked_encodings` cannot become true for any BN462 suite until this profile freezes the serialization, because the CFRG draft defines no BN462 point encoding. |
| S-DFB vs C-DIRECT | §16 decision 2 | determines which tagged-union arm exists at all, and whether the clone inventory vector exists |
| per-deposit, aggregate, active-count caps | §16 decision 9 (governance) | `u64` field *values*, not widths — but a codec must not clamp them |
| admission expiry, revocation, cooldown | §16 decision 10 | `AdmissionPolicyEpochV1` validity fields |
| evidence schemas, external signer rosters | §16 decision 11 (auditors + governance) | audit manifest and activation certificate vector maxima |

If a reviewer finds a value in §4 that silently answers one of these, that is a
defect in this document and should be reported as such.

---

## 6. Finding: decision 4 is two decisions, and only one is blocked

Read literally, §16 decision 4 cannot be ratified until decisions 1, 2, 3, 5, 8
and 11 are ratified, because every numeric maximum in §4.3–§4.5 depends on at
least one of them. That makes the cheapest decision on the critical path
transitively the most expensive, which is the wrong conclusion.

The dependency is not uniform. Split it:

**Layer A — structural. Depends on nothing upstream.**

- the magic registry and its four invariants (§4.1)
- the version-field semantics (§4.2)
- the NUMS role registry and `output_index` semantics (§4.6)
- the domain-tag registry and the unsigned-canonical-body rule (§4.7)
- the vector maxima that are already fixed rather than proposed: exactly two
  query slots, 2..64 preimages (§4.4)

**Layer B — numeric. Blocked on decisions 1, 2, 3, 5, 8, 11.**

- every section maximum in §4.3
- every proposed roster/vector maximum in §4.4
- every suite-bearing byte-string maximum in §4.5

**What Layer A ratification does and does not buy.**

It does **not** unlock §15 step 2. §4.2 says codec implementation may not begin
while *any* field width or bound remains an owner-selected default, and Layer B
is entirely field widths and bounds. Anyone reading this document as permission
to start the codec has misread it.

What it does buy:

1. It closes the *decision* half of obligation 1. The NUMS role/index semantics
   stop being a research profile and become a pinned one; only the
   implementation remains.
2. It stops magic and domain-tag collisions accruing. Every new object added to
   either tree between now and Layer B ratification currently allocates its
   magic ad hoc. Seven eight-byte object magics, one seven-byte envelope
   magic, and twelve domain tags are already allocated that way. That is a namespace being consumed without a registry.
3. It converts decision 4 from a six-way blocked decision into a one-signature
   decision plus a numeric table that fills in mechanically as decisions 1, 2,
   3, 5, 8 and 11 land.

This split is itself a proposal. If the owners judge that a partial freeze of
the wire profile creates a false sense of settledness — and given §4.2's
"changing the wire profile creates a new subject," that is a serious objection —
then reject the split and ratify decision 4 as a single unit after Layer B's
upstream decisions. The objection is legitimate and this document does not
pretend to resolve it.

---

## 7. Conformance defects found while drafting

These are observations about the existing tree, not part of the proposal. Each
is either a real deviation from §4.2 or a gap that will block §4.2's
Python/Rust differential requirement.

**D-1 — the admission envelope magic is 7 bytes; §4.2 mandates 8.**
`crates/db/src/fdb/row_spec/v026_admissions_v2.rs:17` defines
`ENVELOPE_MAGIC: &[u8; 7] = b"RL26ADM"` with `ENVELOPE_HEADER_LEN = 7 + 2`.
A parser that reads eight bytes of magic per §4.2 sees `RL26ADM\x00` — the
seven magic bytes plus the high byte of the `u16` version. This is a persistence
envelope rather than a wire object, so it may be out of scope for
`WireProfileV1`; the owners must say which, because §4.2's wording is *"every
magic value."* If it stays out of scope, the registry invariant in §4.1(2)
becomes permanent rather than transitional.

Updated 2026-08-23: the family now has three members. `v026_admissions_v3` was
added with the same seven-byte magic at envelope version 3, deliberately — see
the 2026-08-23 decision-log entry. Forking the header layout under a shared
magic would be strictly worse than consistent nonconformance, because a reader
dispatching on `RL26ADM` plus a `u16` version would misparse. So the question
for the owners is no longer "does a V3 envelope exist"; it is whether the whole
`RL26ADM` family migrates to an eight-byte magic. Because the frozen V1/V2/V3
bytes cannot change, that migration is a V4 envelope and a new subject, not an
edit to any existing one.

**D-2 — the NUMS role registry is explicitly non-authoritative.** Six roles,
all `funding_eligible() == false` by construction
(`crates/connectors/src/ranklock_nums.rs:37`–`:56`), with undefined
`output_index` semantics. This is obligation 1, restated at its source.

**D-3 — `MAX_CONTEST_COUNTERPROOF_V2_DATA = 998`.**
`crates/connectors/src/contest_counterproof_v2.rs:34` bounds the operator
signature count at 998 as a `usize`. It fits a `u16` vector count, so it is not
a framing violation, but it is not derived from any pinned wire maximum and is
not in any registry. It must either appear in §4.4 or be justified as
out-of-scope.

**D-4 — two transaction ceilings coexist in the Python tree.** 400,000 and
4,000,000, cited in §4.3. Not a conflict between them; a conflict with §4.2's
prohibition on inherited defaults.

**D-5 — the 2..64 preimage bound is enforced on both sides, but the shared
golden vectors are still absent.**

*Corrected 2026-08-25.* The first version of this defect claimed the bound
existed "only in Python" and that no Rust counterpart was found. **That was
wrong**, and the error was one of search rather than reading: the original grep
looked for `vector_hash` / `VectorHash` and missed the Rust connector, which
uses `ACK_PREIMAGES` naming.

Both sides enforce it. Python: `src/ranklock/split_scalar_lock.py:946` and
`:982`. Rust: `crates/connectors/src/counterproof_resolution_v2.rs` declares
`MIN_ACK_PREIMAGES: usize = 2` and `MAX_ACK_PREIMAGES: usize = 64` and applies
`(MIN_ACK_PREIMAGES..=MAX_ACK_PREIMAGES).contains(...)` at `:50`. §1 of the
protocol says the *Strata* connector accepts exactly one `[u8; 32]`, which
remains true and is why v0.26 introduces its own connector rather than reusing
that one — it is not a statement about this file.

What survives of the defect: §4.2 requires Python and Rust to **share golden
vectors and differential fuzz tests** for the wire profile. Two independent
implementations of the same numeric bound are not shared vectors. Until those
exist, obligation 27 (Rust graph projection unverified against the Python model)
cannot close — but the reason is a missing differential harness, not a missing
connector, and the remaining work is correspondingly smaller.

---

## 8. Ratification block — unsigned

Decision 4's owners per §16 are **protocol + implementation + crypto**. This
document is not a decision until this block is completed in a signed commit by
each named owner.

| Role | Owner | Layer A | Layer B | Date | Signature |
|---|---|---|---|---|---|
| Protocol | *(unnamed)* | ☐ accept ☐ amend ☐ reject | ☐ accept ☐ amend ☐ reject | | |
| Implementation | *(unnamed)* | ☐ accept ☐ amend ☐ reject | ☐ accept ☐ amend ☐ reject | | |
| Cryptography | *(unnamed)* | ☐ accept ☐ amend ☐ reject | ☐ accept ☐ amend ☐ reject | | |

The owner column is blank because §16 names roles, not people. Naming the three
individuals is itself a prerequisite and is not something this document can do.

On ratification, the accepted content moves into
`58_V026_FUNDS_SAFETY_PROTOCOL.md` §4.2/§4.3 as authoritative text, a dated
entry is added to `11_DECISION_LOG.md`, and this file is marked superseded. Until
then doc 58 is unchanged — editing the authoritative protocol document *is* the
ratification, and this draft deliberately does not perform it.

---

## 9. What this document does not establish

- It does not make RankLock safe for funds. `safe_for_funds` is `false` in
  `STATUS.json` and is correct at `false`.
- It does not close any blocker. Obligations 1, 24 and 27 remain open; a signed
  Layer A closes the *decision* portion of obligation 1 only, and the
  implementation portion remains.
- It does not authorize codec implementation. §4.2's prohibition stands until
  Layer B is ratified.
- It does not decide anything owned by §16 decisions 1, 2, 3, 5, 8, 9, 10 or 11.
- Its numeric values have no security argument behind them. They have
  arithmetic derivations and headroom, which is a different and weaker thing.
  A maximum that is merely large enough is not a maximum that was chosen.
- It is not evidence. Nothing here was produced by a run, and nothing here
  should be cited in `results/` or `09_CLAIMS.md`.
