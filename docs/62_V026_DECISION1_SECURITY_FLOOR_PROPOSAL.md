# v0.26 §16 decision 1 — security floor, curve target, and native backend

**Status: PROPOSED. NOT RATIFIED. NOT AUTHORITATIVE.**

Decision input for the first open decision in
`58_V026_FUNDS_SAFETY_PROTOCOL.md` §16:

| Decision | Owner | Must be fixed before |
|---|---|---|
| Ratify the 128-bit floor and BN462 target; select, harden, audit, and pin a native backend | cryptography + governance | suite implementation commitment |

This document makes no decision. It moves no blocker. `safe_for_funds` remains
`false`, every `funding_eligible` remains `false`, no `results/` artifact was
written, and `src/ranklock/proof_suite_registry.py` was not modified.

Unlike decision 4 (`60_V026_DECISION4_WIRE_SIGNATURE_PROFILE_PROPOSAL.md`),
this decision's owner set is **not** purely internal. It includes governance,
and its completion requires paid external audits. That makes it slower and more
expensive than decision 4 — but §15 puts it in step 1, ahead of everything else,
because it is a kill decision: *"Stop if any cannot be made safe."*

---

## 1. Why this decision is first

§15's work programme opens with kill decisions: *"set the security floor, ratify
S-DFB versus C-DIRECT and its honest-boundary assumption, and prove timeout fund
preservation."* This is the first of those three.

It also gates the largest single obligation in the gap map. Obligation 28
(`release-cryptography-evidence-unverified`) is the sole CRYPTO-class item, and
`59_V026_CRITICAL_PATH_GAP_MAP.md` §5 shows it expanding into 25 gate-level
entries. Kill criterion 8 — *"BN254 remains in the proof or conditional-lock
trust path"* — is the most-cited kill criterion in that map (**OBSERVED**: three
mentions; no other criterion is cited more than once), and only this decision
can retire it.

---

## 2. Method and provenance

Same three tags as doc 60. Nothing is asserted without one.

| Tag | Meaning |
|---|---|
| **FIXED** | Already stated in `58_V026_FUNDS_SAFETY_PROTOCOL.md`. Restated, not decided. |
| **OBSERVED** | Read from source, or produced by executing the live registry this session. |
| **PROPOSED** | New. Owner must accept, amend, or reject. |

Registry facts below were produced by *running*
`src/ranklock/proof_suite_registry.py`, not by reading it. The dry-run
constructed a fully populated profile with dummy digests in a scratchpad to
test whether the decision-1 checklist is sufficient; that object was never
written to the registry or anywhere durable, and a dummy-signed profile must
never be.

---

## 3. What the registry says today

**OBSERVED**, by enumerating `registered_proof_suites()`:

| Suite id | Curve | Status | Attack upper bound | Approved floor |
|---|---|---|---|---|
| `RL25-BN254-SPLIT-N` | BN254 | disqualified | **100** | none |
| `RL26-BLS381-DFB-SPLIT-N` | BLS12-381 | research-candidate | **126** | none |
| `RL26-BLS461-DFB-SPLIT-N` | BLS12-461 | research-candidate | none | none |
| `RL26-BN462-DFB-SPLIT-N` | BN462 | research-candidate | none | none |
| `RL26-BN462-DIRECT-CUSTODY-N` | BN462 | research-candidate | none | none |

Two things in that table drive everything below: BLS12-381's bound is **126**,
and BN462's is **absent**.

---

## 4. Finding 1 — the floor is not a preference, it is an arithmetic gate

`ProofSuiteProfile.__post_init__` rejects any profile whose approved floor
exceeds its known attack upper bound. **OBSERVED** by execution:

```text
BLS12-381, approved_security_floor_bits=128
  -> ProofSuiteQualificationError:
     "approved security floor exceeds the known attack upper bound"

BLS12-381, approved_security_floor_bits=126
  -> ProofSuiteQualificationError:
     "approved security floor requires a 32-byte report digest"
```

Those are **different failures**, and the difference is the decision.

- At 128, BLS12-381 fails on **arithmetic**. 126 < 128. No signed report, no
  auditor, and no amount of engineering can construct that profile. It is
  impossible, not incomplete.
- At 126, it fails on **provenance** — the typed signed report is missing. That
  is ordinary unfinished work.

So ratifying the 128-bit floor is not "choosing BN462 over BLS12-381." It
*removes BLS12-381 from the set of constructible options by invariant.* The
converse is the real fork:

> **Choosing BLS12-381 is not a curve choice. It is an amendment to §1.4's
> 128-bit baseline**, and it must be argued as one, in writing, against
> everything §5.2 says.

**FIXED**, §5.2, on why the alternatives are not symmetric: the CFRG draft
publishes parameters *and pairing test vectors* for BN462 and recommends it at
the 128-bit level; BLS12-381 is *"close to but below the baseline's strict
conservative 128-bit target"*; and the draft's general statement that BLS12
curves need a characteristic of at least 461 bits *"is not enough to qualify an
arbitrary BLS12-461 parameter set or backend."* The registry mirrors that
exactly — BLS12-461 has no recorded upper bound at all.

**PROPOSED:** ratify the 128-bit floor and the BN462 strict target as §1.4 and
§5.2 already state them. The substantive work is not the choice; it is §5 and
§6 below.

---

## 5. Finding 2 — the target curve has no recorded attack bound

**OBSERVED:** `RL26-BN462-DFB-SPLIT-N.attack_security_upper_bound_bits` is
`None`. So is the direct-custody variant's.

BN254 has `100`. BLS12-381 has `126`. The curve the protocol names as its
strict target has nothing. The technical precondition for approving *any* floor
on BN462 is currently unrecorded.

**FIXED**, §5.2, and this is the trap to avoid: *"The registry records known
attack upper bounds separately from an independently approved conservative
suite floor; a curve recommendation or attack upper bound can never satisfy a
minimum-security gate by itself."* Recording the bound is necessary and never
sufficient.

**PROPOSED** procedure, deliberately not a number:

1. Resolve the bound from the primary source — the IRTF CFRG pairing-friendly
   curves draft linked in §17 — together with the exTNFS analysis it cites.
   Record the exact draft revision, not "the CFRG draft."
2. Populate `attack_security_upper_bound_bits` **by a generator run** that cites
   its source, in the same discipline as
   `scripts/generate_v026_threshold_v3_gap_results.py`. Hand-editing the
   registry destroys provenance exactly as hand-editing `results/` would.
3. Only then approve a conservative floor at or below it, via §6.

This document does **not** propose a value for that field. Doing so from
recall is precisely the failure mode §5.2 warns about, and the number is load
bearing.

---

## 6. What ratification concretely means

**OBSERVED:** ratification is machine-checkable. It is **eight** fields moving
from `None` to values that construct without `ProofSuiteQualificationError` —
six `security_floor_*` fields plus the two bit-count fields — after which
`permanent_blockers` shrinks as evidence lands. The provenance fields are
all-or-nothing — the constructor rejects
*"security-floor provenance exists without an approved floor"* — so this is one
atomic act, not a gradual fill.

Two different mechanisms enforce these, and the difference matters to an owner:
a constructor failure is a defect in the ratification itself, while a gate
failure is per-activation and can recur long after signing.

Enforced by `ProofSuiteProfile.__post_init__` — ratification-time:

| Field | Requirement |
|---|---|
| `attack_security_upper_bound_bits` | integer 1..256; see §5 |
| `approved_security_floor_bits` | integer 1..256; **must not exceed** the bound above |
| `security_floor_approval_digest` | exactly 32 bytes |
| `security_floor_report_schema` | exactly `ranklock-security-floor-report-v1` |
| `security_floor_approver_set_digest` | exactly 32 bytes |
| all six provenance fields | all-or-nothing; present only alongside an approved floor |

Enforced by `evaluate_proof_suite` — activation-time. **OBSERVED:** the
constructor receives neither an activation time nor a required lifetime, so it
cannot check coverage; these four are evaluated per activation:

| Field | Requirement |
|---|---|
| `security_floor_approved_at_unix` | activation must not precede approval |
| `security_floor_valid_through_unix` | approval must not have expired at activation, **and** must not expire before `activation + required_lifetime_days` |
| `security_floor_lifetime_days` | must be at least the required deployment lifetime |

Separately, and not a `None`-to-value field:

| `permanent_blockers` | curve/backend entries removed as evidence lands |

**FIXED**, §5.2: *"An untyped 32-byte digest or integer floor is not approval
evidence."* The digest must resolve to a real typed report carrying profile
digest, approver roster, approval time, expiry, and maximum deployment lifetime.

---

## 7. Finding 3 — decision 1 clears 10 of 17 gates, and cannot clear the rest

The total is measured. The attribution is argued, one string at a time, and the
classification below is applied mechanically rather than by hand — every one of
the 17 strings lands in exactly one bucket, with none unclassified.

**OBSERVED:** calling `evaluate_proof_suite` on `RL26-BN462-DFB-SPLIT-N` today
returns `funding_eligible=False` with **17 blocker strings** — five from
`permanent_blockers` and twelve computed from the profile's booleans, with
deliberate overlap in wording between the two lists.

Fully ratifying decision 1 — floor approved, bound recorded, backend built,
encodings canonical, constant-time, both audits delivered — clears the
curve/floor/backend/encoding/constant-time/audit entries. **OBSERVED**, by
classifying all 17 strings:

| Bucket | Strings |
|---|---|
| closed by decision 1 | **10** |
| belongs to §16 decision 2 (release profile) | 6 |
| implementation, no decision can close it | 1 |
| unclassified | 0 |

**These seven survive:**

| Surviving blocker | Whose decision |
|---|---|
| the adaptive DFB/output-mask security argument is not closed | §16.2 (release profile) |
| adaptive DFB security argument is open | §16.2 — the computed near-duplicate of the row above; both strings are emitted, and both are listed here rather than silently merged |
| positive-lock security argument is open | §16.2 |
| one-shot state security argument is open | §16.2 |
| secret-erasure security argument is open | §16.2 |
| secret result transport and conditional-key security argument is open | §16.2 |
| signed security-report and canonical activation-window verifier is not implemented | implementation |

The last one deserves emphasis. `_QUALIFICATION_EVIDENCE_VERIFIER_IMPLEMENTED`
is a module-level `Final = False`, and `evaluate_proof_suite` appends its
blocker unconditionally. **FIXED**, §5.2: the registry *"carries an
unconditional implementation blocker even if every suite fact is otherwise set
to qualified."* So even a perfectly ratified, fully audited BN462 suite is
still not funding-eligible until that verifier exists. No governance act can
short-circuit it.

**Read this correctly:** decision 1 is necessary and is genuinely first, but
ratifying it does not make the suite eligible. It makes the *remaining* work
well-defined.

---

## 8. What decision 1 must not decide

| Value | Belongs to |
|---|---|
| DFB vs direct-scalar custody — i.e. `RL26-BN462-DFB-SPLIT-N` vs `RL26-BN462-DIRECT-CUSTODY-N` | §16 decision 2. Floor, curve and backend apply identically to both; the release mechanism does not follow from the curve. |
| The five release-profile security arguments in §7 | §16 decision 2 |
| BN462 point serialization | §16 decision 4 — see §9 |
| Artifact-size targets | Nothing. **FIXED**, §1.4: the sub-MiB target *"MUST NOT select a weaker curve"*, and §5.2 records a reproduced projection showing a curve swap does not preserve it. |

---

## 9. Cross-dependency with decision 4, in both directions

**FIXED**, §5.2: the CFRG draft *"explicitly does not define a BN462 point
serialization"* — a 58-byte coordinate leaves two spare high bits while the
generic compressed format needs three. `WireProfileV1` must therefore freeze a
RankLock-owned leading-byte encoding, sign convention, identity rule, subgroup
validation, exact lengths, and independently reproduced vectors *before any
suite codec or setup artifact exists.*

That obligation is shared and neither decision can discharge it alone:

- **Decision 1 → decision 4.** Until the curve is ratified, the byte widths in
  doc 60 §4.5 cannot be fixed. Doc 60 already marks them blocked on §16.1 and
  records that today's observed 356-byte proof and 488-byte public values are
  BN254 figures, *not* the target.
- **Decision 4 → decision 1.** Until `WireProfileV1` freezes the serialization,
  `canonical_subgroup_checked_encodings` cannot become `true` for any BN462
  suite — and that boolean is one of decision 1's own gates.

Neither is circular: decision 1 ratifies the curve, decision 4 then freezes its
encoding, and only then does the encoding boolean flip. The ordering must be
stated in whichever document is signed first.

---

## 10. Backend selection — criteria, not candidates

This document deliberately names **no** candidate library.

**FIXED**, §5.2: *"A primitive library, HSM marketing claim, or small unaudited
crate is not a production dependency merely because it claims constant-time or
non-exportable operations."* **OBSERVED:** the repository contains no production
BN462 or BLS12-381 group/pairing backend; existing BLS12-381 material is
field-cost or exponent-space modelling, and one file references BN462 — the
registry itself, which only names the candidate ids.

Proposing a library from recall would be the single most damaging error this
document could contain, so the qualification criteria are given instead. A
candidate must satisfy every one, each mapping to a registry field:

1. **End-to-end**, not primitives — G1, G2, GT, scalar, proof, VK, pairing.
   Partial coverage cannot set `end_to_end_proof_backend`.
2. **Canonical subgroup-checked encodings**, matching the §9 frozen profile,
   with independently reproduced vectors.
3. **Native constant-time and fault-hardened** secret operations.
4. **A real audit history** with published scope and findings. §17 records that
   `zkcrypto/bls12_381`'s own README says it is not audited, and that such an
   audit *"cannot substitute for RankLock's implementation audit"* regardless.
5. **Maintenance and licence** compatible with a pinned build digest, since the
   suite records native implementation and build digests.

**PROPOSED follow-up, explicitly not done here:** a sourced survey of BN462
backends against these five criteria, with citations, produced as a run.
Migration is all-or-nothing — **FIXED**, §5.2: *"Migrating only `PositiveLock`
is invalid,"* since proof, VK, A/B/C elements, projectivizer, scale proof and
pairing certificates share one assumption.

---

## 11. Ratification block — unsigned

Owners per §16: **cryptography + governance**.

| Role | Owner | 128-bit floor | BN462 target | Backend criteria (§10) | Date | Signature |
|---|---|---|---|---|---|---|
| Cryptography | *(unnamed)* | ☐ accept ☐ amend ☐ reject | ☐ accept ☐ amend ☐ reject | ☐ accept ☐ amend ☐ reject | | |
| Governance | *(unnamed)* | ☐ accept ☐ amend ☐ reject | ☐ accept ☐ amend ☐ reject | ☐ accept ☐ amend ☐ reject | | |

Rejecting the 128-bit floor is a legitimate outcome, but it is an amendment to
§1.4 and must carry written justification per §4.

On ratification: the accepted floor moves into a typed
`ranklock-security-floor-report-v1` report, the registry is updated **by a
generator run**, a dated entry is added to `11_DECISION_LOG.md`, and this file
is marked superseded. Doc 58 and the registry are unchanged until then.

---

## 12. What this document does not establish

- It does not make RankLock safe for funds. `safe_for_funds` is `false` and is
  correct at `false`.
- It does not close any blocker. BN462 reports 17 today and will report 17
  after this document is read.
- It does not record BN462's attack-security upper bound, and deliberately
  proposes no value for it.
- It does not name a backend, and a candidate table assembled from memory would
  be worse than none.
- It does not decide the release profile, which is §16.2's, or the encoding,
  which is §16.4's.
- It is not evidence. Nothing here was produced by a qualifying run, and
  nothing here should be cited in `results/` or `09_CLAIMS.md`. The registry
  execution quoted above is reproducible but was performed for analysis, not as
  an evidence artifact.
