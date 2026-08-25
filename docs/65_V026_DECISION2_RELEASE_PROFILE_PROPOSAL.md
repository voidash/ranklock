# v0.26 §16 decision 2 — S-DFB versus C-DIRECT release profile

**Status: PROPOSED. NOT RATIFIED. NOT AUTHORITATIVE.**

Decision input for the second open decision in
`58_V026_FUNDS_SAFETY_PROTOCOL.md` §16:

| Decision | Owner | Must be fixed before |
|---|---|---|
| Select S-DFB or the separately versioned C-DIRECT custody model; for C-DIRECT pin the exact device/firmware/attestation/clone/backup and conditional-result-key service policy | cryptography + protocol + governance + operations | contribution schema or participant implementation |

This document makes no decision. It moves no blocker. `safe_for_funds` remains
`false`, every `funding_eligible` remains `false`, no `results/` artifact was
written, and neither the protocol nor the registry was modified.

**Why now.** §15 makes this a step-1 kill decision. Doc 62 §7 measured that of
the seven blockers surviving full ratification of decision 1, **six belong to
this decision**. It is the largest remaining cryptographic gate.

---

## 1. Method

Tags as in docs 60, 62 and 64: **FIXED** (already in the protocol; restated,
not decided), **OBSERVED** (read from cited source or produced by executing the
registry), **PROPOSED** (new; owners must accept, amend, or reject).

**OBSERVED.** Registry facts were produced by running
`src/ranklock/proof_suite_registry.py`, not by reading it. No Rust build, Core
test, FoundationDB test, or SP1 command was run.

---

## 2. The two profiles, as fixed

**FIXED** (`58:503-508`). The profiles "produce the same public algebraic object
but have different retained secrets, failure modes, and security theorems.
Their suite ids, contribution schemas, ceremonies, state machines, and audit
evidence MUST remain distinct."

**FIXED** (§1.4 item 10). "`Profile S-DFB` removes the raw scalar but still
lacks its adaptive/output-mask theorem. `Profile C-DIRECT` removes DFB but
retains the scalar in an online conditional-release custodian. Governance must
ratify one exact trust model and new suite id; neither is fundable today."

**FIXED** (§5.3.1). Under S-DFB each participant samples `r_j` and `k_j`,
publishes `R_j = [r_j]delta` with a proof of knowledge and `h_j = SHA256(k_j)`,
and **before funding erases** `r_j`, `k_j`, free-XOR deltas, generator random
tapes, graph-building intermediates, and every seed not required by the
one-shot evaluator. What survives is two compartmentalized slot states with
separate label trees, opening seeds, recovery material and envelope keys.

**FIXED** (§5.3.2). C-DIRECT "is a new incompatible candidate, not an
optimization flag on S-DFB. It removes the garbled projectivizer by retaining
`r_j` inside a subject-unique, non-exportable, rollback-resistant custody
module." And, decisively:

> That trade is explicit: while `r_j` survives, the module can compute the
> positive-lock session `Y^r_j` and recover `k_j` without a proof. Erasing
> plaintext `k_j` is duplicate-secret hygiene; it does not remove the ACK
> capability. A software-owned ciphertext, ordinary sealed file, or restorable
> backup does not qualify this profile.

---

## 3. Finding 1 — the residual work is not the same *kind* of work

**OBSERVED.** Both BN462 suites carry six or five blockers, four of which are
identical and belong to decision 1 (backend, canonical encodings, constant-time
implementation, audits). The profile-specific remainder is:

| Suite | Profile-specific blockers |
|---|---|
| `RL26-BN462-DFB-SPLIT-N` | **1** — "the adaptive DFB/output-mask security argument is not closed" |
| `RL26-BN462-DIRECT-CUSTODY-N` | **2** — "the direct-scalar custody module and one-shot theorem are absent"; "positive-lock hiding with public leakage and guarded one-shot scalar-service access is not independently reviewed" |

**OBSERVED.** Dedicated kill criteria, counted across all 56:

| Profile | Dedicated criteria | Which |
|---|---|---|
| S-DFB | **1** | 44 — slot-state separation, certified losing-slot erasure, honest-boundary duration |
| C-DIRECT | **4** | 52 — `r_j` non-exportability and clone/backup containment; 53 — no caller-supplied `A`, no pre-reservation output, exactly one bound input; 54 — constant-time and fault hardening, result-plaintext confinement, envelope quorum readback, device tombstone recovery, no-result teardown, activation-race prevention; 55 — positive-lock hiding under the exact CRS/VK, leakage and toxic-waste model |

**PROPOSED.** The counts understate the difference, because the two remainders
are not interchangeable in nature:

- **S-DFB's remainder is one open proof.** The adaptive/output-mask argument is
  a cryptography problem. It is closed by analysis and review. It needs no
  procurement, no vendor, and no physical device.
- **C-DIRECT's remainder is one open proof *plus* a hardware qualification
  stack.** Criterion 55 is analysis, like S-DFB's. Criteria 52–54 are not:
  §5.3.2 imposes seven numbered device requirements including internal key
  generation with no export, a single subject-level handle shared across retry
  slots, internal validation and extraction of `A` from the proof bytes, an
  irreversibly bound monotonic handle, a durable one-shot `OUTPUT_INTENT` before
  entering scalar code, a sealed result key created before scalar erasure, and a
  `ConditionalResultKeyEnvelopeV1` under a pinned threshold recovery service
  with forward-secure child shares. No amount of analysis discharges those. They
  require selecting, procuring, and qualifying physical devices with pinned
  firmware and attestation, plus operating a separate threshold key service.

**PROPOSED.** So the decision is not "which profile has fewer blockers." It is:
**do we accept an open cryptographic theorem, or a hardware supply chain and a
new online service?**

---

## 4. Finding 2 — the profiles differ on whether the secret still exists

**PROPOSED, and this is the load-bearing distinction.**

Under S-DFB, `r_j` and `k_j` are erased before funding (§5.3.1 step 7). After
that point no party — honest, compromised, or coerced — holds the scalar,
because it no longer exists. Safety rests on erasure having happened.

Under C-DIRECT, `r_j` survives for the whole subject lifetime inside the custody
module, and §5.3.2 states in terms that the module can therefore recover `k_j`
without a proof. Safety rests on the device continuing to behave correctly, for
the entire graph lifetime, against an adversary who may eventually possess it
physically.

**PROPOSED consequence.** These are different security postures, not different
implementations of one posture:

| | S-DFB | C-DIRECT |
|---|---|---|
| ACK capability after setup | Does not exist | Exists, confined to hardware |
| Compromise of the retained boundary yields | Slot states — an evaluator input, not the scalar | The scalar, hence `k_j`, hence ACK |
| Safety depends on | An erasure that already happened | A device that keeps behaving |
| Adversary needs | To have won before erasure | To win at any time before subject expiry |
| Failure is bounded by | A past event | A future duration |

**PROPOSED.** A property secured by a completed erasure is strictly easier to
audit than one secured by an ongoing device guarantee, because the first has a
finite evidence window and the second must hold under every future firmware
version, physical attack, and supply-chain event within the subject lifetime.
Kill criterion 52's insistence that no "clone/backup can escape the same
consumed monotonic state" is exactly the difficulty of proving a negative about
the future.

---

## 5. Finding 3 — C-DIRECT imports a second trust domain

**FIXED** (§5.3.2 item 7). The conditional result key must be created under "the
pinned threshold recovery service using subject-specific forward-secure
child-key shares," and before activating any child share the service must
validate a durable signed `RESULT_KEY_SEALED` receipt plus the exact proposed
envelope/activation-attempt digest.

**PROPOSED.** That is a second online, quorum-operated service with its own
availability, corruption, and lifecycle assumptions — beyond the safety
registry, and beyond the custody devices themselves. Selecting C-DIRECT
therefore expands the trusted computing base by:

1. the custody device and its firmware,
2. the attestation root that vouches for it,
3. the anti-clone/monotonic-state mechanism,
4. the threshold conditional-result-key service and its roster.

**PROPOSED.** Each is a separate operational decision the §16 owner list already
anticipates ("pin the exact device/firmware/attestation/clone/backup and
conditional-result-key service policy"), and each must be settled *before* the
contribution schema — meaning C-DIRECT cannot be selected in principle and
detailed later.

---

## 6. Finding 4 — the ecosystem is already asymmetric

**OBSERVED.** Of the five registered suites, four declare
`release_mechanism = "dfb-projectivizer"` and one declares
`"direct-scalar-custody"`. The DFB lineage includes the disqualified BN254
suite, so the modelling, tooling and existing analysis are concentrated on the
S-DFB path.

**PROPOSED.** This is not a security argument and must not be used as one. It is
a cost observation: selecting C-DIRECT abandons more existing modelling than
selecting S-DFB, and the protocol is explicit (§5.3) that the two cannot share
suite ids, contribution schemas, ceremonies, state machines, or audit evidence.

---

## 7. Recommendation

**PROPOSED: select `Profile S-DFB`, conditionally.**

Rationale, in order of weight:

1. **It removes the secret rather than relocating it** (§4). After erasure the
   ACK capability does not exist. C-DIRECT's survives in hardware for the
   subject lifetime, and its safety must hold against future physical access.
2. **Its residual work is one proof, not a supply chain** (§3). The
   adaptive/output-mask argument can be closed by analysis and review; criteria
   52–54 cannot.
3. **It does not expand the trusted computing base** (§5). C-DIRECT adds four
   trust domains, including a second online quorum service.
4. **It keeps the existing modelling relevant** (§6) — a cost point, not a
   security one.

**The condition, and it is a real one.** S-DFB is recommended **only if the
adaptive/output-mask security argument can be closed.** If it cannot, S-DFB is
not merely blocked — it is refuted, and that is a kill signal. §15 places this
in step 1 precisely so such a signal arrives before implementation, not after.

**PROPOSED sequencing.** Attempt the adaptive/output-mask argument *first*, on a
fixed time budget, before ratifying either profile. The outcome is decisive
either way:

- argument closes → ratify S-DFB and proceed to the contribution schema;
- argument refuted → C-DIRECT becomes the only candidate, and its hardware
  qualification begins with the knowledge that it is not optional;
- argument neither closes nor refutes within budget → that is itself the
  finding, and owners choose between an unproved theorem and a hardware TCB with
  eyes open.

**PROPOSED.** Do not ratify C-DIRECT as a hedge. §5.3 forbids sharing schemas,
ceremonies and state machines, so "start both" means building two protocols.

---

## 8. What decision 2 must not decide

| Value | Belongs to |
|---|---|
| Curve, floor, backend | §16 decision 1 (doc 62). Both profiles share those four blockers identically. |
| Release quorum and timeout liability | §16 decision 3 (doc 64). A profile choice does not answer N-of-N vs `t-of-n`, and doc 64 §12 records the reverse dependency. |
| Wire encodings for whichever profile is selected | §16 decision 4 (doc 60). Tagged-union arms differ per profile; doc 60 §4.4 already marks the C-DIRECT clone-inventory vector as absent under S-DFB. |
| Exact device, firmware, attestation root, threshold service roster | §16 decision 2's own follow-on, but only if C-DIRECT is selected. Do not pin a vendor here. |
| Participant counts and control domains | §16 decision 5. |

**PROPOSED.** In particular this decision must not be recorded as "S-DFB, and we
will pick devices later." Selecting S-DFB means there are no devices.

---

## 9. Ratification block — unsigned

Owners per §16: **cryptography + protocol + governance + operations**. Four
roles — the largest owner set of any §16 decision, which is itself a signal
about the weight of the choice.

| Role | Owner | S-DFB | C-DIRECT | Defer pending the adaptive/output-mask attempt | Date | Signature |
|---|---|---|---|---|---|---|
| Cryptography | *(unnamed)* | ☐ | ☐ | ☐ | | |
| Protocol | *(unnamed)* | ☐ | ☐ | ☐ | | |
| Governance | *(unnamed)* | ☐ | ☐ | ☐ | | |
| Operations | *(unnamed)* | ☐ | ☐ | ☐ | | |

**Required acknowledgements** (all four roles):

| Acknowledgement | ☐ |
|---|---|
| The two profiles have different security theorems and cannot share suite id, contribution schema, ceremony, state machine, or audit evidence | ☐ |
| Under S-DFB the ACK capability ceases to exist at erasure; under C-DIRECT it persists in hardware for the subject lifetime | ☐ |
| If C-DIRECT: the device, firmware, attestation root, anti-clone mechanism, and conditional-result-key service enter the trusted computing base and must be pinned before the contribution schema | ☐ |
| If S-DFB: selection is conditional on closing the adaptive/output-mask argument, and failure to close it is a kill signal, not a delay | ☐ |
| Neither profile is fundable today, and this ratification closes no blocker | ☐ |
| `safe_for_funds` and every `funding_eligible` remain false | ☐ |

**OBSERVED.** Owner fields are blank because §16 names roles, not people.

---

## 10. What this document does not establish

- **FIXED:** it does not make RankLock safe for funds. `safe_for_funds` remains
  correctly `false`.
- **OBSERVED:** it closes no blocker. Both BN462 suites report the same status
  after this document as before it.
- **PROPOSED, not proved:** that the adaptive/output-mask argument *can* be
  closed. §7's recommendation is explicitly conditional on an attempt that has
  not been made.
- **OBSERVED:** it does not prove any custody module exists, is qualifiable, or
  can satisfy criteria 52–55; nor that positive-lock hiding holds under either
  profile.
- **OBSERVED:** it names no vendor, device, firmware, attestation root, or
  threshold service, and a candidate proposed from recall would be worse than
  none — the same rule doc 62 §10 applies to backends.
- **OBSERVED:** it ran no Rust build, Core test, FoundationDB test, or SP1
  command. The registry was executed for counts only.
- **OBSERVED:** it is not evidence and must not be cited from `results/` as
  though an owner decision had occurred.
