# RankLock v0.26 — handoff for an assistant without build access

Date: 2026-08-24. Written for a capable assistant (ChatGPT) that can read and
reason but **cannot compile, run tests, reach a FoundationDB cluster, run the
SP1 toolchain, or regenerate evidence artifacts.**

The point of this document is to hand you the work that does not need any of
that, with enough context that you can do it correctly and enough boundary that
you cannot do damage.

---

## 0. The single most important rule

**Do not claim RankLock is safe for funds, and do not produce text that could be
pasted somewhere and read as such.**

`safe_for_funds` is `false` in `STATUS.json`. Every capability reports
`funding_eligible = false`. That is the correct value, not an oversight. It
stays false until 28 distinct obligations close, of which 24 are not code. If
any output of yours would move that flag or imply it should move, you have gone
wrong.

Two related rules:

- **Never hand-edit anything under `results/` or `STATUS.json`.** Those are
  run-generated evidence. Hand-editing destroys provenance, which is the whole
  basis of the project's claims. If a number in them looks wrong, say so and
  name the generator that would fix it.
- **Never edit `docs/58_V026_FUNDS_SAFETY_PROTOCOL.md`.** That is the
  authoritative protocol. Editing it *is* the act of ratifying an open
  decision, and you are not an owner. Propose in a new document instead.

---

## 1. What RankLock is, in one paragraph

RankLock v0.26 is a Bitcoin bridge safety protocol built on top of Alpen Labs'
Strata bridge. Depositors' funds are protected by a transaction graph in which
an invalid claim can be counterproved and slashed. v0.26 exists because the
deployed v0.25 graph is provably unsafe under a single shared N-of-N release
withholder. The v0.26 redesign uses split-scalar custody — each setup
participant independently owns one scalar and one ACK preimage, and the Bitcoin
ACK requires the ordered preimage vector, so no coordinator ever learns an
aggregate secret.

None of it is funded, deployed, or eligible. It is a research protocol with a
detailed and deliberately hostile self-assessment.

---

## 2. Read these, in this order

All paths are relative to the repository root (`worktree-v0.25.2/`).

| # | File | Why |
|---|---|---|
| 1 | `docs/09_CLAIMS.md` — the v0.26 section only | The claim boundary. What may and may not be said. Read this before writing a single sentence. |
| 2 | `docs/59_V026_CRITICAL_PATH_GAP_MAP.md` | The map of all 28 obligations, classified, with owners and ordering. Your index. |
| 3 | `docs/58_V026_FUNDS_SAFETY_PROTOCOL.md` | The authoritative protocol, ~161 KB. Read §1 (executive decision), §4 (objects, encoding, signatures), §5 (cryptographic profile), §14 (56 kill criteria), §15 (work programme), §16 (open decisions). |
| 4 | `docs/60_V026_DECISION4_WIRE_SIGNATURE_PROFILE_PROPOSAL.md` | A worked example of the deliverable shape you should produce. |
| 5 | `docs/62_V026_DECISION1_SECURITY_FLOOR_PROPOSAL.md` | The second worked example, and the one with the sharpest finding. |

If you read only two, read §16 of the protocol and doc 60.

---

## 3. Where the work stands

§15 defines a ten-step work programme. **Step 1 is three kill decisions**, and
the protocol is explicit that implementing before they are settled "would
automate an ambiguous protocol."

| §16 decision | Owner | Status |
|---|---|---|
| 1 — security floor, BN462 target, native backend | cryptography + governance | **drafted** (doc 62), unratified |
| 2 — S-DFB vs C-DIRECT release profile | crypto + protocol + governance + operations | **not drafted** |
| 3 — timeout/NACK economics; N-of-N vs threshold | protocol + Bitcoin economics | **not drafted** |
| 4 — wire maxima/widths and signature profile | protocol + implementation + crypto | **drafted** (doc 60), unratified |
| 5 — participant and graph-signer counts | governance + operations | not drafted |
| 6 — parent-release and ACK/NACK finality depths | Bitcoin economics + operations | not drafted |
| 7 — CSV delay, fee reserve, CPFP, halt threshold | Bitcoin economics | not drafted |
| 8 — registry `f`, BFT engine, replica roster | operations + security | not drafted |
| 9 — per-deposit, aggregate, active-count caps | governance | not drafted |
| 10 — admission expiry, revocation, cooldown | governance + operations | not drafted |
| 11 — evidence schemas and external signer rosters | auditors + governance | not drafted |

Recently completed engineering, for context only — none of it moved a funding
obligation:

- A fulfilled Succinct network Groth16 receipt was recovered and verified
  offline. It closes the deterministic final Groth16 evidence gate **and
  nothing else**; the suite is BN254, which kill criterion 8 disqualifies from
  the funding path regardless.
- The threshold-v3 observation got a FoundationDB persistence envelope
  (`v026_admissions_v3`). Persistence is not adoption; the blocker count stayed
  at 17.
- The `strata-bridge-db` test suite now runs against a live cluster and in
  parallel, after fixing a test-isolation defect.

---

## 4. What you can do well — ranked

These need reading and reasoning, not a compiler.

### 4.1 Draft §16 decision 3 — timeout/NACK economics — **highest value**

This is the one with a *demonstrated hole*, not merely missing evidence.

The problem, from the gap map's obligation 4: a world where the claim is
**valid but a participant withholds the ACK**, and a world where the claim is
**invalid and no counterproof appears**, are economically indistinguishable on
chain. Both end in the same timeout trace. §1.4 item 7 states the requirement
plainly: N-of-N prevents an invalid ACK when one participant is honest, but one
participant can block a *valid* ACK, so "the timeout outcome MUST be
economically fund-preserving under that failure, or the protocol must
explicitly adopt a weaker `t-of-n` corruption model."

That is a genuine fork and nobody has taken it. Your job is to lay it out:
what each branch costs, what it changes in the security theorem and the loss
bound, and what evidence would settle it. Read §12 (economics gates) and the
`timeout_economics` sections before writing.

Supporting material you can read without running anything:
`src/ranklock/v026/timeout_economics.py`,
`src/ranklock/v026/timeout_economics_reference.py`, and
`results/v026_timeout_economics.json` (read only — never edit).

### 4.2 Draft §16 decision 2 — S-DFB vs C-DIRECT

Also a step-1 kill decision. §1.4 item 10: "Profile S-DFB removes the raw
scalar but still lacks its adaptive/output-mask theorem. Profile C-DIRECT
removes DFB but retains the scalar in an online conditional-release custodian."
Neither is fundable. C-DIRECT drags in hardware custody, attestation, clone
inventory, and one-shot state — see kill criteria 52–55, which are unusually
specific and are your checklist.

Note the coupling doc 62 §7 measured: **6 of the 7 blockers that survive
decision 1 belong to decision 2.** These two decisions together account for
almost the whole cryptographic gate.

### 4.3 Design the `ranklock-security-floor-report-v1` schema

Doc 62 §6 establishes that ratifying decision 1 means populating eight registry
fields, one of which is a 32-byte digest of a typed signed report. **The report
schema itself does not exist.** §5.2 requires it to carry an exact profile
digest, approver roster, approval time, expiry time, and maximum deployment
lifetime, and states that "an untyped 32-byte digest or integer floor is not
approval evidence."

Designing that schema is pure specification work. It needs no compiler and it
unblocks a concrete field.

### 4.4 Specify the BN462 point serialization

§5.2 records that the CFRG draft **explicitly does not define one**: a 58-byte
field coordinate leaves two spare high bits, while the generic compressed
format needs three metadata bits. `WireProfileV1` must therefore freeze a
RankLock-owned leading-byte encoding, sign convention, identity rule, subgroup
validation, exact lengths, and independently reproduced vectors.

This is a shared obligation between decisions 1 and 4 — doc 62 §9 explains the
dependency in both directions. It is well-posed, self-contained, and you can do
it properly on paper.

### 4.5 Survey BN462 backends against fixed criteria

Doc 62 §10 deliberately names no candidate library, because the repository has
none and proposing one from recall is the way that document could be most
damagingly wrong. It gives five qualification criteria instead. **If you have
web access, doing this survey with real citations is genuinely useful.**

Hard requirement: cite every claim. "I recall library X is constant-time" is
worse than no answer. §5.2 pre-empts exactly this: "A primitive library, HSM
marketing claim, or small unaudited crate is not a production dependency merely
because it claims constant-time or non-exportable operations."

### 4.6 Adversarially review docs 60 and 62

Both are unratified proposals written by one assistant. Both would benefit from
a hostile read. Specific things worth attacking:

- Doc 60 §6 proposes splitting decision 4 into a structural Layer A (signable
  now) and a numeric Layer B (blocked). Is that split sound, or does a partial
  freeze create false settledness given that "changing the wire profile creates
  a new subject"?
- Doc 60 §4.1 proposes fifteen 8-byte magics and §4.7 ten domain tags. Check
  for collisions and for anything that silently answers a decision it should
  not.
- Doc 62 §4 claims ratifying 128 bits excludes BLS12-381 *by arithmetic*. Verify
  the reasoning against `src/ranklock/proof_suite_registry.py`.
- Both documents tag every claim FIXED / OBSERVED / PROPOSED. Find untagged
  assertions, and find any tagged OBSERVED that is really PROPOSED.

### 4.7 Draft the cheaper governance decisions

Decisions 5, 6, 7, 9, 10 are mostly parameter selection with stated
consequences. Lower value than the above, but each is self-contained and each
unblocks numeric fields that doc 60 currently marks as blocked.

---

## 5. What you must not attempt

| Task | Why not |
|---|---|
| Anything requiring `cargo build/test/clippy` | You cannot run it, and a plausible-looking Rust patch that does not compile costs more to review than it saves. |
| Regenerating anything in `results/` | Requires runs. Hand-written JSON there is provenance destruction. |
| Editing `STATUS.json` or any `funding_eligible` / `safe_for_funds` flag | See §0. |
| Editing `docs/58_...PROTOCOL.md` | Editing it is ratification. Propose in a new numbered doc. |
| Ratifying any §16 decision | You are not an owner. Produce proposals with unsigned ratification blocks. |
| Anything touching the SP1 network key | It lives only in the macOS Keychain, it is pending rotation because its value reached a chat log, and no current work needs it. |
| Submitting proof requests | One reserved request was fulfilled and recovered. Do not submit another. |
| Naming a cryptographic backend from memory | See §4.5. |

---

## 6. House style, which is not optional here

This project's entire value is that its claims are checkable. Match it.

1. **Tag every claim.** FIXED (already in the protocol, restated), OBSERVED
   (read from a cited `file:line`, or produced by a run), PROPOSED (new, needs
   an owner). An untagged assertion is a defect.
2. **Cite `file:line`.** Not "the registry says" — `proof_suite_registry.py:18`.
3. **Count, don't estimate.** If you write "most" or "all" or a number, it
   should be countable from something you cite. A superlative you did not
   measure is a bug; this exact error was caught and corrected in doc 62 §1.
4. **State what your document does *not* establish.** Every proposal doc ends
   with that section. It is the most important one.
5. **Distinguish "impossible" from "not yet done."** Doc 62 §4 turns on exactly
   this and it is the model to follow.
6. **Separate what a decision decides from what it must not decide.** Doc 60 §5
   and doc 62 §8 both have this section. Silently answering an upstream
   decision is the most common failure mode.
7. **Do not be reassuring.** Every optimistic-sounding sentence in this project
   has been wrong. If the honest answer is "this cannot be established," write
   that.

Deliverable shape: a new file `docs/6N_V026_DECISION<k>_<TOPIC>_PROPOSAL.md`
with a **PROPOSED / NOT RATIFIED / NOT AUTHORITATIVE** banner, a
method-and-provenance section, the substance, a "what this must not decide"
section, an unsigned ratification block naming §16's owner roles, and a "what
this does not establish" section.

---

## 7. Facts you will want, so you do not have to hunt

- Security floor: **128 bits**. Strict curve target: **BN462**.
- BN254 attack upper bound: **100 bits** — disqualified.
- BLS12-381 attack upper bound: **126 bits** — below the floor, so excluded by
  arithmetic, not by preference.
- BN462 attack upper bound: **unrecorded** (`None` in the registry). Nobody has
  written it down. Do not invent it.
- `evaluate_proof_suite` returns **17 blocker strings** for BN462 today.
  Decision 1 clears 10; 6 belong to decision 2; 1 is implementation.
- `_QUALIFICATION_EVIDENCE_VERIFIER_IMPLEMENTED = False` is a module-level
  constant that appends an unconditional blocker. Even a perfect suite is
  ineligible until that verifier exists.
- The threshold-v3 graph and live admission path carry **17** activation
  blockers; the v2 graph carries 16; the frozen V1 persistence envelope 15.
- Split-scalar does **not** multiply security. Breaking one honest target costs
  about one BN254 attack.
- Kill criteria live in §14. There are **56**. Criterion 8 (BN254 in the trust
  path) and criterion 9 (a new lock wrapping a weaker suite) are the two that
  most often decide an argument.
- Suite ids: `RL26-BN462-DFB-SPLIT-N`, `RL26-BN462-DIRECT-CUSTODY-N`,
  `RL26-BLS381-DFB-SPLIT-N`, `RL26-BLS461-DFB-SPLIT-N`, `RL25-BN254-SPLIT-N`.

---

## 8. Two known open defects, if you want something concrete

- **D-1, in doc 60 §7.** The persisted admission envelope magic is `RL26ADM`,
  seven bytes, while §4.2 mandates eight. The whole `RL26ADM` family (V1, V2,
  V3) is nonconformant. Frozen bytes cannot change, so migrating the family is
  a V4 envelope and a new subject. This needs an owner ruling and the argument
  can be written without a compiler.
- **Test isolation, fixed but instructive.** `strata-bridge-db` tests shared one
  FoundationDB keyspace; proptest's per-test deterministic seeds made different
  tests generate identical keys and overwrite each other. The first diagnosis
  (an API-version limit) was wrong and was corrected in
  `docs/61_LOCAL_FOUNDATIONDB_FOR_V026_ROW_TESTS.md`. Worth reading as a
  cautionary example of a plausible wrong cause surviving until it was tested.

---

## 9. How to hand work back

Produce complete markdown files, not fragments. State plainly at the top of
your response which files you created, what each claims, and — specifically —
**anything you could not verify because you could not run code.** That last
part matters more than the rest: a clearly-flagged gap is useful, and an
unflagged guess presented with the same confidence as a checked fact is the one
outcome this project cannot absorb.
