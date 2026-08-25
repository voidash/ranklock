# RankLock v0.26 critical-path gap map

Date: 2026-08-22 (Asia/Kathmandu)
Status: **non-authorizing decision input.** This document changes no flag, no
claim, and no evidence artifact. `safe_for_funds` and every `funding_eligible`
remain false. Nothing here is a promotion argument.

---

## 1. Purpose and non-goals

The question this answers is not "is RankLock safe for funds" — it is not, and
no document makes it so. The question is: **of everything that must be true
before funds, what kind of work is each item, who can do it, and in what order
does it have to happen.**

Non-goals, explicitly:

- This is not an audit of the 56 hard kill criteria in
  `docs/58_V026_FUNDS_SAFETY_PROTOCOL.md` §14. Kill criteria are cross-
  referenced only where the link to a blocker is direct.
- This does not edit `STATUS.json` or any `results/*.json`. Those are run-
  generated evidence; hand-editing them destroys provenance. Where this
  document finds a discrepancy, it reports it and names the regeneration that
  would fix it.
- This does not restate the claim boundary. `docs/09_CLAIMS.md` §"v0.26
  funds-safety research claim boundary" remains authoritative, and nothing
  below contradicts it.

---

## 2. Method and provenance

Every blocker below was read out of a committed artifact or live source, not
recalled. Enumeration was mechanical: a walk over every `results/**/*.json` plus
`STATUS.json` for any key matching `blocker`, then a source lookup for each
resulting slug.

Primary blocker sets (the three named in the task):

| Set | Count | Exact source path |
|---|---|---|
| Activation | 16 | `results/v026_rust_graph_core.json` → `/activation_blockers` |
| Funding | 13 | `results/v026_timeout_economics.json` → `/assessment/funding_blockers` |
| Terminal policy | 4 | `results/v026_timeout_economics.json` → `/claim_boundary/terminal_policy_qualification_blockers` |

Sets found during enumeration, **beyond the original three** — real, and
included as supporting evidence under their parent obligations:

| Set | Count | Exact source path |
|---|---|---|
| Threshold-release unverified | 16 | `results/v026_threshold_signature_release.json` → `/assessment/unverified_blockers` |
| Deterministic wrapper gate | 9 | `results/v026_threshold_signature_release.json` → `/deterministic_wrapper_gate/blockers` |
| Subject-bound counterproof gate | 7 | `results/v026_threshold_signature_release.json` → `/subject_bound_counterproof_gate/blockers` |
| v0.25.2 release gate (historical) | 7 | `results/v0252_release_gate.json` → `/funds_blockers` |

Slug definitions were read from the enums that emit them:

- `crates/tx-graph/src/v026_graph.rs:221-273` (`V026ActivationBlocker`, 16)
- `crates/tx-graph/src/v026_threshold_graph_v3.rs:246-301` (`V026ThresholdActivationBlockerV3`, 17)
- `src/ranklock/v026/timeout_economics.py:167-224` (`TimeoutSafetyBlockerV1`)
- `src/ranklock/v026/timeout_economics.py:144-164` (`TerminalQualificationBlockerV1`)

Rust paths are relative to the active checkout
`/Users/cdjk/github/llm/ranklock/tmp/strata-v026-f94c`, base commit
`f94c06d08ff29eee746f3e20bd63078d2949b304`. Python and evidence paths are
relative to `worktree-v0.25.2`.

Raw totals: 72 blocker entries across 7 sets, 71 unique strings (one exact
duplicate). See §9 for the conservation reconciliation.

---

## 3. Headline findings

**F1 — This is not a coding problem.** Of the 28 distinct obligations in the
primary map, **4 are implementation work in this repo.** The other 24 are
governance ratifications, control/custody attestations, external execution
evidence, or cryptography that does not exist yet. Corroborating this from the
evidence side: `results/v026_timeout_economics.json` reports
`/assessment/structural_blockers: 0` — every structural property the model can
check already passes. What is missing is external authority, not logic.

| Class | Count | What it means |
|---|---|---|
| GOV — governance/economics ratification | 10 | A decision with a named owner. No code closes it. |
| CTRL — control, possession, custody attestation | 8 | Operations must prove who controls what, and prove erasure. |
| EXEC — external execution evidence | 5 | Bitcoin Core matrix, live FoundationDB, ASM activation, signet. |
| CODE — implementation in this repo | 4 | Actual Rust/Python work. |
| CRYPTO — construction that does not exist | 1 | The proof suite. Blocks a large downstream set. |

**F2 — The SP1/BN254 receipt track is not on the funding path, and cannot be.**
`docs/58_V026_FUNDS_SAFETY_PROTOCOL.md` §14 kill criterion 8: "BN254 remains in
the proof or conditional-lock trust path" keeps `safe_for_funds` false.
Criterion 9 closes the obvious escape: "a new lock wraps a still-authoritative
weaker proof suite." §1.4 states the floor is 128 bits with a BN462 target and
that "Neither suite is implemented or qualified today"; §2 places the current
BN254 `PositiveLock` near 100-bit security with variable-time Python
operations. The subject-bound SP1 Groth16 work is **BN254 Groth16**. That
receipt was recovered and verified on 2026-08-23 (§8, D1). Doing so closed the
deterministic final Groth16 execution/verification evidence gate and nothing
else. It is legitimate research evidence. It is not progress toward
funds-safety, and it must not be reported as such — kill criterion 8 disqualifies
BN254 from the funding path regardless of how well the receipt verifies.

**F3 — Four decisions gate almost everything.** §16 open decisions 1, 2, 3, and
4 (proof suite floor, release profile S-DFB vs C-DIRECT, timeout/NACK
economics, wire profile) sit upstream of the CRYPTO obligation, both CODE
obligations in the identity/codec layer, and the entire GOV cluster. The doc
states outright: "Open decisions are not permission to use defaults. Each one
changes the security theorem or economic loss bound." Until these four are
ratified, downstream implementation automates an ambiguous protocol — which is
exactly what §15 warns against.

**F4 — Published evidence tracks the older graph; the live admission path is
one generation ahead and unpersisted.** Verified in source, not inferred:

- `V026ActivationBlocker` (`v026_graph.rs:256`) — **16** blockers. This is what
  `results/v026_rust_graph_core.json` reports; its `commands` run
  `v026_graph::tests`. The artifact is correctly scoped, not wrong.
- `V026ThresholdActivationBlockerV3` (`v026_threshold_graph_v3.rs:283`) — **17**
  blockers, adding `ThresholdAckWitnessAdoptionUnimplemented` ("Exact ACK
  witness selection lacks complete durable runtime adoption/publication").
- `crates/bridge-sm/src/v026_admission_v3.rs:36` — `V026_BLOCKER_COUNT_V3 = 17`,
  validated by `validate_live_blockers` at line 953. This is the live path.
- FoundationDB row specs when this map was first written: `v026_admissions.rs`
  (v1 envelope, 15 blockers), `v026_admissions_v2.rs` (v2 envelope, 16
  blockers), `v026_ack_witnesses_v3.rs`. **There was no
  `v026_admissions_v3.rs`**, so the v3 threshold observation carrying 17
  blockers had no persistence envelope at all — the same class of gap
  `results/v026_runtime_observation.json` already records for v1
  (`/persistence/v1/current_16_blocker_graph_encodable: false`), one generation
  later, and unlike the v1 case no evidence file named it.

**Closed 2026-08-23.** `v026_admissions_v3.rs` now exists: its own subspace,
envelope version 3, keyed by the content-derived funded-setup digest, with the
frozen V1/V2 bytes untouched and every other envelope version refused by the V3
decoder. Machine-parsed evidence is
`results/v026_threshold_graph_v3_admission_gap.json`; the claim boundary and
`11_DECISION_LOG.md` were extended in the same change.

**This closed persistence, not adoption.** The blocker count is still 17.
`runtime-admission-unimplemented` and `threshold-ack-witness-adoption-
unimplemented` are both unchanged, the stored row is an inert value with no
transition to funding, signing, duties, P2P, or broadcast.

Live FoundationDB execution was then established on 2026-08-24: a throwaway
single-process cluster was stood up in a scratch directory and the complete
`strata-bridge-db` suite passed at 69 tests, up from 35 passed / 33 failed. The
V3 read path executes live. No v0.26 observation of any version has been
durably written and read back, because no test constructs a
`StructurallyVerifiedFundingBlocked*` — write-path coverage is still absent for
all three versions. Procedure and limits in
`61_LOCAL_FOUNDATIONDB_FOR_V026_ROW_TESTS.md`.

**F5 — The v0.25.2 funds blockers are superseded by redesign, not inherited.**
`docs/58_V026_FUNDS_SAFETY_PROTOCOL.md` §2 establishes as implementation fact
that v0.25.2 cannot be promoted in place — the connector accepts one `[u8; 32]`
where the selected safety mode needs 2..64 ordered preimages, and §1.8 forbids
in-place migration entirely. The seven `results/v0252_release_gate.json` funds
blockers are therefore **historical context**, not v0.26 line items. Three of
them (native constant-time implementation, independent cryptography audit,
independent implementation audit) nevertheless recur as v0.26 acceptance gates
in §12 — they were never closed, and they return under new scope.

---

## 4. Primary map — 33 blocker entries, 28 distinct obligations

Class key: **GOV** governance/economics ratification · **CTRL** control/custody
attestation · **EXEC** external execution evidence · **CODE** implementation ·
**CRYPTO** absent construction.

Owner column is taken from §16 where a decision maps directly; otherwise it
names the function §12 assigns the evidence to.

**On external audit.** There is deliberately no AUDIT class, because no
obligation in the primary map is *solely* an audit item — audit is an
attachment, not a category. Independent external review attaches to three
obligations through the §12 gates: obligation 4 (validity-withholding
economics) via *Liveness/economics*, "CSV and contested-payout semantics
independently audited"; obligation 14 (presign erasure) via *Graph signing*,
"at least one honest-share erasure and non-derivability audited"; and
obligation 28 (release cryptography) via *Concrete security* and *Native
implementation*, which require an independent report plus audited constant-time
secret operations. All three land at §15 step 9 and are governed by §16
decision 11 (exact evidence schemas and external signer rosters, owners:
auditors + governance). §14 kill criteria 34 and 35 make the consequence
explicit: audit evidence lacking typed scope/finding/disposition semantics, or
any open critical/high finding, keeps `safe_for_funds` false regardless of
implementation state.

The three v0.25.2 blockers that recur (§3 F5) are the same attachment seen
earlier: independent cryptography audit and independent implementation audit
were open at v0.25.2 and return here against obligation 28.

### 4.1 GOV — decisions with named owners (10)

| # | Obligation | Source slugs | Owner (§16) | Gates |
|---|---|---|---|---|
| 1 | NUMS role/index semantics are a research profile, not the canonical wire profile | `research-nums-profile` (A) | protocol + implementation + crypto | §16.4 wire profile → §15.2 codec |
| 2 | Exact locator, finalized vsize/feerate, aggregate fee policy unqualified | `fee-policy-evidence-unverified` (A) | Bitcoin economics | §16.7 → §12 E2E matrix |
| 3 | Joint finalized roster/weight bound and confirmed-Contest relay policy unfrozen | `atomic-roster-weight-evidence-unverified` (A **and** F — the one exact duplicate) | governance + operations | §16.5 → setup intent |
| 4 | Validity-plus-withholding and invalid-plus-absent timeout worlds economically indistinguishable on chain | `validity-withholding-economics-unresolved` (A), `validity-withholding-ambiguity-unresolved` (F) | protocol + Bitcoin economics | §16.3 → §15.1 kill decision, §15.3 graph-v2 |
| 5 | Resolution connector policy unverified | `resolution-connector-policy-unverified` (F) | protocol + Bitcoin economics | §16.3 |
| 6 | Slash authorization policy unverified | `slash-authorization-policy-unverified` (F) | protocol + governance | §12 Liveness/economics |
| 7 | Terminal principal disposition unmodeled | `terminal-principal-disposition-unmodeled` (F) | protocol + Bitcoin economics | §16.3 |
| 8 | Protected-baseline authority unverified | `protected-baseline-authority-unverified` (T) | governance | §12 Runtime policy |
| 9 | Per-principal allowance authority unverified | `per-principal-allowance-authority-unverified` (T) | governance | §16.9 caps → §13.1 stage 4 |
| 10 | Service fee schedule and baseline authority unverified | `service-fee-schedule-and-baseline-authority-unverified` (T) | governance + Bitcoin economics | §16.7 |

The four terminal-policy blockers (T) are, by their own definition at
`src/ranklock/v026/timeout_economics.py:144-145`, "External authorities absent
from declared-policy satisfiability." They are not modelling gaps. They are
missing authority. `AbstractDeclaredPolicySatisfiedV1` "always carries four
qualification blockers, and cannot authorize funds" (`docs/09_CLAIMS.md:61-63`).

### 4.2 CTRL — control, possession, and custody attestation (8)

Operations work. Each needs an attestation from a named control domain, not a
test.

| # | Obligation | Source slugs | Gates (§12) |
|---|---|---|---|
| 11 | Descriptor possession and independent controller-domain evidence absent | `controller-domain-evidence-unverified` (A) | Setup; External review |
| 12 | External Claim/D/Q/K existence, value, script provenance unverified | `external-output-evidence-unverified` (A) | Funding transaction |
| 13 | Fresh-D cutover and alternate-signature exclusion unverified | `fresh-deposit-evidence-unverified` (A) **merged with** `deposit-alternate-signature-exclusion-unverified` (F) | Funding transaction |
| 14 | Complete presign transcript and one-honest key erasure unverified | `presign-erasure-evidence-unverified` (A) **merged with** `complete-graph-presign-erasure-unverified` (F) | Graph signing |
| 15 | Legacy CP/ACK/NACK/Slash and off-transcript signature exclusion unverified | `legacy-material-exclusion-unverified` (A) | §13.2 Migration |
| 16 | Recovery descriptor control unverified | `recovery-descriptor-control-unverified` (F) | Bitcoin connector |
| 17 | CPFP control unverified | `cpfp-control-unverified` (F) | Liveness/economics |
| 18 | Slash beneficiary control unverified | `slash-beneficiary-control-unverified` (F) | Bitcoin connector |

Obligation 14 is load-bearing far beyond its line: §14 kill criterion 7 ("a live
graph-signing quorum can authorize an alternate parent after funding") and
criterion 42 both depend on certified erasure. `docs/09_CLAIMS.md:54-55`
explicitly forbids claiming this today.

### 4.3 EXEC — external execution evidence (5)

Cannot be produced by reasoning. Requires real Core, real FoundationDB, real
ASM, real signet.

| # | Obligation | Source slugs | Note |
|---|---|---|---|
| 19 | Global stake exclusivity and competing-spender exclusion unverified | `stake-exclusivity-evidence-unverified` (A) **merged with** `stake-exclusivity-unverified` (F) | **Known live counterexample.** `docs/09_CLAIMS.md:25-26`: "A valid competing live-key stake spend is accepted and prevents Slash." `STATUS.json` → `stake_exclusivity_proved: false`. This is not merely unverified; the current design has a demonstrated hole. |
| 20 | Assembled conflict graph has not completed the required Core matrix | `bitcoin-core-execution-evidence-unverified` (A) | 6 Core cases pass today (`/bitcoin_core/branch_acceptance`); §12 Bitcoin connector requires the full matrix including negatives. |
| 21 | Versioned ASM recognition and coordinated activation not installed | `asm-activation-evidence-unverified` (A) | `STATUS.json` → `asm_strata_pin_bumped: false`, `asm_slash_v2_patch_implemented_in_disposable_checkout: true`. Patch exists, pin not bumped. |
| 22 | Bitcoin Core acceptance not bound to the abstract model | `bitcoin-core-acceptance-not-bound-to-model` (F) | Distinct from 20: 20 is matrix coverage, 22 is that passing Core cases are not tied to the Python model's semantics. |
| 23 | By-horizon CSV, reorg, and fee execution unverified | `by-horizon-csv-reorg-and-fee-execution-unverified` (T) | Blocked behind §16.6 finality depths and §16.7 CSV/fee decision. |

### 4.4 CODE — implementation work in this repo (4)

The complete list of "write code" items in the primary map.

| # | Obligation | Source slug | §15 step |
|---|---|---|---|
| 24 | Canonical graph/wire identity and encoding unimplemented | `canonical-wire-identity-unimplemented` (A) | **Step 2** — the doc's stated first implementation milestone |
| 25 | Local Slash header incompatible with pinned Bridge-v1 parser | `slash-header-profile-incompatible` (A) | Step 3 |
| 26 | Runtime state, persistence, and admission do not consume this graph | `runtime-admission-unimplemented` (A) | Step 4 — see F4. The v3 row spec now exists (2026-08-23), but persistence is not adoption and this blocker is unchanged. |
| 27 | Rust graph projection unverified against the Python model | `rust-graph-projection-unverified` (F) | Step 2/3 boundary |

Obligation 24 is blocked on §16 decision 4 (exact wire maxima/widths and
operational signature profile). Writing the codec first means writing it twice.

### 4.5 CRYPTO — construction that does not exist (1)

| # | Obligation | Source slug | Reality |
|---|---|---|---|
| 28 | Qualified proof/PositiveLock/release backend and ceremony absent | `release-cryptography-evidence-unverified` (A) | §1.4: "Neither suite is implemented or qualified today." Needs §16.1 (floor + BN462 + audited native backend) and §16.2 (S-DFB vs C-DIRECT) ratified before implementation begins. |

This single obligation expands into the 16 threshold-release entries and the 9
wrapper-gate entries in §5. It is the largest item in the programme by a wide
margin, and it is the one that cannot start until governance decides.

---

## 5. Supporting gate-level sets (32 entries, beyond the original three)

These are not additional obligations — they are the decomposition of
obligations 28 (CRYPTO) and 26 (runtime admission) at gate granularity, from
`results/v026_threshold_signature_release.json`.

### 5.1 Threshold-release unverified (16) → obligation 28

Four are hard `INCOMPATIBLE`, not merely unverified — these are the ones that
say the deployed stack cannot host the intended construction:

- deployed SP1 6.2.4 gnark Groth16 samples fresh prover randomness `r`, `s` and
  does not instantiate BABE's deterministic non-zero-knowledge `R'` relation;
- deployed SP1 universal Groth16 VK accepts **five** public inputs; the
  base-plus-two-counterproof-limb profile requires **seven**;
- deployed counterproof public values carry only operator key and game index,
  not the selected commitment or exact ACK template digest;
- Python secp256k1/BN254 is variable-time research code, and BN254 concrete
  security is not approved against a funds-at-risk target (→ F2, kill 8).

The remaining twelve cover setup abort/restart semantics, per-alternative scale
randomness and retained-artifact custody, release signing-key erasure attestation,
independent control domains, evaluator-output availability, qualified CRS
generation and toxic-waste disposal, BABE Construction 1 equivalence review,
Python→Rust canonical projection, the cumulative pre-erasure corruption bound on
`f`, ACK template derivation from exact Rust sighash bytes, and — last line —
"no production theorem or ceremony qualifies funds."

### 5.2 Deterministic wrapper gate (9) → obligation 28

Includes: the complete wrapper R1CS, proving key, qualified CRS, and
projectivizer are absent; a deterministic non-zero-knowledge final Groth16
prover is not implemented; the SP1-in-SP1 mechanics example accepts its verifier
as witness input and "is not a sound production wrapper"; BABE equivalence and
public-side-information security have no independent review; and the local SP1
6.2.4 CPU Groth16 attempt was safety-terminated without producing a receipt.

### 5.3 Subject-bound counterproof gate (7) → obligations 26 and 28

Includes: no valid receipt executes the composed path and no duty requires it;
the lower-level witness store remains independently callable; the setup ceremony
does not authorize/persist/distribute the exact signed subject manifest;
threshold release and funding runtimes do not consume the new proof identity;
and the rebuilt current-source legacy ELF differs from the published deployed
artifact, so activation requires a new versioned subject predicate and must not
overwrite legacy identity.

The measured local failure is recorded exactly: two insecure-RNG warnings,
>40 GiB process footprint, 41,239 MiB system swap, safety-terminated after at
least 2,859 wall seconds, no receipt. That constraint is what the reserved
network request solved — see §8.

---

## 6. The §16 inversion — what each decision unblocks

This is the actionable table. §16 lists **11** open decisions (not ten), each
— all three step-1 kill decisions plus decision 4 now have drafted
proposals: `62_V026_DECISION1_SECURITY_FLOOR_PROPOSAL.md` (§16.1),
`65_V026_DECISION2_RELEASE_PROFILE_PROPOSAL.md` (§16.2),
`64_V026_DECISION3_TIMEOUT_ECONOMICS_PROPOSAL.md` (§16.3) and
`60_V026_DECISION4_WIRE_SIGNATURE_PROFILE_PROPOSAL.md` (§16.4). None is
ratified and none moves a blocker. Doc 64 carries an unresolved reviewer
objection in its §0.3; doc 65's recommendation is conditional on an
attempt that has not been made —
with owners and a "must be fixed before" boundary. Inverted:

| §16 decision | Owners | Unblocks |
|---|---|---|
| 1. Ratify 128-bit floor + BN462 target; select, harden, audit, pin native backend | cryptography + governance | Obligation 28; all of §5.1 and §5.2; kill criteria 8, 9, 10, 16, 17. **Root of the largest subtree.** |
| 2. Select S-DFB or C-DIRECT; for C-DIRECT pin device/firmware/attestation/clone/backup policy | cryptography + protocol + governance + operations | Obligation 28 implementation shape; §12 Release mechanism, Setup, One shot; kill criteria 12, 15, 44, 52-55. |
| 3. Timeout/NACK economic semantics; N-of-N vs weaker threshold | protocol + Bitcoin economics | Obligations 4, 5, 7; §15 step 1 kill decision; §12 Liveness/economics; kill 18, 30. |
| 4. Exact wire maxima/widths and operational signature profile | protocol + implementation + crypto | Obligations 1, 24, 27; §15 step 2. **Cheapest high-leverage decision.** |
| 5. Participant and graph-signer counts/control domains | governance + operations | Obligations 3, 11, 14; kill 7, 42, 46. |
| 6. Parent-release and ACK/NACK-finality depths + removal bounds | Bitcoin economics + operations | Obligation 23; §13.1 signet; kill 43, 50. |
| 7. CSV delay, fee reserve, CPFP responsibility, halt threshold | Bitcoin economics | Obligations 2, 10, 17, 23; §12 E2E. |
| 8. Registry `f`, BFT engine, replica roster, retention-key service, cluster lifetime, failure domains | operations + security | Obligation 26; §12 Safety registry, Exact-byte availability; kill 22, 45. |
| 9. Initial per-deposit, aggregate, active-count caps | governance | Obligation 9; §13.1 stage 4 bounded activation; kill 25, 40. |
| 10. Admission expiry, revocation distribution, cooldown | governance + operations | Obligations 8, 26; kill 24, 41. |
| 11. Exact evidence schemas and external signer rosters | auditors + governance | §12 External review; kill 34, 35. |

**Reading:** decision 4 is the cheapest with real downstream unlock (three
obligations plus the §15 step-2 milestone) and its owners are already internal.
Decisions 1 and 2 unlock the most but require external cryptography review and
governance ratification, so they have the longest lead time and should be
started first even though they finish last.

---

## 7. Ordering

§15 fixes the programme order and §13.1 fixes the deployment stages. Neither is
negotiable by engineering convenience. Condensed against the obligations above:

1. **Kill decisions** (§16.1, .2, .3) — security floor, release profile, timeout
   fund preservation. §15.1 says explicitly: "Stop if any cannot be made safe."
   Obligations 4, 5, 7, 28.
2. **Identity DAG and profiles** (§16.4) — obligations 1, 24, 27. §15: "The
   first implementation milestone is therefore not a proof coordinator. It is
   the acyclic identity/profile codec plus graph-v2 connector and presign
   theorem."
3. **Graph v2 and presigning** — obligations 14, 25, and the Core work in 20/22.
4. **Safety registry and admission** (§16.8, .10) — obligation 26, including the
   v3 persistence envelope from F4, whose codec landed 2026-08-23 without
   moving the adoption blocker.
5. **Proof-suite spike** — obligation 28 proper; §5.1 and §5.2 collapse here.
6. **Selected ceremony and participant** — obligations 11, 15.
7. **Coordinator and bridge** — obligations 12, 13, 16, 18.
8. **Live matrix** — obligations 19, 20, 21, 22, 23; full STRATA-010..020
   restoration with zero-exit commands.
9. **Independent review** — cryptography, implementation, Bitcoin economics,
   operations, over exact source/artifact/subject/binaries (§16.11).
10. **Staged activation** — signet → mainnet shadow → governance-capped bounded
    activation (§16.9), all hard gates externally satisfied.

The three v0.25.2 blockers that recur (native constant-time implementation,
independent cryptography audit, independent implementation audit) land in steps
5 and 9.

---

## 8. Deferred work carried out of this session

**D1 — Subject-bound SP1 Groth16 receipt recovery. COMPLETED 2026-08-23.** The
receipt was recovered offline and verified standalone; see
`results/v026_subject_bound_sp1_network_receipt_recovery.json`. The proof had
been valid all along — the pin read the `sp1-prover` crate version instead of
`SP1_CIRCUIT_VERSION`, and `host.verify` rebuilt public input 1 with SHA-256
against a Blake3-committed proof. A third cause, absent from the handoff, was
found during the run: `OPERATOR_KEYPAIR` is `LazyLock::new(generate_keypair)`,
so every test comparing a persisted receipt against a recomputed fixture was
unsatisfiable by construction. This closes the deterministic final Groth16
execution/verification evidence gate and no funding obligation below.
Original specification retained in
`results/v026-subject-bound-sp1/CLAUDE_HANDOFF_2026-08-22.txt`.

Precondition now satisfied: the fulfilled reserved request's public artifact
(request `0da45348…bcc7`, 2179 bytes) carried an S3 expiry of
`Tue, 25 Aug 2026 00:00:00 GMT`, and the decision boundary forbids submitting
another paid request — so the bytes were irreplaceable and on a clock. They have
been fetched and persisted durably:

```
results/v026-subject-bound-sp1/network-proof-0da45348-raw.bincode          (0600, 2179 bytes)
results/v026-subject-bound-sp1/network-proof-0da45348-raw.bincode.sha256
sha256 = 158b6e0c200479499b6232a5a8c80de8eb4bfeb2fc169625547604d77cf1a09d
```

The handoff's "avoid persisting the raw network bincode unless necessary" is
satisfied by necessity: deferring recovery past this session with a hard expiry
and no resubmission path makes durable local retention the only option that
preserves the work. The recovery is now offline and unscheduled.

Its value is bounded by **F2**: it closes the deterministic final Groth16
execution/verification evidence gate and moves no funding obligation.

**D2 — Rotate the SP1 network private key.** The handoff mandates this because
the key value was pasted into chat history. Keychain service and requester account are redacted from this public
repository; both are recorded locally. Not required for D1. Not done
here.

**D3 — Regenerate v3 evidence (F4). COMPLETED 2026-08-23.** Evidence is
`results/v026_threshold_graph_v3_admission_gap.json`, produced by
`scripts/generate_v026_threshold_v3_gap_results.py`, which parses every count
from the live Rust sources and aborts if the graph and admission paths disagree.
Two consecutive runs are byte-identical, so the record is reproducible rather
than merely run-generated. It independently confirms doc 60's defect D-1 by
machine-parsing both admission envelopes as seven-byte `RL26ADM`.

The missing `v026_admissions_v3.rs` row spec was then written rather than only
reported, following the 2026-08-19 V1-to-V2 precedent. The claim boundary and
`11_DECISION_LOG.md` were extended in the same change. Persistence is not
adoption: no blocker count changed and no funding obligation moved.

---

## 9. Reconciliation

Every enumerated entry is accounted for exactly once.

| Stage | Count |
|---|---|
| Raw entries across 7 sets (16+13+4+16+9+7+7) | 72 |
| Exact string duplicates removed (`atomic-roster-weight-evidence-unverified`, in both Activation and Funding) | −1 → **71 unique** |
| Primary sets (Activation 16 + Funding 13 + Terminal 4 = 33 raw, 32 unique after the duplicate) | 32 |
| Supporting gate-level sets (16 + 9 + 7), no overlap with primary | 32 |
| Historical v0.25.2 release gate | 7 |
| **Sum** | **71** ✓ |

Semantic merges applied within the primary set — these are where a blocker can
silently vanish, so each is named with both source slugs:

| Merged obligation | Slug A (Activation) | Slug B (Funding) |
|---|---|---|
| #3 atomic roster weight | `atomic-roster-weight-evidence-unverified` | `atomic-roster-weight-evidence-unverified` (exact duplicate) |
| #4 validity withholding | `validity-withholding-economics-unresolved` | `validity-withholding-ambiguity-unresolved` |
| #13 fresh deposit / alternate signature | `fresh-deposit-evidence-unverified` | `deposit-alternate-signature-exclusion-unverified` |
| #14 presign erasure | `presign-erasure-evidence-unverified` | `complete-graph-presign-erasure-unverified` |
| #19 stake exclusivity | `stake-exclusivity-evidence-unverified` | `stake-exclusivity-unverified` |

Row 1 of that table is the exact duplicate, already removed in the 33 → 32 step;
the remaining four rows are genuine two-slug semantic merges. So:

32 unique primary strings − 4 semantic merges → **28 distinct obligations**,
itemised as #1-#28 across §4.1-§4.5: 10 GOV + 8 CTRL + 5 EXEC + 4 CODE +
1 CRYPTO = 28 ✓

All counts in this section were verified mechanically against the JSON, not
tallied by hand.

Note on merge #13: the merge is not by string similarity. It is licensed by the
enum's own documentation at `crates/tx-graph/src/v026_graph.rs:234` —
"Fresh-D cutover **and alternate-signature exclusion** are unverified."

---

## 10. What this document does not establish

`safe_for_funds` is false. Every `funding_eligible` is false. No blocker was
closed, downgraded, or reinterpreted here. `results/v026_timeout_economics.json`
remains EXACT abstract graph and terminal-policy evidence;
`results/v026_rust_graph_core.json` remains REPRODUCED research graph/Core
evidence; both remain non-authorizing, per `docs/09_CLAIMS.md:79-81`.

This map is an inventory and an ordering. It is decision input for the eleven
§16 owners. It is not evidence of progress.
