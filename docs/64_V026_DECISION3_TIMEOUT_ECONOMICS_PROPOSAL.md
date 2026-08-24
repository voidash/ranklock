# v0.26 §16 decision 3 — timeout/NACK economics and N-of-N versus threshold release

**Status: PROPOSED. NOT RATIFIED. NOT AUTHORITATIVE.**

**Provenance.** The body of this document (§1–§17) was drafted by an assistant
working from `63_CHATGPT_HANDOFF_2026-08-24.md` without build access, against
commit `04f420bfa4b0058f9566f9b06517b048388e706a`. §0 below is a reviewer's note
added afterwards by an assistant that does have repository access. The two are
kept separate on purpose: the draft's reasoning is not silently edited, and the
verification is not presented as if it were part of the original analysis.

---

## 0. Reviewer's note — verification and one unresolved objection

### 0.1 Citation audit

**OBSERVED.** Twelve of the draft's citations were checked mechanically against
the repository at the stated commit. The commit hash is exact. All twelve land
on the claimed content:

| Citation | Result |
|---|---|
| `58:55-58` | Exact — §1.4 item 7, the fund-preserving / `t-of-n` fork |
| `58:112-130` | Correct — §3.1 loss-safety objective |
| `58:132-157` | Correct — §3.2 adversary capabilities |
| `58:255-258` | Exact — timeout/NACK must be independently loss-safe |
| `timeout_economics.py:1-15`, `:11-15` | Exact — the indistinguishability statement |
| `timeout_economics.py:65-76` | Correct — `TerminalBranchV1` / `TerminalWorldV1` |
| `timeout_economics.py:2903-2952` | Exact — `CoverageReserveV2`, "accounting evidence, not a claim that V1 transaction bytes…", and `fusion_with_existing_counterproof_input_authorized` |
| `timeout_economics_reference.py:620-790` | Correct — `bond_value_sat = 100_000_660`, owner/sibling returns |
| `timeout_economics_reference.py:895-950` | Exact — `n=3`, `threshold=2`, `maximum_corruptions=1`, `ASSUMPTION_FAILURE_WORLD` |
| `results/v026_timeout_economics.json` | Exact — `100000660` ×4, `100000000` ×4, `funding_eligible: false` ×4, `protected_value_theorem_established: false` |
| `59:197-211` | Correct — the GOV obligation table containing obligation 4 |

One imprecision: `timeout_economics.py:3025-3075` is cited for the
`0 <= f < t <= n-f` relation. That range contains the
`ThresholdReleaseQualificationV2` class declaration, but the inequality and its
literal error string `"threshold parameters must satisfy 0 <= f < t <= n-f"`
are at approximately `:3080-3086`. The claim is correct; the range is slightly
short. No fabricated citation was found.

### 0.2 The §4.2 lemma holds

**OBSERVED.** The cause-blind payout lemma is correct and is the draft's
principal contribution. If the consensus-visible transcript is identical across
two worlds and settlement is a deterministic function of that transcript and an
immutable policy, the payout vectors are identical. It follows that no bond
size purchases cause-specific liability. This retires an entire family of
"just slash the withholder" proposals, and it should be treated as settled
unless someone produces the additional consensus-bound evidence §6 describes.

### 0.3 Unresolved objection — the recommendation bonds the safety actor

**PROPOSED, and not resolved by the draft.** §15 recommends
`T_OF_N_F_BOUNDED + CAUSE_BLIND_STRICT_LIABILITY` with the selected
counterprover as strict-liability provider. §7.3 states the consequence
plainly: the counterprover forfeits its bond on every selected timeout,
"including a valid counterproof that fails to reach ACK for an infrastructure
or beyond-bound reason."

Counterproving is the mechanism that makes the bridge safe. Under this
recommendation, an actor who submits a **valid** counterproof loses its full
bond when the ACK fails to confirm for reasons wholly outside its control —
registry outage, Core partition, fee spike, or beyond-bound threshold
unavailability. The draft treats that as acceptable strict service liability
and analyses collusion (§7.6), but it does not analyse the effect on
**deterrence**.

The concern is that a rational counterprover counterproves only when the
expected slash reward exceeds `bond × P(ACK fails for any reason)`. Raising the
bond to cover the invalid-counterproof liability therefore also raises the
threshold below which honest counterproofs are not worth submitting. In the
limit, an adversary who can *induce* the failure — fee spikes are cheap to
induce — both keeps an invalid claim and, if it influences the timeout
beneficiary, collects the bond. §7.6's control-domain constraints address the
second half of that and not the first.

**FIXED, and this is the part that makes it a gate rather than a preference.**
`docs/58_V026_FUNDS_SAFETY_PROTOCOL.md:861-866` already anticipates this:

> ACK-anchor bounties and slash rewards are protected only when the signed
> policy makes them unconditional or they contain the beneficiary's contributed
> principal … A stronger incentive-parity claim, including "the refuted operator
> cannot avoid the baseline slash," requires independently locked insurance or a
> validity signal and is a separate mandatory gate if governance relies on that
> deterrent.

A forfeitable bond makes the counterprover's position **conditional** in exactly
the sense that clause excludes. So if governance intends to rely on the slash
deterrent — and the whole v0.26 safety argument does — the recommendation as
written triggers a separate mandatory gate for independently locked insurance
or a validity signal. The draft does not name that gate.

**OBSERVED.** The authoritative protocol contains **zero** occurrences of the
word "counterprover". The role is a construct of the `timeout_economics` model,
not of the signed protocol. Assigning unconditional financial liability to a
role the protocol does not define is itself a specification gap that owners
should close before ratifying.

### 0.4 Reviewer's recommendation to owners

Accept §1–§14 and §17. They are accurate, well-sourced, and the lemma is a
genuine advance.

Treat §15's recommendation as **not yet ratifiable** until one of the following
is added:

1. a quantified deterrence analysis showing the bond does not suppress honest
   counterproofs below the level the safety argument assumes; **or**
2. the independently locked insurance or validity signal that
   `58:861-866` requires when a deterrent is relied upon; **or**
3. an amended liability assignment that does not place forfeitable stake on the
   safety actor.

This objection does not favour the N-of-N branches. It applies to the
liability assignment, not to the quorum choice, and §7's threshold analysis
stands on its own.

---

## 1. Executive finding

### 1.1 The decision is not "how large should the bond be?"

**FIXED.** The loss-safety objective is stronger than transaction value
conservation. A single actor's absence, crash, or withholding must not create an
unauthorized value transfer, and a party capable of causing timeout must not be
able to turn timeout into a profitable attack (`58:112-130`).

**FIXED.** The current one-honest game permits the adversary to control up to
`N-1` split-scalar participants (`58:132-157`). Under an N-of-N release rule,
one corrupt or unavailable participant can therefore cause valid withholding
*inside the stated adversary model*. It is not an operational corner case.

**OBSERVED.** The abstract graph exposes one timeout terminal for both worlds:

```text
W_VH = valid counterproof + required release withheld
W_IA = invalid counterproof + required release absent
```

stated directly at `timeout_economics.py:11-15`.

**PROPOSED formal consequence.** Let `T` be the complete consensus-visible
transcript available to the presigned timeout graph and `P(T, policy)` the
deterministic terminal payout vector. If `T(W_VH) = T(W_IA)` then
`P(W_VH) = P(W_IA)`. No bond amount changes that equality. Cause-specific
liability requires at least one of:

1. new sound, consensus-bound evidence that changes `T`;
2. an explicitly trusted external adjudicator;
3. placing one semantic world outside the signed corruption/liveness model;
4. accepting the same unconditional liability in both worlds.

### 1.2 The current bond result is useful but is not the decision

**OBSERVED.** The no-bond reference fixture is infeasible under its declared
principal policy: a 100,000,000 sat principal deficit per invalid-release-absent
alternative, a required reserve of 100,000,660 sat, zero reserve available.
Fixture values, not protocol parameters.

**OBSERVED.** The atomic-bond candidate uses 100,000,660 sat per alternative and
reports declared coverage adequacy, yet still reports
`funding_eligible = false` and `protected_value_theorem_established = false`,
retaining four qualification blockers: control/possession authority,
execution-schedule authority, Bitcoin-Core graph binding, and runtime
admission/broadcast enforcement.

**OBSERVED.** `CoverageReserveV2` is an accounting overlay; the V1 transaction
bytes do not contain the proposed inputs and outputs, and
`fusion_with_existing_counterproof_input_authorized = false`
(`timeout_economics.py:2903-2952`).

**OBSERVED.** The reference threshold object uses `(n, t, f) = (3, 2, 1)` and
marks every valid-withheld world `ASSUMPTION_FAILURE_WORLD`
(`timeout_economics_reference.py:895-950`). A deterministic fixture, not a
recommendation for decision 3 or 5.

**PROPOSED.** The bond result therefore supports exactly two narrow findings: no
bond is insufficient for the declared fixture, and a cause-blind reserve can
arithmetically cover the fixture's selected liability *after valid withholding
has already been excluded as an assumption failure*. It does not show that
N-of-N valid withholding is economically reconciled, and `09_CLAIMS.md` forbids
saying so.

---

## 2. Method and provenance

Tags follow the house style: **FIXED** (already required by the protocol or
claim boundary), **OBSERVED** (read from a cited source or existing generated
evidence), **PROPOSED** (new; owners must accept, amend, or reject).

**OBSERVED.** Drafted against `v0.25.2-qualification` at
`04f420bfa4b0058f9566f9b06517b048388e706a`. Sources read: `09_CLAIMS.md`,
`58_V026_FUNDS_SAFETY_PROTOCOL.md`, `59_V026_CRITICAL_PATH_GAP_MAP.md`,
`60_…`, `62_…`, `63_…`, `timeout_economics.py`,
`timeout_economics_reference.py`, `results/v026_timeout_economics.json`.

**OBSERVED.** No generator, Rust build, Bitcoin Core test, FoundationDB test,
SP1 command, or evidence regeneration was run for §1–§17. The generated JSON was
read only. This document contributes reasoning and decision structure, not
execution evidence. (§0 was produced with repository access and states its own
checks.)

---

## 3. Already fixed — restate, do not decide

**FIXED.** A timeout may reduce availability but must not become a profitable
attack by a party capable of causing it (`58:112-130`).

**FIXED.** The computational game does not establish availability. Participant,
registry, signer, Core, or fee-path unavailability is acceptable only after the
timeout/NACK path is independently proved economically loss-safe (`58:255-258`).

**FIXED.** N-of-N simultaneously gives one-honest invalid-ACK resistance and
allows one unavailable or malicious participant to block a valid ACK. Decision 3
must preserve the first with a loss-safe timeout, or weaken the corruption model
explicitly (`58:55-58`).

**FIXED.** `results/v026_timeout_economics.json` is EXACT abstract graph and
terminal-policy evidence, non-authorizing, and the two worlds may not be
described as reconciled (`09_CLAIMS.md`).

**FIXED.** Decision 3 owns timeout/NACK economic semantics and the corruption
model. It does not own participant count, finality depths, CSV delay, fee
reserve, release profile, caps, or audit roster.

---

## 4. The economic ambiguity, stated precisely

### 4.1 Semantic worlds

| World | Meaning | Cause-capable class | Current terminal |
|---|---|---|---|
| `NO_COUNTERPROOF` | No counterproof wins selection | claim/deposit side | owner-payout |
| `VALID_RELEASED(j)` | Valid counterproof, ACK completes | none by premise | counterproof → ACK → slash |
| `VALID_RELEASE_WITHHELD(j)` | Valid counterproof, release actors do not complete ACK | release participant, service, registry, signer, Core, fee path | counterproof → timeout |
| `INVALID_RELEASE_ABSENT(j)` | Invalid counterproof, no valid ACK exists | selected counterprover / request side | counterproof → timeout |

**OBSERVED.** The V1 analyzer maps both of the last two to
`TerminalBranchV1.TIMEOUT` with no cause trace.

### 4.2 Cause-blind payout lemma

**PROPOSED lemma.** Assume (i) both worlds expose identical transaction-enabling
data to every presigned parent, (ii) timeout settlement is deterministic in
those data and the immutable policy, and (iii) no separately trusted adjudicator
may alter the graph after funding. Then the terminal roster, values, and spend
conditions are identical in both worlds. In particular an on-chain timeout
cannot slash only the withholder in one and only the invalid counterprover in
the other.

**PROPOSED review consequence.** Any proposal claiming cause-specific punishment
on the current trace is incomplete unless it names the additional
consensus-bound evidence that makes the traces differ. "Off-chain we know who
failed" is not sufficient for a presigned Bitcoin payout.

### 4.3 Why a larger bond does not remove the ambiguity

| Cause-blind allocation | In `VALID_RELEASE_WITHHELD` | In `INVALID_RELEASE_ABSENT` | Required theorem statement |
|---|---|---|---|
| Counterprover bond always pays | A possibly honest counterprover pays for a release-layer failure | The invalid counterprover pays | Unconditional timeout liability, not cause-specific fault |
| Release-participant bond always pays | The withholder class pays | Possibly honest participants pay for an invalid counterproof | Unconditional roster liability |
| Both classes pay | At least one cause-capable class pays; honest members can also lose | Same | Explicit strict-liability loss allowance for every charged principal |
| Mutual insurance / protocol reserve pays | Cause-capable actor may lose nothing | Same | Attack-rate, exhaustion, cap, replenishment, admission-freeze bound |

**PROPOSED.** None is automatically invalid, but the selected one must name the
protected principals, authorized losses, maximum cumulative depletion, and which
party may cause the transfer. Without that, "fund-preserving" has no exact
principal-level meaning.

---

## 5. Candidate A — retain N-of-N with cause-blind strict liability

**FIXED.** N-of-N retains one-honest invalid-ACK resistance.

**PROPOSED.** Liveness is intentionally weak: one missing required actor is an
in-model timeout unless the corruption model is narrowed.

**PROPOSED reserve schema.** For each alternative `j`:

```text
R_j >= L_j + A_j + F_j + H_j
```

with `L_j` the allocated principal liability, `A_j` the authorized operational
allowance, `F_j` the fee budget, and `H_j` justified delay/reorg headroom backed
by spendable value or a signed external reserve. A schema only — decisions 6 and
7 own the numbers, and 100,000,660 sat is not portable to another deposit,
graph, vsize, feerate, or CSV horizon.

**PROPOSED.** A cause-blind reserve is insufficient if an actor can trigger
timeouts repeatedly without consuming at least the loss it causes. The signed
policy must bind reserve provider and possession authority, scope
(per-subject / per-alternative / aggregate / reusable), the consuming event,
retry double-consumption, active and reorg-tail exposure, the exhaustion
admission freeze, replenishment authority and cooldown, and whether the
timeout-causing actor can receive any correlated benefit.

**PROPOSED status.** Admissible only as N-of-N **strict liability**, never as
cause-correct slashing. Its ratification text must state which principal can
lose while honest in each indistinguishable world. If owners will not state
that, this branch is rejected.

---

## 6. Candidate B — retain N-of-N and add cause-distinguishing evidence

**PROPOSED required property.** A new consensus-bound discriminator before
liability releases:

```text
TimeoutCauseV1 =
    VALID_PROOF_RELEASE_WITHHELD(blame_evidence_digest)
  | INVALID_OR_UNQUALIFIED_COUNTERPROOF(invalidity_evidence_digest)
```

useful only if Bitcoin Script, a presigned parent, or a qualified adjudication
connector can verify it under the immutable subject. A registry label or
coordinator assertion is not sufficient.

**PROPOSED evidence requirements.** Sound validity evidence; sound withholding
evidence (silence alone proves nothing); no framing attack by coordinator,
in-bound registry quorum, counterprover, or peer participant; no alternate
parent — every cause-specific payout fully presigned before funding; fee and
reorg safety before CSV maturity; terminal uniqueness across subject,
alternative, slot, graph, and epoch.

**PROPOSED consequences.** This changes the graph bundle, connector policy,
templates, presigning transcript, wire profile, E2E matrix, and likely the
adjudication trust model — a new subject, not a retrofit. It preserves the
strongest corruption statement only if the cause evidence itself stays sound
with up to `N-1` release participants corrupt; a weaker adjudicator bound is
inherited by the whole theorem.

**PROPOSED status.** The principled N-of-N answer when both one-honest safety
and cause-correct liability are required. No such qualified discriminator
exists today, so selecting it keeps graph-v2 finalization blocked.

---

## 7. Candidate C — adopt an explicit t-of-n, f-bounded model

### 7.1 Exact relation

**OBSERVED.** `ThresholdReleaseQualificationV2` requires `0 <= f < t <= n - f`
and rejects rosters outside it.

**PROPOSED.** Read as two requirements — safety `f < t`, liveness `t <= n - f`.
The real theorem must also include registry, Core quorum, graph-signing
material, fee path, and deadline; the inequality alone proves neither arrival
nor confirmation.

### 7.2 Security theorem change

**PROPOSED.** This branch **explicitly gives up one-honest split-scalar
safety**. The protected statement becomes: for one admitted subject, an invalid
ACK is infeasible while fewer than `t` release authorities are corrupt and every
other stated assumption holds; a valid ACK remains available by the deadline
while at least `t` qualified authorities complete and the schedule assumptions
hold. Corruption of `t`, or unavailability of more than `n-t`, is an assumption
failure — both must be explicit in the immutable execution policy and in
external review.

### 7.3 Economic consequence

**PROPOSED.** Threshold release narrows one cause of valid withholding; it does
not remove the obligation. The policy must distinguish at least:

```text
VALID_RELEASE_WITHHELD_PARTICIPANT_WITHIN_BOUND
VALID_RELEASE_WITHHELD_PARTICIPANT_BEYOND_BOUND
VALID_RELEASE_WITHHELD_INFRASTRUCTURE
```

The first should be unreachable after qualification; the second is a threshold
assumption failure; the third covers registry, signer, Core, and fee-path
failure and remains subject to the fixed loss-safety requirement.

**PROPOSED.** All three may still map to the same Bitcoin terminal. The split is
needed to state the theorem and incident boundary, not to create cause-specific
payout. Under the proposed baseline the selected counterprover accepts strict
bond liability on **every** selected timeout, including a valid counterproof
that fails to reach ACK for infrastructure or beyond-bound reasons. *(See §0.3 —
this is the clause the reviewer objects to.)*

### 7.4 Protocol identity consequence

**PROPOSED.** A threshold ACK is not a policy reinterpretation of the ordered
N-preimage vector connector. It requires a new integrated profile/suite
identifier binding: an exact `(n, t, f)` cross-ratified with decision 5; ordered
identities and control domains; exact ACK template ids; the threshold
conditional-release algorithm and message; transcript/DKG evidence; share
custody, backup, rotation, abort and terminal-erasure rules; retry and failover
behaviour; the execution-schedule digest.

### 7.5 Quorum status

**PROPOSED.** Select `T_OF_N_F_BOUNDED` only if owners accept the weaker
corruption theorem in §7.2. Ratifying the quorum closes no implementation or
funding blocker; it authorizes specification work only, and does not authorize
reuse of the reference `(3, 2, 1)` tuple.

### 7.6 Proposed composite topology

**PROPOSED.** For every alternative `j`: the counterprover funds a unique bond
outpoint `B_j` under an authority-bound principal; the no-counterproof owner
payout conflicts with the full bond roster and returns every `B_j`; selecting
`Counterproof_j` returns every sibling `B_k` and moves `B_j` into the unique
resolution path; the threshold-qualified ACK refunds `B_j` in full; the timeout
parent conflicts with ACK and pays `B_j` to the exact timeout beneficiary while
preserving protected recovery outputs and fee anchors; and no retry, sibling
selection, owner payout, reorg recovery, or alternate graph can consume or
refund a bond twice.

**PROPOSED anti-collusion.** The timeout beneficiary, threshold roster, graph
owner, registry, Core quorum, and fee broadcaster must satisfy control-domain
constraints preventing the beneficiary from controlling enough of the release or
execution path to manufacture a profitable timeout. Once a valid ACK witness
reaches its committed publication stage, the beneficiary must not be its sole
custodian or sole fee-bump controller.

**PROPOSED capital.** `locked_bond_capital = Σ B_j` over funded alternatives;
`selected_timeout_loss = B_selected`. Replacing per-alternative bonds with a
shared reserve requires separate proof of selection exclusivity, no collateral
reuse, exact owner/sibling dispositions, and risk-cap accounting.

---

## 8. Side-by-side comparison

| Property | N-of-N strict liability | N-of-N cause-distinguished | t-of-n + selected strict bond |
|---|---|---|---|
| Invalid-ACK bound | One honest boundary blocks it | Same, plus cause-evidence soundness | Excluded only while corrupt authorities `< t` |
| Valid-ACK liveness | Requires every required authority | Same before timeout | Requires `>= t` authorities and schedule assumptions |
| Valid-withheld status | Protected in the `N-1` model unless narrowed | Protected and economically resolved | Within-`f` must not time out; beyond-bound and infrastructure remain defined |
| Timeout payer | One unconditional class or reserve, both worlds | Cause-specific payer | Selected counterprover's bond, without asserting cause |
| Innocent-party loss | Possible unless payer is outside the protected set | Zero within the theorem, bar authorized costs | Counterprover accepts bond loss; others within authorized bounds |
| Graph change | Actual reserve inputs/outputs must replace the overlay | New connector and terminal parents | New threshold profile plus atomic bond topology |
| Dominant new assumption | Reserve solvency, strict-liability acceptance, attack rate | Sound, non-frameable cause evidence | `< t` corrupt, `<= n-t` unavailable, strict-liability acceptance, anti-collusion domains |

**PROPOSED.** The loss bound must be principal-indexed, not only aggregate: for
every protected principal `p`, world `w`, alternative `j`,

```text
terminal_wealth(p, w, j) >= authorized_baseline(p, w, j)
                          - authorized_cost_allowance(p, w, j)
```

Every principal omitted from protection needs one typed status: adversarial by
premise, voluntary strict-liability provider, or assumption-failure participant.
An unnamed "system reserve" is not a principal and cannot own or lose Bitcoin.

---

## 9. Proposed decision record

**PROPOSED.** Provisional; it does not answer decision 4's wire questions.

```text
TimeoutEconomicsDecisionV1 {
    funding_protocol_version
    graph_profile_id
    release_quorum_mode        = N_OF_N_ONE_HONEST | T_OF_N_F_BOUNDED
    timeout_adjudication_mode  = CAUSE_BLIND_STRICT_LIABILITY | CAUSE_DISTINGUISHED
    strict_liability_provider_role?     # cause-blind only
    timeout_beneficiary_role?           # cause-blind only
    semantic_world_roster_digest
    principal_role_roster_digest
    protected_world_status_digest
    liability_policy_digest
    reserve_topology_digest
    threshold_policy_digest?            # threshold only
    timeout_cause_profile_digest?       # cause-distinguished only
    execution_schedule_dependency_digest
    fee_policy_dependency_digest
    participant_count_dependency_digest
    audit_schema_dependency_digest
    protocol_owner_signature
    bitcoin_economics_owner_signature
}
```

Reject the record if fields are inconsistent with the selected mode pair, a
dependency is omitted, it refers to a mutable policy after admission, or a bare
digest's referenced typed object is unavailable. Ratification fixes decision
content only; decision 4 owners then assign encoding, magic, widths, maxima and
signature domains.

---

## 10. Evidence required before the selected branch can close obligation 4

**PROPOSED, common to every branch.** Authoritative principal map; actual
serialized graph with matching Rust and Python projections (an accounting
overlay is insufficient); Bitcoin Core binding accepting every intended branch
and rejecting omitted, duplicated, reordered, alternate, replayed and
conflicting witnesses; by-horizon execution under forced fee pressure; runtime
enforcement that cannot be bypassed; atomic risk accounting against the
immutable risk namespace; crash/retry safety around every irreversible
transition; and independent economics review under typed evidence schemas.

**PROPOSED, cause-blind additionally.** Signed acceptance of unconditional
liability by every charged principal; control-domain and incentive evidence that
no timeout-capable actor can receive the compensation or a correlated benefit
exceeding its committed cost; aggregate exhaustion analysis over concurrent
subjects and reorg tails; an admission freeze before reserves fall below
committed liability; exact owner/sibling return, ACK refund and
timeout-consumption tests; and test worlds where the charged principal is honest
but another class causes timeout, so the accepted loss is visible.

**PROPOSED, cause-distinguished additionally.** Formal soundness and
non-frameability for `TimeoutCauseV1`; complete positive and negative vectors
for both branches; malicious coordinator, counterprover, roster, partition,
delay and equivocation tests; exact parent presigning with one-honest share
erasure; and an audit showing no weaker adjudicator threshold silently replaces
the one-honest claim.

**PROPOSED, threshold additionally.** Exact `n, t, f`, roster and independent
control domains; a proof or reduction for invalid-ACK resistance below `t`;
liveness argument and live tests for every fault pattern of size `<= f`;
threshold setup/transcript qualification and share lifecycle evidence; rejection
of alternate messages, templates, subjects, slots, epochs, graphs and
transcripts; crash/recovery tests proving one completed ACK replays but no
second or invalid ACK forms; and explicit assumption-failure tests for `t`
corrupt or `> n-t` unavailable, which must not claim resistance outside the
signed bound while still leaving the economic settlement defined and executable.

---

## 11. Acceptance matrix for the live E2E specification

**PROPOSED.** Zero-exit rows required for at least: valid proof with release
available; valid proof with one actor withholding; invalid proof with no
release; forged cause evidence; `t-1` corrupt shares attempting invalid ACK;
`t` corrupt shares; more than `n-t` unavailable; registry/Core/signer outage
after selection; fee pressure before the ACK deadline; reorg within the signed
bound; exact retry after crash; and conflicting retry or alternative. "Expected"
means the branch's signed model, not a generic answer.

**PROPOSED.** A modelled-only row, a mocked Script result, or a row that does
not bind actual graph bytes to Core does not close the live-evidence part of the
obligation.

---

## 12. Dependencies on other §16 decisions

| Dependency | Why decision 3 needs it | Must not pre-empt |
|---|---|---|
| 2 — S-DFB vs C-DIRECT | Determines who can withhold, what is erased, how blame or threshold evidence is produced | Selecting the release boundary |
| 4 — wire/signature profile | Every decision, liability, threshold and cause object needs canonical bytes | Magics, widths, maxima, signature encoding |
| 5 — participant counts | Threshold needs exact `n, t, f`; all modes need control domains | Adopting the reference `(3,2,1)` roster |
| 6 — finality depths | Common-prefix and terminal observation assumptions | Choosing block depths |
| 7 — CSV, fees, CPFP, halt | Determines `F_j`, `H_j`, deadlines, by-horizon spendability | Promoting fixture fees or 144-block values |
| 8 — registry profile | Release and timeout transitions rely on exact CAS/finality semantics | Choosing BFT engine or replica count |
| 9 — caps | Bounds aggregate depletion and reorg-tail exposure | Using a cap as a substitute for per-subject loss safety |
| 10 — expiry/revocation | Must not strand an admitted subject's timeout/ACK path | Making execution policy mutable |
| 11 — evidence schemas | Owners and auditors need typed signed evidence | Treating a bare digest as qualification |

**PROPOSED.** If threshold mode is selected, decisions 2 and 4 must record that
threshold release is a separately versioned integrated profile. An existing
N-of-N subject cannot be upgraded by replacing its runtime quorum.

---

## 13. Defects and open questions exposed by this draft

**D3-1 — the adversary model and the threshold fixture classify valid
withholding differently.** The protocol permits up to `N-1` corrupt participants
while the fixture labels every valid-withheld world an assumption failure. This
is the unresolved decision-3 fork, and becomes a contradiction only if threshold
world statuses are adopted without changing the signed corruption model.

**D3-2 — adequate bond accounting is not graph accounting.** The overlay is
absent from V1 transaction bytes and fusion is unauthorized, so a result can
show declared adequacy while remaining funding-ineligible. Any task titled
"close the timeout economics blocker" must begin by serializing a new graph
profile, not by relabelling the analyzer's output.

**D3-3 — the reference bond assigns compensation without proving cause.** Funded
by the selected counterprover, refunded on ACK, paid to the owner on timeout.
Since both worlds share the timeout trace this is strict counterprover liability
in both, not proof of fault. Relabelling the output "compensation" does not
establish cause.

**D3-4 — threshold adoption is a construction, not a parameter edit.** It must
create a named work item with its own proof, connector, ceremony, runtime and
Core evidence, not a boolean or quorum integer on the existing path.

**D3-5 — one `VALID_RELEASE_WITHHELD` status is too coarse.** Threshold
ratification must not blanket-exclude every valid-withheld execution; the
policy/evidence layer needs cause metadata separating within-bound, beyond-bound
and infrastructure failure even when all three share the same Bitcoin terminal.

---

## 14. What decision 3 must not decide

**FIXED:** it must not edit or ratify `58_V026_FUNDS_SAFETY_PROTOCOL.md`.

**PROPOSED:** it must not select the exact `(n,t,f)` tuple or control-domain
roster (decision 5 cross-ratifies); the release boundary (decision 2); exact
CSV, confirmation, reorg, CPFP, fee or halt numbers (decisions 6 and 7); or
initial and aggregate caps (decision 9).

**PROPOSED:** it must not adopt 100,000,660 sat, `(3,2,1)`, 144 blocks, or any
other reference-fixture value as a production parameter; must not treat
cause-blind strict liability as cause proof; must not mark valid withholding an
assumption failure without a justifying signed model and live evidence; and must
not silently reinterpret an N-of-N vector-hash graph as threshold release.

**FIXED:** it must not change `safe_for_funds`, any `funding_eligible` value,
`STATUS.json`, or generated evidence.

---

## 15. Proposed owner decision

**PROPOSED recommendation.**

```text
release_quorum_mode       = T_OF_N_F_BOUNDED
timeout_adjudication_mode = CAUSE_BLIND_STRICT_LIABILITY
strict_liability_provider = SELECTED_COUNTERPROVER
timeout_beneficiary       = exact authority-bound role from the terminal policy
```

The threshold component makes one in-bound participant insufficient to block a
valid ACK; the strict bond makes every residual selected timeout economically
defined without pretending the chain proved its cause.

**Conditional on** explicit acceptance of the weaker corruption theorem (§7.2),
the anti-collusion constraints (§7.6), and an actual serialized bond topology.
Not an endorsement of the reference tuple or bond amount.

**Reviewer's dissent: see §0.3.** The strict-liability assignment places
forfeitable stake on the safety actor and engages `58:861-866`'s separate
mandatory gate. The quorum half of this recommendation is unaffected.

**PROPOSED fallback.** If owners reject the weaker corruption model:
`N_OF_N_ONE_HONEST + CAUSE_DISTINGUISHED`, accepting that graph-v2 finalization
stays blocked on a new cause-evidence construction.

**PROPOSED rejection.** `N_OF_N_ONE_HONEST + CAUSE_BLIND_STRICT_LIABILITY` only
if owners name every unconditional payer and protected-world loss, and every
additional authority required to approve that economic contract signs it.

**PROPOSED.** "Keep N-of-N and decide later" is not an option. It leaves
obligation 4 and the step-1 kill decision open, so graph-v2 finalization must
not proceed.

---

## 16. Ratification block — unsigned

**FIXED.** Owners are **protocol + Bitcoin economics**. Not a decision until
both complete a signed ratification commit.

**Release quorum**

| Role | Named owner | `N_OF_N_ONE_HONEST` | `T_OF_N_F_BOUNDED` | Reject / remain blocked | Date | Signature |
|---|---|---|---|---|---|---|
| Protocol | *(unnamed)* | ☐ | ☐ | ☐ | | |
| Bitcoin economics | *(unnamed)* | ☐ | ☐ | ☐ | | |

**Timeout adjudication**

| Role | Named owner | `CAUSE_BLIND_STRICT_LIABILITY` | `CAUSE_DISTINGUISHED` | Reject / remain blocked | Date | Signature |
|---|---|---|---|---|---|---|
| Protocol | *(unnamed)* | ☐ | ☐ | ☐ | | |
| Bitcoin economics | *(unnamed)* | ☐ | ☐ | ☐ | | |

**Strict-liability fields, if selected:** provider role; timeout beneficiary
role; protected-world status of provider; liability formula digest;
reserve-topology digest; anti-collusion/control-domain policy digest.

**Required acknowledgements** (both owners): the selected pair changes the
security theorem and/or loss bound; no reference-fixture number is adopted; the
current bond overlay is accounting-only and non-authorizing; non-selected mode
combinations are forbidden for this graph profile; graph-v2 finalization stays
blocked until §10 evidence exists; `safe_for_funds` and every
`funding_eligible` remain false. **Additionally, if cause-blind strict liability
is selected:** the §0.3 objection has been considered and either answered or
accepted.

**OBSERVED.** Owner fields are blank because §16 names roles, not people.

---

## 17. What this document does not establish

- **FIXED:** it does not make RankLock safe for funds. `safe_for_funds` remains
  correctly `false`.
- **OBSERVED:** it closes no blocker. It drafts the owner decision that precedes
  implementation and evidence.
- **OBSERVED:** it does not prove the reference bond protects production
  principals, that any `t-of-n` construction is sound, live, implemented or
  Bitcoin-compatible, or that cause-distinguishing evidence can be built under
  the one-honest model.
- **OBSERVED:** it authorizes no fixture value — not `(3,2,1)`, not
  100,000,660 sat, not 144 blocks, not any fixture script or output.
- **OBSERVED:** §1–§17 serialized no graph, ran no Core, executed no Script,
  tested no CPFP or reorg, ran no Rust or Python tests, and regenerated no
  evidence. §0's checks were reads and greps, not runs.
- **OBSERVED:** it selects no release profile, wire profile, participant roster,
  finality depth, fee policy, registry, cap, expiry policy, or audit roster.
- **OBSERVED:** it is not evidence, and must not be cited from `results/` as
  though an owner decision or execution run had occurred.
