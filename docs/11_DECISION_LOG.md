# Decision Log

## 2026-08-04 — Rebuild v0.13 as a clean handoff

The v0.12 visible package omitted foundational modules and could not reproduce its claimed test count. Reconstructed minimal formal field/group/projective-cost modules, merged v0.10/v0.12 sources, and established a clean baseline.

Decision: all future claims use the clean suite only.

## 2026-08-04 — Downgrade field mismatch from fundamental blocker to implementation risk

A 3×85-bit representation safely embeds BN254 Fq arithmetic into BN254 Fr or BLS12-381 Fr. Generic schoolbook multiplication needs nine native limb products before range/carry overhead.

Decision at the time: pursue one concrete non-native AIR implementation before searching for a new pairing curve. Superseded on 2026-08-05 by the rank-5 convolution schedule below.

## 2026-08-04 — Reject one-shot “one-beacon” AIR API

An invalid trace with a quotient tailored after `zeta` passes the legacy verifier.

Decision: commitments and quotients must be fixed in `phased_air` before beacon-derived `zeta`.

## 2026-08-04 — Reject one-shot tuple permutation API

A non-permutation with `Z=1` and point-tailored `Q` passes the legacy verifier.

Decision: use a two-beacon phase schedule.

## 2026-08-04 — Reject independently committed memory components

Permutation and AIR proofs can refer to unrelated sorted tables.

Decision: require exact shared commitments for the access columns.

## 2026-08-04 — Treat KZG batching as an additional phase

Known `rho` allows false individual opening values to cancel in the aggregate.

Decision: values must be bound before `rho`; account for an extra beacon unless a native PCS removes the requirement.

## 2026-08-05 — Replace schoolbook 3×85 multiplication with rank-5 convolution

Three limbs are coefficients of degree-two polynomials. Five fixed evaluation products determine all five convolution coefficients; interpolation is native-field linear. Coefficient and carry bounds lift the native equations to exact integer equalities.

Decision: the current single-field baseline is 3×85 with five, not nine, native nonlinear products. The known 25,889-product subtotal falls from 233,001 to 129,445 native multiplication gates before parser/hash/PCS costs.

Evidence: `low_rank_convolution.py`, `low_rank_field_bridge.py`, and their adversarial/randomized tests.

## 2026-08-05 — Replace byte-granular lookup accounting with explicit packed tuple accounting

A reusable 16-bit tuple table can range-check one chunk while exposing its constituent bytes and boundary pieces. Canonical serialization therefore costs sixteen logical tuple lookups per 32-byte value, not thirty-two byte lookups. Signed carries can be range-checked as the nonnegative offset `c + M`, avoiding a separate sign-bit multiplication.

Decision: use the packed logical inventory as the current ESTIMATE, while reporting the fixed table size and warning that logical events are not physical rows.

Updated per-product cost points at that stage, with both `z` and quotient fully canonicalized. These are historical and were superseded later the same day by the bounded-quotient decision below:

```text
3×85 rank-5: 5 products +  96 lookups
2×127 split: 4 products + 223 lookups
CRT owner:   2 products +  94 lookups, but cross-field binding missing
CRT lower:   2 products +  66 lookups, not a construction
```

The earlier 132/255/190/98 event counts are superseded byte-granular estimates.

## 2026-08-05 — Keep 2×127 as a benchmark challenger, not the baseline

A BLS12-381-Fr 2×127 split-product construction is exact with four native products. Under the then-current canonical-quotient inventory it required 223 logical lookup events versus 96 for 3×85 rank-5.

Decision at that stage: retain 2×127 for real-backend measurement; it broke even only for `w > 127`. The later bounded-quotient inventory changes these points to 206 versus 76 and the threshold to `w > 130`.

## 2026-08-05 — Do not select dual-field CRT from its two-product core

The executable canonical-byte model links residues in Python, but no cryptographic equality proof binds the BN254-Fr and BLS12-381-Fr PCS traces to one table. Owner-side and free-sharing estimates are therefore unsound cost points, not selectable routes.

Decision: mark CRT non-selectable until a compact cross-PCS common-table binding and conditional-lock conjunction are constructed and costed.

## 2026-08-05 — Add a transparent constraint compiler before real-backend integration

The exact witness verifiers and cost estimators could drift independently. `constraint_backend.py` now executes the modeled multiplication, linear, boundary, and tuple/range relations and asserts exact agreement with each estimator.

Initial reproduced event inventories, before removing the quotient's redundant canonical-slack proof:

```text
3×85 rank-5: 5 multiplications,  96 lookups, 23 linear relations
2×127 split: 4 multiplications, 223 lookups, 30 linear relations
CRT owner:   2 multiplications,  94 lookups, 36 linear relations
```

Decision: use the event stream as the integration contract for P0-PCS-1. The reduced-quotient entry below updates the normative stream and counts. Do not call it a proof system; it has transparent witness access and no PCS, lookup argument, degree bound, or cryptographic cross-field binding.


## 2026-08-05 — Remove the internal quotient's redundant canonical-slack proof

For canonical `x,y,z < q`, the exact integer relation `x*y = z + quotient*q` uniquely determines every nonnegative quotient. The honest quotient is at most `q-2` and therefore fits 254 bits. A separate witness for `quotient + slack = q-1` does not restrict the relation further.

The transparent compilers now range-check 254 quotient bits and bind those chunks to the arithmetic limbs, while keeping `z` canonical. A regression corrupts the unused quotient slack/carry fields and still passes; byte, limb, arithmetic, and bit-bound tampering remains rejected.

For dual-field CRT, the residual magnitude is below `max(q^2, 2^b*q)`. BN254 Fr times BLS12-381 Fr gives a safety ratio of approximately `1.81138` for `b=254`, but `0.90569` for `b=255`. Thus 254 bits is the largest quotient range certified by this bound.

Updated 16-bit logical cost points:

```text
3×85 rank-5: 5 multiplications,  76 lookups, 17 linear relations
2×127 split: 4 multiplications, 206 lookups, 26 linear relations
CRT owner:   2 multiplications,  63 lookups, 20 linear relations
CRT lower:   2 multiplications,  49 lookups, 12 linear relations
```

Decision: use the bounded internal quotient as the normative field-bridge semantics. The earlier 96/223/94/66 lookup points remain historical canonical-quotient references only. 2×127 now breaks even only when a multiplication costs more than 130 logical lookup events.

## 2026-08-05 — Unify AIR and permutation opening points

AIR trace/quotient commitments are fixed before permutation beacon one. Delaying AIR opening until permutation phase two is committed permits one combined second-beacon `zeta` for both components.

Decision: the phase-correct memory proof uses a shared `zeta`; after value publication and beacon-three batching, 72 individual KZG openings reduce to four opening statements at `zeta`, `zeta+1`, `0`, and `row_count`.

Evidence: `unified_memory_opening.py` and `tests/test_unified_memory_opening.py`.

## 2026-08-05 — Opening count is not the main CDS blocker

Four dynamic KZG-WE headers and four pairings are small. Standard multi-constraint KZG-WE grows linearly, but same-point batching makes the current conjunction compact.

Decision: stop treating dozens of opening equations as the decisive obstacle. The decisive obstacle is static encapsulation to future commitments and values.

## 2026-08-05 — Reject reusable public affine updates for standard KZG-WE

Two standard headers under one reused randomizer reveal `r[1]_2`, making every KZG-WE session public.

Decision: a direct solution must use one-time selected projective delivery, a fixed authenticated-witness relation, or a stronger commitment-oblivious primitive. Do not expose a reusable standard-header updater.

## 2026-08-05 — Treat authenticated witness lift as prior-art-adjacent

Future inputs can be witness variables in a fixed relation when unforgeable authentication binds them to the protocol event. The generic gadget/composition methodology is covered by the 2025 LVA-WE framework.

Decision: novelty must come from the concrete RankVM/authenticated-input compiler, malicious activation, and complete performance/security improvement—not the generic witness lift.

## 2026-08-05 — Compress authenticated future inputs with BLS plus inner product, but require one-time delivery

A fixed per-deposit relation can authenticate all 132 future bytes with one aggregate BLS signature equation and one inner-product constraint tying the aggregate public key to the same byte witnesses consumed by RankVM. This matches prior-art LVA-WE gadget shapes, so the generic compression is not a novelty claim.

The affine token family leaks its slope after two values for one coordinate and one session. The full 256-entry token catalog likewise lets an evaluator select arbitrary bytes.

Decision: retain the algebraic authenticated-input relation as the P0-CDS-2 candidate, but make one-time selected delivery a formal security requirement. Account for the naïve 1,622,016-byte token catalog and do not claim a sub-megabyte artifact until a projective delivery construction is instantiated.

## 2026-08-05 — Replace the naïve affine-token catalog with a vector-OLE candidate

The selected BLS-token scalar is an affine function `t_i=a_i+v_i b_i`, exactly matching vector OLE. Duty-Free Bits already supplies a malicious-receiver vector-OLE-from-bit-OT primitive with `O((lambda+n) log p)` communication.

For 132 coordinates and a 255-bit field, the literal leading expression is 66,300 bits (8,288 bytes), before constants and base OTs. Public affine bases add 25,344 modeled bytes. This is far below the 1,622,016-byte naïve token catalog, but it is not a concrete implementation byte count.

Decision: promote DFB vector OLE plus aggregate BLS/inner-product authentication to the leading P0-PROJ/P0-CDS input candidate. Require one-shot sender state; a second vector query recovers affine secrets. Do not claim the projective layer is solved until the real protocol, malicious distributed generation, restart semantics, and complete bytes are measured.

## 2026-08-05 — Accept real OT/KZG components, reject complete hybrid

Real secp256k1 OT/projective input delivery and actual BN254 KZG-opening WE both pass adversarial tests. Their direct XOR hybrid needs an online trace encapsulator because the KZG statement is future-dependent.

Decision: keep both primitives as concrete baselines; reject the hybrid as a no-online-authority solution.

## 2026-08-05 — Move future statements into a fixed relation witness

A fixed linear relation successfully combines future authenticated bytes and a future trace witness under one setup-time ciphertext.

Decision: timing blocker is closed for fixed relations. Succinctness and complete RankVM semantics remain open.

## 2026-08-05 — Batch relation-key setup proofs

One random-linear-combination DLEQ replaces one proof per scaled base and approximately halves the per-coordinate key slope.

Decision: adopt as reference ROM setup check; do not treat it as malicious distributed activation.

## 2026-08-05 — Kill direct full-trace fixed-linear relation

Current full logical inventory would retain 159.82 MiB; even multiplication-only retains 8.27 MiB.

Decision: require a succinct/folding/recursive wrapper or structured LVA gadgets.

## 2026-08-05 — Reject unvalidated parallel breakthrough label

The parallel checkpoint’s R1CS/IPA backend failed two tests.

Decision: merge only independently passing formal components and relabel them as a candidate.

## 2026-08-07 — Kill generic public algebraic PCG expansion for independent verifier bases

**Result:** exact coefficient-rank analysis shows that a public source-group expander using group
addition and public-scalar multiplication needs at least the rank of the desired hidden-scalar
bases. Independent per-event bases therefore need one seed direction per event.

**Decision:** do not pursue an ordinary public PRG/PCG seed as a replacement for the direct
verifier-key table. Standard PCGs remain relevant inside a multi-party setup because their seeds
are private party state. Scope: algebraic source-group lower bound, not a universal computational
impossibility theorem.

## 2026-08-07 — Accept low-rank fixed-G2 correlation compression

**Result:** a real BN254 construction stores `k` scaled G2 anchors for a rank-`k` fixed-base PPE.
An 11-term / 2-anchor envelope uses 1,719 total retained bytes and two decryption pairings in the
current serialization model.

**Decision:** make fixed-G2 coefficient rank an explicit compiler metric. This closes verifier
correlation storage only after a proof system supplies the low-rank pairing relation.

## 2026-08-07 — Replace “compact PCG” target with target-separated wrapper target

**Result:** KZG/PLONK-style equations have low fixed-G2 rank but identity target; Groth16 has a
nonidentity target but a future G2 proof element. Neither directly matches the lock interface.
Publishing a target decomposition over scaled anchors also breaks the real prototype.

**Decision:** target a transcript-bound, knowledge-sound wrapper with only future G1 terms,
constant/polylog fixed-G2 rank, and a nonidentity target unavailable from public scaled-anchor
preimages.

## 2026-08-07 — Same-scalar proof is not malicious distributed activation

**Result:** replacing the ciphertext leaves the common-scalar setup proof valid and creates an
undetectable activation-time denial of service until a satisfying future witness appears.

**Decision:** require a public proof that encrypted fault/adaptor shares match their commitments
and the activated Bitcoin condition. P0-SETUP-1 remains open.

## 2026-08-07 — Replace nonidentity-target rule with split-basis/session separation

**Evidence:** real BN254 KZG-as-split-basis construction and statement-span disclosure attack.

**Decision:** identity normalization is not a universal blocker. The lock is safe only when the statement session cannot be reconstructed from the scaled witness-anchor span.

## 2026-08-07 — Accept one-sided rank-two final equation as the wrapper target

**Evidence:** real BN254 equation with only future G1 proof elements and rank-two fixed G2 bases; modified proof elements are rejected.

**Decision:** continue the one-sided wrapper route, but treat its full proof system, outer curve, and CRS as unimplemented.

## 2026-08-07 — Kill raw hidden-challenge adaptation

**Evidence:** all ten audited Fiat–Shamir challenges enter nonlinear prover work.

**Decision:** verify the public transcript inside the fixed relation or design a new LVA protocol.

## 2026-08-07 — Remove encrypted fault-secret payload

**Evidence:** the accepting pairing session deterministically derives a real secp256k1 scalar and public point; changed witnesses fail to recover the activated key.

**Decision:** use session-derived Bitcoin keys. Activation now proves anchor/session/public-key consistency, not ciphertext correctness.

## 2026-08-07 — Adopt tight fixed-statement wrapper envelope as the next implementation gate

**Evidence:** the 300-constraint/G1 scenario totals 1,036,471 bytes including the future proof; 400 constraints/G1 fails.

**Decision:** proceed only if the real shared point/transcript gadget stays below approximately 325 constraints per G1 under the current proxy. Do not call this a construction until the proxies are replaced.

## 2026-08-11 — Close the real DFB/Embryo execution gate

A reference-compatible implementation now generates, serializes, reparses and evaluates the full 1,795/1,282 affine map. The deterministic artifact passes the fixed-key AES CCRH vector, all 256 conditional Jacobian checks, the five-element curve check and final BN254 `[r]A` equality.

Decision: mark `P0-DFB-1` complete at the research-execution level. Correct execution does not imply adaptive privacy, malicious setup security or production readiness.

## 2026-08-11 — Separate join payload from final output masks

The real fused-extraction join stream is 449,779 bytes, 61,440 bytes below the v0.21 paper-derived slot model. A standalone public evaluator additionally needs 228,083 bytes of final CRT output masks, giving a 677,862-byte slot.

Decision: withdraw the v0.21 two-complete-slot sub-MiB envelope as a current claim. Two standalone slots plus the historical 748-byte manifest total 1,356,472 bytes, 307,896 above one MiB.

## 2026-08-11 — Promote output-mask fusion to the primary gate

The remaining storage question is whether Embryo can consume DFB's masked outputs directly without serializing one final mask residue per affine output, while preserving correctness and the required adaptive multi-instance privacy.

Decision: set `P0-MASK-FUSION-1` as the primary gate. Kill the two-slot sub-MiB route if no sound fusion or compression exists.

## 2026-08-11 — Require byte-only artifact replay

The release now emits a 677,862-byte standalone bundle and two future input-label files, reparses them independently, and reevaluates the complete application. Truncation, non-canonical padding and payload mutation fail closed.

Decision: in-memory garbler state is no longer accepted as evidence for the exact artifact gate.

## 2026-08-18 — Bind fixed NACKs by complete transaction at both boundaries

The imported v0.25.2 handoff closed ACK preimage verification but still routed
and accepted the supposedly fixed NACK using only its witness-excluding
BIP141 `txid`. An adversarial finalized NACK with one witness byte changed kept
the same `txid` and reached the old recognition condition.

Decision: reconstruct the finalized NACK from persisted signatures and compare
the complete transaction independently in the classifier and the state
transition. Preserve separate same-txid/different-witness regressions for both
boundaries. Treat the earlier ACK-only P4 result as incomplete, and keep funds
disabled until the production proof-to-ACK boundary and STRATA-010..020 are
executed.

## 2026-08-18 — Require manifest coverage, not only hash verification

The standalone integration manifest passed `shasum -c` while omitting every
post-format P4 diff, because the checksum tool verifies only named paths. Those
unlisted files are executable installer inputs and include the witness-binding
security fixes.

Decision: compare the exact distributable file set against the manifest before
checking hashes, fail on either missing or extra paths, and pin all three P4
deltas in a regression test. A hash ledger with no coverage assertion is not
release-integrity evidence.

## 2026-08-18 — Make ACK publication write-once and setup-bound

The exporter could overwrite a setup commitment, trusted an unchecked SQLite
path, and let colliding publishers commit separate ledger rows before racing
on one predictable output name. The proof-gated call also did not prove that
its expected commitment was the commitment already used for graph setup.

Decision: use private inode-checked ledger storage and write-once file
publication, validate exact private bytes after every publication, require the
published setup commitment before proof-gated export, and preserve a released
binding when the exact bytes are visible but only directory-sync reporting is
ambiguous. This is local host hardening; it does not replace external rollback
witnesses.

## 2026-08-18 — Bind the proof session to the complete ACK destination

The proof-gated exporter accepted a caller-supplied positive-lock session and
an independent `AckContext`. A valid unlock could therefore authenticate one
statement while selecting another bridge/transaction tuple for publication,
including a tuple sharing the same partial setup-commitment path.

Decision: remove `session_context` from the release API. Setup and release both
derive the positive-lock session from the complete canonical `AckContext`, so
the authenticated statement, output filename and one-shot ledger identity
cannot diverge. This closes the local redirect but does not supply the missing
deployed producer.

## 2026-08-18 — Accept only unavailable or exactly pinned Core evidence

The hardening generator accepted only an unavailable Core report, so the
official reproduction workflow failed after a successful run of the qualified
binary.

Decision: accept either an explicit unavailable fail-closed result or a
successful Core 31.1 result carrying the exact numeric version and qualified
binary SHA-256. Reject contradictory, incomplete, wrong-version and
wrong-binary success reports.

## 2026-08-18 — Never hide abort/rollback-witness recovery failure

The two-phase sidecar silently swallowed failures while finalizing and
anchoring an abort after the primary phase-two error.

Decision: surface the primary and recovery failures together through a typed
error. A caller must never mistake a rejected operation for a durably witnessed
abort when recovery itself failed.

## 2026-08-18 — Wire the RankLock consumer and pin the deployment image

The Strata executor read `STRATA_RANKLOCK_DIR`, but compose neither set nor
mounted it and still selected Bitcoin Core 30 by mutable tag while qualification
used Core 31.1.

Decision: require an explicit host RankLock export root, mount it read-only in
all three bridge containers, set the executor path, and pin the Core 31.1
multi-architecture digest. This wires only the consumer; it does not count as
proof-to-ACK deployment until a verified producer exists and STRATA-010..020
execute.

## 2026-08-18 — Reject coercible setup secrets and context fields

Python's `bytes(integer)` constructor creates that many zero bytes. The setup
derivation therefore accepted integer `32` as public all-zero entropy despite
its `bytes` annotation, and context parsing similarly accepted coercible
indices and mutable byte containers.

Decision: validate runtime types before conversion, require immutable exact
bytes in durable ACK contexts, require real bounded integers for u32 fields,
and length-prefix entropy under a bumped v2 derivation domain. Type hints are
not a security boundary, and changed derivation semantics must not retain the
old domain version.

## 2026-08-18 — Make provenance mandatory for passing matrix phases

The verifier's Core-hash and Strata-commit comparisons ran only when both
identity fields existed. Omitting a field therefore skipped the check.

Decision: require the pinned Core executable hash for every phase with passed
cases, require the pinned Strata commit for passing Strata evidence, and make
the E2E runner record the resolved Core path, hash and version. Absence can
describe an unexecuted phase; it cannot accompany a pass.

## 2026-08-18 — Regenerate artifacts after generator-critical source changes

The imported branch's public conformance binaries did not match fresh output
from its own generator-critical source. Two clean generations agreed with each
other, ruling out runtime randomness and identifying stale packaged artifacts.

Decision: regenerate all ten changed committee/split-scalar artifacts and
their canonical evidence, then require a clean extraction to reproduce them
byte-for-byte. A prior report for a different archive digest does not qualify
the current source tree.

## 2026-08-18 — Keep post-build qualification outside its subject archive

The clean report contains the source-archive digest, and the v0.25.2 release
gate contains the clean-report digest. Packaging either report creates a
checksum cycle after qualification.

Decision: exclude both post-build companions from the v0.25.1 source archive,
retain pre-build matrix evidence, and regression-test that boundary. The final
gate and clean report are detached evidence over an already fixed archive. An
absent optional clean companion must be represented as absent and keep the
fact false; it must never be dereferenced merely because the CLI has a default
path.

## 2026-08-19 — Select shared counterproof gating, but reject it as universal proof

The per-slot no-counterproof-gate proposal allowed several counterproofs to
confirm and then stranded every losing resolution behind shared settlement
inputs. Requiring owner payout to spend all per-slot gates also expanded its
dynamic presignature surface.

Decision: use the existing contest-payout outpoint as the graph-v2 global
selection gate. Every `CounterproofV2_i` and owner payout spends it; the winner
creates one resolution connector; ACK and timeout conflict on that resolution;
timeout conflicts with slash and its declared template allocates the exact
deposit amount to a committed recovery-policy script. Preserve this as a narrow
output-allocation direction only until descriptor control and terminal
reachability are independently established.
The executable abstract model must remain non-authorizing because Bitcoin
cannot distinguish a valid counterproof whose N-of-N release was withheld from
an invalid counterproof with no release. Do not claim universal funds safety
without consensus-valid adjudication, a newly audited threshold-availability
theorem, or fully reserved coverage of both worlds.

Independent review rejected the first positive field name and exposed missing
terminal edges: current Slash is not ACK-gated and can consume the settlement
input after counterproof selection, while live claim-payout burn parents can
consume another settlement input. Decision: rename the executable result to
`counterproof_selection_allocates_exact_deposit`, add terminal-disposition and recovery-
control funding blockers, count the no-counterproof branch's full abandoned
reserve, forbid graph-owner change, require one exact independent CPFP output,
and bind the result to a deterministic fixture/generator. Shared selection
remains a direction, not a recovery theorem.

Independent review also found that reusing the counterproof/ACK CPFP actor as
the timeout broadcaster lets the actor who selects the counterproof control a
timeout-critical path. Decision: use distinct counterproof/ACK and timeout CPFP
descriptors, require recovery and timeout-broadcaster controls to be disjoint
from graph-owner, release, and counterproof controls, and retain separate
funding blockers until those controls are verified against exact Bitcoin
descriptors.

A further audit found that the first model named the two counterproof
alternatives like RankLock query slots and used one CP/ACK descriptor for all
watchtowers. Decision: the graph dimension is an ordered `u32` Strata
watchtower/counterproof alternative roster, independent of the exactly two
RankLock query slots. Bind one CP/ACK CPFP descriptor per alternative and one
common resolution connector value/script/policy commitment; keep resolution
Script semantics categorically unverified until the versioned Rust connector
and Bitcoin Core tests exist.

The next terminal audit superseded that layout. Decision: `CounterproofV2_i`
spends the selected counterproof input, shared contest-payout output, and
deposit, then immediately allocates the exact deposit amount to the recovery
descriptor while creating the resolution and CPFP anchor. This makes every
legacy deposit spender invalid after counterproof confirmation. `ACKV2_i`
spends only the resolution and creates a distinct slash-authorization output
plus its CPFP anchor. `SlashV2_i` must spend that authorization, contest-slash,
and exclusively reserved stake, so Slash has consensus-visible ACK provenance.
Timeout spends resolution and contest-slash, but never deposit or the
independently burnable claim-payout output. Before counterproof confirmation,
the existing D-only CooperativePayout remains a possible hidden-signature race;
keep funding blocked until an exhaustive one-subject presign/erasure theorem or
a confirmed script-only deposit cutover excludes it.

## 2026-08-19 — Accept the v0.26 Rust graph as research evidence only

At this checkpoint (superseded by the atomic-reserve decision below), the
side-by-side Rust slice contained typed NUMS connectors, exact
Contest/Counterproof/ACK/Timeout/Slash/Owner templates, and a canonical
private-field `V026Graph` assembler. Five real Bitcoin Core tests independently
accept both counterproof alternatives, the mature owner payout, ACK, timeout at
the exact CSV boundary, and an ACK-descended Slash. Losing branches are retried
only after their own maturity, so rejection is attributable to the intended
shared inputs rather than an incidental timelock. Two independent read-only
audits found no P0/P1 within that scope.

Decision: classify this as **REPRODUCED research evidence**, not activation
evidence. Keep all fifteen assembler blockers and funding disabled. In
particular, the Core suite deliberately demonstrates that a separately signed
live-key stake spend can preempt Slash. Do not translate local graph structure
into stake exclusivity, complete presign/erasure, runtime admission, ASM
activation, or universal funds-safety claims. The next integration boundary is
a versioned runtime/admission consumer of the exact graph digest; it must not
mint a `funding_safe` capability.

## 2026-08-19 — Persist only a funding-blocked runtime observation

Current GraphData, signed content bytes, GraphSM persistence, and bridge duties
are v1-specific and cannot reconstruct or admit the v0.26 plan. Extending them
before the wire profile is frozen would invent activation identity and mutate
existing persisted enums.

Decision: add only a separate `StructurallyVerifiedFundingBlockedV1` lane. It
persists a local txid manifest plus the exact fifteen blocker codes under an
`RL26ADM` V1 envelope and a separate FDB subspace. Creation is atomic
first-writer-wins; exact replay is idempotent; a different manifest is an
explicit non-overwriting conflict. Parse→canonical-reencode equality is
mandatory, and the row/key/value types are crate-private so callers cannot use
the generic DB primitive to inject a mismatched body. There is no transition
from this record to admitted, ready, signing, duty, P2P, funding, or broadcast
state. Any future active certificate is a different versioned authority after
canonical wire identity and evidence verification exist.

## 2026-08-19 — Enumerate terminals, but reject caller policy as a theorem

Pairwise conflict checks could not establish who controls terminal value or
whether residual outputs are independently spendable by a fixed horizon.
Decision: add deterministic live-UTXO enumeration and require one disposition
for every positive terminal output. The two-alternative reference must produce
exactly five maximal traces and seven semantic worlds, with valid-withheld and
invalid-absent sharing the exact timeout trace.

Adversarial review then showed that a caller could relabel a recovery output,
reuse a policy digest after changing spendability, invent vacuous baselines,
inflate service fees, or vary an unused horizon. Decision: bind dispositions to
committed beneficiaries, derive the policy digest from canonical content, and
rename the positive engine result to `AbstractDeclaredPolicySatisfiedV1`.
Never call it a theorem. Baseline authority, per-principal allowances,
service-fee schedule/baseline authority, and by-horizon CSV/reorg/fee execution
remain immutable qualification blockers. At this checkpoint the committed
reference returned typed infeasibility with six locked-reserve witnesses and
remained non-fundable; the atomic-reserve decision below supersedes only that
reserve-disposition result.

## 2026-08-19 — Replace reserve sweeps with atomic all-reserve selection

A delayed per-reserve sweep was rejected because CSV provides earliest
validity, not priority: after maturity the immediate counterproof and sweep
would race for the same `C_i`. An aggregate sweep was also rejected because one
selected reserve makes it invalid, while subset sweeps require an exponential
template family.

Decision: every CounterproofV2 sibling atomically spends the complete ordered
`C` roster, followed by shared `P,D`; its selected input uses the
graph-plus-operator leaf and every sibling input uses the graph-only
reserve-recovery leaf. It returns each non-selected reserve at exact face value
to its setup-bound beneficiary. Owner payout atomically spends `D,Q,P,S` plus
the complete `C` roster and returns every reserve. This removes abandoned
reserve value without introducing a post-CSV race, while preserving the
selected equation after exact returns cancel.

The construction is not a covenant. Qualification still requires an exhaustive
exact-template signing allowlist, one-honest key/nonce/derivation/backup
erasure, and exclusion of legacy/off-transcript signatures. It also has
quadratic presign/storage growth and version-3 relay limits. The measured
two-alternative, `n_data=128` CounterproofV2 is 10,690 WU: Core rejects it as an
unconfirmed v3 child and accepts the identical signed transaction after Contest
confirms. Add `AtomicRosterWeightEvidenceUnverified` as blocker sixteen and do
not derive a general roster bound from this fixture.

The abstract reference now returns `AbstractDeclaredPolicySatisfiedV1` with
zero abandoned reserve value. This supersedes the locked-reserve result only;
it remains non-fundable and is not a protected-value theorem.

## 2026-08-19 — Preserve observation V1 and add a non-forgeable V2 lane

Appending blocker sixteen to the existing `RL26ADM` V1 record would silently
change a frozen persisted schema. Decision: keep the exact fifteen-code V1
bytes, decoder, DB methods, and subspace; make V1 fail closed for the current
graph; and add a separate V2 envelope, sixteen-code registry, FDB subspace, and
typed CAS outcome.

Independent review found that public `Deserialize` on the live observation type
let callers mint a value named `StructurallyVerified` without running the graph
verifier. Decision: live V1/V2 write capabilities are observer-created and not
deserializable. Private wire DTOs decode into validated persisted read models,
preserving V1 golden bytes without minting a write capability. Neither version
has any transition to funding, signing, duties, P2P, or broadcast.

## 2026-08-20 — Treat subject receipt confirmation as a live reorg-sensitive capability

A subject-bound receipt proves a relation over a BridgeProof transaction id,
but it is not itself evidence that the exact witness-bearing transaction is
confirmed on Bitcoin's active chain. Persisting or cloning a successful lookup
would also erase the time at which its reorg assumption held.

Decision: compose the unforgeable receipt with an exact Bitcoin Core
transaction lookup, minimum depth, Merkle-valid block membership, active
height/hash identity, and a repeated lookup before returning. Represent success
as a non-serializable, non-cloneable point-in-time capability. Do not add it to
the legacy preimage duty, do not persist it as admission, and do not let it
authorize release or funding. A versioned threshold runtime must recreate and
consume the capability immediately before ACK witness publication, with an
explicit reorg rollback policy. Until a valid receipt and that consumer exist,
funding remains disabled.

The next narrow slice composes the live confirmation with an exact
observer-verified ACK witness and immutable selected-commitment CAS. It checks
the receipt subject and witness-stripped transaction, queries Bitcoin before
and after the database action, and rejects conflicts. This is still a helper,
not enforced runtime authority: the lower-level database method remains
callable, an FDB write cannot be atomic with Bitcoin consensus, and no positive
receipt executes the path. Durable rows remain inert and funding remains
disabled.

## 2026-08-23 — Give the seventeen-blocker threshold-v3 observation a persistence envelope

The live threshold-v3 admission path validates seventeen activation blockers,
but FoundationDB row specs stopped at the fifteen-blocker V1 and sixteen-blocker
V2 envelopes. A V3 observation had nowhere to be durably recorded, so the
seventeen-blocker set existed only in memory.

Decision: add a separate `v026_admissions_v3` row spec, subspace, and envelope
version 3, exactly as the 2026-08-19 V1-to-V2 split did. Frozen V1 and V2 bytes,
decoders, and subspaces are untouched, and the V3 decoder refuses every envelope
version other than 3 — so no earlier row can be reinterpreted under the
seventeen-blocker schema. The V3 row is keyed by the content-derived
funded-setup digest rather than a `GraphIdx`, matching the threshold-v3 ACK
witness rows, because a V3 observation carries no graph index.

As with V1 and V2 the stored row is an inert value. It is not admission, not
receipt or chain authority, and has no transition to funding, signing, duties,
P2P, or broadcast. Both the live and persisted types report
`funding_eligible = false` by construction, and the write outcome remains a
typed first-writer-wins Created/ExactReplay/Conflict with no funding path.

The envelope reuses the frozen seven-byte `RL26ADM` family magic. Protocol §4.2
mandates an eight-byte magic, so the whole family is nonconformant; that is
recorded as defect D-1 in
`60_V026_DECISION4_WIRE_SIGNATURE_PROFILE_PROPOSAL.md` and belongs to the
wire-profile owners. Diverging here would fork the header layout under a shared
magic — strictly worse than being consistently nonconformant, because a reader
dispatching on `RL26ADM` plus a `u16` version would misparse. Moving the family
to eight bytes is a new envelope version and a new subject, not an edit to this
one.

Codec, key-packing, and fail-closed negatives are covered by pure tests that
need no cluster. Live FoundationDB execution remains unverified: no `fdbserver`
runs on the development host, and the existing `fdb::bridge_db` tests
additionally panic on `the fdb select api version can only be run once per
process`, which makes them unrunnable except serially.

## 2026-08-24 — Isolate FoundationDB tests per test rather than per process

The `strata-bridge-db` suite failed 33 of 68 tests on a host with no running
FoundationDB. Restoring a cluster fixed those, but the suite then failed 11 of
69 under the default parallel harness while passing serially. The convenient
reading — that FDB tests simply need `--test-threads=1` — was wrong, and acting
on it would have preserved the defect behind a flag.

Two distinct causes were conflated. The
`the fdb select api version can only be run once per process` panics were a
cascade, not a cause: `OnceLock::get_or_init` re-runs its closure when the
closure panics, so one failed `FdbClient::setup` against a dangling cluster file
left the cell empty and every later test re-entered setup. With a working
cluster that message does not appear at all.

The real defect is that `get_client()` built one client under one root
directory and shared it across every test, making one keyspace for the whole
suite. proptest draws from a per-test deterministic seed, so different tests
routinely generate the same key; in parallel one test read a row another had
just overwritten. Caught directly: `deposit_state_roundtrip` read back a
`DepositSM` carrying its own `deposit_idx` but a different test's
`operator_table`.

Decision: isolate by keyspace, not by serializing the harness.
`FdbApiBuilder::build` and the `NetworkAutoStop` network thread are genuinely
once-per-process, but `Database::new` and the directory layer are not. A
test-only `FdbClient::additional_in_root` opens a further client in its own root
directory without re-selecting the API version, and a `get_client!()` macro keys
each test's keyspace to its own name. `process_client()` still boots the network
exactly once and its `MustDrop` guard outlives every derived client.

Collisions between tests are now impossible rather than improbable. The suite
passes in parallel across repeated runs, in roughly 16 seconds against 125
serially — the serialization was most of the runtime. No production code path
changed: the new constructor is `#[cfg(test)]`, and no row, blocker count, or
funding flag moved.
