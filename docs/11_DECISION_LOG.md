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
