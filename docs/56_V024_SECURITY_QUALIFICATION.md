# RankLock v0.24.1 conditional security qualification

**Date:** 2026-08-13  
**Scope:** two independently randomized, one-shot DFB/Embryo slots tied to one hidden BN254 scalar  
**Decision:** the corrected two-instance theorem has an executable construction and a reduction path. The result is **conditional**, in the random-oracle model, and is not a production-funds approval.

## 1. What this version proves—and what it does not

RankLock v0.24.1 addresses the security question that remained after v0.23 reached the one-MiB storage target:

> Two independently randomized retained objects use the same hidden scalar `r`. An evaluator sees both offline objects, chooses `A1`, receives `[r]A1`, then chooses `A2` after seeing the first transcript and receives `[r]A2`. What additional power does the retained view provide?

The v0.24.1 claim is deliberately narrower than “the adversary learns nothing about `r`” and narrower than “it cannot derive any third group output.” Both formulations are false or imprecise:

* the authorized outputs themselves depend on `r`;
* from `Y1=[r]A1` and `Y2=[r]A2`, anyone can derive `[r](uA1+vA2)=uY1+vY2` for known scalars `u,v`.

The corrected claim is:

1. the sealed RankLock/DFB artifacts add no efficiently usable information about `r` beyond the two authorized outputs and explicitly declared public positive-lock side information;
2. exactly two context-bound protocol evaluations can be accepted;
3. unissued, malformed, mixed-slot and replayed labels cannot be accepted except by breaking the stated authentication assumptions;
4. a third **independently sampled post-query challenge** cannot be answered except by breaking the stated one-more scalar-multiplication assumption; and
5. algebraically derived raw group points are not confused with an authorized third RankLock evaluation.

The theorem remains conditional on the exact fused slot satisfying the selective DFB/Embryo privacy reduction under CCRH, on the Bellare–Hoang–Rogaway random-oracle transform, and on the explicit authentication and group assumptions listed below.

## 2. Construction chronology

For a context digest `ctx` and slots `i in {0,1}`, setup performs the following before either evaluator point is known.

1. Generate two complete fused plaintext slots `P0,P1` using independent DFB tapes, Embryo tapes, deltas, masks, PRF state and nonce namespaces, while tying both slots to the same hidden scalar `r`.
2. Sample independent 256-bit program seeds `R0,R1`.
3. Seal the complete slot—including the DFB program and fused decoder/mask state—using

   ```text
   Ci = Pi XOR SHAKE256("ranklock/rom-prv-to-prv1/program-pad/v1", ctx, i, Ri, |Pi|).
   ```

4. Independently sample every projective input-label pair. Commit all 1,024 labels per slot—two labels for each of 256 x-coordinate bits and 256 y-coordinate bits—in a canonical Merkle tree. Bind its root to `ctx`, the slot id and `H(Ri)`.
5. Bind the ciphertext root, label root, positive lock, generator-code digest, ceremony transcript digest and contributor keys into the signed activation manifest.
6. Publish the manifest and both ciphertexts.

The online sequence is then:

1. the evaluator fixes canonical `A1`;
2. the authorization path atomically releases `R0` and exactly one committed label for every coordinate bit, signed over the complete context, slot, point, root and authorization transaction id;
3. slot 0 is irreversibly burned before point parsing, opening verification or evaluation, and returns `Y1=[r]A1` if valid;
4. the evaluator chooses `A2` after seeing the complete first transcript and `Y1`, while slot 1 is still sealed;
5. slot 1 follows the same release-and-burn path and returns `Y2=[r]A2`;
6. no third slot exists, and either slot rejects replay.

The executable qualification fixture derives `A2` from `SHA256(Y1)`, so the second point is genuinely transcript-adaptive rather than merely different.

## 3. Formal game

Let `Lr` denote the explicit public BABE/positive-lock side information tied to `r`. This theorem does not hide or re-prove `Lr`; its security remains a separate assumption.

The real game is:

```text
r <- Zq*
(P0,E0),(P1,E1) <- independent fused setup under r
R0,R1 <- {0,1}^256
C0 <- P0 XOR RO(ctx,0,R0)
C1 <- P1 XOR RO(ctx,1,R1)
rho0 <- Commit(ctx,0,H(R0),E0)
rho1 <- Commit(ctx,1,H(R1),E1)
M <- signed manifest(ctx,Lr,C0,C1,rho0,rho1,...)

A1 <- Adv(M,C0,C1,Lr)
release0 <- Authorize(ctx,0,A1,R0,E0)
Y1 <- Evaluate(C0,release0) = [r]A1

A2 <- Adv(M,C0,C1,Lr,A1,release0,Y1)
release1 <- Authorize(ctx,1,A2,R1,E1)
Y2 <- Evaluate(C1,release1) = [r]A2

return Adv's final output and complete view
```

The ideal simulator receives:

```text
ctx, public shape metadata, Lr, A1, Y1, A2, Y2
```

but never receives `r`.

### Corrected theorem

Assume:

* `FusedSel` is selectively private for the exact uniform-pad, mask-fused DFB/Embryo slot, with a simulator that may begin from a fixed uniformly distributed selected projective input encoding;
* the exact CCRH/PRF implementation is secure for legal, domain-separated nonce queries;
* the whole-slot mask is modeled as a programmable random oracle with independent 256-bit seeds;
* the pre-published input-label commitment is binding and computationally hiding for independently sampled 128-bit label pairs;
* the authorization signature is EUF-CMA secure;
* inputs are canonical non-infinity BN254 G1 points in the prime-order subgroup;
* the positive lock satisfies its own security definition for the explicit side information `Lr`.

Then there exists a probabilistic polynomial-time simulator `S` such that

```text
View_real(r)  ~=c  S(ctx, shape, Lr, A1, [r]A1, A2, [r]A2).
```

A conservative decomposition is

```text
Adv_view <= 2 Adv_FusedSel
          + Adv_CCRH/PRF
          + 2 Qpre / 2^256
          + Adv_label-root-hide
          + eps_no-wrap
          + eps_exceptional
          + eps_sampler-watchdog.
```

For the executable parameterization:

* `Qpre = 2^64` random-oracle queries per unreleased slot gives a two-slot seed-guessing term at most `2^-191`;
* the two-slot no-wrap conditioning union bound is below approximately `2^-129.12`;
* the hidden exceptional-point union bound is below approximately `2^-243.6`, in addition to the ROM bad event;
* the 65,536-attempt exact-sampler watchdog has per-pad failure exponent above 1.5 million bits for every CRT prime.

These are concrete statistical/bad-event terms. They do not replace the computational selective-privacy and CCRH assumptions.

## 4. Simulator and hybrids

### H0 — real execution

Both complete plaintext slots are generated honestly under the same `r`, independently sealed, and activated before `A1`.

### H1 — opaque offline artifacts

Before a program seed is released, replace each whole-slot ciphertext by an independent random string of the same length. Under the random-oracle transform this is perfect unless the adversary queried the corresponding 256-bit seed beforehand. Across two slots the bad-event probability is bounded by

```text
2 Qpre / 2^256.
```

The simulator can generate the signed public shape, seed commitments and projective label roots before the inputs because these values require no knowledge of `r`.

### Why the pre-published label roots do not require equivocation

For each bit `j`, setup samples a uniform 128-bit base label `M_j` and an independent nonzero Free-XOR delta `Delta`. The two labels are

```text
L_j,0 = M_j
L_j,1 = M_j XOR Delta.
```

For any fixed bit vector `x`, the selected vector is

```text
L_x = (M_j XOR x_j Delta)_j.
```

For fixed `x` and `Delta`, the map `(M_j)_j -> L_x` is a bijection. Therefore the entire selected encoding is jointly uniform even though all pairs were committed before `x` was known. The simulator samples the full pairs and roots honestly without `r`, then uses the already committed selected vector as the uniformly random input encoding with which the DFB simulator begins. This matches the DFB proof strategy, whose simulator first samples the evaluator input encoding uniformly and then propagates labels through the switch system.

This argument relies on the input masks and deltas being sampled independently of `r` and on the hash tree not revealing feasible preimages. The executable generator domain-separates the two slots and uses fresh entropy in the production-like mode.

### H2 — open and simulate slot 0

After `A1` is fixed, obtain `Y1=[r]A1` from the ideal functionality. Run the selectively secure fused-slot simulator using the selected labels already committed for `A1`, producing a simulated plaintext slot `P0*` consistent with `A1,Y1`.

Program the random oracle at `(ctx,0,R0)` so that

```text
C0 XOR RO(ctx,0,R0) = P0*.
```

Release `R0` and the selected label openings. Slot 1 remains an opaque random ciphertext, so its shared high-level scalar cannot affect the first adaptive choice through its plaintext representation.

### H3 — open and simulate slot 1

The adversary now chooses `A2` after seeing the first complete transcript. Obtain `Y2=[r]A2`, run the selective simulator for slot 1 using its precommitted selected labels, and program the independent slot-1 oracle point so that `C1` opens to the simulated plaintext `P1*`.

The resulting view depends on `r` only through `Lr,Y1,Y2`. This yields the corrected two-instance simulation statement.

## 5. Why mask fusion is simulatable under the selective assumption

v0.23 correlated an Embryo affine slope with the preceding DFB body readout. v0.24.1 closes the load-bearing algebraic gap and keeps the remaining cryptographic step explicit.

### 5.1 Exact body pads

For each CRT prime `p`, every body pad is sampled by 32-bit rejection sampling. A candidate `c` is accepted below

```text
floor(2^32 / p) * p
```

and reduced modulo `p`. Every residue has the same number of accepted preimages. The old nibble-slice-then-reduce bias is gone.

### 5.2 Independent sum and readout

For pads `z_0,...,z_{m-1} in Z_p`, define

```text
S = sum_i z_i
R = sum_i i z_i.
```

The linear map from pads to `(S,R)` has rank two because its columns for indices zero and one are `(1,0)` and `(1,1)`, whose determinant is one in every `Z_p`. Thus `S` and `R` are jointly uniform when the body has at least two rows.

### 5.3 Slope-free online label simulation

Let `h` be the evaluator's hot row. Write

```text
S = c + z_h
R = d + h z_h,
```

where `c,d` contain all non-hot contributions. If the private affine slope is `a`, the public join and evaluated raw label are

```text
J = S + a
L = R + h a.
```

Eliminating both the hidden hot pad and the private slope gives

```text
L = d + h (J - c) mod p.
```

The simulator can therefore derive the evaluator-visible raw label from the public join, the selected control labels and non-hot simulated pads, without learning `a`.

### 5.4 Triangular fusion graph

The concrete Embryo layout contains 3,077 body-output lanes. Its readout-to-later-slope dependencies form 2,050 disjoint directed chains with 1,027 edges. Every non-root lane has exactly one predecessor; there are no cycles.

If a later slope `a_v` is a deterministic function of an earlier readout, its join is

```text
J_v = S_v + a_v.
```

Because `S_v` is fresh uniform state independent of the earlier chain prefix, `J_v` is uniform even after conditioning on that prefix. Conversely, once the prefix and `J_v` are fixed, `S_v=J_v-a_v` is unique. Induction in topological order gives a triangular bijection between the fresh body sums and public joins. The executable harness extracts the exact graph from the real Embryo plans, checks the chain partition, checks rank two for all 91 primes, and exhaustively verifies a nonlinear toy chain.

The remaining selective-security step is still stated as an assumption/reduction target: the complete fixed-key CCRH switch system, fused PRF terms, terminal masks and curve-check composition must satisfy the DFB simulator's computational indistinguishability argument. The machine checks establish the algebra needed by that reduction; they are not a substitute for independent peer review of the complete CCRH proof.

## 6. Label authenticity and cross-instance binding

Every release contains exactly 512 selected labels: one for each bit of the canonical x and y coordinates. Each selected 16-byte label is paired with the 32-byte hash of its unrevealed sibling. Because every sibling pair is represented, the verifier reconstructs the complete Merkle root without carrying a ten-level path for every label.

The signed release binds:

```text
context digest
slot id
canonical compressed BN254 point
activated input-label root
authorization transaction id
whole-slot program seed
authorizer public key
SHA-256 digest of all 512 selected-label openings
```

The opening digest is load-bearing for availability: without it, an outsider
could mutate an honestly signed opening vector, pass the pre-burn header
signature, and consume the one-shot slot. In v0.24.1, altered unsigned openings
fail before burn. A malformed opening vector deliberately signed by the
authorizer still burns before root reconstruction and evaluation.

The context digest itself binds chain genesis, program id, verifier-key digest, deposit outpoint, game index, operator index, counterproof transaction id, epoch and deadline height.

A successful forged or cross-wired release therefore implies at least one of:

* an authorization-signature forgery;
* a SHA-256 collision/second preimage in the label tree or root binding;
* guessing an unreleased 128-bit label;
* forging the contributor-signed activation manifest;
* breaking canonical point/subgroup parsing or persistent slot-state enforcement.

For `N` online guesses, a schematic bound is

```text
Adv_forge <= Adv_BIP340-EUF-CMA
           + Adv_SHA256-collision/second-preimage
           + Adv_manifest-signature
           + N / 2^128
           + eps_parser/state.
```

Cross-slot substitution is rejected even if the altered release is re-signed by the fixture authorizer, because the activated slot descriptor contains a different input-label root and artifact root. A validly authorized malformed opening or wrong seed burns the slot before failure; an outsider signature/root failure is rejected before burn.

The executable negative suite covers forged signatures, outsider opening tampering, validly re-signed cross-slot releases, deliberately signed bad openings, outsider seed substitution, validly signed wrong seeds and replay.

## 7. Exceptional curve inputs

The DFB conditional-addition polynomial is incorrect at its hidden exceptional point. v0.24.1 does not pretend the formula became complete. Instead it makes the exceptional point unavailable when the evaluator chooses its input:

* every hidden `phi` remains inside the sealed whole-slot ciphertext;
* the point is fixed before the seed is released;
* a valid authorization burns the slot before parsing/evaluation, so a public failure cannot be retried against the same hidden state.

Setup samples 256 nonzero `phi` scalars subject to one homogeneous weighted-zero constraint. The accepted distribution is invariant under multiplying every scalar by any nonzero field element. This scaling action is transitive, so every coordinate marginal is uniform over `Z_q*`. A fixed non-infinity point collides with `phi` or `-phi` with probability at most `2/(q-1)` per conditional map.

Across two slots and 256 maps per slot:

```text
eps_exceptional <= 2 * 2 * 256 / (q-1),
```

which is below approximately `2^-243.6`, plus the probability of defeating the whole-slot ROM wrapper before input selection.

This is an adaptive one-shot statistical treatment, not a complete-formula replacement. A complete constant-time curve formula remains preferable for production hardening.

## 8. Consequences of the view theorem

### 8.1 Recovering `r`

Suppose an adversary recovers `r` from the complete v0.24 view. Replacing the view by the simulator loses at most `Adv_view`, yielding an algorithm that recovers `r` from the explicit positive-lock side information and the two authorized pairs `(A1,[r]A1),(A2,[r]A2)`.

In BN254 G1, every accepted non-infinity point generates the prime-order group. In particular, choosing `A1=G` exposes `rG`, so scalar recovery contains the ordinary discrete-log problem. The precise theorem must include whatever leakage the positive lock permits; RankLock's sealed artifacts do not repair a broken positive-lock assumption.

### 8.2 Internal-label forgery

The simulator provides no extra label-forging capability. Acceptance of an unissued label vector reduces to the signature, commitment, label-guessing, canonical-parser or persistent-state terms above.

### 8.3 Cross-wiring

Each slot has a distinct ciphertext root, input-label root, seed commitment, DFB delta set, PRF state and nonce namespace. The manifest and release bind the exact slot and context. Acceptance of slot-0 material by slot 1 therefore reduces to the same authentication/binding failures.

### 8.4 Third points

The following raw computation is unavoidable:

```text
A3 = u A1 + v A2
Y3 = u Y1 + v Y2 = [r]A3.
```

This is not treated as a RankLock forgery. The security property is that no third protocol evaluation is accepted without a third activated one-shot slot and its valid authorization.

For a fresh point sampled independently after both queries are consumed, success in computing `[r]A3` gives a solver for the explicit post-challenge two-query one-more scalar-multiplication problem. The v0.24.1 theorem therefore states that assumption directly rather than hiding group linearity behind an impossible claim.

## 9. Executable evidence

The v0.24.1 generator and verifier enforce the theorem's chronology rather than merely recording booleans:

* both complete slots and the signed manifest are built before `A1`;
* both plaintext slots are sealed at equal length;
* `A1` is fixed, then slot 0's seed and exactly-one-per-bit labels are released;
* `A2` is derived from the first output while slot 1 remains sealed;
* both outputs are independently checked against direct hidden-scalar multiplication inside the setup fixture;
* the independent verifier reparses the opaque retained object, verifies the current generator-code binding, verifies both releases, publicly replays both slots without `r`, verifies the adaptive `A2` derivation, consumes both slots and rejects a third accepted use;
* it records the publicly derivable raw linear pair `A1+A2`, `Y1+Y2` as the intentional theorem boundary.

The retained object remains exactly 1,044,952 bytes—3,624 bytes below one MiB—because whole-slot XOR sealing preserves ciphertext length and the release witnesses are online/post-use material rather than retained artifact bytes.

## 10. Assumptions and remaining production gates

### Cryptographic assumptions retained by the theorem

1. Selective privacy of the **exact fused** DFB/Embryo slot under the stated CCRH/PRF assumptions, including the fixed-uniform-input-encoding simulator interface.
2. Bellare–Hoang–Rogaway `rom-prv-to-prv1` security for whole-program and decoder sealing in the programmable random-oracle model.
3. SHA-256 commitment/collision/second-preimage resistance and BIP340 EUF-CMA security.
4. BN254 discrete logarithm and the explicitly stated post-challenge two-query one-more scalar-multiplication assumption.
5. Security of the BABE/positive-lock public side information.
6. A secure entropy source and CSPRNG/domain separation for production generation.

### Gates not crossed by v0.24.1

1. The exact fused-and-sealed generator has not been executed inside an actively secure dishonest-majority MPC with one honest contributor.
2. Bitcoin witness extraction has not yet been wired to enforce atomic seed/label release, persistent burn, reorg behavior and transaction-context binding in Bitcoin Core regtest.
3. The Python reference implementation is variable-time and not hardened against denial of service or side channels.
4. The full selective fusion reduction and this composition proof have not received independent cryptographic review.
5. The fixed SHAKE256 instantiation is a practical ROM heuristic, not a standard-model proof.

Therefore:

```text
corrected two-instance theorem construction:   IMPLEMENTED
algebraic fusion obligations:                  MACHINE-CHECKED
adaptive whole-slot chronology:                IMPLEMENTED
label authenticity/cross-wire harness:         IMPLEMENTED
retained object below one MiB:                 PRESERVED
production bridge replacement:                 NOT YET
safe for funds:                                NO
```

## 11. Primary references

* Mihir Bellare, Viet Tung Hoang and Phillip Rogaway, **Adaptively Secure Garbling with Applications to One-Time Programs and Secure Outsourcing**, ASIACRYPT 2012 / IACR ePrint 2012/564. In particular, the `rom-prv-to-prv1` transform masks the garbled function and decoder under a random-oracle pad derived from a short random seed and programs that oracle point after the output is known.
* Nakul Khambhati, Anwesh Bhattacharya and David Heath, **Duty-Free Bits: Projectivizing Garbling Schemes**, 2026 preprint. Its proved privacy definition is selective; the paper explicitly identifies random-oracle encryption of a selectively secure garbled program as the straightforward route to adaptive security.

## 12. Reproducibility boundary

v0.24.1 restores the complete source and test tree missing from the surviving
v0.24 evidence. The public conformance fixture uses an explicit deterministic
seed, performs two full generations and requires byte-identical artifacts plus
normalized-equal reports. That fixture exposes all setup secrets by design and
must never be funded. A single-process OS-entropy fixture is retained only as
unfunded evidence and does not replace an active distributed ceremony.
