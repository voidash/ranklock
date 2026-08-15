> **Historical v0.21 construction document.** Its 511,219-byte slot is paper-derived join accounting. v0.22 generated the real program and measured a 449,779-byte join stream plus 228,083 bytes of standalone output masks. See `docs/53_REAL_DFB_EMBRYO_EXECUTION.md`.

# Bounded-Query Embryo via Active MPC

**Checkpoint:** RankLock v0.21 candidate  
**Date:** 2026-08-10  
**Evidence class:** executable composition and exact serialization arithmetic, conditional cryptographic construction  
**Decision:** construction-level breakthrough candidate; end-to-end breakthrough gate not met

## 1. Problem

The missing primitive after v0.19 is a static public object for a hidden BN254 scalar `r` with the interface

```text
Setup(r, q, context) -> public artifact
Eval(slot_i, A_i, authenticated input labels) -> [r]A_i
```

subject to all of the following:

- at most `q` future, adaptively selected inputs;
- no party holding `r` remains online after activation;
- the evaluator learns no more about `r` than the authorized outputs;
- a malicious setup coalition with up to `n-1` corrupt contributors cannot activate a malformed artifact;
- every failed, aborted, timed-out or retried evaluation consumes a slot;
- wrong outputs are publicly rejected;
- retained verifier-specific material should remain below one MiB.

A single affine/projective state cannot safely answer two different inputs. If labels have the form

```text
t = a + b*v mod p,
```

two distinct pairs `(v_1,t_1)` and `(v_2,t_2)` recover both `a` and `b`. The executable regression is `recover_affine_state_from_two_queries`.

## 2. v0.19 and v0.20 disposition

### v0.19

v0.19 added positive-lock, Bitcoin-connector, semantic-binding and proof-carrying projectivizer modules, but it did not close the bounded-query malicious-generator problem. Its checkpoint explicitly left a compact bounded-multi-query hidden-scalar evaluator as the primary target.

The stored tree also had a reproducibility defect: two new modules imported `ranklock.bip340`, but that module was absent. The reported focused tests did not import those paths. v0.21 adds a BIP340 implementation and checks it against Bitcoin's official test vectors.

### v0.20

v0.20 split `r` additively across contributors and certified each output share with a pairing equation. That is algebraically sound, but corrupt contributors can make their static artifacts selectively fail. Its fallback was commit-and-open cut-and-choose. More than 40 bits requires 44 copies, around 22.5 MB of setup material per contributor at the 500 KiB planning size. That does not meet the retained-size objective and still needs the exact Embryo generator.

## 3. Construction

The v0.21 construction replaces per-contributor cut-and-choose with one actively secure distributed generation ceremony.

### 3.1 Setup

Let there be `n >= 2` registered contributors, at least one honest. They execute a maliciously secure dishonest-majority MPC protocol with abort.

Inside MPC they:

1. jointly sample the hidden scalar `r` without reconstructing it;
2. sample independent random tapes `rho_0, ..., rho_(q-1)`;
3. execute the exact canonical Duty-Free-Bits/Embryo generator for each slot:

   ```text
   artifact_i = Embryo.Garb(r; rho_i)
   ```

4. construct the positive proof-conditioned lock under the same `r` and exact session context;
5. output artifact roots, input-label roots, slot-independence digests, the lock, the generator-code hash and the MPC transcript digest.

No output is activated unless every registered participant signs the exact canonical manifest. The honest participant signs only an output accepted by the active MPC protocol and matching the deployment context. After activation, all scalar shares and generator state are erased.

The security role of MPC is correctness and privacy of artifact generation. The participant signatures are an activation certificate and exact-committee binding; they are not a substitute for MPC security.

### 3.2 Public manifest

`UnsignedBoundedEmbryoManifest` binds:

- session/context digest;
- exact generator-code hash;
- active-MPC transcript digest;
- positive Groth16 lock;
- canonical consecutive slot identifiers;
- artifact byte lengths and artifact roots;
- authenticated input-label roots;
- per-slot independence digests;
- a lexicographically canonical contributor committee.

`SignedBoundedEmbryoManifest` adds one 64-byte BIP340 signature from every contributor and a domain-separated checksum. Parsing rejects truncation, trailing bytes, duplicate keys, duplicate slot roots, noncanonical ordering and cardinality drift.

### 3.3 Evaluation

For slot `i`:

1. verify the signed activation manifest against the exact registered committee and deployment context;
2. verify the transaction/input-label authorization for `(context, i, A_i)`;
3. atomically mark slot `i` consumed **before** evaluating;
4. evaluate the one-shot artifact to obtain `Z_i`;
5. verify the public certificate

   ```text
   e(Z_i, delta) = e(A_i, [r]delta);
   ```

6. feed the certified output into the positive proof-conditioned lock.

A malformed output, crash, abort, timeout or retry leaves the slot burned.

The repository executes steps 1, 3, 4's output boundary, 5 and the positive-lock integration. Step 2 still needs the exact authenticated adaptive label-release compiler used by the Bitcoin transaction graph.

## 4. Conditional security theorem

### Theorem target

Assume:

1. the active-MPC protocol securely realizes the canonical Embryo generator against up to `n-1` malicious corruptions, with privacy and correctness with abort;
2. the exact one-shot Embryo instance is adaptively private for a future input chosen after the artifact, with auxiliary input sufficient for bounded multi-instance composition;
3. each slot uses independent generator randomness and unique nonces;
4. the authenticated input-label mechanism reveals exactly one legal label per input bit and binds it to the session, slot, transaction, game, operator and proof statement;
5. BIP340 is unforgeable and the hash functions satisfy the stated random-oracle/CCRH assumptions;
6. BN254 discrete logarithm remains hard and the pairing implementation enforces canonical subgroup-valid points.

Then, for at most `q` slot attempts:

- **setup privacy:** a coalition of at most `n-1` contributors learns no aggregate scalar `r`;
- **artifact correctness:** any activated slot is the canonical generator output for the jointly committed `r` and its independent tape;
- **bounded privacy:** the evaluator's public view can be simulated from the authorized ideal outputs `[r]A_i` and public context, up to the adaptive multi-instance Embryo assumption;
- **output correctness:** an accepted output equals `[r]A_i` except with the soundness error of the group/pairing assumptions;
- **one-shot safety:** no slot can be evaluated twice, including after abort or timeout;
- **no online authority:** after activation, evaluation needs only the public artifacts and transaction-authenticated input labels.

### Proof sketch

- Active-MPC privacy hides `r` and all honest randomness during generation; active correctness means a completed output is the prescribed circuit output. A corrupt majority may abort setup, but cannot cause the honest participant to sign a different completed output.
- The all-signature manifest pins the exact committee, code, transcript, context, lock and slot roots. A manifest mutation requires either a signature forgery or a changed checksum/signing digest.
- For evaluator privacy, replace each real slot view with its adaptive simulator one at a time. Independent random tapes prevent the two-query affine-state recovery attack. This hybrid requires an adaptive, auxiliary-input/multi-instance theorem for the DFB switch-system garbling; the current DFB paper proves only selective privacy, so this is an explicit open lemma rather than an inherited fact.
- The public pairing equation rejects a wrong `Z`. Canonical group parsing rejects malformed points.
- Atomic burn-before-evaluate state prevents replay, retry and selective-failure probing of the same affine state.

## 5. Exact retained-size envelope

`EmbryoPaperCost` reconstructs Appendix-C arithmetic without rounding:

| Component | Bytes | Hash calls |
|---|---:|---:|
| Boolean-to-CRT chunk conversion, per coordinate | 14,848 | 188,352 |
| Residue evaluation, per coordinate | 126,720 | 1,147,358 |
| Information-theoretic scalar-map labels | 227,712 | 3,174,552 |
| Curve check | 371 | 0 |
| **One complete slot** | **511,219** | **5,845,972** |

For `q=2`, two contributors and a 32-byte positive-lock payload:

```text
2 Embryo slots:          1,022,438 bytes
canonical manifest:            748 bytes
------------------------------------------------
retained object:         1,023,186 bytes
one-MiB margin:             25,390 bytes
hash calls:              11,691,944
```

Three slot artifacts alone are `1,533,657` bytes, so `q=3` cannot meet one MiB under this construction.

This is an exact reconstruction of the paper's communication formulas plus an exact local manifest serialization. It is **not** a local serialization of the DFB artifact. The remaining 25,390-byte margin must still absorb any complete BABE material, final transaction-graph metadata or differences uncovered by the exact serializer.

## 6. Executable evidence

The v0.21 suite covers:

- exact Appendix-C arithmetic;
- exact `q=2` manifest and retained-byte count;
- `q=3` impossibility under the one-MiB cap;
- BIP340 official vectors, invalid signatures and Taproot helpers;
- canonical manifest round trip;
- exact-committee enforcement;
- missing-signature and byte-tampering rejection;
- duplicate artifact/input-label/randomness roots;
- burn-before-evaluate behavior on success, malformed output and abort;
- executable two-query affine-state recovery;
- real BN254 pairing certification of honest and wrong outputs;
- import and execution of the previously untested v0.19 Bitcoin/semantic modules.

Full clean source result:

```text
74 test files
277 tests passed
0 failed
```

## 7. What changed relative to v0.20

| Property | v0.20 | v0.21 candidate |
|---|---|---|
| Hidden scalar | additive contributor shares | secret-shared inside active MPC |
| Malformed generator defense | cut-and-choose copies | malicious-secure MPC correctness with abort |
| 40-bit setup object | 44 copies / ~22.5 MB per contributor | two final one-shot slots / 1,023,186 B total |
| Wrong runtime output | pairing-certified | pairing-certified |
| Retry | independent fallback copy | slot permanently burned |
| Exact DFB implementation | missing | still missing |
| Adaptive privacy theorem | missing | isolated as the decisive lemma |

## 8. Remaining gates

The end-to-end breakthrough flag remains false until all of these are closed:

1. **Exact DFB generator and serializer.** Generate and parse the real 511,219-byte artifact rather than a paper-derived cost object.
2. **Adaptive DFB theorem.** Prove the switch-system projectivizer secure when inputs are selected after seeing the artifact, including two instances sharing `r` and arbitrary auxiliary input.
3. **Concrete active MPC.** Compile and benchmark the approximately 11.69 million hash calls plus arithmetic for `q=2` under an `n-1`-corrupt active protocol.
4. **Authenticated label release.** Bind exactly one label per bit to the real transaction, slot, game, operator, deposit and proof context.
5. **Complete byte accounting.** Serialize the full BABE/Embryo lock and validity-first Bitcoin graph; the current margin is only 25,390 bytes.
6. **End-to-end proof and execution.** Prove the composition and run all branches on Bitcoin Core regtest.

## 9. Kill criteria

Kill or reframe the sub-MiB breakthrough claim if any of the following occurs:

- the exact two-slot artifacts plus complete lock exceed 1,048,576 bytes;
- adaptive security requires an online decryption-key holder or a circuit-linear wrapper;
- independent same-scalar instances admit a cross-instance leakage attack;
- active-MPC generation cannot achieve privacy/correctness with `n-1` corruptions without retaining a trusted party;
- authenticated label release allows two labels, alternate-context replay or selective retry;
- Bitcoin transaction semantics cannot atomically burn a slot before observing success;
- the complete system offers no material same-security advantage over Mosaic/BABE/Argo after setup bandwidth, retained bytes and runtime are normalized.

## 10. Correct claim boundary

The result is stronger than v0.19 and v0.20 in one narrow, measurable sense:

> A two-query hidden-scalar evaluator can fit below one MiB **at the construction and exact-envelope level** by using two independent one-shot Embryo instances and replacing malicious-generator cut-and-choose with an actively secure distributed generation ceremony.

It is not yet a formal adaptive-security theorem, exact DFB implementation, complete Strata replacement or production cryptosystem.
