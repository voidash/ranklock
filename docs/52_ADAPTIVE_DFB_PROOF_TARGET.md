> **v0.22 note.** The adaptive theorem remains open, and any proof must now include the output-mask fusion question exposed by `docs/53_REAL_DFB_EMBRYO_EXECUTION.md`.

# Adaptive Security Target for the DFB Switch-System Projectivizer

**Priority:** P0-ADAPT-1  
**Decision:** plausible proof route; no direct theorem currently established for Embryo

## 1. Why this is the decisive gate

Duty-Free Bits defines privacy selectively: the evaluator's input is fixed independently of the garbled program. RankLock publishes the artifact before the future Groth16 proof and its `A` point exist. Therefore the evaluator can choose the input after seeing the artifact, and selective privacy is insufficient.

The generic random-oracle upgrade described in the DFB discussion encrypts the complete garbled program and sends the decryption key in the online phase. That restores adaptive security but introduces an online key holder, violating RankLock's target.

The desired theorem must retain the same static artifact and no online authority.

## 2. Relevant adaptive-garbling results

Two positive results show that adaptive security can sometimes be proved without modifying the implementation:

- Guo, Yang, Wang, Yu and Liu prove that unmodified Half-Gates and Three-Halves satisfy adaptive security in their ideal-primitive setting using an adversary-dependent statistical-distance analysis and an H-coefficient argument.
- Barnum, Heath, Kolesnikov and Ostrovsky give a framework for adaptive garbling in the non-programmable random-oracle model and apply it to existing techniques, including a concretely efficient tri-state-circuit garbling.

A negative result by Acharya, Azari and Kamath shows that selective security of Free-XOR-based schemes cannot in general be lifted to adaptive security in the plain model under the same assumptions.

These results do **not** automatically prove adaptive security for DFB. DFB uses a legal switch system with a global Free-XOR-style correlation, unique gate nonces, homomorphic label propagation, explicit join differences and CCRH-based switch transitions. A scheme-specific proof or a verified instantiation of a generic framework is required.

## 3. Exact theorem to prove

Define `DFB.SwitchGarb` for a legal switch system `S`, private garbler input `y`, public context `ctx`, and random tape `rho`.

The adaptive game is:

1. challenger samples `(P,e) <- SwitchGarb(S,y;rho)` and gives `P,ctx` to the adversary;
2. the adversary chooses legal input `x` after seeing `P` and may use arbitrary auxiliary information;
3. the challenger gives the exact authenticated projective input encoding for `x`;
4. the adversary outputs a bit.

Prove indistinguishability from a simulator receiving only

```text
S, ctx, x, S(x,y)
```

and public size leakage.

For RankLock, strengthen this to `q=2` independent instances with one shared private scalar `r`:

```text
(P_0,e_0) <- Embryo.Garb(r;rho_0)
(P_1,e_1) <- Embryo.Garb(r;rho_1)
```

where `rho_0` and `rho_1` are independent, and the adversary adaptively chooses `A_0`, then `A_1` after seeing all public artifacts and the first authorized output.

The simulator receives only the public context and ideal outputs `[r]A_0`, `[r]A_1`.

## 4. Proposed proof program

### Lemma A — nonce legality survives adaptive choice

DFB assigns a unique `gid` to every switch and its CCRH definition restricts oracle queries to unique nonces. Formalize that the evaluator's adaptively selected control path cannot cause two correlation-related hash queries to reuse the same nonce, including malformed-label attempts.

### Lemma B — deferred input-mask simulation

The current selective proof begins by sampling the evaluator's encoded input and then simulating gates. Replace this with a simulator that commits to the offline artifact distribution before `x` is known and later opens exactly one consistent input label per bit.

The key question is whether the offline join differences and switch masks can be sampled from an input-independent distribution and equivocated only through ideal-primitive answers—not by programming a random oracle after the fact.

### Lemma C — hidden-correlation H-coefficient bound

Adapt the H-coefficient/statistical-distance method used for Half-Gates to DFB's switch transitions:

```text
Y = H(S, gid) + X
```

versus the inaccessible branch involving `S xor Delta`. Classify bad transcripts where the adversary queries both correlated inputs, collides nonces, or derives a forbidden label. Bound their total probability for the full switch system.

### Lemma D — information-theoretic wire types

Prove that non-control-friendly labels, join differences, pair gates, homomorphism gates and subgroup gates preserve the adaptive simulation once switch outputs are replaced. These components are affine/homomorphic and should not require random-oracle programming, but the proof must account for auxiliary correlations across all derived labels.

### Lemma E — projectivization composition

Lift adaptive security of `PGS_aff-Fp` through Theorem 5.3 to the Embryo scalar-multiplication scheme. The proof must handle the information-theoretic base garbling, curve-validity check and the fact that all affine maps encode one shared scalar.

### Lemma F — two-instance same-scalar composition

Prove an auxiliary-input hybrid for two independently randomized artifacts sharing `r`. A single-instance theorem that assumes no correlated auxiliary view is insufficient. Either establish multi-instance security directly or define the primitive with arbitrary efficiently generated auxiliary input.

### Lemma G — authenticated adaptive labels

Compose the adaptive garbling theorem with the Bitcoin label-authentication mechanism. The evaluator must receive exactly one label per bit, bound to one slot and one context; abort or malformed evaluation must not reveal an alternative label.

## 5. Implementation work supporting the proof

A proof-oriented implementation should expose:

- canonical switch identifiers/nonces;
- a transcript of every hash-domain query;
- explicit wire-type and correlation metadata;
- a simulator mode that creates the offline artifact before the input is selected;
- a forbidden-query detector for both correlated switch labels;
- two-instance tests with shared `r` and independent tapes;
- adversarial input selection based on the complete public artifact;
- mutation tests for join differences, gate identifiers, label roots and context binding.

This instrumentation is more valuable than immediately optimizing native performance because it either yields the missing adaptive proof or produces a concrete counterexample.

## 6. Success criteria

P0-ADAPT-1 succeeds only when all of the following hold:

1. a formal adaptive privacy definition matching future Bitcoin inputs is written;
2. the offline artifact is distributed before `x` is selected;
3. no online key or programmable-oracle decryption step is introduced;
4. the proof covers the exact DFB switch construction used by Embryo, not only generic Half-Gates;
5. the proof supports arbitrary auxiliary input and two same-scalar instances;
6. concrete security loss is calculated for the complete 5.8-million-hash artifact;
7. the implementation records and rejects every bad transcript class used in the proof.

## 7. Kill criteria

Kill this route if:

- a valid adversary can use the offline join/switch material to force both correlated oracle inputs for one nonce;
- simulation requires programming the oracle after observing `x` in a model stronger than the intended deployment assumption;
- adaptive repair requires encrypting the whole program with a key released by an online party;
- multi-instance security fails when two artifacts share `r`;
- the smallest safe compiler adds more than the 25,390-byte two-slot margin or returns to circuit-linear garbling.

## 8. Current conclusion

The adaptive literature makes the missing theorem credible enough to attack directly, but it does not license an inherited security claim. The immediate research target is a DFB-specific NPRO/H-coefficient proof or a concrete adaptive attack. Either outcome is decisive.
