# Candidate construction: Rank-Folded Distributed CDS

This is a research construction sketch, not a theorem.

## 1. Certified RankIR

Compile the canonical verifier into public linear maps and nonlinear modules. Each bilinear module
has a certificate

```text
B(x, y) = sum_i l_i(x) * m_i(y) * w_i
```

with rank `r`. The v0.10 compiler proves the identities exactly on basis coefficients.

Repeated uses reference the template digest; they do not carry another description of `B`.

## 2. Native execution and residual trace

The evaluator executes the verifier natively and records, for every nonlinear instance,

```text
r_j = claimed_output_j - B_j(left_j, right_j).
```

Linear wiring is checked through public commitments/linear identities. The complete trace is bound
before any folding challenge is sampled.

## 3. Rank folding

Derive transcript challenges after the trace, program, template registry, public input, and Bitcoin
policy are committed. Fold the residual vector:

```text
rho_t = sum_j eta[t,j] * r_j.
```

For a fixed nonzero residual vector and an independent uniform challenge vector, one fold accepts
with probability exactly `1/p`. The executable attack in `ranklock.attacks` shows that the check is
useless if the residual vector can be chosen after the challenge.

v0.10 now implements the degree-three RankFold sumcheck. For 645,221 rank terms it uses 20
rounds and 83 transmitted field elements. The unresolved step is the binding succinct multilinear
PCS: the transparent oracle recomputes complete vectors, and an explicit attack succeeds when the
terminal openings are not bound. See `RANKFOLD_ARGUMENT.md`.

## 4. Vector algebraic authentication

Replace per-gate aHMAC/HSS evaluation with a vector primitive that authenticates a complete folded
layer or low-rank module. Desired interface:

```text
SetupTemplate(B_digest) -> compact public template key
AuthenticateInputs(active projective encodings)
FoldTrace(commitment, native trace) -> O(1) authenticated residual tags per round
OpenInvalid(tags, final_output) -> fault secret or bottom
```

The expensive group/HSS operations should scale with unique templates and multiplicative depth.
The evaluator may perform `O(R)` ordinary field operations because those are comparable to native
execution; it must not perform `O(R)` exponentiations, Paillier operations, or HSS restricted
multiplications.

## 5. Distributed generation

Contributors jointly generate:

- global authentication-key shares;
- fault-secret shares;
- vector-HSS/aHMAC evaluation material;
- projective input correlations;
- commitments and proofs for every template and batch binding.

At least one honest contributor keeps the aggregate authentication/fault key hidden. All active
checks are proven during setup. A malicious coalition can abort before activation but cannot create
an accepted malformed artifact.

Potential ingredients:

- dishonest-majority arithmetic garbling or VOLE/PCG preprocessing;
- distributed sumcheck to lift additive security to malicious security;
- publicly verifiable secret sharing for fault-key shares;
- standard-assumption leveled aHMAC when depth dependence is acceptable;
- Fiat–Shamir only after a transcript-binding proof is defined.

## 6. Projective Bitcoin input

Use a projectivization layer so each of the 132 byte values supplies one active encoding without
publishing affine large-field labels. The projective translator must be included in the same setup
proof and game/epoch binding.

## 7. Conditional Bitcoin output

The final authenticated result must derive the exact Bitcoin fault secret or adaptor completion only
for canonical `INVALID`. No API or online signer performs a trusted branch.

## Central research hypotheses

### H1 — width-free vector authentication

A vector aHMAC/HSS can evaluate a full rank-decomposed layer using a constant or logarithmic number
of expensive operations plus native field work.

### H2 — template-amortized setup proof

Correct generation can be proven once per unique template and batch-bound to all instances with
proof size and verification independent of the instance count.

### H3 — projective composition

Projective bit/byte input encodings compose with the vector authentication layer without restoring a
per-bit `lambda` factor or permitting reusable-label forgeries.

### H4 — no hidden online trust

The distributed setup leaves a noninteractive artifact whose safety and release completeness no
longer depend on an honest live signer.

If any hypothesis fails, RankLock is not the intended breakthrough.

## 8. Refined breakthrough fork

There are now two implementation paths:

```text
A. real PCS + garbled/authenticated tiny RankFold verifier
B. a RankFold-native conditional lock that turns the opening identity directly into disclosure
```

Path A is a credible same-security systems result, but the broad architecture “prove natively,
garble the succinct verifier” already exists. Path B is the cryptographic-breakthrough path. It
must avoid one expensive HSS/group operation per rank term and avoid assuming an online signer.

A major theorem would show that a committed RankFold trace can drive conditional disclosure with
polylogarithmic expensive work, while the prover performs only near-linear native field arithmetic.
