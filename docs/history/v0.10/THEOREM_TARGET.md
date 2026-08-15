# Target theorem

## Program class

Let `P` be an arithmetic verifier over a prime field `F_p`, represented as a RankIR program with:

- `m` public/projective input coordinates;
- `N` nonlinear module instances;
- `T` unique certified templates;
- total bilinear rank `R` across instances;
- multiplicative/template depth `D`;
- one release bit `b = P(x)`.

## Desired result

Under explicit standard assumptions (candidate set: DCR, LPN/VOLE correlation security, binding
commitments, and random-oracle Fiat–Shamir), construct an `n`-party distributed RankLock scheme
secure against a static malicious adversary corrupting up to `n-1` setup parties such that:

### Public artifact

```text
|artifact| = poly(lambda, m, T, D, log p)
```

and is independent of `N` and `R`, except for data-availability commitments to the native trace or
program that are already public and highly compressible.

### Setup communication

```text
poly(lambda, m, T, D, log p) + o(R * lambda)
```

with a concrete goal below 1 MiB of retained verifier-specific material for the SP1 instance.

### Evaluation

```text
native_time(P)
+ O(R) cheap F_p operations
+ poly(lambda, T, D, log p) expensive cryptographic operations.
```

The concrete target is no more than 2× the native verifier runtime.

### Online communication

```text
poly(lambda, m, T, D, log p)
```

with a concrete target below 256 KiB excluding the ordinary 132 completed Bitcoin signatures.

### Security

- false release: negligible in `lambda`;
- malicious-generator withholding after activation: negligible;
- selective failure/input inconsistency: negligible;
- statistical rank-folding error: at most `p^-2` for two independent folds;
- no online trusted party and no aggregate fault secret.

## The claim that would shake the space

> RankLock is the first fully succinct conditional-disclosure/garbling construction whose **artifact
> and expensive evaluation cost are width-independent** for a practical class of large-field
> algebraic programs, while retaining projective inputs, public evaluation, and dishonest-majority
> malicious setup security.

“First” remains a target and must be established against the complete OHMG, HSS garbling, aHMAC,
Argo/BABE, arithmetic-BMR, and vector-HSS literature before submission.

## Executable RankFold lemma (v0.10)

Let committed vectors `a,b,c ∈ F^N` be fixed before Fiat–Shamir challenges, with `N=2^m`. The
RankFold transcript proves `c_i=a_i b_i` on the Boolean domain using an outer random multilinear
residual point and a degree-three sumcheck. Assuming a binding PCS for the three terminal openings,
the conservative statistical soundness error is at most

```text
(m + 3m) / |F| = 4m / |F|.
```

For `m=20` over BN254 Fq this exceeds 247 bits. The harness implements the complete algebraic
transcript; the PCS assumption and conditional-disclosure reduction are not yet instantiated.
