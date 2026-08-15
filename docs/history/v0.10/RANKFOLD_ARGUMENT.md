# RankFold argument — executable v0.10 milestone

## Relation

For a committed batch of prime-field values, RankFold proves

```text
c_i = a_i · b_i,  i ∈ [R].
```

The vectors are padded to `N = 2^m`. The transcript derives a random outer point `r ∈ F^m` after
commitment and defines

```text
g(x) = eq(r, x) · (A(x)B(x) - C(x)),
```

where `A`, `B`, and `C` are the multilinear extensions of the tables. A degree-three sumcheck proves
that the Boolean-hypercube sum of `g` is zero. At the terminal point `s`, the verifier checks

```text
claim_m = eq(r, s) · (A(s)B(s) - C(s)).
```

A sound multilinear PCS must bind the three terminal openings to the committed vectors.

## What is achieved

- Fiat–Shamir transcript with domain separation and rejection-sampled BN254 challenges.
- Degree-three coefficient-form prover using ten field multiplications per active pair per round.
- Exact verification of every sumcheck consistency equation.
- Transparent reference openings that recompute multilinear evaluations from complete vectors.
- Integration with the certified rank-54 `Fq12` multiplication template.
- Negative tests for relation corruption, transcript corruption, opening corruption, and context
  substitution.
- An explicit all-zero forgery against an `AcceptAllOpeningOracle`, proving that a hash commitment
  without a sound opening argument is insufficient.

## Full retained-SP1 scale

For `R = 645,221` certified rank terms:

```text
padded constraints                 1,048,576
sumcheck rounds                    20
transmitted field elements         83
transcript bytes excluding PCS     2,720
PCS openings                       3
conservative statistical bound     ≤ 80 / q
conservative soundness             > 247 bits over BN254 Fq
```

The 2,720-byte figure is real for the RankFold transcript format. It is **not** the final artifact or
conditional-disclosure size. A real PCS opening proof and the cryptographic lock remain additive.

## Why the PCS is the decisive boundary

Sumcheck proves an algebraic claim about values opened at one random point. Without a binding
commitment, an attacker chooses terminal values after seeing the challenges and makes the final
identity true. `forge_with_unbound_openings()` demonstrates this attack and passes only against the
deliberately insecure oracle.

The next construction must provide:

1. binding commitments to `A`, `B`, and `C`;
2. succinct openings at a transcript-derived multilinear point;
3. malicious distributed commitment generation or publicly checkable trace binding;
4. a way to turn verifier acceptance into offline conditional disclosure rather than merely a
   boolean result.

## Novelty boundary

Sumcheck and multilinear PCS are known. Garbling a succinct proof verifier is also known. RankFold
becomes a major contribution only if the lock layer can exploit this particular linearly structured
argument to obtain all of the following together:

```text
sub-megabyte persistent material
near-native O(R) field-only prover/evaluator work
polylogarithmic expensive cryptographic work
public future inputs through projective encodings
n-1 corrupt distributed activation
no online authority
same malicious security goal as Mosaic
```

A generic SNARK plus generic witness encryption is a valid baseline, not the claimed breakthrough.
