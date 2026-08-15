# One-Sided Pairing Wrapper Frontier

## Required final shape

A useful wrapper should expose only future \(G_1\) proof elements and use a constant-rank fixed \(G_2\) basis. The final equation modeled in v0.17 is

\[
e(Q,[s]_2)=e(R+\alpha^{-1}Q,[1]_2).
\]

After moving the right side left, the fixed \(G_2\) coefficient rank is two. No future \(G_2\) proof element is required.

`OneSidedFinalPairingEquation` implements this equation with real BN254 arithmetic and rejects a modified future \(G_1\) element.

## Reference proof-system profile

The planning profile follows the public shape reported for *A Flexible SNARK via the Monomial Basis*:

- 10 prover-defined \(G_1\) elements;
- 20 scalar elements;
- two final pairings;
- no prover-defined \(G_2\) element;
- fixed rank-two \(G_2\) basis;
- universal/updateable but circuit-linear reusable CRS;
- combined prover MSM length proportional to circuit size.

This repository does not implement that SNARK or its outer curve.

## Why this helps RankLock

Groth16 contains a future \(G_2\) proof element, producing a future–future pairing term that a static hidden scalar cannot attach to using ordinary bilinear operations. The one-sided shape avoids that term.

The wrapper still must prove the fixed statement:

```text
authenticated future bytes
        + complete RankVM/SP1 verification
        + INVALID output
        + transcript and context binding.
```

## Storage classification

The wrapper separates:

- **reusable system CRS**, which may be circuit-linear; and
- **per-deposit conditional material**, which is the sub-megabyte target.

This is a practical systems relaxation from the original polylog-total-artifact theorem. It is not an asymptotic breakthrough by itself.
