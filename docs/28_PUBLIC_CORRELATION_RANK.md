# Public Correlation Rank: Generic PCG Route and Low-Rank Escape

**Date:** 2026-08-07
**Evidence:** **EXACT algebraic linear-rank model**
**Code:** `src/ranklock/public_correlation_rank.py`
**Result:** `results/public_correlation_checkpoint.json`

## Question

Can relation-specific verifier correlations be expanded from a polylogarithmic **public**
static seed, with no secret state remaining online?

The answer splits cleanly.

1. For arbitrary algebraically independent source-group bases, **not by ordinary public
   group-linear expansion**: the seed needs at least the rank of the desired bases.
2. For a verifier whose fixed bases already have public coefficient rank `k`, **yes**: `k`
   scaled anchors generate every scaled term base.

This is a scoped algebraic result, not a universal computational impossibility theorem.

## Exact rank statement

Let fixed G2 term bases be represented over algebraically independent anchors by rows of a
matrix `A`:

```text
B_i = sum_j A[i,j] U_j.
```

Setup hides a scalar `r`. A public algebraic expander receives `s` source-group seed elements.
Each seed element has one coefficient vector in the hidden-scalar space. Public group addition
and multiplication by public field scalars only produce vectors in the span of those `s`
vectors. Therefore:

```text
number of public source-group seed elements >= rank(A).
```

For `n` independent bases, `A = I_n`, so the lower bound is `n`. Pairings can create products
in GT but ordinary bilinear groups provide no algebraic GT-to-G2 map, so pairings do not reduce
the source-group rank.

The implementation computes rank over BN254 Fr with exact modular Gaussian elimination and
includes a no-allocation identity-matrix certificate for the current RankVM widths.

## Consequence for the current direct relation

Treating each current verifier event as an independent fixed source-group base gives no
polylogarithmic seed in this model:

```text
known linear-relation events: 440,113
all current logical events:  2,537,122
minimum public seed directions under independence: same as the event count
```

This strengthens the old byte barrier. The earlier 8.27 MiB / 159.82 MiB result was a cost kill
for one concrete inner-product gadget. The new result explains why replacing its table with an
ordinary public PRG/PCG seed does not work for independent algebraic bases.

## Why standard PCGs do not directly answer the cold-start problem

Silent OT/VOLE and MPC PCGs stretch short seeds into large correlated **party views**. The
parties retain private seeds or secret state and locally expand their own shares. That is a
different interface from RankLock's target, where every evaluator starts from one public
artifact and no party-private state remains after activation.

The distinction is explicit in the literature:

- Boyle et al., ePrint 2019/1159, use low-communication setup followed by local silent
  computation for two-party correlations.
- FOLEAGE, ePrint 2024/429, describes parties stretching short seeds into MPC correlations.
- Couteau--Zarezadeh, ePrint 2023/072, has each party publish an encoding **and store secret
  state** for later noninteractive inner-product computation.

These are relevant building blocks for a distributed setup ceremony, but publishing all seed
state is not a secure public cold-start expander.

## Positive low-rank escape

If the verifier compiler produces a fixed-base coefficient matrix of rank `k`, setup publishes
only:

```text
r U_1, ..., r U_k.
```

Any scaled term base is derived publicly as:

```text
r B_i = sum_j A[i,j] (r U_j).
```

For the executable 11-term / 2-anchor envelope:

```text
independent scaled bases: 11 G2 = 704 bytes
low-rank scaled anchors:   2 G2 = 128 bytes
cryptographic compression: 5.5x
```

This does not make a large verifier low-rank. The proof/compiler must supply the structure.

## Scope and non-claims

The lower bound excludes:

- obfuscation-like public programs that contain hidden state;
- multilinear maps or a source-group map from GT;
- trusted hardware;
- private PCG seeds held by parties;
- verifiers whose bases already have low public coefficient rank;
- computational compression outside the algebraic interface.

Do not state that all public correlation generators are impossible. The supported statement is:

> A public algebraic source-group expander using ordinary group-linear operations needs at least
> the coefficient rank of the desired hidden-scalar verifier bases.
