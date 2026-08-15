# Transparent Constraint Backend

**Evidence class:** REPRODUCED executable constraint trace.
**Security class:** no cryptographic security; transparent witness access.

## Purpose

The exact witness modules and schedule estimators previously existed as separate layers. A formula could drift from the relations actually checked by the witness verifier. `constraint_backend.py` closes that engineering gap before real proof-system integration.

For one concrete foreign multiplication it emits and executes:

- native multiplication constraints;
- standalone exact or modular linear constraints;
- linear output relations fused into multiplication gates;
- fixed-width tuple/range lookup events;
- fixed boundary checks and explicit trace-reuse assumptions.

Each event stream is deterministically hashed. The compiler asserts that multiplication, lookup, and linear-relation totals match the route estimator exactly.

## Implemented traces

### 3×85 rank-5

```text
5 native multiplication constraints
76 logical tuple/range lookups
17 linear relation events
```

`x` and `y` are prebound. Fresh `z` receives packed canonical serialization, slack-limb ranges, and canonical carry checks. The internal quotient receives only a 254-bit packed range and three byte-to-limb relations. Signed arithmetic carry offsets, five point-product gates, and five final carry equations complete the trace.

Interpolation coefficients are derived linear forms of the point-product outputs; they are not free witness values.

### 2×127 split products

```text
4 native multiplication constraints
206 logical tuple/range lookups
22 standalone linear constraints
4 linear output forms embedded in multiplication gates
26 linear relation events total
```

The trace checks canonical `z`, a 254-bit quotient binding, low/high product chunks, constant-modulus products, normalized digits, and both carry chains.

### Dual-field CRT owner-side cost point

```text
1 multiplication in BN254 Fr
1 multiplication in BLS12-381 Fr
63 owner-side logical tuple/range lookups
20 linear relation events
```

The BLS12-381-side ledger owns the canonical output table and bounded quotient chunks. Both ledgers locally recompose residues. They still consume only host-equal words: no common PCS commitment or verified equality proof binds those words across fields. The report is therefore deliberately non-selectable.

## Quotient-elimination regression

The compiler intentionally ignores quotient slack limbs and canonical-addition carries. A regression corrupts those unused fields and still compiles the trace. It then changes the quotient bytes while keeping the arithmetic limbs fixed and is rejected. Separate tests reject a 255-bit CRT quotient encoding.

This distinguishes a real constraint elimination from a mere accounting change: the removed witness cells are not load-bearing, while the bounded bytes, limb packing, and arithmetic relation remain enforced.

## What the backend establishes

- honest concrete witnesses satisfy the emitted relation set;
- targeted product, chunk, digit, carry, residue, byte, limb, and bit-bound tampering is rejected;
- estimator and emitted relation counts agree exactly;
- route comparisons share one explicit event model;
- the reduced quotient policy has executable acceptance/rejection semantics.

## What it does not establish

It provides no:

- polynomial or vector commitment;
- lookup argument or physical row packing;
- degree bounds or SRS sizing;
- extractability, binding, zero knowledge, or cryptographic soundness;
- cross-field commitment equality;
- proof generation, verification, or proof bytes;
- conditional disclosure or secret release.

Calling this a real R1CS/PLONK/AIR backend would be incorrect.

## Real-backend integration contract

P0-PCS-1 must preserve:

1. `x` and `y` may be amortized only when their exact prebound table cells are reused.
2. Fresh `z` is canonical; the internal quotient is nonnegative and bounded to 254 bits, not redundantly canonicalized.
3. Quotient lookup chunks must be linearly bound to the arithmetic limbs.
4. Signed carries use offset decomposition with a public exact bound.
5. Rank-5 coefficients are derived from five product outputs, never accepted as independent witness columns.
6. Lookup tuple width, fixed-table rows, copy constraints, and physical row packing are reported separately.
7. Any semantic deviation requires an adversarial test and decision-log entry.

Generated evidence is written to `results/constraint_backend.json`.
