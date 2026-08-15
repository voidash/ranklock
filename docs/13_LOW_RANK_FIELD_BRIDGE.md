# Rank-5 Foreign-Field Convolution

**Evidence class:** exact algebraic/witness model plus reproduced transparent constraint trace and logical lookup estimate. This is not a real PCS or production circuit.

## Result

The original 3×85-bit bridge used schoolbook multiplication and counted nine variable-variable native products per BN254-Fq multiplication. That count is not minimal.

For

```text
x = x0 + x1*B + x2*B^2
y = y0 + y1*B + y2*B^2
B = 2^85,
```

form degree-two polynomials

```text
X(T) = x0 + x1*T + x2*T^2
Y(T) = y0 + y1*T + y2*T^2.
```

Their product has degree four. Five fixed, distinct evaluation points determine all five convolution coefficients. Only

```text
X(alpha_i) * Y(alpha_i), i = 0..4
```

are nonlinear gates; evaluation and interpolation are fixed native-field linear combinations.

This is classical evaluation/interpolation multiplication, not a novelty claim. Its significance here is the concrete reduction of RankLock's foreign-field multiplication subtotal.

## Exactness lemma

Let `p` be the native proof field and let `n` ranged limbs satisfy `0 <= limb < B`. For `2n-1` distinct native-field points, the point products uniquely determine the degree-`2n-2` convolution modulo `p`.

For every supported RankLock geometry,

```text
n * (B - 1)^2 < p.
```

Each interpolated coefficient is therefore the unique corresponding nonnegative integer coefficient. The signed-carry equations enforce

```text
x*y = z + quotient*q,
```

and `LimbConfig.safe_no_wrap` bounds every carry equation strictly below `p`, so a zero field residue cannot hide a nonzero integer multiple of `p`.

## Bounded-quotient lemma

The trace separately proves canonical `x,y,z < q`. Once the integer relation above is exact, any nonnegative quotient satisfying it is unique. Every honest multiplication quotient obeys

```text
0 <= quotient <= q - 2 < 2^254.
```

Consequently the quotient only needs a 254-bit range decomposition bound to the arithmetic limbs. A full canonical witness with quotient slack and canonical carries adds no soundness. The transparent compiler accepts a witness whose unused quotient slack/carry fields are corrupted, but rejects changes to quotient bytes, limbs, range, or arithmetic relations.

## Executable implementation

- `low_rank_convolution.py` implements generic rank-`2n-1` fixed-point convolution.
- `low_rank_field_bridge.py` composes it with the foreign multiplication carry trace and reduced-quotient estimate.
- `field_bridge.py` contains canonical-output and bounded-quotient logical inventories.
- `constraint_backend.py` emits and executes the five multiplication constraints, output canonical relations, quotient range/packing, signed-carry lookups, and final carry equations.
- `test_low_rank_convolution.py` covers 3-, 4-, 5-, 6-, and 8-limb geometries.
- `test_low_rank_field_bridge.py` checks the complete 3×85 witness composition.
- `test_constraint_backend.py` rejects forged point products, bytes, limbs, and range violations while proving quotient slack is unused.

Interpolation coefficients are derived linear forms of the five point-product outputs; they are not unconstrained coefficient witnesses.

## Complete logical inventory at 16-bit chunks

`x` and `y` are prebound, `z` is newly canonical, and the quotient is newly 254-bit bounded.

| Cost point | Native nonlinear products | Logical lookups | Linear relations | Selectable now? |
|---|---:|---:|---:|---|
| 3×85 rank-5 convolution | 5 | 76 | 17 | yes, current single-field model |
| 3×85 schoolbook reference | 9 | 76 | 17 | no, dominated |
| 2×127 exact split products | 4 | 206 | 26 | yes, backend-dependent challenger |
| dual-field CRT owner-side table | 2 | 63 | 20 | no; cross-PCS equality missing |
| dual-field CRT free-share lower bound | 2 | 49 | 12 | no; not a construction |

One logical lookup event is not one universal proof row. The model assumes a reusable fixed-width tuple table whose row range-checks one chunk and exposes constituent bytes or boundary pieces. It excludes fixed lookup-argument overhead, PCS commitments/openings, parser/hash constraints, and conditional disclosure.

For 25,889 foreign products, rank-5 convolution gives:

```text
129,445 native multiplication gates
1,967,564 logical lookup events
440,113 linear relation events
103,556 fewer native multiplication gates than schoolbook 3×85
517,780 fewer lookup events than the canonical-quotient reference
155,334 fewer linear relations than the canonical-quotient reference
```

## Geometry sweep

Using rank-`2n-1` convolution and the same 16-bit logical range model:

| Limbs × bits | Nonlinear products | Lookups | Simple products+lookups |
|---|---:|---:|---:|
| 3×85 | 5 | 76 | 81 |
| 4×64 | 7 | 81 | 88 |
| 6×43 | 11 | 85 | 96 |
| 5×51 | 9 | 88 | 97 |
| 7×37 | 13 | 95 | 108 |
| 8×32 | 15 | 97 | 112 |

Thus 3×85 remains the provisional single-field baseline after logical range/carry accounting.

## Lookup-width sensitivity

| Chunk bits | Fixed table rows | 3×85 lookups | 2×127 lookups | 2×127 break-even `w` |
|---:|---:|---:|---:|---:|
| 8 | 256 | 147 | 406 | 259 |
| 12 | 4,096 | 102 | 281 | 179 |
| 16 | 65,536 | 76 | 206 | 130 |
| 20 | 1,048,576 | 63 | 179 | 116 |

A larger fixed table reduces logical events but increases fixed-table degree and setup/backend cost. Those costs must be measured rather than assumed free.

## Decision boundary

The 2×127 route saves one multiplication but adds 130 logical lookup events per product at 16-bit chunks. In

```text
cost = lookups + w * native_multiplications,
```

2×127 wins only when one multiplication costs more than 130 logical lookup events. No current backend measurement establishes that ratio. Both selectable routes must therefore be compiled into the same real lookup backend before killing the challenger.
