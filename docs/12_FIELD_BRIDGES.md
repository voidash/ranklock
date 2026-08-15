# Foreign-Field Bridge Candidates

RankVM's verifier arithmetic uses the BN254 base field `Fq`, while a pairing PCS normally commits polynomials over a curve scalar field. v0.13.2 contains three executable arithmetic routes: two selectable single-field models and one unresolved dual-field composition.

All lookup counts below use a **16-bit logical tuple table**. One table row range-checks a 16-bit chunk and may expose constituent bytes or boundary pieces. Logical lookup events are not physical proof rows; fixed-table, copy-constraint, and lookup-argument overhead remain backend-dependent.

The per-product accounting assumes `x` and `y` are already bound trace values. The output `z` is freshly bound as a canonical field element. The internal reduction quotient is freshly bound only as a nonnegative 254-bit integer.

## Shared quotient lemma

For canonical `0 <= x,y,z < q`, suppose the circuit proves the exact integer relation

```text
x*y = z + quotient*q
```

and `0 <= quotient < 2^254`. Then `quotient` is forced to be the unique integer `(x*y-z)/q`, hence the honest `floor(x*y/q)`, which is itself below `q`. A second witness for

```text
quotient + slack = q - 1
```

is therefore redundant. Removing it saves range and linear constraints without changing the accepted relation.

The exactness premise is load-bearing. In the single-field routes it comes from coefficient and carry no-wrap bounds. In the CRT route it comes from the two-modulus residual theorem below.

## Route A — one native field, 3×85-bit limbs with rank-5 convolution

Represent every `Fq` value as three 85-bit limbs. Instead of nine schoolbook products, evaluate the two degree-two limb polynomials at five fixed points, multiply pointwise, and linearly interpolate the five convolution coefficients. Signed radix carries enforce the exact reduction relation.

### Executable modeled cost

```text
5 native nonlinear products
76 logical tuple/range lookups
17 linear relation events
```

Per product, the 76 lookups consist of:

```text
canonical z serialization/slack/carries: 36
254-bit quotient range:                 16
signed arithmetic carry offsets:        24
```

For the current 25,889-product known subtotal:

```text
129,445 native nonlinear products
1,967,564 logical lookup events
440,113 linear relation events
```

This excludes fixed lookup-argument overhead, parser/hash constraints, PCS commitments/openings, and conditional disclosure.

### Advantages

- one proof field and one PCS;
- exact integer relation with explicit no-wrap bounds;
- four fewer native products than schoolbook 3×85;
- no redundant quotient canonical-slack proof;
- concrete witness, tamper, and transparent-constraint tests;
- estimator and emitted relation ledger agree exactly.

### Remaining work

- compile into a real cryptographic lookup/R1CS/AIR backend;
- measure physical rows, columns, fixed-table degree, proof size, and prover memory;
- integrate squaring, inversion, equality, and complete verifier traces;
- include parser and hash constraints.

See `docs/13_LOW_RANK_FIELD_BRIDGE.md` and `docs/14_CONSTRAINT_BACKEND.md`.

## Route B — one BLS12-381 scalar field, 2×127-bit split products

Because `2^254 < BLS12-381 Fr`, every 127×127-bit limb product is exact in the native field. Four variable products are split into low/high 127-bit chunks, and both `x*y` and `quotient*q+z` are normalized into four common radix digits.

### Executable modeled cost

```text
4 native nonlinear products
206 logical tuple/range lookups
26 linear relation events
```

This route saves one multiplication relative to rank-5 3×85 but adds 130 logical lookup events. Under

```text
cost = lookups + w*native_multiplications
```

it wins only for `w > 130`. Backend packing may change this boundary, so it remains a measured-backend challenger rather than the baseline.

For the current subtotal:

```text
103,556 native nonlinear products
5,333,134 logical lookup events
673,114 linear relation events
```

## Route C — two native fields with CRT exactness

Use the coprime scalar fields

```text
m1 = BN254 Fr
m2 = BLS12-381 Fr
M  = m1*m2.
```

For canonical `x,y,z < q`, a 254-bit quotient `0 <= k < 2^254`, and residual

```text
D = x*y - z - k*q,
```

the positive side is below `q^2` and the negative side has magnitude below `2^254*q`. The current moduli satisfy

```text
M / (2^254*q) ≈ 1.81138.
```

Therefore `D = 0 mod m1` and `D = 0 mod m2` imply `D=0` over the integers. The same simple bound does **not** certify a 255-bit quotient range: its ratio is approximately `0.90569`. Thus 254 bits is both sufficient for every honest quotient and maximal under this residual argument.

### Arithmetic core and owner-side trace

```text
one native multiplication in BN254 Fr
one native multiplication in BLS12-381 Fr
63 owner-side logical tuple/range lookups
20 linear relation events
```

The optimistic free-shared-table lower bound is:

```text
2 native multiplications
49 logical lookups
12 linear relations
```

For the current subtotal, the arithmetic core remains 51,778 native multiplications total, 25,889 in each proof field.

### Load-bearing consistency condition

Both residue traces must encode the **same bytes** for every reused input, canonical output, and bounded quotient. Reusing one Python object or passing host-equal words to two transparent ledgers is not a cryptographic binding. Without a common commitment or equality proof, the two congruences can describe unrelated multiplications; the executable split-brain regression demonstrates this.

The 63-lookup owner-side point and 49-lookup lower bound both omit the cross-PCS equality proof, dual PCS openings, and conditional lock for the conjunction. Neither is selectable.

### Advantages

- only two nonlinear products per foreign multiplication;
- no wide signed carry chain;
- simple exact CRT theorem with a tight 254-bit quotient range.

### Unresolved costs and risks

- cryptographic common-table binding across two fields;
- two PCS systems and their setup;
- conjunction of both proof/conditional-lock relations;
- security limited by the weaker backend;
- operational and implementation complexity.

## Apples-to-apples table

| Cost point | Native products | Logical lookups | Linear relations | Proof fields | Selectable? |
|---|---:|---:|---:|---:|---|
| 3×85 rank-5 | 5 | 76 | 17 | 1 | yes, provisional baseline |
| 3×85 schoolbook reference | 9 | 76 | 17 | 1 | no, dominated |
| 2×127 split | 4 | 206 | 26 | 1 | yes, benchmark challenger |
| CRT owner-side | 2 | 63 | 20 | 2 | no, cross-field binding missing |
| CRT free-share lower bound | 2 | 49 | 12 | 2 | no, not a construction |

## Current decision

- **Provisional baseline:** 3×85 rank-5 single-field bridge.
- **Benchmark challenger:** 2×127 split-product single-field bridge.
- **Blocked route:** dual-field CRT until a compact, sound common-table binding exists.

This is an ESTIMATE-level route decision backed by exact witnesses and reproduced transparent constraint traces, not a production proof benchmark.
