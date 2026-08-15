# 42 — BN254-direct one-sided wrapper

## Decision

The outer-curve route from v0.17 fails the point-binding gate. A consistent CP6-style candidate needs 523 logical canonical/on-curve rows per proof point, and a conventional subgroup check adds at least 31,779 native products per point before range constraints.

The surviving route runs the one-sided wrapper on BN254 itself and represents RankVM's BN254 base-field arithmetic non-natively over BN254 Fr.

## Exact point object

Each one-sided proof point is a canonical uncompressed 64-byte encoding:

```text
x || y
```

Both coordinates are represented as three 85-bit limbs. The wrapper enforces:

1. limb range constraints;
2. canonical reconstruction below BN254 Fq;
3. the affine curve equation `y² = x³ + 3`;
4. rejection of the point at infinity;
5. a shared typed object for transcript and pairing verification.

BN254 G1 has cofactor one, so an on-curve non-infinity point is already in the prime-order subgroup. No scalar-multiplication subgroup check is required.

The current exact logical ledger is:

```text
267 rows per G1 proof element
10 proof elements
2,670 rows total
```

The old gate was 325 rows per G1 element, so this component passes.

## Transcript packing

For limb index `i`, the transcript absorbs:

```text
x_i + 2^85 y_i
```

Because `x_i,y_i < 2^85`, the map is injective and the packed value is below `2^170 < Fr`. Ten G1 elements therefore contribute 30 native transcript field elements, not 60.

## Field bridge

A BN254-Fq multiplication is lowered to an exact 3×85 rank-5 non-native multiplication over BN254 Fr. The retained verifier inventory is:

```text
25,889 Fq products
129,445 native nonlinear products
1,967,564 logical lookup events
440,113 linear relation events
2,537,122 total logical events
```

## Security boundary

This module establishes canonical point binding and an exact arithmetic inventory. It is not a SNARK implementation and does not supply conditional disclosure.

Evidence:

- `src/ranklock/bn254_direct_wrapper.py`
- `results/v018_bn254_direct_wrapper.json`
