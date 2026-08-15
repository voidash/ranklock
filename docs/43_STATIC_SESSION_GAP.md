# 43 — Static accepting-session gap

## Result

The one-sided final pairing equation is small, but its ordinary normalized residual is the public identity element in GT.

A verifier equation of the form

```text
e(Q, [s]G2) = e(R + α⁻¹Q, G2)
```

is excellent for public verification. It does not, by itself, produce a hidden accepting session suitable for deriving a Bitcoin fault key.

## Failed shift

A natural attempt is to add a public affine target `T` and arrange that acceptance yields `T^r`. If a public decomposition of `T` over the fixed G2 anchors is known, the scaled anchors reveal `T^r` without any future proof.

The repository includes a real BN254 attack demonstrating this leakage.

## Consequence

The v0.18 value

```text
862,693 bytes
```

is an arithmetic-and-transcript coordinate envelope. It is not an instantiated conditional key. A valid construction still needs either:

1. a group-aware witness-dependent predictable token;
2. a hard-YES secure witness PRF;
3. a concrete projective positive-predicate backend after transaction-graph polarity inversion.

Evidence:

- `src/ranklock/one_sided_static_session_gap.py`
- `src/ranklock/one_sided_lva_decomposition.py`
- `results/v018_static_session_checkpoint.json`
- `results/v018_lva_decomposition.json`
