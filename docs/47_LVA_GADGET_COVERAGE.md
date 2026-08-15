# 47 — Conditional-gadget coverage audit

The previous 66-byte-per-coordinate slope comes from a real secp256k1 inner-product witness-encryption gadget for known scalar witnesses satisfying:

```text
Σ w_i U_i = T
```

It is not a compiler for arbitrary verifier constraints.

## Uncovered load-bearing witness kinds

The complete wrapper contains:

- authenticated future bytes;
- BN254 G1 points with unknown discrete logarithms;
- canonical point and curve constraints;
- Poseidon2 `x^5` trace constraints;
- scalar multiplication/inversion constraints;
- a pairing-product witness;
- a hidden accepting session.

The scalar inner-product gadget consumes none of the unknown-log G1 or nonlinear trace objects directly.

## Classification correction

```text
862,693 bytes
```

is classified as:

```text
ARITHMETIC_AND_TRANSCRIPT_COORDINATE_ENVELOPE
```

It is not an actual serialized full LVA/WE key.

Evidence:

- `src/ranklock/lva_gadget_coverage.py`
- `results/v018_lva_gadget_coverage.json`
