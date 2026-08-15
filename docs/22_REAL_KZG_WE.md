# Real BN254 KZG-Opening Witness Encryption

## Result class

**REPRODUCED executable cryptographic prototype.**

`real_kzg_we.py` implements actual BN254 group and pairing arithmetic, a local KZG SRS, polynomial commitments, opening verification, same-point batching, and KZG-opening witness encryption.

For statement `(C,z,y)`, setup chooses nonzero `r` and publishes

```text
H = r([tau]_2 - z[1]_2).
```

The encrypted session is derived from

```text
e(r(C-y[1]_1), [1]_2),
```

while a valid opening proof `pi` derives the same value through

```text
e(pi, H).
```

## Measured reference case

`results/real_kzg_we.json` records a degree-eight run:

```text
SRS:                 416 B
commitment:           32 B
opening witness:      32 B
WE ciphertext:       112 B
opening verified:     yes
secret recovered:     yes
```

The ciphertext is one compressed BN254 G2 header plus a 48-byte authenticated payload.

## What this closes

The repository no longer relies only on an exponent-space KZG model for the opening-WE component. Correct openings decrypt and modified openings or ciphertexts fail under actual pairing arithmetic.

## What it does not close

KZG-opening WE is statement-bound. A ciphertext for a future trace commitment cannot be generated during static bridge setup because the commitment, point, and value do not yet exist. The local SRS trapdoor is also not a production ceremony, and the implementation is variable-time and unaudited.

## Source

- `src/ranklock/bn254_real.py`
- `src/ranklock/real_kzg_we.py`
- `tests/test_real_kzg_we.py`
