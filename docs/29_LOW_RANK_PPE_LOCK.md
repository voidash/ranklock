# Low-Rank Fixed-G2 PPE Conditional Lock

**Date:** 2026-08-07
**Evidence:** **REPRODUCED real BN254 arithmetic** + **EXACT serialization accounting**
**Code:** `src/ranklock/low_rank_ppe_lock.py`
**Tests:** `tests/test_low_rank_ppe_lock.py`

## Relation

Future proof/witness elements are in G1. Every G2 verifier base is fixed:

```text
product_i e(A_i, B_i) = T,
```

where `T` is a fixed nonidentity GT element. The fixed bases have public coefficient rank `k`:

```text
B_i = sum_j a[i,j] U_j.
```

Setup samples hidden `r` and publishes only the scaled anchors `r U_j`.

For a satisfying witness, decryption computes:

```text
C_j = sum_i a[i,j] A_i
product_j e(C_j, r U_j)
  = product_i e(A_i, r B_i)
  = T^r.
```

The lock KDFs `T^r` into a ChaCha20-Poly1305 key. Evaluation uses `k` pairings and
`O(mk)` public-scalar G1 work, rather than `m` pairings and `m` stored scaled G2 bases.

## Real executable result

The implementation uses the dependency-free BN254 group and optimal-Ate pairing backend.
The focused tests establish:

- direct `m`-term pairing evaluation equals the `k`-anchor evaluation;
- a satisfying witness decrypts;
- changing one G1 witness element fails AEAD authentication;
- replacing one scaled anchor invalidates the setup proof;
- publishing a target decomposition over the scaled anchors fully breaks secrecy;
- a valid common-scalar proof does **not** certify ciphertext correctness.

This is real elliptic-curve/pairing arithmetic, but variable-time unaudited research code.

## Same-scalar setup proof

A generalized Schnorr proof uses one nonce and one response to prove simultaneously:

```text
R_0 = r G2
R_j = r U_j  for every anchor j.
```

The proof contains:

```text
(nonce * G2)
(nonce * U_j) for each anchor
one Fr response
```

This is exact per-anchor verification, not random-linear-combination batching. It proves only
that one scalar generated all scaled anchors.

## Exact 11-term / 2-anchor envelope

The current executable serialization model reports:

```text
term count:                             11
anchor rank:                             2
coefficient matrix:                    704 B
relation (anchors + coefficients + T): 1,255 B
setup key + same-scalar proof:          416 B
ciphertext:                              48 B
------------------------------------------------
total retained model:                 1,719 B
compressed pairings:                      2
uncompressed term pairings:              11
```

This is far below the 935,830-byte post-projective-input budget. It is only a wrapper-shape
cost envelope; there is no knowledge-sound 11-term RankVM wrapper yet.

## Fatal target-preimage condition

If public points `X_j` satisfy

```text
product_j e(X_j, U_j) = T,
```

then anybody computes

```text
product_j e(X_j, r U_j) = T^r
```

and decrypts without the future proof. The regression test deliberately publishes those points
and recovers the secret.

A secure wrapper must therefore have a target whose satisfying decomposition over the scaled
anchors is unavailable before a valid future proof. `T != 1` alone is insufficient.

## Malicious-activation gap

The same-scalar proof authenticates the key, but a corrupt setup party can replace the 48-byte
ciphertext with arbitrary bytes while retaining a valid proof. No public checker can detect the
failure before a future satisfying witness exists. This is an executable selective-failure/DoS
certificate.

A complete n-1-corrupt activation protocol must additionally prove that:

- each encrypted fault-secret/adaptor share matches its public commitment;
- the ciphertext uses the same hidden lock scalar as the scaled anchors;
- all shares combine to the activated Bitcoin public condition;
- abort/retry cannot bias or reuse one-shot material.

That proof is not constructed here.
