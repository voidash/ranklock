# Algebraic Authentication for Fixed Future Inputs

## Purpose

The static KZG-WE timing barrier disappears if future bridge inputs are moved from the WE statement into the witness of one fixed relation. That move is sound only when the relation cryptographically authenticates the future values and binds the same values into the RankVM trace.

This document gives a concrete pairing-friendly candidate for that authentication layer. It is an executable formal algebraic model, not a secure protocol.

## Fixed per-deposit relation

For a session tag `H` and byte coordinate `i`, setup samples affine secret-key coefficients `a_i,b_i` and publishes:

```text
A_i = [a_i]_2
B_i = [b_i]_2
```

The public key associated with selected byte `v_i` is:

```text
pk_{i,v_i} = A_i + v_i B_i.
```

Setup creates a BLS-style token:

```text
sigma_{i,v_i} = H * (a_i + v_i b_i) in G1.
```

After projective delivery of exactly one token per coordinate, the evaluator computes:

```text
apk   = sum_i pk_{i,v_i}
sigma = sum_i sigma_{i,v_i}.
```

A fixed WE relation combines two prior-art gadget shapes:

1. **signature gadget**

   ```text
   e(sigma, [1]_2) = e(H, apk)
   ```

2. **inner-product gadget**

   ```text
   apk - sum_i A_i = sum_i v_i B_i.
   ```

The byte witnesses `v_i` must be shared with the RankVM trace gadget. The signature check alone is not sufficient: an adversary can generate a fresh BLS key and signature for any tag. The inner-product constraint binds the aggregate key to the fixed coordinate bases and the same selected bytes.

The 2025 LVA-WE framework already provides BLS-signature and inner-product gadget methodology with constant-size ciphertext at the gadget level. Therefore this generic compression is not itself a novelty claim. The open contribution is a complete RankVM relation, projective delivery, malicious activation, and end-to-end cost/security improvement.

## Executable positive result

`algebraic_input_auth.py` confirms:

- 132 selected byte tokens aggregate into one G1 signature and one G2 public key;
- one BLS pairing equation verifies the aggregate signature;
- one inner-product relation binds the aggregate key to all 132 bytes;
- a session-specific tag rejects cross-deposit replay;
- omitting the inner-product relation permits a fresh-key substitution attack.

## One-time-delivery attack

The token family is affine in the selected value:

```text
sigma_{i,v} = sigma_{i,0} + v * (H b_i).
```

If an evaluator obtains two values for the same coordinate under the same session tag, then:

```text
H b_i = (sigma_{i,v1} - sigma_{i,v0}) / (v1-v0).
```

The evaluator can then derive a valid token for every byte value at that coordinate. Publishing the full token catalog is therefore equivalent to surrendering input authenticity.

Required rule:

> For each `(session, coordinate)`, at most one affine authentication token may ever be released.

This is stronger than ordinary replay protection. Abort/retry logic must burn the coordinate-session token state, or refresh the tag/key material.

## Concrete inventory

Using compressed BLS12-381-style sizes only as a byte-count model:

```text
coordinates:                          132
values per coordinate:                256
naive token catalog:               33,792 G1 elements
naive token catalog bytes:      1,622,016
selected runtime tokens:              132 G1 elements
selected runtime token bytes:       6,336
public affine bases:                  264 G2 elements
public affine basis bytes:         25,344
aggregate relation witness:             1 G1 + 1 G2
LVA gadget shapes:                      1 signature + 1 inner product
```

The catalog is already close to, but above, the one-megabyte target before any projective-delivery wrapper, distributed contributors, trace proof, WE key/CRS, or fault-secret ciphertext.

## Security and implementation gaps

The model does not provide:

- a real BLS implementation or concrete assumption proof;
- a projective/oblivious mechanism releasing exactly one token;
- malicious distributed generation of affine token shares;
- proof that token-table setup matches the public `A_i,B_i` bases;
- an exact LVA-WE encryption-key/CRS or decryption cost;
- composition with the full RankVM trace relation;
- a sub-megabyte retained artifact.

## Research decision

The authenticated-witness route remains viable and is now more concrete:

```text
future bytes
    -> one-time affine BLS tokens
    -> one aggregate signature gadget
    -> one inner-product gadget
    -> shared byte witnesses in the RankVM invalidity relation
```

The next task is to instantiate the complete fixed relation in the LVA-WE framework and determine whether the encryption key/CRS, witness group work, and decryption work remain width-free in the dimensions that matter for RankLock.
