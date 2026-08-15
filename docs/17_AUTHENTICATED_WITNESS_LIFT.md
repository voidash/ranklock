# Authenticated Witness Lift

## Alternative to a future statement

A future input need not be part of the witness-encryption statement. It can be existentially quantified as a witness if the fixed relation verifies an unforgeable, session-bound authentication token for that input.

The fixed relation becomes:

```text
R(context; input, authentication, proof) =
    VerifyAuthentication(context, input, authentication)
    AND VerifyInvalidity(context, input, proof).
```

The ciphertext can then be created at deposit activation against fixed `context`.

## Substitution attack without authentication

If `input` is moved into the witness without authentication, the relation is usually trivial to satisfy: the adversary selects any convenient invalid proof rather than the actual protocol input.

`authenticated_witness_lift.py` contains both variants:

- the unsafe fixed relation accepts an attacker-selected invalid input;
- a hash-based one-time signature binds the actual dynamic input and rejects retargeting.

The hash-based signature is only a relation model. It is not the intended Strata transport.

## Strata interpretation

The existing 132 completed adaptor signatures are candidate authentication witnesses for:

```text
4 bytes of game/public input
128 bytes of compressed counterproof
```

A fixed outer relation could verify those signatures, recover the bytes, and verify that the authenticated proof is invalid. This removes the need to encrypt directly to a future KZG commitment.

However, all authentication checks must be cryptographically inside the linearly verifiable relation. A host-side software check does not constrain witness decryption.

## Prior-art collision

The CRYPTO 2025 framework for witness encryption from linearly verifiable SNARKs explicitly permits witness elements such as signatures and public keys to be composed with inner-product and degree-check gadgets, with logical AND/OR composition and constant-size ciphertexts in its applications.

References:

- https://eprint.iacr.org/2025/1364
- https://hackmd.io/@guruvamsi-policharla/S1WuMrAFxe

Therefore the generic transformation:

```text
future authenticated input -> witness variable -> fixed WE relation
```

is not a safe novelty claim.

## Remaining research question

The possible contribution is concrete rather than generic:

> Can the complete Strata relation—132 authenticated bytes, canonical parsing, sparse SP1 invalidity, and transaction binding—be compiled into a linearly verifiable relation whose retained key/ciphertext and expensive decryption work beat BABE/Argo and Mosaic under the same malicious model?

The decisive costs are:

- encryption key / CRS size, not only ciphertext size;
- witness/prover group operations;
- signature-authentication cost;
- malicious setup and extractability assumptions;
- input/session uniqueness;
- full proof and Bitcoin execution.
