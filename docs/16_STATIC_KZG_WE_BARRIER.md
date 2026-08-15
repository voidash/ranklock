# Static KZG-WE Timing Barrier

## Standard construction is statement-bound

For KZG statement `(C, alpha, beta)`, standard witness encryption chooses hidden `r` and forms:

```text
H(alpha) = r ([tau]_2 - alpha [1]_2)
S         = e(r(C - beta[1]_1), [1]_2).
```

The encrypted payload is masked with a key derived from `S`. Both `H` and `S` depend on the future statement.

## Positive restricted case: fixed commitment

When `C` is fixed during setup, point and value can be delivered projectively.

The formal model precomputes:

```text
base        = M / e(C, r[1]_2)
point label = r([tau]_2 - alpha[1]_2)
value label = e(beta[1]_1, r[1]_2)
```

The selected payload is:

```text
base * value_label,
```

and a valid opening computes the missing factor through the selected point header. The model recovers the protected `GT` element and rejects a wrong value selection.

This requires a one-time delivery mechanism that reveals only the selected labels. Publishing all point headers reveals their differences.

## Reusable update attack

Suppose a public updater reuses one randomizer `r` and returns standard headers for arbitrary points. Two queries give:

```text
H(alpha_0) - H(alpha_1)
-------------------------------- = r[1]_2.
       alpha_1 - alpha_0
```

Once `r[1]_2` is known, anyone computes the witness-only session for any future statement:

```text
e(C - beta[1]_1, r[1]_2).
```

The executable attack is in `commitment_oblivious_lower_bound.py`.

## Scope of the barrier

The attack rules out only the direct family:

```text
standard KZG-WE
+ one reusable hidden randomizer
+ arbitrary public point updates.
```

It does not rule out:

- one-time selected projective headers;
- a fresh randomizer with an online encapsulator;
- a stronger functional/witness-encryption primitive;
- a fixed relation in which future inputs are authenticated witness variables;
- a construction not algebraically equivalent to standard KZG-WE.

## Exact remaining primitive

A direct breakthrough primitive would be **commitment-oblivious projective witness encryption**:

```text
StaticSetup(program, secret) -> artifact
PublicUpdate(artifact, future commitment/opening statement) -> selected ciphertext
Decrypt(selected ciphertext, valid opening) -> secret
```

with these properties:

- update is public and noninteractive;
- update does not reveal the encapsulation session;
- ciphertext and retained material are sublinear, ideally polylogarithmic, in trace length;
- malicious setup is secure with one honest contributor;
- future input selection is one-time and non-equivocating.

Standard KZG-WE does not provide this interface.
