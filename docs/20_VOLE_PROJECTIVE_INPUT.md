# Vector-OLE Delivery for Algebraic Input Authentication

## Result

The 1.62 MiB naïve catalog of 132×256 affine BLS tokens is not fundamental at the primitive-interface level.

For fresh per-deposit affine secrets `a_i,b_i` and selected bytes `v_i`, the evaluator only needs:

```text
t_i = a_i + v_i b_i mod p.
```

This is vector oblivious linear evaluation (VOLE). The evaluator derives locally:

```text
pk_i    = [t_i]_2 = A_i + v_i B_i
token_i = t_i H(session).
```

The selected tokens then enter the one-signature plus one-inner-product relation documented in `docs/19_ALGEBRAIC_INPUT_AUTH.md`.

Duty-Free Bits gives a non-interactive reduction from vector OLE over a large prime field to 1-out-of-2 OTs, secure against a malicious receiver, with communication `O((lambda+n) log p)` bits. This is directly aligned with the projective input problem, but the RankLock repository does not yet implement that protocol.

Reference:

- https://eprint.iacr.org/2026/476

## Formal interface model

`vole_input_auth.py` implements the ideal affine-output interface and verifies that:

- one 132-byte receiver vector yields 132 affine output scalars;
- those scalars locally produce valid aggregate input authentication;
- the sender state is consumed after one evaluation;
- cross-session transcripts cannot be combined;
- two receiver vectors under one affine sender state recover every affected `a_i,b_i` and therefore every future value.

## Leading-expression inventory

Using `lambda=128`, `n=132`, and a 255-bit scalar field:

```text
(lambda+n) log p = (128+132)*255 = 66,300 bits
ceiling:                               8,288 bytes
```

This number is only the literal leading expression appearing in the asymptotic bound. It is **not** a protocol byte count. It excludes:

- hidden big-O constants;
- base OTs;
- malicious consistency checks;
- framing and authentication;
- distributed sender generation;
- public affine bases;
- the LVA-WE key/CRS and trace relation.

Other modeled sizes:

```text
public A_i,B_i bases:     25,344 bytes
receiver affine outputs:   4,224 bytes
naïve token catalog removed: 1,622,016 bytes
```

Even after adding the public bases, the idealized interface is comfortably below one MiB. That is evidence that projective delivery may be solvable; it is not evidence that the complete RankLock artifact is below one MiB.

## One-shot security requirement

Two evaluations at different values reveal:

```text
b_i = (t_i' - t_i)/(v_i' - v_i)
a_i = t_i - v_i b_i.
```

Therefore:

> Affine VOLE state is one-shot per deposit/session and must be irreversibly burned on completion, abort, timeout, or retry.

A safe retry requires fresh `(a_i,b_i,session)` material. Merely changing network nonces is insufficient.

## Integration hypothesis

The current candidate stack is:

```text
1-out-of-2 OTs / existing projective bit delivery
        ↓
Duty-Free-Bits vector OLE
        ↓
selected affine scalars t_i
        ↓
aggregate BLS token + aggregate public key
        ↓
1 signature gadget + 1 inner-product gadget
        ↓
shared byte witnesses in the fixed RankVM invalidity relation
```

This potentially eliminates both:

- the future-statement timing problem for the 132 bytes; and
- the 256-token-per-coordinate catalog.

## Remaining blockers

- instantiate and benchmark the actual DFB vector-OLE protocol;
- show its receiver inputs are exactly the existing adaptor-selected bits/bytes;
- distribute affine sender shares with one honest setup contributor;
- prove abort/restart one-shot semantics;
- instantiate the signature and inner-product gadgets in the LVA-WE framework;
- include trace-proof gadgets, CRS/key bytes, decryption work, and fault-secret ciphertext;
- compare against BABE/Argo/DFB using complete, normalized costs.

## Decision

P0-PROJ-1 is no longer “find any sub-megabyte idea.” It has a concrete leading candidate: DFB vector OLE feeding an algebraic authenticated-witness relation. The evidence remains a formal interface and asymptotic cost inventory.
