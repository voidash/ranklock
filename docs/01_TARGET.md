# Breakthrough Target

## Problem statement

Let `P` be a deterministic RankVM program over a large prime field. A future public input `x` and public witness/proof `w` determine a bit `P(x,w)`. The protected Bitcoin secret `s` should be recoverable exactly on the designated fault branch, for example when `P(x,w)=0`.

We seek a static public artifact produced before `x` and `w` are known.

## Target interface

```text
DistributedSetup(1^lambda, P, shares(s))
    -> public artifact A, local erasures/certificates

ProjectiveEncode(A, x)
    -> public input encodings E_x

Evaluate(A, E_x, w, public beacons)
    -> s or bottom
```

After setup, no party is online or holds an aggregate release key.

## Required correctness

For every well-formed input:

```text
P(x,w) = fault  -> Evaluate(...) = s
P(x,w) = valid  -> Evaluate(...) = bottom
```

Malformed encodings, noncanonical proofs, and verifier errors must return `bottom`; they must never be reinterpreted as evidence of the fault branch.

## Required security properties

1. **Fault-secret secrecy:** if no valid fault witness exists for the activated statement, `s` remains hidden.
2. **Evaluator authenticity:** an evaluator cannot forge another internal or output encoding.
3. **Generator/setup soundness:** malicious setup contributors cannot activate a different program, input schema, output predicate, or Bitcoin key.
4. **Dishonest-majority setup:** security with up to `n-1` corrupted setup contributors, assuming one contribution is honest and erased.
5. **Projectivity:** future inputs are delivered bitwise/bytewise through a simple externally compatible mechanism.
6. **Public cold start:** a new evaluator needs only `A`, public chain/bridge data, and the active input encodings.
7. **Noninteractive post-activation evaluation:** no online secret holder or signer.
8. **Replay/equivocation safety:** one activation/session cannot be reused for another game, graph, transaction, or challenge sequence.
9. **Selective-abort safety:** abort/retry cannot bias challenge generation enough to violate soundness.

## Complexity target

For total certified nonlinear rank/trace work `R`, unique template count `T`, and depth `D`:

```text
static retained artifact:    poly(lambda, T, D, log R, log p)
expensive crypto at runtime:  poly(lambda, T, D, log R, log p)
native evaluator work:       O(R polylog R)
projective input material:    below 1 MiB for Strata's complete boundary
```

Concrete target:

- at least 100× less retained/setup material than current Mosaic deployment accounting;
- competitive with Argo/BABE for Groth16, or a clear generality advantage at a small constant-factor cost;
- no weaker online-honesty assumption than Mosaic.

## What would count as the paper

A paper-worthy result requires all of:

- a new primitive or theorem, not only an IR;
- a formal construction and proof;
- a real compiler generating cryptographic artifacts;
- same-security end-to-end comparison;
- complete Strata counterproof and Bitcoin execution.

The target has **not** been met.

## v0.17 practical theorem split

The surviving one-sided wrapper currently separates two targets:

1. **Strong asymptotic target:** total setup/artifact, including the reusable CRS, is polylogarithmic in execution size. This remains open.
2. **Practical Strata target:** the reusable universal CRS may be circuit-linear, but per-deposit retained material is below one MiB, no party remains online, and the total setup/proving cost decisively improves the deployed Mosaic infrastructure under the same malicious model.

Meeting only the second target can justify a strong systems/applied-cryptography result, but it is not the original fully succinct theorem. Every paper draft must state which target is proved.
