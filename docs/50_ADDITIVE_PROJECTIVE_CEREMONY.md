# Additive Projective Ceremony + Fallback Cut-and-Choose

**Checkpoint:** v0.20 candidate  
**Decision:** promising malicious-setup reduction; breakthrough gate not yet met.

## Core construction

Split the BABE hidden scalar across setup contributors:

\[
r = \sum_i r_i \pmod q.
\]

Contributor `i` publishes `[r_i]delta` in BN254 G2 and commits a set of independently generated one-shot Embryo copies for the map

\[
A \mapsto [r_i]A.
\]

At runtime every returned share `Z_i` is certified publicly:

\[
e(Z_i,\delta)=e(A,[r_i]\delta).
\]

Certified shares add:

\[
\sum_i Z_i=[\sum_i r_i]A=[r]A.
\]

This separates the two malicious-setup problems:

1. **secrecy:** a corrupt contributor learning or leaking its own `r_i` does not reveal `r` while one honest share remains hidden;
2. **liveness/correctness of a corrupt contributor's static artifact:** use committed one-shot copies with post-commit random partitioning and runtime fallback.

This is materially cleaner than one monolithic garbler that knows the aggregate scalar.

## Pairing certification

Wrong or malformed outputs are not accepted. For each contributor the evaluator verifies

```text
e(Z_i, delta) == e(A, R_i)
R_i = [r_i]delta
```

and then verifies the aggregate equation again. This is implemented over the existing real BN254 backend in `src/ranklock/additive_projective_ceremony.py`.

## Exact fallback cut-and-choose bound

Let a contributor commit `N=t+q` independent one-shot copies before an unpredictable partition challenge:

- `t` copies are opened and checked completely;
- `q` copies remain unopened and are consumed one at a time as runtime fallbacks.

Assume an opened malformed copy is detected with probability 1. To both pass setup audit and make **all** `q` live copies malformed, the adversary can have exactly `q` malformed copies and the random live set must equal that malformed set. Therefore

\[
\Pr[\text{audit passes and all live copies fail}] \le \binom{t+q}{q}^{-1}.
\]

Balanced exact minima under the current 500 KiB/copy Embryo planning size are:

| target | audit | live | total | achieved bits | setup bytes / contributor | post-activation live bytes / contributor |
|---:|---:|---:|---:|---:|---:|---:|
| 40 | 22 | 22 | 44 | 40.936 | 22,528,000 | 11,264,000 |
| 64 | 34 | 34 | 68 | 64.625 | 34,816,000 | 17,408,000 |
| 80 | 42 | 42 | 84 | 80.474 | 43,008,000 | 21,504,000 |
| 128 | 66 | 66 | 132 | 128.149 | 67,584,000 | 33,792,000 |

The earlier informal `20+20 -> 40 bits` intuition was wrong; it is only ~37.0 bits. The implementation uses exact binomial coefficients.

## Why this may matter

The construction no longer needs a single malicious garbler to hold the aggregate hidden scalar. The one-honest-contributor secrecy argument can be localized to one independently generated contributor layer, while public pairing checks eliminate undetected wrong outputs from every layer.

The remaining malicious behavior of a corrupt layer is selective failure. Runtime fallback consumes at most one query from each one-shot copy, preserving the one-query security discipline.

At 80-bit statistical setup soundness, the conservative setup object is ~43.0 MB **per contributor** before other BABE/graph material; post-activation live material is ~21.5 MB per contributor. This is not the sub-megabyte target, but it is a concrete same-model route worth comparing against the full Mosaic/cut-and-choose baseline rather than comparing only to semi-honest Embryo.

## What is still missing

This checkpoint deliberately does **not** claim the breakthrough gate:

- exact Duty-Free-Bits Embryo code is not in this tree;
- the assumption that an opened copy admits perfect deterministic generation checking must be instantiated against the real DFB artifact format;
- contributor-local generation must be shown composable without cross-layer leakage;
- activation must bind every contributor anchor, copy commitment, partition beacon, session, and Bitcoin graph;
- the exact Strata public-input/proof object and Bitcoin Core regtest path are still absent;
- complete cost must include DFB input encodings, commitments/openings, BABE linear-WE material, contributor count, activation proof, and graph bytes.

## Next decisive experiment

Implement the exact DFB Embryo artifact and answer one binary question:

> Can an opened contributor-local Embryo copy be deterministically verified against its committed generation randomness/share without revealing the honest contributor's live-copy secret state?

If **yes**, the theorem above gives a concrete malicious distributed setup path with exact statistical soundness and no online secret holder. If **no**, proof-carrying generation remains necessary.
