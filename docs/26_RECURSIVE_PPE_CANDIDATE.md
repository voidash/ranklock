# Recursive PPE Candidate

## Candidate reduction

A possible route is:

```text
complete RankVM execution
        -> transparent proof over BLS12-381 Fr
        -> recursive Groth16 wrapper
        -> one fixed Groth16 pairing-product relation
        -> fixed PPE witness-encryption lock.
```

The future context digest is encoded injectively as two canonical 128-bit scalars. Reducing an arbitrary 256-bit digest to one scalar is explicitly rejected: the all-zero string and the scalar-modulus encoding have the same modular image.

The formal model binds program, statement, transparent verifier key, wrapper key, deployment identifier, and invalid-result tag.

## Evidence class

**FORMAL MODEL / ESTIMATE.**

The repository contains an exponent-space Groth16 equation and a byte envelope for projective context selection. It does not contain:

- a complete transparent RankVM proof system;
- a correct recursive wrapper circuit and prover;
- a secure PPE witness-encryption scheme;
- a justified number of projective components per bit;
- a malicious distributed setup theorem.

The retained envelope reported in `formal_recursive_candidate.json` is therefore not an artifact-size claim.

## Parallel-checkpoint review

The parallel archive named `ranklock-v0.15-research-breakthrough.zip` was not accepted as a release baseline. Its suite produced 109 passes and two failures in the new R1CS/IPA backend. Only the independent formal context/PPE model was retained, and its status was downgraded to `FORMAL_RECURSIVE_REDUCTION_CANDIDATE`.

## Source

- `src/ranklock/groth16_projective_lock.py`
- `src/ranklock/recursive_lock_architecture.py`
- `tests/test_groth16_projective_lock.py`
- `results/formal_recursive_candidate.json`
- `results/parallel_checkpoint_validation.json`
