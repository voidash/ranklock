# Hidden-Challenge Audit

## Question

Can RankLock avoid verifying the public Fiat–Shamir transcript by placing the verifier challenges secretly in the conditional key while leaving the prover unchanged?

## Result

**No, for the audited monomial-basis protocol.**

The protocol derives ten challenge scalars across eight challenge-generating transcript stages. Those challenges enter nonlinear prover computations, including:

- grand-product or rational recurrences;
- hidden-point polynomial evaluations;
- quotient commitments;
- challenge powers and inversions;
- challenge-dependent shifts and combinations.

A prover who does not know the challenges cannot compute the existing proof messages.

## Scope

This kills only the shortcut:

> hide the raw Fiat–Shamir challenges and run the published prover unchanged.

It does not rule out:

- a purpose-built linear interactive proof;
- a different LVA protocol whose responses are projectively computable;
- MPC/oblivious evaluation of challenge-dependent prover work;
- verification of the public Fiat–Shamir transcript inside the fixed relation.

## Decision

The current surviving route verifies the public transcript inside a compact fixed relation. The cost of that relation is modeled in `transcript_mini_lock.py`.
