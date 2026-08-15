# 44 — Laconic SHVZK / witness-encryption frontier

Generic theory relates efficient-prover laconic special-HVZK arguments and witness encryption. That theory does not directly instantiate RankLock.

## Why the generic route is not concrete

The current one-sided proof contains ten G1 elements and twenty scalars, approximately 10,240 public proof bits under the present encoding. A generic histogram-style transformation over the entire prover-message space has support size `2^10240` and is therefore not a concrete compiler.

## Missing property

The one-sided proof candidate uses direct, unblinded commitments. The repository has not established:

- honest-verifier zero knowledge;
- special honest-verifier zero knowledge;
- a simulator with the exact coupling needed by the conditional lock;
- public witness-computable simulator coins.

A fixed-challenge Schnorr toy model shows the distinction: a simulator can produce an accepting transcript, but computing the coupled simulated response from an honest witness may require solving a discrete logarithm.

## Decision

Laconic-SHVZK theory remains a prior-art/theorem guide, not an implementation plan. The active targets are the hard-YES WPRF and the validity-first graph.

Evidence:

- `src/ranklock/laconic_shvzk_we_frontier.py`
- `src/ranklock/coupled_shvzk_frontier.py`
- `results/v018_laconic_shvzk_frontier.json`
- `results/v018_coupled_shvzk_frontier.json`
