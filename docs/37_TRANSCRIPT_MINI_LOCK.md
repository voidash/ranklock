# Transcript Mini-Lock Cost Envelope

## Purpose

The one-sided proof is public and noninteractive, so the fixed RankLock relation must recompute its transcript challenges and verify the scalar equations. This document estimates whether that wrapper relation fits the remaining per-deposit key budget.

## Planning profile

The current model assumes a Poseidon2-style width-3, rate-2 permutation with:

- 8 full rounds;
- 56 partial rounds;
- \(x^5\) S-box;
- 3 multiplication constraints per S-box.

This yields 240 multiplication constraints per permutation in the simplified model.

The transcript inventory contains:

- 10 future \(G_1\) proof elements;
- 20 scalar proof elements;
- 8 challenge-generating stages and 10 challenges;
- statement/context/domain-separation fields.

The conservative model uses 38 permutations, or 9,120 hash constraints.

## Tight point-binding threshold

The fixed relation budget from v0.15 allows 13,912 trace coordinates after the projective input layer. Reserving 1,024 scalar-verifier constraints and 512 fixed wrapper constraints leaves a maximum of approximately:

```text
325 constraints per each of 10 G1 proof elements.
```

Scenarios:

| Point binding per G1 | Wrapper width | One-MiB result |
|---:|---:|---:|
| 200 | 12,656 | passes |
| 300 | 13,656 | passes narrowly |
| 400 | 14,656 | fails |

The 300-constraint scenario leaves only a small total margin after the future proof and manifest allowance.

## Shared-object repair

Transcript hashing and final pairings must consume the same parsed proof object. Parsing two independent representations creates a split-brain attack. `shared_proof_binding.py` enforces one canonical typed value, but the real outer-curve parsing/subgroup cost is not measured.

## Evidence boundary

This is a parameterized envelope, not a constructed outer-curve gadget or real LVA-WE key.
