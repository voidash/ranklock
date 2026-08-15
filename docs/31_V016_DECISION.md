# v0.16 Research Decision

**Date:** 2026-08-07

## Breakthrough target

**Not met.**

## Closed in this checkpoint

1. The generic “publish a short PCG seed and expand arbitrary scaled verifier bases” route is
   killed in the public algebraic source-group model by an exact rank lower bound.
2. A positive low-rank escape is constructed with real BN254 arithmetic: rank-`k` fixed G2
   verifier bases require only `k` scaled anchors.
3. An 11-term / 2-anchor cost envelope is 1,719 retained bytes and two decryption pairings.
4. Changed-witness and setup-generator substitutions are rejected in executable tests.
5. Publishing a target decomposition is shown to destroy secrecy.
6. A valid same-scalar setup proof is shown insufficient for malicious activation because it
   does not prove ciphertext/plaintext consistency.
7. KZG/PLONK-style identity targets and Groth16-style dynamic G2 proof elements are separated as
   distinct wrapper blockers.

## New primary target

Construct a **target-separated low-rank fixed-G2 wrapper** for complete RankVM invalidity:

```text
complete RankVM invalidity
        -> near-linear transparent/folding proof
        -> transcript-bound knowledge-sound wrapper
        -> only future G1 terms
        -> constant/polylog fixed G2 anchor rank
        -> nonidentity target with no public scaled-anchor preimage
        -> low-rank PPE conditional lock
        -> maliciously certified fault-secret/adaptor shares.
```

## Required theorem and implementation evidence

A surviving construction must provide:

- the exact proof relation and extraction theorem;
- a concrete wrapper prover and verifier;
- exact fixed-G2 anchor rank;
- proof, universal CRS, verifier-specific key, lock, and ciphertext sizes;
- target-separation argument;
- transcript and future-context binding;
- a public malicious setup proof for both scaled anchors and encrypted fault-secret shares;
- malformed proof, target substitution, replay, selective failure, and abort/retry tests;
- total RankVM and Strata end-to-end cost against Mosaic, Argo, BABE, and HSS garbling.

## Kill/reframe rules

Kill or reframe the breakthrough claim if:

- target separation requires obfuscation/iO or assumptions outside the intended practical
  envelope;
- the wrapper reintroduces a circuit-linear verifier-specific CRS with no concrete advantage;
- malicious ciphertext/share consistency requires trace-linear cut-and-choose;
- the only complete result is a generic recursive SNARK plus known LVA/PPE-WE with no new theorem
  or compelling same-security system advantage;
- projective future input still needs an honest online sender.

## Evidence files

- `src/ranklock/public_correlation_rank.py`
- `src/ranklock/low_rank_ppe_lock.py`
- `src/ranklock/verifier_shape_frontier.py`
- `src/ranklock/correlation_seed_experiment.py`
- `tests/test_public_correlation_rank.py`
- `tests/test_low_rank_ppe_lock.py`
- `tests/test_verifier_shape_frontier.py`
- `results/public_correlation_checkpoint.json`
