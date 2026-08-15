# 46 — Why ordinary witness encryption is insufficient

## Fixed relation

The setup-time relation fixes the verifier, program, deposit, epoch, and projective-authentication keys. Future proof bytes remain witness variables.

Because the projective layer is designed to support every future byte choice and malformed/invalid proofs exist, the fixed relation has at least one accepting witness before the actual bridge event.

```text
fixed statement ∈ L
```

This is true even when no adversary currently possesses an authenticated accepting witness.

## Definition gap

Ordinary witness-encryption secrecy is required for statements outside the language. It does not promise secrecy for an already-YES statement whose witness happens to be unavailable.

The repository contains a toy executable separation:

- the public statement is provably a YES instance;
- a real private authentication token is an accepting witness;
- exhaustive public guessing over short tokens does not find it.

Language membership and witness availability are different facts.

## Required replacement

RankLock needs hard-YES pseudorandomness, extractability, witness invariance, and one-honest-contributor distributed setup security—or a protocol transformation that uses an already instantiated projective positive-predicate garbling scheme.

Evidence:

- `src/ranklock/fixed_yes_instance_gap.py`
- `results/v018_yes_instance_gap.json`
