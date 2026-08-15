# RankLock v0.24.1 checkpoint — reproducibility recovery

## Decision

```text
COMPLETE SOURCE RECOVERY:                    IMPLEMENTED
CLEAN REPRODUCTION TARGET:                   PENDING FINAL ARCHIVE CHECK
CONDITIONAL SECURITY HARNESS:                EXECUTABLE
PRODUCTION / SAFE-FOR-FUNDS TARGET:          NOT MET
```

v0.24.1 reconstructs the source that was absent from the surviving v0.24
evidence. It is a reproducibility and security-harness release, not a funded
bridge release.

## Recovered implementation

The package now contains the previously missing implementations for:

- whole-slot adaptive sealing;
- context-bound input-label authorization;
- executable security qualification;
- exact finite-group body-pad sampling;
- per-slot CCRH nonce namespaces.

The authorization signature also commits to the complete opening vector. This
prevents an outsider from mutating an honestly signed release and consuming a
slot. A deliberately malformed release signed by the configured authorizer is
still burned before semantic parsing, preserving one-shot selective-failure
control.

## Current executable result

```text
complete sealed slot:                         522,102 bytes
two sealed slots:                           1,044,204 bytes
signed positive-lock manifest:                    748 bytes
complete retained object:                  1,044,952 bytes
margin below one MiB:                           3,624 bytes
authorized online release per slot:            24,836 bytes
```

The deterministic conformance fixture is public and must never protect funds.
An OS-entropy fixture is evidence only; it is not a production ceremony.

## Test result

```text
78 test files
305 tests passed
0 failures
```

The complete 91-prime generator additionally creates two full slots and the
independent verifier replays both without the hidden scalar.

## Conditional security boundary

The executable qualification remains conditional on:

- selective privacy of the exact fused DFB/Embryo slot under its CCRH model;
- the whole-garbled-function coarse-adaptive transform in the random-oracle model;
- SHA-256 and BIP340 assumptions;
- BN254 discrete logarithm and the explicit post-challenge one-more assumption;
- the separate positive-lock assumption.

Group-linear raw outputs remain derivable. The protocol property is that only
two activated evaluations are accepted.

## Gates still required before funds

1. Actively secure dishonest-majority MPC for the exact fused and sealed generator.
2. Bitcoin witness extraction that atomically releases the seed and selected labels.
3. Durable one-shot burn across crashes, concurrent evaluators, reorgs and forks.
4. Bitcoin Core regtest covering valid, malformed, replay, timeout, fee/CPFP and reorg paths.
5. Constant-time implementation, parser/DoS hardening and secret-state erasure.
6. Independent cryptographic review and an implementation audit.

`safe_for_funds` remains false.
