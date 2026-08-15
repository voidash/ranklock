> **Historical checkpoint.** v0.22 replaced this paper-derived envelope with a real execution and found that standalone output masks raise one slot to 677,862 bytes. See `V022_CHECKPOINT.md`.

# RankLock v0.21 Bounded-MPC Embryo Candidate

**Date:** 2026-08-10  
**Decision:** construction-level breakthrough candidate; full breakthrough target not met

## Storage audit

The stored v0.19 archive was not a clean breakthrough baseline:

- the top-level metadata remained v0.18;
- its checkpoint left bounded multi-query hidden-scalar evaluation open;
- eight new modules were not covered by the inherited suite;
- two new modules imported a missing `ranklock.bip340` dependency.

The stored v0.20 candidate added a correct additive-share/pairing composition, but malicious-generator liveness still used large cut-and-choose schedules.

## New v0.21 result

v0.21 implements and tests the composition layer for:

```text
q independent one-shot Embryo artifacts
+ one shared hidden scalar generated inside active MPC
+ all-contributor BIP340 activation certificate
+ exact canonical manifest
+ burn-before-evaluate slot ledger
+ real BN254 output certification
```

For `q=2`, two contributors and a 32-byte lock payload:

```text
one paper-derived Embryo slot:    511,219 B
canonical manifest:                   748 B
complete two-slot envelope:     1,023,186 B
margin below 1 MiB:               25,390 B
```

`q=3` cannot fit one MiB even before the manifest.

## Reproducibility

A fresh archive extraction passed manifest verification, compilation and the complete suite:

```text
74 test files
277 tests passed
0 failed
```

The suite includes official BIP340 vectors, manifest mutations, missing signatures, duplicate roots/random tapes, replay/burn behavior, the two-query affine-state recovery attack, real BN254 pairing checks and execution of the previously untested v0.19 connector/semantic modules.

## Claim boundary

The candidate is conditional on:

- an exact serialized DFB/Embryo generator;
- concrete `n-1`-corrupt active-MPC generation;
- an adaptive, auxiliary-input and two-instance security theorem for DFB;
- authenticated one-label-per-bit Bitcoin input release;
- complete BABE/graph byte accounting and Bitcoin Core regtest.

Therefore `breakthrough_target_met` remains `false`.

## Read order

1. `BREAKTHROUGH_REPORT.md`
2. `docs/51_BOUNDED_MPC_EMBRYO.md`
3. `docs/52_ADAPTIVE_DFB_PROOF_TARGET.md`
4. `results/v021_bounded_mpc_embryo.json`
5. `results/v021_storage_audit.json`
6. `STATUS.json`
