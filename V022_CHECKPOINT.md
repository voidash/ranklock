# RankLock v0.22 checkpoint — real DFB/Embryo execution

**Date:** 2026-08-11  
**Decision:** implementation gate passed; two-slot standalone sub-MiB gate failed under current accounting.

## Closed gate

`P0-DFB-1` is complete at the research-execution level.

The package generates, serializes, parses and evaluates the real Duty-Free-Bits switch program for the complete Embryo affine map. It uses future input labels only after the public program has been generated. The resulting 3,077 field values pass the curve check, all 256 conditional group maps, and final hidden-scalar multiplication.

```text
DFB program bytes:                   449,779
program SHA-256:                     7e6d94ced9b0d663c32941f2687e90e4f7629b370044b298eadfbde1690540e0
standalone decoder/output masks:     228,083
complete one-slot standalone object: 677,862
conditional maps verified:          256
final output equals [r]A:            yes
```

## Source-suite result

```text
75 test files
285 tests passed
0 failed
```

## Clean-archive verification

```text
75 test files
285 tests passed
0 failed
manifest verified
compileall passed
```

## Corrected storage decision

The 449,779-byte program contains the switch-system join payload. Public standalone decoding additionally requires 228,083 bytes of final output masks.

```text
q=2 join-only + v0.21 manifest:       900,306 B
q=2 standalone + v0.21 manifest:    1,356,472 B
one-MiB overage, standalone:           307,896 B
```

The old 1,023,186-byte v0.21 envelope must now be treated as historical paper-derived accounting, not the current complete-object estimate.

## New primary gate

```text
P0-MASK-FUSION-1
```

Either construct a secure application-level label-flow in which Embryo consumes the masked DFB outputs without serializing one CRT mask residue per output, or decisively show that two standalone slots cannot meet one MiB.

This gate is coupled to `P0-ADAPT-1`: any fusion must preserve the adaptive, auxiliary-input and two-instance security target rather than merely reproduce correct outputs.

## Evidence

- `src/ranklock/dfb_real.py`
- `src/ranklock/embryo_real.py`
- `tests/test_real_dfb_embryo.py`
- `scripts/generate_v022_results.py`
- `results/v022_real_dfb_embryo_execution.json`
- `artifacts/embryo-v022-dfb-program.bin`
- `artifacts/embryo-v022-standalone-decode-state.bin`
- `docs/53_REAL_DFB_EMBRYO_EXECUTION.md`

## Remaining breakthrough gates

1. output-mask fusion or a decisive storage impossibility result;
2. adaptive two-instance DFB proof or attack;
3. concrete active malicious MPC execution;
4. authenticated future input-label release;
5. complete BABE/Bitcoin graph accounting;
6. Bitcoin Core regtest and end-to-end proof.

`breakthrough_target_met` remains `false`.
