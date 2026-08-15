# RankLock v0.22 real DFB/Embryo execution report

**Date:** 2026-08-11

## Verdict

The exact DFB/Embryo execution gate is passed, but the complete two-slot sub-MiB breakthrough target is not.

v0.22 generates and evaluates the full production-shape switch system rather than relying on paper arithmetic. The run delivers all 3,077 Embryo affine outputs, validates the curve check, verifies 256 conditional Jacobian maps and produces the exact BN254 point `[r]A`.

## Reproducible artifact

```text
join program:                         449,779 bytes
SHA-256: 7e6d94ced9b0d663c32941f2687e90e4f7629b370044b298eadfbde1690540e0
standalone output-mask state:         228,083 bytes
complete standalone slot:             677,862 bytes
```

The implementation uses the pinned `alpenlabs/duty-free-bits` construction: fixed-key AES CCRH, 128-bit labels, exact nonce domains, fused `[8,8,6]` extraction, fold/body scalings and canonical LSB-first packing.

## Regression result

```text
75 independently executed test files
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

## What execution corrected

The old v0.21 `511,219 B` slot number reconstructed Appendix-C join arithmetic. The real reference path fuses extraction and lowers the join payload to `449,779 B`.

But the switch-system output theorem also needs a final output mask. For 3,077 outputs over an 80-prime, 593-bit CRT basis, those masks occupy `228,083 B`.

Consequently:

```text
2 x join program + 748-byte manifest =    900,306 B
2 x standalone slot + manifest =        1,356,472 B
standalone over one MiB =                  307,896 B
```

The former 25,390-byte margin is no longer the current claim boundary.

## What is now implemented

- real DFB chunk/extract/fold/body garbling and evaluation;
- exact AES CCRH golden vector;
- program generation before future-input binding;
- canonical serializer and parser;
- separate standalone output-mask serialization;
- complete 1,795/1,282 Embryo affine map;
- five-element curve-secret check;
- 256 conditional Jacobian maps;
- final hidden-scalar group equality;
- deterministic artifact and adversarial parser/accounting tests.

## What remains

1. construct and prove output-mask fusion, or accept that q=2 exceeds one MiB;
2. prove or break adaptive auxiliary-input two-instance security;
3. execute the generator in active dishonest-majority MPC;
4. authenticate one future input label per bit and bind Bitcoin context;
5. serialize the complete BABE/validity-first graph;
6. run Bitcoin Core regtest and complete the end-to-end proof.

## Research conclusion

The main uncertainty is no longer whether the DFB/Embryo computation can be implemented. It can, and it runs at full dimensions.

The decisive storage question is now narrower and more concrete: **can the 228,083-byte final output-mask state be consumed inside Embryo without being retained as standalone public data, while preserving the required security notion?**
