# 53 — Real DFB/Embryo execution

**Checkpoint:** v0.22.0  
**Reference implementation revision:** `alpenlabs/duty-free-bits@e2b45be8ceaea0d51e4e7a9ef862b91b59ff255e`

## 1. Result

The exact implementation gate left open by v0.21 is now closed:

- a real Duty-Free-Bits affine switch is generated;
- all join payloads are canonically packed into a byte string;
- the byte string is parsed back into an independent evaluator object;
- evaluator input labels are bound only after the public program exists;
- two 256-bit coordinate executions deliver the 3,077 affine values required by Embryo;
- the five-element curve polynomial recovers its secret;
- all 256 conditional Jacobian maps verify;
- the final group output equals hidden-scalar multiplication.

This is executable cryptography rather than Appendix-C arithmetic. It remains variable-time research code.

## 2. Exact profile

The implementation preserves the reference construction's concrete choices:

```text
security parameter:                 128
input width per coordinate:         256 bits
CRT primes:                         first 80 primes, largest 409
CRT reconstruction width:           593 bits
chunk width:                        8 bits
working ring:                       Z_(2^22)
fused extraction widths:            [8, 8, 6]
body batch size:                    128 affine outputs
Embryo x dimension:                 1,795
Embryo y dimension:                 1,282
total affine outputs:               3,077
conditional additions:             256
curve-check outputs:                5
```

The port uses the same fixed-key AES CCRND/CCRH, 128-bit boolean labels, arithmetic-label packing, nonce-domain split, fold schedule and body scaling construction as the pinned Rust revision.

## 3. Execution sequence

The deterministic fixture performs the following sequence.

1. Garble the Embryo sum-of-monomials encodings for a hidden 256-bit scalar.
2. Generate a DFB template for the x/y affine coefficient vectors while the future point is still represented by zero placeholders.
3. Serialize all join payloads with canonical LSB-first bit packing.
4. Parse the serialized program and reject non-canonical padding or trailing material.
5. Select the future BN254 input point and bind exactly one input label per bit.
6. Evaluate both DFB coordinate programs and decode all CRT output residues.
7. Reconstruct the 3,077 field outputs.
8. Recover the curve-check secret and use it to remove the Embryo PRF masks.
9. Verify every conditional Jacobian map against either `Phi_i` or `Phi_i + A` according to the hidden scalar bit.
10. Combine the 256 points and compare the result with direct `[r]A` multiplication.

The program hash is unchanged by choosing a different future input; only the 4,096-byte-per-coordinate input-label strings change.

## 4. Reproducible fixture

```text
hidden scalar:
0x123456789abcdef00112233445566778899aabbccddeeff

DFB join-program SHA-256:
7e6d94ced9b0d663c32941f2687e90e4f7629b370044b298eadfbde1690540e0

input point:
8ba173a9155665e0f39b925d3118c2e68a63e5da3563e34603ffc5eb3e638584

expected/output point:
ad5fab5a4706e606ea59783b23d52de5111c4330b244e23d9ba111fca3633cd8
```

Observed reference run:

```text
garbler AES blocks:                 6,089,838
evaluator AES blocks:               6,058,542
peak RSS:                           approximately 134 MiB
complete Python execution:          approximately 8.4 seconds
conditional maps verified:          256 / 256
output equals [r]A:                 yes
```

Timing numbers are machine-specific. Artifact hashes, dimensions and byte counts are deterministic.

## 5. The storage boundary exposed by execution

The generated DFB join program is smaller than the old Appendix-C model because the reference implementation fuses extraction:

```text
real canonical join program:        449,779 bytes
v0.21 paper-derived slot model:      511,219 bytes
delta:                              -61,440 bytes
```

However, a standalone public evaluator also needs the final garbler output masks. The executable decoder state is:

```text
3,077 outputs x 593 CRT bits:        1,824,661 bits
canonical output-mask state:           228,083 bytes
join program + output masks:            677,862 bytes
```

The two objects have deliberately separate types:

- `DfbProgram`: public join payload;
- `DfbDecodeState`: final output masks needed to decode standalone affine outputs.

The distinction is cryptographic, not file-format overhead. The DFB switch-system theorem appends a final output mask unless a downstream construction consumes masked labels directly.

## 6. Consequence for the two-slot target

Using the existing 748-byte two-slot manifest fixture:

```text
join-only accounting:
2 x 449,779 + 748 =                 900,306 bytes
margin below one MiB =              148,270 bytes

standalone accounting:
2 x 677,862 + 748 =               1,356,472 bytes
over one MiB =                       307,896 bytes
```

Therefore the former v0.21 statement—two complete standalone Embryo slots below one MiB—is not supported by the real execution.

A sub-MiB result remains possible only if an application-level construction safely fuses or eliminates the 228,083-byte final-mask state per slot. No such construction or proof is present in v0.22.

## 7. What was implemented

### DFB layer

- reference-compatible fixed-key AES CCRH;
- exact nonce windows and bulk/solo domain separation;
- chunk, fused extract, fold and body garbling/evaluation;
- 128-bit and width-`l` label packing;
- deterministic template generation before input selection;
- late one-label-per-bit binding;
- strict canonical serializer/parser;
- standalone output-mask serializer;
- CRT residue verification and reconstruction;
- golden-vector and production-profile tests.

### Embryo layer

- five-element curve-check polynomial;
- fixed 7-x/5-y scalar encoding split for each conditional-addition map;
- all 256 conditional Jacobian maps;
- PRF masking keyed by the curve-check secret;
- weighted-zero auxiliary points;
- full 3,077-element affine map;
- direct and encoded polynomial checks;
- final BN254 group equality.

## 8. What remains open

1. **P0-MASK-FUSION-1:** construct and prove an Embryo label-flow that consumes DFB output masks without retaining one residue per output, or prove this route cannot meet one MiB.
2. **P0-ADAPT-1:** prove or break adaptive, auxiliary-input, two-instance security for the exact switch system.
3. **P0-MPC-1:** execute the complete generator inside an active `n-1`-corrupt MPC backend and measure communication, memory and abort behavior.
4. **P0-GRAPH-2:** authenticate one label per future bit, bind all Bitcoin contexts, serialize BABE/graph data and run Bitcoin Core regtest.

## 9. Claim boundary

v0.22 proves that the exact DFB join program and complete Embryo algebra execute correctly at the intended production dimensions.

It does **not** prove that two standalone artifacts fit below one MiB, that output masks can be omitted, that DFB is adaptively secure, that active MPC generation works, or that the Bitcoin transaction system is complete.
