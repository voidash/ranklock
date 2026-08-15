# 55 — v0.23 mask-carrying Embryo and compact CRT joins

## Verdict

The retained-storage target is met at the executable construction and exact-byte level:

```text
compact 91-prime DFB program per slot:       497,718 B
fused final-polynomial masks per slot:         24,384 B
complete retained slot:                       522,102 B

2 independent slots:                        1,044,204 B
signed manifest + positive lock:                  748 B
-------------------------------------------------------
complete retained object:                   1,044,952 B
one MiB:                                    1,048,576 B
margin:                                         3,624 B
```

The generated object is not a spreadsheet envelope. `artifacts/ranklock-v023-two-slot-retained-object.bin` is exactly 1,044,952 bytes, contains a verified 748-byte signed two-slot manifest followed by two independent 522,102-byte slot artifacts, and round-trips through strict canonical parsers. Each parsed slot also replays from the fixed public Embryo layout plus future input labels, without access to the hidden scalar, map coefficients, φ-points, or generator random tape.

This does **not** make RankLock production-secure. The fusion correlates Embryo intercept lifts with DFB body readouts, and that correlated distribution is not covered by the current DFB security theorem. The biased finite-group pad sampler, adaptive two-instance theorem, active-MPC execution, authenticated Bitcoin label release, and regtest integration also remain open.

## 1. The output-mask problem

For one affine output, the DFB information-theoretic body produces a raw CRT label

\[
L = R + a x \pmod M,
\]

where `R` is the final pad readout and `M` is the CRT primorial. The standalone decoder retains

\[
m = R - B \pmod M
\]

for the integer lift `B` of the affine intercept, then recovers `a*x+B` as `L-m`.

At 91 primes, retaining all 3,077 masks costs:

```text
3,077 outputs × 692 residue bits = 2,129,284 bits
standalone decode state           =   266,161 bytes / slot
```

That cannot fit twice below one MiB.

## 2. Mask-carrying fusion

Embryo evaluates each monomial through a telescoping chain of affine encodings. Every nonterminal chain intercept is random. The fused generator waits until the DFB body readouts `R_j` are fixed, then chooses the corresponding transmitted field intercept so that the BN254 mask is zero:

\[
\widetilde b_j = R_j \bmod q,
\]

or, for PRF-masked scalar-map entries,

\[
b_j = R_j - \operatorname{PRF}_j \pmod q.
\]

Therefore the evaluator can use the raw DFB label directly after BN254 reduction and PRF removal. Only terminal chain entries retain a field mask. Terminal entries have suffix weight one, so their masks add to one constant per final polynomial.

The fixed Embryo layout has:

```text
256 conditional maps × (X,Y,Z) = 768 final polynomial masks
curve-check masks                =   0 retained masks
```

The curve-check secret is random, so it is chosen after the two curve-terminal readouts to make their aggregate mask exactly zero.

Tight 254-bit packing gives:

```text
768 × 254 bits = 195,072 bits = 24,384 bytes / slot
```

The full execution checks that all 1,027 nonterminal affine masks are zero and only the 2,050 chain-terminal masks can be nonzero before polynomial aggregation.

## 3. The mandatory no-wrap condition

A tempting but invalid shortcut is to reduce arbitrary raw CRT labels modulo BN254. If `R+a*x` wraps modulo `M`, reducing the reconstructed residue to BN254 introduces an unwanted `M mod q` term.

The prototype therefore rejects setup unless every output readout satisfies

\[
R_j + (q-1)^2 < M.
\]

Because every affine slope and every future canonical input are below `q`, this guarantees no CRT wrap for any future BN254 input—not merely for the test input. The two release slots satisfy this condition for every one of their 3,077 outputs. The evaluator additionally reconstructs every raw label and asserts equality with the exact integer `R+a*x` before Embryo evaluation.

## 4. Compact CRT join serialization

The standard DFB serializer stores each body join as 91 independently padded residues:

```text
sum ceil(log2(p_i)) = 692 bits / affine output
```

But a canonical 91-residue tuple is exactly one value in `Z_M`, and the 91-prime primorial has bit length 649. The compact serializer therefore applies CRT once during serialization and stores one canonical integer in `[0,M)`:

```text
standard body-join width: 692 bits
compact body-join width:  649 bits
saving:                    43 bits / output
```

Across 3,077 outputs this saves 16,539 bytes per slot. Parsing rejects values `>=M`, expands each integer back to its 91 residues, and reserializes byte-for-byte. This transformation is bijective and does not alter the DFB computation or its nonce schedule.

```text
standard 91-prime program: 514,257 B
compact 91-prime program:  497,718 B
saving:                     16,539 B / slot
```

Without compact CRT joins, fusion alone would leave the two-slot object 29,454 bytes over one MiB.

## 5. Manifest and positive-lock accounting

The retained binary contains the actual canonical v0.21 manifest format, regenerated against the two v0.23 slot roots:

```text
header/version/counts:                         16 B
context + generator + transcript digests:      96 B
BABE-style positive lock:                     196 B
  vk digest                                    32 B
  statement digest                             32 B
  [r]delta G2                                  64 B
  payload length                                4 B
  masked 32-byte Bitcoin payload               32 B
  payload hash                                 32 B
two slot descriptors:                         216 B
two contributor public keys:                   64 B
two BIP340 signatures:                        128 B
manifest checksum:                             32 B
----------------------------------------------------
total:                                        748 B
```

The positive lock binds a fixed Groth16 verifying-key digest. As in the existing bridge accounting, the full fixed verifying key is treated as globally deployed bridge data rather than per-game retained material. The future Groth16 proof and future Bitcoin-released input labels are runtime inputs, not setup-retained bytes.

Deleting the entire manifest would save only 748 bytes; it was never sufficient to close the former 29,454-byte gap. The decisive savings are output-mask fusion and compact CRT joins.

### Committee-size frontier

The current manifest keeps one 32-byte x-only public key and one 64-byte BIP340 signature per setup contributor. With two fixed slot descriptors, the current positive lock and checksum, its exact size is:

```text
manifest(n contributors) = 556 + 96n bytes
complete object           = 1,044,760 + 96n bytes
```

Therefore the exact all-signatures format supports up to **39 setup contributors** while remaining below one MiB:

```text
39 contributors: 1,048,504 B  (72 B margin)
40 contributors: 1,048,600 B  (24 B over)
```

The release fixture uses two contributors and has 3,624 bytes of margin. This means ordinary small active-MPC committees do not require signature aggregation for the storage target; a committee of 40 or more would require aggregation or another manifest-format change.

## 6. Two independent slots

The complete retained object contains two independently seeded artifacts under the same hidden scalar. The slots have distinct:

- compact-program hashes;
- fused-mask hashes;
- artifact roots;
- input-label roots;
- independence digests; and
- DFB input masks, deltas and nonce namespaces.

No header or body randomness is shared between the two slots. This preserves the current bounded-use architecture; the prototype does not rely on unsafe byte deduplication between one-shot affine states.

## 7. Parameter frontier

Using the same fusion and compact serializer:

| CRT primes | Per-component smudging | Conservative whole two-slot bound | Total bytes | Margin to 1 MiB |
|---:|---:|---:|---:|---:|
| 88 | 115 bits | 102.41 bits | 1,010,552 | +38,024 |
| 89 | 123 bits | 110.41 bits | 1,022,274 | +26,302 |
| 90 | 132 bits | 119.41 bits | 1,033,998 | +14,578 |
| 91 | 141 bits | 128.41 bits | **1,044,952** | **+3,624** |

The exact rows are machine-generated in `results/v023_mask_fusion_retained_object.json`. The 91-prime profile is the first profile that clears the conservative 128-bit whole-two-slot union bound used by v0.22.1.

## 8. What the prototype proves

It proves, executably:

1. real 91-prime DFB generation for both Embryo coordinates;
2. mask-carrying monomial evaluation with only 768 retained field masks;
3. the no-wrap property for every affine output and every canonical future field input;
4. canonical 649-bit CRT-packed join serialization and parsing;
5. two independent full-size slots under one hidden scalar;
6. all 256 conditional Jacobian maps for each slot;
7. final output equality with direct `[r]A`;
8. a real signed 748-byte positive-lock manifest; and
9. an exact 1,044,952-byte canonical retained object; and
10. public replay from retained bytes + runtime labels only, with no generator-side secret metadata.

## 9. What it does not prove

The following gates remain before a secure Alpen replacement can be claimed:

1. **Correlated-lift composition theorem.** Show that choosing Embryo random intercepts from DFB readouts and retaining only terminal aggregates is simulatable under the intended DFB/Embryo assumptions.
2. **Uniform finite-group pads.** Replace the current biased raw-slice `Z_p` sampler with a proved uniform sampler without changing the wire format.
3. **Adaptive two-instance security.** Inputs are chosen after both public artifacts exist, with Bitcoin auxiliary information.
4. **Concrete active MPC.** Run the exact fused generator inside an active `n-1`-corrupt MPC and bind the same scalar to the positive lock.
5. **Authenticated Bitcoin label release.** Enforce exactly one canonical label per input bit and one-shot slot consumption.
6. **Full bridge integration.** Preserve pre-signing, fee/CPFP, timeout, slash and contested-payout behavior and pass Bitcoin Core regtest.

## 10. Verification status

The clean source tree completed 76 independently executed test files: 299 passed, zero failed, and one designated heavy regeneration fixture was skipped. The release generator runs that full-size path twice and verifies both emitted slots. See `results/v023_source_verification.json`.

## 11. Reproduction

```bash
PYTHONPATH=src pytest -q tests/test_embryo_mask_fusion.py
PYTHONPATH=src pytest -q tests/test_real_dfb_embryo.py tests/test_bounded_mpc_embryo.py
PYTHONPATH=src python scripts/generate_v023_mask_fusion_results.py
PYTHONPATH=src python scripts/verify_v023_retained_object.py
```

Primary evidence:

- `src/ranklock/embryo_mask_fusion.py`
- `tests/test_embryo_mask_fusion.py`
- `results/v023_mask_fusion_retained_object.json`
- `artifacts/ranklock-v023-two-slot-retained-object.bin`
- `scripts/verify_v023_retained_object.py`
- `results/v023_release_verification.json`
