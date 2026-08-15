# RankLock v0.22.1 security checkpoint

## Verdict

The v0.22 correctness milestone survives, but the original artifact was not a
faithful private instantiation of DFB.  This checkpoint corrects statistical
smudging and x/y instance separation, then records a complete 90-prime
DFB/Embryo execution with 128 smudging bits requested **per affine component**.
A conservative two-slot whole-vector bound is only about 119.4 bits at this
profile, and the body-pad sampler remains nonuniform.

## Corrected executable result

```text
90 CRT primes, largest 463
132 available full smudging bits/component; 128 requested
independent x/y deltas
independent x/y nonce namespaces
real Embryo output equals direct [r]A
program:    508,395 bytes
masks:      262,699 bytes
standalone: 771,094 bytes
```

## Security decision

**Do not call this secure RankLock or an Alpen bridge replacement.**

It is a substantially better correctness/security-audit baseline, but a deeper
pass found that the reference-compatible body-pad sampler is nonuniform over the
odd CRT primes, so the selective DFB proof still does not apply end-to-end.  The
immediate implementation blocker is proved uniform hash-to-`Z_p`; the larger
critical gates are an adaptive, auxiliary-input, two-instance theorem, real
Bitcoin-authenticated one-shot label release, and active malicious MPC generation.

## Next priority

1. Replace the biased nibble-slice body pads with proved uniform hash-to-`Z_p`.
2. Add slot-level nonce namespaces and use a 91-prime profile for a conservative 128-bit whole-q=2 target.
3. Formalize and attack the adaptive q=2 experiment.
4. Integrate canonical Bitcoin label release and burn-before-evaluate semantics.
5. Execute the exact generator in an active dishonest-majority MPC.
6. Determine whether output-mask fusion and the remaining system fit in the corrected 19,314-byte join-only margin.
