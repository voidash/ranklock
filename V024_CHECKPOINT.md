> **Historical incomplete checkpoint.** The surviving v0.24 evidence did not include the complete implementation or tests. Use `V0241_CHECKPOINT.md` and the v0.24.1 clean archive instead.

# RankLock v0.24 checkpoint — corrected two-instance security qualification

## Decision

```text
CORRECTED THEOREM BARRIER: CROSSED CONDITIONALLY
PRODUCTION / FUNDS BARRIER: NOT CROSSED
```

v0.24 turns the corrected same-scalar theorem into an executable construction and public replay harness while preserving the v0.23 retained-object size.

## Closed gates

* exact rejection sampling into every CRT `Z_p` body group;
* 3,077-lane fusion graph extracted and checked as 2,050 disjoint acyclic chains;
* rank-two body sum/readout map for all 91 primes;
* slot-separated CCRH nonce namespaces;
* complete program-plus-decoder sealing under independent 256-bit ROM seeds;
* both ciphertexts and the manifest published before `A1`;
* transcript-adaptive `A2` while slot 1 remains sealed;
* canonical 512-label release per slot, bound to context, slot, point, root, authorization transaction and program seed;
* burn before point/opening/program parsing;
* forged, re-signed cross-slot, malformed, wrong-seed and replay regressions;
* explicit raw-linearity versus accepted-third-evaluation boundary;
* independent public replay without the hidden scalar.

## Concrete bounds

```text
ROM pre-release seed-query term, Q=2^64/slot:   191 bits
no-wrap two-slot union bound:                    >129 bits
hidden exceptional-point two-slot union bound:  >243 bits
sampler watchdog failure exponent per pad:       >1,500,000 bits
```

## Storage

```text
complete retained object: 1,044,952 bytes
margin below one MiB:          3,624 bytes
online release per slot:      24,836 bytes  (not retained)
```

## Claim boundary

The public view is simulatable from the two authorized outputs **plus explicit positive-lock side information**, conditional on selective privacy of the exact fused slot, CCRH/PRF security, the BHR random-oracle transform and the stated authentication/group assumptions.

Raw linear combinations such as `[r](A1+A2)=Y1+Y2` remain derivable. What is prevented is a third **accepted** RankLock evaluation; a fresh independently sampled third challenge is covered only by the explicit one-more scalar-multiplication assumption.

## Still required before funds

* actively secure dishonest-majority MPC execution of the exact generator;
* Bitcoin Core regtest enforcing atomic seed/label extraction, persistent burn and reorg behavior;
* constant-time production implementation and DoS hardening;
* independent cryptographic review of the selective fusion reduction and composition proof.
