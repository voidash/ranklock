# RankLock v0.22.1 release notes

This checkpoint audits and corrects the v0.22 DFB/Embryo correctness fixture.

## Corrected

- DFB Theorem-5.2-style statistical lifting with an independent `mu` per affine output;
- a 90-prime BN254 profile supporting 132 full statistical bits, with 128 requested;
- independent Free-XOR offsets for x and y;
- disjoint per-coordinate CCRH nonce namespaces;
- canonical target-field input rejection before label binding;
- corrected 90-prime execution accounting, 91-prime whole-`q=2` target accounting, and deterministic artifacts.

## Newly identified in the deeper audit

- reference-compatible body pads are not uniform over `Z_p` (worst TV distance 17.16%);
- the 90-prime profile gives about a 119.4-bit conservative whole-q=2 smudging bound;
- q=2 needs slot-level nonce domains in addition to x/y separation;
- SHA-256-as-RO/PRF remains a heuristic instantiation boundary.

## Still open

- adaptive privacy for inputs chosen after the public program;
- q=2 composition under one shared hidden scalar;
- authenticated Bitcoin label release and consensus-enforced one-shot use;
- actively secure MPC generation of the exact program;
- sound output-mask fusion;
- complete exceptional-input handling and end-to-end Bitcoin regtest.

The package is research code and must not protect funds.
