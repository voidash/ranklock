> **Historical incomplete checkpoint.** The surviving v0.24 evidence did not include the complete implementation or tests. Use `V0241_CHECKPOINT.md` and the v0.24.1 clean archive instead.

# RankLock v0.24 release notes

## Security qualification

v0.24 replaces the impossible “no third raw point” claim with a correct two-part boundary: group-linear outputs may be derived, but only two activated, context-bound evaluations can be accepted; a fresh post-query third challenge is reduced to an explicit one-more scalar-multiplication assumption.

## Main changes

1. Replaced biased nibble-slice body pads with exact 32-bit rejection sampling in every CRT prime.
2. Added per-slot DFB nonce namespaces without increasing retained bytes.
3. Added an executable mask-fusion proof harness covering the exact 3,077-lane Embryo layout, body rank, slope elimination, triangularity and no-wrap conditioning.
4. Sealed every complete fused slot—program plus decoder state—with a 256-bit whole-slot ROM seed, preserving length.
5. Added complete precommitted projective label trees and canonical 24,836-byte online release witnesses.
6. Bound releases to context, slot, canonical point, root, authorization transaction and program seed with BIP340 signatures.
7. Enforced burn-before-parse/evaluate and replay rejection.
8. Added a two-instance generator where `A2` is derived only after observing `[r]A1` while slot 1 remains sealed.
9. Added an independent verifier that replays both slots without `r` and records the unavoidable raw linear third-output boundary.
10. Switched v0.24 security fixtures to fresh OS entropy by default; deterministic reproduction requires an explicit insecure environment variable.

## Non-claims

This release is not a safe-for-funds artifact. Active MPC, Bitcoin witness extraction/regtest, constant-time hardening and independent cryptographic audit remain open.
