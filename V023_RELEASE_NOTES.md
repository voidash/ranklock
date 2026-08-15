# RankLock v0.23 research release notes

v0.23 closes the retained-storage engineering gate at the executable level.

- Added raw-output-label DFB evaluation.
- Added mask-carrying Embryo generation and evaluation.
- Reduced standalone output-mask state from 266,161 bytes to 24,384 bytes per 91-prime slot.
- Added canonical CRT-packed body joins, reducing each program from 514,257 to 497,718 bytes.
- Added strict no-wrap checks for all future canonical BN254 inputs.
- Generated two independent full-size slots under one hidden scalar.
- Generated and verified the actual 748-byte signed BABE-style positive-lock manifest.
- Generated an exact 1,044,952-byte retained object, 3,624 bytes below one MiB.
- Measured the exact committee frontier: the current all-signatures manifest fits up to 39 contributors; 40 contributors are 24 bytes over one MiB.
- Added ten focused mask-fusion, public-replay and compact-format tests.
- Added a public replay evaluator that consumes only the parsed slot, public future point and external input labels.
- Added a standalone retained-object verifier for signatures, roots, format, label commitments, public replay and direct `[37]A` checks.

Security remains conditional. The correlated-lift composition theorem, uniform finite-group sampler, adaptive two-instance proof, active-MPC execution and Bitcoin integration are not complete.

Verification: 76 test files, 299 passed, 0 failed, 1 designated heavy regeneration fixture skipped; the release generator executes that full-size path twice.
