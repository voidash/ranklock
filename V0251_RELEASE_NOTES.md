# RankLock v0.25.1 release notes

RankLock v0.25.1 consolidates the first complete local funds-safety candidate around the
sub-MiB v0.24.1 retained object.

## Added

- durable SQLite one-shot ledgers with audit chains;
- signed rollback-witness checkpoints, receipts and mTLS-capable clients;
- committee activation, signed preauthorization and selected-label shares;
- two-phase release: labels before broadcast, program seed after confirmation;
- exact txid/wtxid/witness-digest and canonical-point binding;
- enforcing 512-selector Tapscript construction and static policy audit;
- precommitted two-transaction authorization plan;
- split-scalar N-of-N setup mode with scalar-share knowledge proofs;
- Core 31.1 fail-closed regtest harness;
- base-pinned Strata `ValidityFirstCounterproofConnector` handoff;
- canary observation, signed deployment policy and release qualification;
- clean-archive and evidence-verification tooling;
- active-MPC qualification statements now bind the deployment context and chain genesis;
- funding attestations now commit to an exact stable Bitcoin Core observation and expire
  within at most one hour;
- the per-file qualification runner now terminates entire timed-out process groups;
- supplied Bitcoin Core executables are rejected unless their SHA-256 is pinned.

## Fixed

- authorization signatures now cover all released openings;
- stale permissive `OP_DROP` witness script replaced by exact hash checks;
- seed shares are withheld until the confirmed witness selects the
  preauthorized point;
- rollback-witness anchoring occurs before response files become visible;
- local harness failures can no longer be bypassed by supplying external
  deployment attestations.

## Claim boundary

The release is reproducible and suitable for research, integration work and an
unfunded canary. It is not safe for funds until all external gates listed in
`docs/57_V025_FUNDS_SAFETY.md` are satisfied by independent evidence.
