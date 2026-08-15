# RankLock v0.19 Research Checkpoint

This checkpoint is the complete v0.18 reproducible research tree plus the latest v0.19 breakthrough-path implementation modules.

## v0.19 additions

- `babe_positive_lock.py` — positive Groth16 conditional lock prototype.
- `predicate_locked_hashlock.py` — hash-preimage-conditioned ACK connector model.
- `hashlocked_validity_bitcoin.py` — validity-first ACK/NACK Bitcoin state-machine model.
- `authenticated_counterproof_semantics.py` — game/operator/session/transaction binding model.
- `self_certifying_embryo.py` — public certification of hidden-scalar output.
- `rerandomized_projective_liveness.py` — Groth16 rerandomization and density-soundness analysis.
- `proof_carrying_embryo.py` — proof-carrying activation relation prototype.
- `proof_carrying_artifact_format.py` — strict artifact serialization and validation.

## Latest research conclusion

The validity-first polarity inversion is the strongest current route. Positive Groth16 verification can condition an immediate ACK while timeout yields the NACK path. The remaining breakthrough target is a compact bounded-multi-query projective hidden-scalar evaluator, or a structurally superior proof-carrying projectivizer, that removes malicious-generator cut-and-choose without becoming a reusable hidden-scalar oracle.

## Important status

The complete inherited v0.18 suite previously passed 261 tests. The latest v0.19 delta reported 30 focused passing tests during development, but the full inherited suite was not rerun after every v0.19 change. Treat this as a research checkpoint, not a production release.
