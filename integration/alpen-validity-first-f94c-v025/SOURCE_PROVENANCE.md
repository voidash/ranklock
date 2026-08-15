# Source provenance

- Alpen source inspected through the connected GitHub repository `alpenlabs/strata-bridge`.
- Exact integration base: `f94c06d08ff29eee746f3e20bd63078d2949b304`.
- RankLock source: locally retained v0.22.1 security-audit package.
- Included RankLock reference files are unmodified copies of:
  - `src/ranklock/predicate_locked_hashlock.py`
  - `tests/test_validity_first_graph.py`
- `ranklock_reference/STATUS_RELEVANT.json` is a mechanical subset of v0.22.1 `STATUS.json` containing the top-level decision and v0.22/v0.22.1 checkpoints.

The Rust code was authored for this integration bundle. It was not copied from an existing Alpen branch or pull request.
