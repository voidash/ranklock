# RankLock v0.25 handoff into the validity-first graph

The Rust patch remains deliberately narrow: it consumes one 32-byte positive
unlock preimage on the immediate ACK branch and otherwise exposes the existing
CSV NACK branch. It does not parse RankLock artifacts inside Rust.

For v0.25, the producer of that preimage must be the public evaluator after:

1. the setup activation, witness policy, and stripped transaction plan verify;
2. every committee participant has durably burned the slot and anchored the
   phase-one checkpoint at independent rollback witnesses;
3. Bitcoin Core confirms the exact witness transaction and the witness labels
   decode to the signed point;
4. every participant releases its program-seed share only after the stable
   Core recheck;
5. the public evaluator verifies the retained artifact and positive relation,
   then recovers the 32-byte positive-lock payload;
6. the adapter verifies `SHA256(preimage)` equals the commitment embedded in
   graph data and writes the context-specific unlock file atomically.

The Python reference implementation for steps 1–4 is in
`ranklock.two_phase_sidecar`. The final evaluator/preimage export remains a
separate process boundary so the bridge executor never receives setup secrets,
participant shares, or an alternative signing key.

## Base update

The prior patch was pinned to `e7623c2e...`. GitHub comparison to
`f94c06d08...` showed three intervening commits and modifications only in:

- `crates/bridge-exec/src/graph/counterproof.rs`;
- `crates/proofs/bridge-counterproof/src/statements.rs`.

Neither path is edited or overlaid by this installer. The exact patch targets
and anchors are otherwise unchanged, so this bundle updates the fail-closed
base pin to `f94c06d08...`. Cargo and Bitcoin Core execution are still required
in a real checkout before promotion.
