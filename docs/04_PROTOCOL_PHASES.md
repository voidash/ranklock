# Protocol Phases and Challenge Timing

Challenge timing is load-bearing. This document is normative for the current model.

## Phase 0 — static activation

Before a game input is known:

- pin RankVM/SP1 program, verifying key, input schema and Bitcoin output predicate;
- generate/distribute the conditional-lock artifact;
- complete malicious setup verification and erasures;
- bind an activation/session namespace.

This phase is not implemented cryptographically.

## Phase 1 — trace commitments

The prover fixes:

- RankVM trace columns;
- every deterministic local-AIR quotient;
- unsorted memory-access component columns;
- sorted memory/AIR columns.

The sorted tuple commitments and AIR commitments for the four access components must be byte-identical.

## Beacon 1

From domain-separated transcript digests, beacon 1 derives:

- tuple compression challenge `eta`;
- grand-product challenge `beta`;
- local AIR evaluation challenge `zeta_air`.

The prover may now open the already committed AIR polynomials at `zeta_air`.

## Phase 2 — permutation commitments

After `eta` and `beta` are known, the prover computes and commits:

- grand-product polynomial `Z`;
- recurrence quotient `Q`.

Neither commitment may depend on the later permutation evaluation challenge.

## Beacon 2

Beacon 2 derives `zeta_perm` from the phase-two transcript. The prover opens tuple components, `Z`, and `Q` at the required points.

## Optional value phase and Beacon 3

To batch many same-point KZG openings into one equation:

1. all individual claimed opening values must first be published/bound;
2. beacon 3 derives random batching scalar `rho`;
3. the prover supplies one aggregate opening.

If `rho` is known before the values are bound, false values can cancel. See `tests/test_batched_opening.py`.

## Beacon requirements

A concrete deployment must define:

- source: e.g. a buried Bitcoin block or multi-party randomness;
- commitment deadlines;
- confirmation depth;
- domain separation;
- rejection sampling;
- collision/pole abort policy;
- retry and equivocation behavior.

The current code models 32-byte unbiased beacons and uses rejection sampling in `beacon.py`.

## v0.17 activation and evaluation phases

### Phase A — fixed relation and contributor activation

1. Pin program, verifier, projective-input schema, graph, epoch, and proof-system versions.
2. Each contributor samples a fresh setup scalar and generates its scaled low-rank anchors.
3. Each contributor derives its secp256k1 fault-share key from the accepting statement session.
4. Each contributor proves the public activation NP relation.
5. Verify the complete contributor roster and all proofs.
6. On any abort/failure, burn the epoch and restart with fresh scalars.
7. Fund the Bitcoin graph only after all activation receipts are accepted.

### Phase B — future input realization

1. The existing bridge/adaptor boundary selects the future counterproof bytes.
2. The projective layer yields one-shot authenticated witness values.
3. Any retry uses fresh input-authentication state.

### Phase C — public proof and unlock

1. Build the complete RankVM/SP1 invalidity witness from the selected bytes.
2. Produce the one-sided proof.
3. Canonically parse every proof element once.
4. Recompute and verify the public transcript over that shared object.
5. Verify the final rank-two PPE and derive each contributor pairing session.
6. Hash sessions into secp256k1 fault-share scalars and aggregate/sign the precommitted NACK path.

Malformed encodings or verifier errors return bottom; they never count as invalidity evidence.
