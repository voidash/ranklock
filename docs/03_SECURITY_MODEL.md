# Security Model

## Actors

- **Setup contributors:** jointly activate the static artifact and fault secret.
- **Prover/operator:** supplies future counterproof bytes and bridge inputs; may be malicious.
- **Evaluator/challenger:** publicly evaluates the artifact; may be malicious.
- **Beacon source:** supplies public unpredictable randomness after specified commitments.
- **Bitcoin/Strata environment:** fixes the game, graph, public inputs, NACK transaction and fault key.

## Corruption target

The desired setup model tolerates any `n-1` corrupt setup contributors. One honest contribution must be enough for secrecy/soundness, though all contributors may be needed for setup liveness.

No online actor may be trusted after activation.

## Security games to define formally

### Correctness

An honest activated artifact releases the correct fault secret on every valid fault witness and never on the valid branch.

### Secret hiding

For an activated instance with no accepting fault witness, an adversary controlling the prover, evaluator and up to `n-1` setup contributors cannot distinguish the protected secret.

### Program binding

An adversary cannot activate an artifact that is accepted as the canonical program while implementing another relation.

### Input binding

The evaluated statement must bind:

- authority/program manifest;
- exact public-values schema;
- operator key and game index;
- canonical proof bytes and metadata;
- bridge graph and Bitcoin fault-output commitment;
- all beacon epochs/challenges;
- one-time session identifier.

### Evaluation authenticity

The evaluator cannot synthesize a valid internal/output encoding not reachable from the active input encodings.

### Challenge soundness

Every challenge must be unpredictable at the point required by the proof. Abort/retry rules must be included in the game.

### Composition soundness

Proof components referring to the same trace/table must use the same binding commitment or a verified equality relation.

## Assumptions currently present only in models

- formal KZG binding/extractability;
- unbiased external beacons;
- bounded polynomial degree;
- canonical field/range encoding;
- correct erasure by one setup contributor;
- availability of a conditional-disclosure construction for the final linear/PPE relation.

These are not yet assembled into a theorem.

## v0.17 session-derived Bitcoin key

The activated artifact no longer contains an encrypted fault-secret payload. For contributor `i`, the accepting pairing session `K_i` is mapped to a secp256k1 scalar with a domain-separated hash over:

- relation/program digest;
- epoch/session identifier;
- signer identifier;
- accepting session.

Activation publishes the corresponding secp public point and proves before funding that one hidden setup scalar consistently generates all scaled anchors, the accepting session, and that public point. This removes ciphertext-substitution from the security game but introduces a cross-relation activation proof whose soundness must be included in program/setup binding.
