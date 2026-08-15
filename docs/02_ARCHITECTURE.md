# Architecture

## Intended construction stack

```text
Canonical SP1/Groth16 verifier
          |
          v
Semantic / sparse arithmetic compiler
          |
          v
Fixed-width RankVM trace + memory accesses
          |
          +-----------------------------+
          |                             |
          v                             v
Local AIR identities            sorted-memory table
          |                             |
          |                      tuple permutation
          +---------------+-------------+
                          v
                 committed proof state
                          |
                       Beacon 1
                  eta, beta, AIR zeta
                          |
                  commit permutation Z,Q
                          |
                       Beacon 2
                    permutation zeta
                          |
             publish opening values / claims
                          |
                 optional Beacon 3
                  KZG batching rho
                          |
                          v
           small linear/PPE verifier relation
                          |
                          v
           projective conditional-disclosure lock
                          |
                          v
                 Bitcoin fault secret
```

## Layers already modeled

### Sparse arithmetic compiler

`pairing_rank.py` models sparse Miller-loop arithmetic, residue-witness final pairing checks, fixed-G2 lines, dynamic MSM and group checks. It reports a known arithmetic subtotal, not a full verifier cost.

### Non-native field bridge

`nonnative_field.py` encodes BN254 Fq values in three 85-bit limbs over a pairing scalar field and enforces the integer relation:

```text
x*y = z + quotient*q
```

through limb convolution and signed carries.

### Local trace proof

`phased_air.py` commits trace and quotient polynomials before deriving an evaluation point from an external beacon.

### Memory and permutation

`phased_permutation.py` separates component commitments, the `eta/beta` beacon, `Z/Q` commitments, and the `zeta` beacon.

`phased_memory.py` binds the permutation's right-side access-table commitments to the exact AIR trace commitments for:

```text
address, timestamp, value, is_write
```

### Opening batching

`batched_opening.py` proves that batching coefficients must be sampled only after all claimed values are bound. It introduces a possible third challenge phase.

## Missing architectural layer

The diagram ends in a “projective conditional-disclosure lock,” but no real construction currently instantiates that box for the conjunction of the AIR/permutation/PCS equations. That is the central research blocker.

## v0.17 fixed-statement architecture

The current primary path no longer conditionally verifies the original RankVM trace directly. It proves the complete fixed statement with a one-sided proof and conditionally evaluates only its compact verifier:

```text
projective authenticated bytes
        -> complete RankVM-invalidity witness
        -> one-sided public proof
        -> shared canonical proof object
        -> transcript mini-lock + rank-two PPE
        -> pairing session
        -> secp256k1 fault scalar.
```

The reusable one-sided CRS is system-wide. The per-deposit artifact contains projective input state, the fixed conditional relation key, activation manifest, and contributor fault-key commitments.
