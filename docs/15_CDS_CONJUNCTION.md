# Conditional Disclosure for the Opening Conjunction

## Decision

The opening-equation count is no longer the primary blocker.

A phase-correct memory proof in the current formal model contains 72 individual KZG openings. By delaying the AIR opening until permutation phase two is committed, AIR and permutation use one shared second-beacon evaluation point. After publishing every claimed opening value and deriving a third-beacon batching challenge, all 72 openings aggregate into four KZG opening statements:

```text
zeta
zeta + 1
0
row_count
```

The executable model then encrypts and recovers one message using four KZG-opening witness-encryption headers and four decryption pairings.

This is a dynamic encapsulation result, not a static RankLock construction.

## Prior-art boundary

Fleischhacker, Hall-Andersen and Simkin construct extractable witness encryption for one KZG opening with a one-group-element ciphertext and one pairing for encryption/decryption. Their multi-opening extension uses one independently randomized header per opening constraint, so ciphertext and pairing work are linear in the number of constraints.

Reference:

- https://eprint.iacr.org/2024/264

The 2025 linearly-verifiable-SNARK witness-encryption framework supports composable constant-size gadgets, including logical composition and constant-ciphertext inner-product gadgets. Therefore, neither “compose opening witness encryptions” nor “obtain constant ciphertext from a linearly verifiable argument” is itself a novelty claim.

References:

- https://eprint.iacr.org/2025/1364
- https://hackmd.io/@guruvamsi-policharla/S1WuMrAFxe

## Executable results

### Multi-constraint KZG-WE

`kzg_we_conjunction.py` implements the published algebra in RankLock's exponent-space model:

```text
header_j  = r_j ([tau]_2 - alpha_j [1]_2)
session_j = e(r_j (C_j - beta_j [1]_1), [1]_2)
```

A valid opening witness recovers the same session via:

```text
e(pi_j, header_j).
```

The model confirms:

- honest conjunction decryption;
- failure when one opening is replaced;
- linear ciphertext/pairing cost;
- same-point random aggregation;
- the known-rho false-value cancellation attack.

### Unified memory opening

`unified_memory_opening.py` changes the proof schedule:

```text
commit AIR trace and quotients
commit unsorted/sorted access columns
        |
     beacon 1
        |
commit permutation grand product and quotient
        |
     beacon 2
        |
derive one shared zeta
open AIR and permutation together
        |
publish all claimed opening values
        |
     beacon 3
        |
batch by evaluation point
```

For the executable sorted-memory skeleton:

```text
raw openings:          72
unique points:          4
batched openings:       4
batch group sizes: 2, 1, 65, 4
```

The large group is all commitments opened at `zeta`. The other groups cover `0`, `row_count`, and `zeta+1`.

## Why this does not finish RankLock

The four aggregate statements contain commitments, points, and values generated only after the future trace and three challenge phases exist. Standard KZG-WE must encapsulate to those concrete statements. The setup party holding the protected fault secret is no longer available at that time.

Thus the problem has narrowed from “encrypt to dozens of equations” to:

> How can a static artifact conditionally disclose a secret for a future arbitrary commitment/opening statement without an online encapsulator?

See `docs/16_STATIC_KZG_WE_BARRIER.md`.
