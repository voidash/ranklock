# Fixed-Relation Material Budget

## Setup-proof batching

The original reference key published one 64-byte DLEQ proof per relation coordinate. v0.15 derives a Fiat–Shamir scalar only after all original/scaled base pairs are fixed, forms one random linear combination, and proves one aggregate DLEQ statement.

For relation width `n`:

```text
old key law:     66 + 130 n bytes
batched key law: 130 + 66 n bytes
```

At width 328:

```text
old:       42,706 B
batched:   21,778 B
saved:     20,928 B
```

The ROM soundness error of the aggregate consistency check is bounded by approximately `(n-1)/q`. This is not a malicious distributed-setup proof.

## One-MiB envelope

After paying the concrete 132-byte projective layer:

```text
projective static material:      112,746 B
remaining raw budget:            935,830 B
maximum reference relation:       14,176 scalars
input relation width:                 264 scalars
maximum remaining trace width:     13,912 scalars
```

## Direct-compilation kill result

The current known verifier inventory contains:

```text
129,445 native multiplication events
1,967,564 logical lookup events
440,113 linear relation events
2,537,122 total logical events
```

Using one reference coordinate per event gives:

```text
multiplication-only retained material:   8.27 MiB
all-event retained material:            159.82 MiB
```

Therefore direct one-coordinate-per-event compilation is killed for the one-MiB target. This is a scoped cost result for the current gadget, not a universal lower bound on all LVA-WE systems.

A succinct/folding/recursive wrapper or a substantially more structured relation gadget is mandatory.

## Source

- `src/ranklock/fixed_relation_budget.py`
- `src/ranklock/direct_relation_barrier.py`
- `results/fixed_relation_budget.json`
- `results/direct_relation_barrier.json`
