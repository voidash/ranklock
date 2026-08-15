# Shared Proof-Object Binding

## Split-brain attack

A composed verifier is unsound if it hashes one proof encoding into Fiat–Shamir but feeds a different group point to the final pairing equation.

The attack interface is:

```text
transcript_group_encodings = honest proof
pairing_group_encodings    = substituted proof
```

The transcript digest remains honest while the pairing subsystem sees another witness.

## Repair

Each group element is canonically parsed once into a typed object. The transcript gadget and pairing gadget both consume that same object. No second proof witness is accepted.

The real BN254 regression proves the attack and the repair.

## Cost consequence

A shared object can remove a separate cross-gadget equality proof, which helps the tight 325-constraint-per-G1 threshold. The actual outer-curve cost of:

- decompression;
- sign-bit binding;
- on-curve and subgroup checks;
- exposing coordinates to both transcript and pairing gadgets

remains unmeasured.
