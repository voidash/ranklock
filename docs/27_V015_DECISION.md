# v0.15 Research Decision

## Breakthrough target

**Not met.**

## Closed in this version

1. The ideal projective-input oracle has a real 1,056-OT execution path under a clearly scoped online baseline.
2. KZG-opening witness encryption is implemented with actual BN254 pairings.
3. The concrete hybrid isolates the exact online-encapsulator failure.
4. A fixed relation eliminates that encapsulator when future values are witness variables.
5. Aggregate setup-proof batching approximately halves the fixed-linear key slope.
6. Direct one-coordinate-per-event compilation is concretely killed under the one-MiB target.
7. A misleading parallel “breakthrough” checkpoint was rejected after its failing tests were reproduced.

## Decisive open construction

Build a real fixed relation for RankVM invalidity that is simultaneously:

- knowledge-sound;
- linearly verifiable or reducible to a small fixed PPE;
- compatible with one-shot projective future inputs;
- static before the future counterproof exists;
- below one MiB of verifier-specific retained material;
- public after setup;
- secure with all but one setup contributor malicious;
- free of an online secret holder.

## Next parallel split

### Conditional-lock lane

- faithfully instantiate the Duty-Free-Bits malicious-receiver projectivization;
- implement/cost the needed LVA-WE or PPE-WE gadgets;
- determine whether recursive compression can beat BABE/Argo under complete same-security accounting;
- design malicious distributed setup and one-shot abort semantics.

### Proof/backend lane

- continue the common real-backend benchmark for rank-5 3×85 and 2×127;
- produce physical rows, lookup tables, proof size, memory, and timings;
- compile parsing and hash constraints.

## Kill rule

If the only complete route is a generic recursive proof plus generic PPE-WE with no concrete cost or generality advantage over BABE/Argo, the “space-shaking” claim must be killed or reframed.
