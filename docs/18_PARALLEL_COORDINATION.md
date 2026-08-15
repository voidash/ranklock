# Parallel Research Coordination

## Shared baseline

The field-bridge agent's `v0.13.2` patch is integrated unchanged as the baseline. It contributes:

- rank-5 3×85 convolution;
- 2×127 challenger;
- dual-field CRT split-brain analysis;
- transparent constraint ledgers;
- a 96-test clean baseline.

This branch adds P0-CDS-1 work and does not supersede the field-bridge results.

## Work ownership

### Parallel field/PCS lane

Continue:

- real lookup/PCS backend for rank-5 3×85 and 2×127;
- physical row, fixed-table, SRS, prover, memory, proof and verifier measurements;
- cross-PCS table binding only if it beats the single-field baseline.

### This CDS lane

Completed in v0.14:

- formal multi-constraint KZG-WE;
- same-point aggregation and cancellation regression;
- unified AIR/permutation second-beacon opening;
- 72-to-4 opening-conjunction reduction;
- static KZG-WE public-update attack;
- fixed-commitment projective positive model;
- authenticated-witness lift and substitution attack.

Next:

1. map the four-point verifier plus non-opening equations into the 2025 LVA-WE gadget framework theorem by theorem;
2. account for encryption key/CRS and decryption group work, not only ciphertext bytes;
3. build a fixed per-deposit relation including 132 authenticated bytes;
4. compare directly against BABE's WE + residual EC component;
5. attempt a commitment-oblivious projective gadget only if the fixed-relation route cannot meet the cost target.

## Merge rule

Every imported result must include:

- exact patch/base version;
- passing test command;
- evidence class (`EXACT`, `REPRODUCED`, `FORMAL MODEL`, `ESTIMATE`, `HYPOTHESIS`);
- affected claims and attack-ledger entries.
