# Prior-art collision matrix

This matrix records the boundary RankLock must cross. It is deliberately pessimistic: a collision
means we narrow or abandon the claim rather than relabel known work.

| Work | What it already achieves | Why RankLock is not allowed to claim it | Remaining possible separation |
|---|---|---|---|
| Mosaic, ePrint 2026/812 | Malicious security via cut-and-choose; polynomial label correlation makes on-chain input labels independent of copy count; adaptor-signature missing share | “Remove 181× on-chain labels” is already Mosaic's contribution | Remove the **off-chain** copies, tables, setup bandwidth and storage under the same malicious model |
| Succinct aHMAC/CDS, ePrint 2024/2073 | Fully succinct CDS for general circuits with communication independent of circuit size under group assumptions/circular variants | “Circuit-size-independent conditional disclosure” already exists theoretically | Near-native evaluation, projective inputs, distributed malicious setup, public activation, concrete 254-bit verifier |
| HSS succinct garbling, ePrint 2025/442 | About 1 bit per Boolean gate and `O(log p)` bits per arithmetic gate; layered variants below one bit/gate | “Sub-λ material per gate” is known | Eliminate expensive per-gate HSS/group evaluation by folding/vectorizing whole layers/templates |
| OHMG, ePrint 2025/2338 | Authenticity-only UC garbling for arithmetic/tensor/EC operations; at most one ciphertext per arithmetic gate | “One ciphertext per arithmetic gate” and privacy-free authenticity are known | Expensive work independent of **number of repeated gates**, plus dishonest-majority public setup |
| Authenticated Tensor Gates, ePrint 2025/1831 | Maliciously secure binary tensor gates with `O((n+m)κ+nm)` communication | “Use tensor gates” is known | Practical large-prime-field rank folding and persistent size independent of total tensor instances |
| AuthOr, ePrint 2025/775 | Authenticity-oriented Boolean garbling with large circuit-dependent savings | “Drop privacy to save gates” is known | Algebraic width-free evaluation rather than Boolean circuit optimization |
| Duty-Free Bits, ePrint 2026/476 | Projectivizes large-field garbling; major input-encoding reductions for BABE/Argo | “Projective field inputs” is known | Compose projectivization with distributed, width-free RankLock without restoring linear cost |
| Argo MAC, ePrint 2026/049 | Homomorphic EC MAC translation; >1000× improvement for garbled SNARK verifiers | “Field/EC MACs shrink Groth16 locks” is known | General RankIR compiler and same-security distributed setup with lower or comparable total cost |
| BABE, ePrint 2026/065 | Witness encryption for linear pairing relations plus Argo EC scalar multiplication; ~three orders of magnitude off-chain reduction | “Specialize Groth16 algebra rather than garble all pairings” is known | General arithmetic-program primitive; or materially beat BABE on the same verifier/security accounting |
| Dishonest-majority arithmetic garbling, ePrint 2026/1105 | Constant-round, constant-rate malicious MPC over bounded integers with up to `n-1` corruptions | “Dishonest-majority arithmetic BMR” is known | Noninteractive public post-setup evaluation and fully succinct retained material |
| Vector HSS, ePrint 2026/1517 | ConvertInput-free vector HSS and large batched inner-product speedups | “Batch HSS inner products” may already cover part of H1 | Extend vector batching to composable aHMAC/CDS, malicious setup, projective inputs, and trace folding |
| Sumcheck malicious compiler, ePrint 2025/177 | Small constant-overhead lift from additive semi-honest MPC to malicious security | “Use sumcheck for active security” is known | Template-amortized public activation for a noninteractive conditional-disclosure artifact |
| Row-reduced n-party garbling, ePrint 2025/829 | 25% table reduction and sublinear preprocessing for dishonest-majority garbling | “3nκ per AND” is known | Avoid storing one authenticated row per scalar gate altogether |

## The narrow claim still plausibly open

The intersection below is the research target:

```text
fully succinct CDS
+ width-independent expensive evaluation
+ native large-field trace execution
+ projective Bitcoin inputs
+ public cold-start evaluation
+ malicious generator / n-1 corrupt setup security
+ no online authority
+ real production verifier compiler
```

No item in the matrix is presently known to provide the full intersection. That statement remains a
research hypothesis until the complete papers and proofs are compared theorem by theorem.
