# RankLock v0.22 agent rules

## Mandatory first reads

1. `HANDOFF.md`
2. `BREAKTHROUGH_REPORT.md`
3. `V022_CHECKPOINT.md`
4. `docs/53_REAL_DFB_EMBRYO_EXECUTION.md`
5. `docs/52_ADAPTIVE_DFB_PROOF_TARGET.md`
6. `results/v022_real_dfb_embryo_execution.json`
7. `STATUS.json`

## Current priority

```text
P0-MASK-FUSION-1:
    eliminate or securely consume the 228,083-byte DFB final-mask state.

P0-ADAPT-1:
    prove or break adaptive, auxiliary-input, same-scalar two-instance security.

P0-MPC-1:
    execute the exact generator in n-1-corrupt active MPC.

P0-GRAPH-2:
    complete authenticated labels, BABE bytes and Bitcoin regtest.
```

## Mandatory claim discipline

- Never describe the 449,779-byte join stream as a standalone public evaluator artifact.
- Never omit `DfbDecodeState` unless a concrete label-flow fusion and proof replace it.
- Never present the old 1,023,186-byte v0.21 envelope as current.
- Never infer adaptive security from correct execution or selective privacy.
- Never reuse one affine/projective state for two inputs.
- Burn a slot before evaluation, not after success.
- Require exact committee, context, generator, transcript and slot-root binding.
- Treat all Python cryptography as variable-time research code.
- Preserve the deterministic full execution and every adversarial regression.

## Breakthrough gate

Do not set `breakthrough_target_met=true` until:

1. complete retained bytes, including all decoder/fusion state, fit the selected target;
2. adaptive two-instance security is proved under explicit assumptions;
3. active malicious generation with `n-1` corruptions is executed;
4. authenticated labels and atomic two-slot lifecycle are complete;
5. BABE/Bitcoin graph bytes fit the target;
6. all graph outcomes pass Bitcoin Core regtest;
7. a clean archive reproduces the full suite;
8. independent attack review survives.
