# RankLock v0.20 Candidate Research Checkpoint

This checkpoint extends the stored v0.19 tree with an executable additive-share projective ceremony model.

## New result

The aggregate BABE scalar can be decomposed across contributors, while each contributor's future scalar-multiplication output is independently pairing-certified and then added. This localizes secrecy to one honest contributor share and turns corrupt-contributor artifact malformation into a per-contributor liveness problem.

For one-shot copies committed before an unpredictable audit/live partition, the exact probability that all malformed copies land in the live fallback set while the audit passes is `1 / C(t+q, q)`. Minimal balanced schedules are 44 copies for >40 bits, 68 for >64 bits, 84 for >80 bits, and 132 for >128 bits.

## Evidence

- `src/ranklock/additive_projective_ceremony.py`
- `tests/test_additive_projective_ceremony.py`
- `docs/50_ADDITIVE_PROJECTIVE_CEREMONY.md`

Focused test result: `4 passed`.

## Decision

**Breakthrough target is not yet met.** The result is a concrete malicious-setup composition route, but it still depends on instantiating and opening/verifying the exact Duty-Free-Bits Embryo artifact and on the Strata/Bitcoin integration gates.
