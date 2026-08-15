# RankLock v0.24.1 handoff

## Current decision

The reproducibility gap from v0.24 has been repaired. The canonical next target
is production qualification, not further storage optimization.

```text
retained object below one MiB:                 yes
complete source and test tree:                 yes
deterministic two-run equality:                required by reproduce script
conditional security harness:                  executable
safe for funds:                                no
```

## Start here

1. `V0241_CHECKPOINT.md`
2. `REPRODUCE.md`
3. `results/v0241_reproducibility.json`
4. `results/v0241_security_qualification.json`
5. `results/v0241_independent_verification.json`
6. `docs/56_V024_SECURITY_QUALIFICATION.md`
7. `src/ranklock/authorized_labels.py`
8. `src/ranklock/adaptive_sealing.py`
9. `src/ranklock/security_qualification.py`
10. `STATUS.json`

## Immediate production milestone

Implement the exact v0.24.1 generator inside an actively secure
`n-1`-corrupt setup protocol and connect its authorization record to a durable,
Bitcoin-enforced one-shot state machine. The acceptance test must include
crash/restart, concurrent use, reorg, alternate context, malformed witness,
timeout and fee/CPFP cases.

Do not use the public deterministic fixture or any single-process fresh fixture
with funds.
