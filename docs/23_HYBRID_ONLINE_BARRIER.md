# Concrete Hybrid and the Online-Encapsulator Barrier

## Construction tested

The full 32-byte fault secret is XOR-shared into:

1. an input share protected by the real projective OT lock; and
2. a trace share protected by real BN254 KZG-opening witness encryption.

The future KZG polynomial binds the selected byte-vector digest and trace-payload digest. Honest projective and opening witnesses reconstruct the secret; wrong bytes, wrong openings, split-brain substitutions, and repeated encapsulation fail.

## Failure certificate

The hybrid requires `OnlineTraceEncapsulator` to retain the second secret share until the future KZG commitment exists. This violates the target:

```text
no online fault-secret holder
```

The construction is therefore a concrete isolation of the remaining timing failure, not a RankLock solution.

`results/hybrid_online_barrier.json` records the failure and the required replacement:

> make future commitments, openings, authenticated bytes, and invalidity evidence witness variables of one fixed relation.

## Source

- `src/ranklock/hybrid_conditional_lock.py`
- `tests/test_hybrid_conditional_lock.py`
