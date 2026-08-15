# RankLock v0.25.1 checkpoint — durable two-phase authorization

## Decision

```text
REPRODUCIBLE SOURCE AND TEST BARRIER:       CROSSED
DURABLE TWO-PHASE AUTHORIZATION HARNESS:    CROSSED
STATIC BITCOIN POLICY ENVELOPE:              CROSSED
DEALER-FREE SPLIT-SCALAR SAFETY MODE:        CROSSED
REAL BITCOIN CORE / STRATA EXECUTION:         OPEN
NATIVE CONSTANT-TIME HARDENING:               OPEN
INDEPENDENT AUDITS AND OPERATIONS:             OPEN
SAFE FOR FUNDS:                                NO
```

## Executed evidence

- 100 source test files, 423 passed, zero failed;
- two independent full 91-prime same-scalar slots in compact mode;
- two independent two-slot artifacts in split-scalar mode;
- adaptive second input after the first aggregate output;
- exact txid, wtxid, witness-digest and canonical-point binding;
- SQLite `WAL`/`FULL` burn before label-share release;
- exact retry stability and conflicting-point rejection;
- signed monotonic rollback-witness receipts and restored-snapshot rejection;
- phase-two seed withholding until stable Core confirmation checks;
- reorg-race abort with no seed-share file emitted;
- 10 base-pinned Strata handoff checks;
- canonical evidence verifier: all load-bearing checks passed;
- live-Core-bound active-MPC funding attestations are context/chain bound, short lived,
  and require distinct approved ceremony and MPC verifiers;
- the qualification runner kills entire timed-out process groups and cannot strand
  inherited result pipes.

## Compact mode

The retained object remains 1,044,952 bytes, 3,624 bytes below one MiB. The
committee path splits every selected label and program seed with N-of-N XOR
shares. Its conformance generator still knows the hidden scalar and complete
shares, so this mode is not a funded setup until the exact generation is moved
inside an actively secure ceremony.

## Split-scalar mode

Two participants independently choose scalar shares and generate separate full
artifacts with disjoint DFB nonce namespaces. Their outputs add to `[r]A`; the
ACK requires both independently locked preimages. The signed contribution bundle
contains proofs of scalar-share knowledge. No dealer learns the aggregate
scalar. The cost is 2,090,910 retained bytes and N-of-N liveness.

## Bitcoin boundary

The static transaction audit verifies 512 selector items of 64 bytes, exact
37,889-byte hash-check scripts, clean-stack shape, precommitted outputs, positive
fees and transaction weight 71,587. Actual Bitcoin Core 31.1 acceptance,
confirmation, reorg, fee/CPFP and package behavior was not executed in this
runtime because `bitcoind` is absent.

## Deployment boundary

`ranklock.release_qualification` and `ranklock.deployment_policy` fail closed.
A local test report cannot mint its own Core, bridge, constant-time, operations
or independent-audit attestations. Enforce mode additionally requires a signed
immutable subject and role-specific unexpired attestations from configured,
independent authorities.
