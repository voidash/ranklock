# RankLock v0.25.1 — funds-safety candidate, fail-closed

**Decision:** the reproducible two-slot construction now has a durable,
context-bound, two-phase Bitcoin authorization protocol and a dealer-free
split-scalar setup alternative. The local source and adversarial suites pass.
The package is **not safe for funds** because real Bitcoin Core/Strata execution,
production secret handling, independent witnesses and independent audits remain
external gates.

## Two setup modes

### Compact committee mode

```text
complete retained object:  1,044,952 bytes
margin below one MiB:           3,624 bytes
full 91-prime slots:                 2
```

This preserves the sub-MiB target and exercises N-of-N label/seed sharing, but
the conformance generator is a public dealer fixture. A funded deployment needs
the exact generator executed by an actively secure ceremony.

### Split-scalar N-of-N mode

```text
participant retained objects: 2 × 1,044,952 bytes
signed contribution bundle:             1,006 bytes
complete retained material:         2,090,910 bytes
```

Each participant independently locks its own scalar share, proves knowledge of
that share relative to the common verifier key, and contributes a distinct ACK
preimage. No dealer learns the aggregate scalar. One honest participant protects
ACK safety, while any participant can block liveness. This route deliberately
trades the sub-MiB target for a simpler one-honest setup boundary.

## Two-phase Bitcoin authorization

1. A signed preauthorization binds a canonical BN254 point to one precommitted
   stripped transaction.
2. Every participant durably burns the slot and releases only the 512 selected
   input-label shares.
3. The reconstructed 512 witness items satisfy the exact committed hash-check
   tapscript. No program-seed share is released yet.
4. After the exact txid, wtxid, witness digest, block and confirmation depth are
   checked twice through Bitcoin Core, participants release program-seed shares.
5. A reorg or conflicting observation terminates the slot; it never reopens.
6. Remote rollback-witness receipts must be anchored before any response bytes
   become visible.

The conformance transactions use 512 witness items of 64 bytes and a 37,889-byte
hash-check tapscript. The static serialized-policy audit passes with transaction
weight 71,587, below the standard 400,000-weight envelope. This is not a
substitute for Core execution.

## Verification

```text
source test files:                100
source tests passed:              423
source failures:                    0
v0.25.1 security-focused tests:    30 passed
Strata handoff checks:             10 passed
full-size committee generator:      pass
full-size split-scalar generator:   pass
static Bitcoin policy audit:        pass
Bitcoin Core 31.1 regtest:          not executed here
Rust/Strata workspace execution:    not executed here
safe for funds:                     false
```

## Reproduce

```bash
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
./scripts/reproduce_v025.sh
```

The bundled conformance artifacts and files prefixed `UNSAFE-PUBLIC-FIXTURE`
contain deterministic public setup material. They must never protect funds.

Read `V0251_CHECKPOINT.md`, `docs/57_V025_FUNDS_SAFETY.md`, `REPRODUCE.md`,
`results/v025_release_gate.json` and `STATUS.json` before using the code.
