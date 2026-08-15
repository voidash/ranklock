# Alpen `ValidityFirstCounterproofConnector` integration

This bundle is an apply-ready, base-pinned Rust integration for:

- repository: `alpenlabs/strata-bridge`
- reviewed base commit: `f94c06d08ff29eee746f3e20bd63078d2949b304`
- RankLock handoff: v0.25 two-phase authorization plus the 32-byte positive-lock preimage

It makes the smallest graph-preserving replacement of Alpen's current counterproof ACK/NACK mechanism:

| Property | Current Alpen path | This patch |
|---|---|---|
| Immediate branch | Mosaic/fault-key NACK | RankLock-preimage ACK |
| Delayed branch | N/N ACK after CSV | exact N/N-pre-signed NACK after CSV |
| ACK transaction | fixed and pre-signed | fixed and pre-signed; adds one 32-byte preimage |
| NACK transaction | mutable, wallet-funded, fault-key signed | fixed one-input transaction, N/N pre-signed |
| Parent graph/outpoints | existing | unchanged outside the counterproof child pair |
| ACK downstream meaning | `Acked` -> slash | unchanged |
| NACK downstream meaning | all NACKs -> contested payout | unchanged |
| P2P/DB graph-data schema | `fault_pubkeys: [32 bytes]` | same slot carries SHA256 ACK commitment |

## Security boundary

The released RankLock value is a **32-byte preimage**, not a Bitcoin signing key. Spending the ACK leaf additionally requires the existing N/N signature over the exact ACK transaction. A recovered preimage therefore cannot authorize an alternate output, fee mutation, different game/deposit, or replayed transaction template.

The two leaves are:

```text
ACK now:
    <N/N pubkey> CHECKSIGVERIFY SHA256 <H(preimage)> EQUAL

NACK after CSV:
    <delay> CSV DROP <N/N pubkey> CHECKSIG
```

The Taproot internal key is NUMS/unspendable. ACK and NACK conflict on the same `CounterproofTx::ACK_NACK_VOUT`.

## Apply

```bash
git clone <your accessible strata-bridge remote>
cd strata-bridge
git checkout f94c06d08ff29eee746f3e20bd63078d2949b304
python /path/to/alpen-validity-first/apply_validity_first.py . --check
python /path/to/alpen-validity-first/apply_validity_first.py .
```

The installer refuses a different commit, a dirty worktree, missing anchors, duplicate anchors, or pre-existing new files. It preflights all edits before writing and finishes with `git diff --check`.

Set the sidecar root before graph-data generation:

```bash
export STRATA_RANKLOCK_DIR=/var/lib/strata/ranklock
```

The included deterministic fixture can create setup/unlock files for regtest. It is test plumbing, not the RankLock proof evaluator:

```bash
python scripts/ranklock_sidecar_fixture.py setup \
  --root "$STRATA_RANKLOCK_DIR" --owner 0 --deposit 1 --game 1 --watchtower 1

python scripts/ranklock_sidecar_fixture.py unlock \
  --root "$STRATA_RANKLOCK_DIR" --owner 0 --deposit 1 --game 1 --watchtower 1 \
  --bridge-txid <64-hex> --counterproof-txid <64-hex> --ack-txid <64-hex> \
  --mode valid
```

## File handoff

Setup commitment:

```text
$STRATA_RANKLOCK_DIR/setup/
  owner<owner>-deposit<deposit>-game<game>-watchtower<watchtower>.commitment
```

Concrete ACK unlock:

```text
$STRATA_RANKLOCK_DIR/unlock/
  bridge<bridge_txid>-counterproof<counterproof_txid>-ack<ack_txid>.preimage
```

Each value is either exactly 32 raw bytes or 64 hexadecimal characters. Missing unlock means “no positive release yet” and is a retryable no-op. Malformed or hash-mismatched data is a hard executor error and is never broadcast.

## Fee and CPFP accounting

At 2 sat/vB:

- finalized ACK: **211 vB**, fee **422 sat**;
- fixed NACK for CSV delay up to 16: **137 vB**, fee **274 sat**;
- fixed NACK for delay 144: **138 vB**, fee **276 sat**.

The connector surcharge funds the larger ACK. ACK retains the existing keyed anchor. NACK pays an intrinsic fixed fee and sends its sole output to the operator descriptor; that output implements `ParentTxCombined`, so an operator wallet can attach a CPFP child without mutating the pre-signed parent.

## Verification status

Executed in this bundle environment:

```text
10 passed  bundle/sidecar/static integration checks
 6 passed  retained validity-first graph reference tests
```

The Rust source and Bitcoin Core regtest cases are included, but this environment had no Rust toolchain, `bitcoind`, Docker, or package-network access. Consequently, this bundle does **not** claim that `cargo check` or Core regtest was executed here. See `TEST_LEDGER.md` for the exact matrix and commands.

## Scope

This updates the Alpen graph-integration handoff to the reviewed `f94c06d` base and RankLock v0.25 two-phase authorization boundary. It is still an apply-ready candidate, not a production qualification: the Rust workspace and Bitcoin Core regtest must pass in the target environment, the exact compact setup still needs malicious-secure generation, and independent cryptographic and implementation audits remain mandatory.
