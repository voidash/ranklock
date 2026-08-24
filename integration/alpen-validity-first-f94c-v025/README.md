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

> **Funds-safety kill:** this graph is not fundable. With a valid
> counterproof, one participant shared by every N-of-N RankLock release can
> withhold, suppress all ACKs, let the exact CSV NACKs pay the graph owner, and
> then let contested payout pay that owner while the canonical slash is
> avoided. Longer CSV and CPFP do not repair intentional withholding. The
> bundle ships a typed, read-only economic kill witness so this failure is
> executable rather than a prose caveat; it is deliberately disconnected from
> authorization.

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

For native graph-data generation, set the sidecar root to the path the bridge
process can read:

```bash
export STRATA_RANKLOCK_DIR=/var/lib/strata/ranklock
```

For Compose, set `STRATA_RANKLOCK_DIR` to an existing absolute **host** path
owned by the exporter user and inaccessible to group/other writers. The
installer mounts that path read-only at `/var/lib/strata/ranklock` in all
three bridge containers. It also pins Bitcoin Core 31.1 to the qualified
multi-architecture registry digest; `docker compose config` must be run with
the host variable set before deployment.

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

Current v0.25.2 qualification:

```text
13 passed  bundle/sidecar/static integration checks
 6 passed  retained validity-first graph reference tests
452 passed strata-bridge-sm tests
952 passed complete serialized Strata workspace tests
  9 passed STRATA-001..009 build-matrix cases
```

The Rust results were reproduced from a pristine pinned checkout using Bitcoin
Core 31.1 and FoundationDB 7.3.43. They establish the local build and
state-machine baseline. They do not establish funds safety. The current
timeout graph has an executable one-withholder economic counterexample, and
the release-level Core matrix plus live STRATA-010..020 service-boundary matrix
remain fail-closed. See `TEST_LEDGER.md` for commands and the exact claim
boundary.

The Compose change is consumer wiring only. This bundle still does not ship a
proof-verifying producer that calls `export_ack_from_verified_unlock`; the
deterministic fixture is never an acceptable substitute.

## Scope

This updates the Alpen graph-integration handoff to the reviewed `f94c06d` base and RankLock v0.25 two-phase authorization boundary. It is an apply-ready diagnostic/regtest candidate, not a production qualification. Even a perfect backend would inherit the current timeout loss trace. The graph therefore needs a fund-preserving refund/insurance terminal or an explicitly weaker threshold-release theorem before further deployment work matters.
