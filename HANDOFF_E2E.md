# Handoff: RankLock funds-safety work

**Goal:** cryptographic soundness + the whole thing running end to end.
**Imported branch:** `v0.25.2-qualification` at
`94440e3b6e251d888402def5b59bb4977c831c05`. The workspace lane contains
uncommitted fund-safety hardening described below; nothing was pushed.

Read `V0252_THREAT_MODEL.md` first — especially §3b, which records the
largest thing found here — then this file. `V0252_CHECKPOINT.md` has the
full history including every wrong turn and its correction.

---

## Non-negotiable rules

From `00_START_HERE.md`. These are not style preferences.

1. **Never fund any deterministic conformance fixture.** Its secrets are
   public by design.
2. **Do not set `safe_for_funds=true` from local tests.** Only independent,
   correctly scoped evidence may satisfy external gates.
3. **Do not fabricate audit, ceremony, rollback-witness, or governance
   attestations.** Six facts are hardcoded `False` in
   `scripts/generate_v0252_release_gate.py` for exactly this reason, and
   `test_a_fully_passing_local_matrix_still_cannot_open_the_funds_gate` pins
   it. Do not "fix" that test.
4. **Preserve every negative test and the fail-closed gate.** If a check you
   add makes tests fail, establish whether the tests were wrong before
   weakening the check — twice here, they were.
5. **Do not push or open a PR.** Local commits only.
6. Commit messages carry no AI attribution.

---

## Current state, all verified from pristine clones

| | |
|---|---|
| Python suite | 525 passed / 1 skipped |
| `strata-bridge-sm` | 452 passed / 0 failed |
| Full Strata workspace | 952 passed / 0 failed (serialized) |
| Evidence verifier | 88 checks, 0 failing |
| STRATA matrix | 9/9 passed |
| Signet gate | green (`signet_ready: true`) |
| Funds gate | `safe_for_funds: false`, `maximum_mode: canary` — correct |

### 2026-08-19 P0: current timeout graph is economically refuted

Do not describe funds safety as merely waiting for more E2E coverage. The
applied `f94c06d` validity-first graph has a concrete loss trace: with a
semantically valid counterproof, one participant shared by every N-of-N
release can withhold, suppress all ACKs, let the exact CSV NACKs pay the graph
owner, and then let contested payout pay that owner while the canonical slash
is avoided. Longer CSV and CPFP improve inclusion but cannot repair deliberate
withholding.

The integration bundle now adds
`crates/tx-graph/src/funds_safety.rs`, a typed read-only analyzer that derives
the transaction conflicts, beneficiaries, txids, outpoints, and value totals
from a real generated graph. The real `AllNackd -> contested payout` bridge-sm
test asserts `funds_safe_under_premise=false`; a 1-of-2 control returns
`Ok(None)` only to prove the detector is narrow, never to authorize funds.
Fresh pinned-checkout installer preflight, rustfmt, the analyzer test, and the
bridge state test pass. The bundle scope is now 33 modified + 5 new paths and
its 28-entry manifest plus 13 Python checks pass.

The next protocol decision is unavoidable: either redesign timeout into a
principal-preserving refund/insurance terminal, or adopt a t-of-n/BFT release
and explicitly weaken/re-audit the corruption theorem. Do not continue with a
vector connector or proof backend as though either choice were settled.

The first graph-v2 research slice is now executable in
`src/ranklock/v026/timeout_economics.py`. It models the selected shared-`P`
topology: all counterproof alternatives and owner payout consume the same
contest-payout outpoint; each counterproof also consumes the deposit and
immediately allocates its exact amount to a distinct, plan-committed P2TR
recovery descriptor; ACK and timeout consume the selected resolution; ACK alone
creates the authorization required by Slash; and timeout consumes contest-slash
but not the independently burnable claim-payout output. Fifty focused
regressions pass.
Counterproof alternatives are explicitly
the ordered Strata watchtower roster—not the two RankLock query slots—and every
resolution output is bound to one plan-level connector policy. The honest result is narrow:
`counterproof_selection_allocates_exact_deposit=true`, but
`universal_funds_safety_established=false` and `funding_eligible=false` because
recovery/CPFP/Slash-beneficiary control, resolution/slash-authorization Script policy, the
exclusion of hidden alternate graph signatures, exclusive stake reservation,
and terminal principal disposition are not verified, the
valid-counterproof/withheld-release and invalid-counterproof/no-release worlds
remain indistinguishable, the Rust graph is not implemented, and no Bitcoin
Core acceptance has run. In particular, the abstract v2 parents fix the current
post-selection deposit, Slash, and claim-payout burn races. They do not prove
that an adversary lacks a pre-created cooperative deposit signature, that stake
is exclusively reserved, or that the complete terminal graph preserves every
principal. Do not convert this abstract result into an authorization input.
The Slash policy separately binds the required zero-value protocol header and
the ordered penalty-payout descriptors; it does not conflate them with CPFP
keys.

Landed: the proof-to-ACK library binding, ACK witness verification, Tier 0
crypto hardening, t-of-n VSS with resharing, and fixes for defects found by
adversarial review. This continuation also closed the witness-blind NACK gap
Claude left behind: both classification and transition now reconstruct and
compare the complete finalized pre-signed NACK, with same-txid/different-wtxid
regressions. The installer now preflights every post-format P4 delta in a
disposable worktree before touching its target. The standalone integration
manifest now covers every distributable file, including all three executable
P4 deltas, and its check rejects unlisted files as well as hash drift. The
exporter now uses private, inode-checked SQLite state and write-once
publication, and the two-phase abort path no longer hides rollback-witness
failures. Passing CORE, Strata-build, and Strata-E2E evidence now has to name
the pinned binary and commit rather than bypassing provenance checks by
omission. Compose mounts the exporter root read-only into every bridge and
pins the qualified Core image by registry digest; this wires the consumer,
not the still-missing proof-verifying producer. The stale public conformance
artifacts were regenerated from the actual generator-critical source, and
post-build clean/gate companion evidence is no longer packaged into the
archive it attests. The proof-gated exporter now derives its positive-lock
session from the exact `AckContext`; a caller can no longer present a valid
unlock under one statement while redirecting publication to another bridge or
transaction tuple.
The v0.25.1 hardening generator also now accepts the verified Core 31.1
execution while rejecting missing, contradictory, wrong-version, or
wrong-binary success evidence; the official reproduction path no longer fails
merely because the pinned node actually ran.

---

## Environment — get this right before anything else

**Bitcoin Core 31.1**, signature-verified, at
`/tmp/core311/bitcoin-31.1/bin/bitcoind`, SHA-256
`d55c12b0b02001cc16b1481c4075361dcba193100a8143924abda911174c09ec`.
Put it **first** on `PATH`. Do not substitute Core 30 — the verifier
cross-checks that the CORE and E2E matrices used the same binary.

**FoundationDB 7.3.43** client is installed. A local cluster runs from the
extracted package (never installed):

```
/tmp/fdb743/expanded/FoundationDB-server.pkg/Payload/usr/local/libexec/fdbserver \
  -p 127.0.0.1:4689 -d /tmp/fdbcluster/data -L /tmp/fdbcluster/logs \
  -C /tmp/fdbcluster/fdb.cluster
```

`/usr/local/etc/foundationdb/fdb.cluster` symlinks to it. **The server does
not survive a reboot** — restart it, or `strata-bridge-db` fails 32 tests
with a misleading "fdb select api version can only be run once per process".
That panic is a *symptom* of an unreachable cluster, not the cause.

**Python:** `source .venv/bin/activate`, `export PYTHONPATH=$PWD/src`.

**Disk:** builds repeatedly filled a 461 GB disk. Each clone's `target/` is
6–16 GB. Run `cargo clean --manifest-path <clone>/Cargo.toml` on clones you
are done with. One matrix run died on `No space left on device` and the
failure looked like a code defect.

---

## Task 1 — the end-to-end run (STRATA-010..020)

This is the binding constraint and it is **infrastructure, not a harness**.

`scripts/run_v0252_strata_e2e_matrix.py` exists and correctly reports all 11
cases `not_executed` with the missing prerequisite named. Case definitions
are verbatim from `03_ACCEPTANCE_MATRIX.md` in
`src/ranklock/strata_e2e_v0252.py`. The runner **cannot** mark a case
passed — `CaseResult` refuses a passed row without a recorded zero-exit
command. Adding execution means adding real commands.

### What it requires

`compose.yml` in the patched Strata tree brings up **13 services**:
`foundationdb`, `asm-runner`, `asm-params-init`, 3× `secret-service` (each
with TLS material), 3× `strata-bridge`, 3× `mosaic`, `bitcoind`.

### Traps, all confirmed by probing

- **The installer now pins Core 31.1 by registry digest.** The exact image is
  `bitcoin/bitcoin:31.1@sha256:da25cedc...5c40d63`; changing the tag or digest
  invalidates the deployment qualification and must be recorded.
- **`docker/asm-runner/Dockerfile` hardcodes `FROM --platform=linux/amd64`**,
  so it is emulated on arm64 regardless of VM architecture. `bitcoin` and
  `foundationdb` images do publish arm64.
- **`mosaic` builds from an external repo** (`github.com/alpenlabs/mosaic.git`
  at a pinned commit) — needs network to a third-party host.
- **`bridge-base:latest` must exist** before `strata-bridge` builds.
- **Colima silently ignores `--arch` when reusing a profile.** Switching
  needs `colima delete`, which destroys other images in that VM — use
  `--profile <name>` instead. The user has unrelated images there.
- **Only the consumer half is wired.** The installer mounts the host
  `STRATA_RANKLOCK_DIR` read-only into all three bridge containers and sets the
  executor variable. No deployed producer invokes
  `export_ack_from_verified_unlock`; a mounted empty directory is still an
  absent proof-to-ACK path. The host directory must be an existing private
  absolute path owned by the exporter user.

### The cheaper path, not yet attempted

`bin/strata-bridge` and `bin/secret-service` are binaries this workspace
already builds; the host already runs FDB and verified Core 31.1 natively;
the workspace compiles natively (that is STRATA-005). A **native** bring-up
would sidestep emulation and the external `mosaic` fetch. `asm-runner` and
`mosaic` are the unresolved pieces —
neither is a binary of this workspace. **Evaluate this before committing to
Docker.**

---

## Task 2 — remaining cryptographic soundness

In priority order.

### 2a. Setup entropy is still a capability

`derive_setup_payload(entropy=...)` produces the ACK preimage from entropy
alone. `export_ack_from_verified_unlock` is now the only *accidental*-proof
path — `export_unlock` refuses without `allow_unverified_payload=True` — but
whoever holds the entropy can still compute the preimage and publish it.

Closing this means taking the entropy-only derivation off the release path,
which changes how commitments are provisioned. Design decision, not a patch.

### 2b. H2 — the ~100-bit BABE lock

`babe_positive_lock.py` publishes `[r]δ` alongside a mask keyed on `Y^r`,
giving an offline attacker a DLP in `GT ⊂ F_p^12` — roughly 2^100 on BN254
under exTNFS, not the 2^127 the G2 ECDLP suggests. A reviewer built the
instance from public data and recovered the payload.

**This is a decision for the designers, not an implementation task.** The
lock is not currently on the ACK path (§3b), which lowers today's exposure
but does not settle whether it should ever be. Migrating to BLS12-381
(~126-bit GT) means reimplementing curve arithmetic. Do not start without a
decision.

### 2c. DKG to retire the dealer

`dealer_split_fixture` sees every aggregate label and seed. Note carefully:
**wiring in the t-of-n Feldman VSS does not fix this** — Feldman is itself
dealer-based. Removing the dealer requires distributed key generation. The
VSS module (`src/ranklock/threshold_sharing.py`, 10 tests) solves a
different problem: operator churn, where n-of-n made a departure equal fund
loss.

### 2d. Wire VSS into the protocol

Not a drop-in. `ParticipantSlotSecrets` holds 32-byte XOR shares; VSS shares
are indexed field elements. A correct integration changes the participant
type, the reconstruction path, and the share-root commitment — and that root
is bound into on-chain tapscript hash-locks, so it needs a migration
decision: existing deposits keep XOR, or regenerate.

---

## Traps that cost real time here

- **Never trust a "pre-existing defect" claim without testing the pristine
  base.** A subagent reported 21 tx-graph failures as pre-existing; the base
  was 46/0 and the patch was 25/21. It was a regression the patch caused.
- **Filtered test runs hide regressions.** `-p strata-bridge-tx-graph
  game_graph` passed 7/0 the entire time the crate was 25/21.
- **"Environmental" is usually a real defect one layer down.** Twice: an
  api-version panic that was an unreachable cluster, and a port-binding
  failure that was fixed libp2p memory addresses colliding process-globally.
- **Use AST, not regex, for Python call-site sweeps.** A regex missed two
  sites and broke 17 tests; another overlapped substrings and duplicated
  fields.
- **`git stash` on a patched-but-uncommitted tree reverts to the pristine
  base**, discarding the patch, not just your change.
- **Regenerating the post-format P4 diffs has one working recipe** — see
  `integration/.../pending/README.md`. A diff against the pristine base
  carries the whole installer as context; one from a long-lived scratch
  clone carries formatting the installer never produces.
- **Run the full suite before committing.** A gate went green on a tree that
  was actually broken, because the gate ran first.

---

## Verification loop

```
cd <ranklock>
source .venv/bin/activate && export PYTHONPATH=$PWD/src
export PATH=/tmp/core311/bitcoin-31.1/bin:$PATH

python -m pytest tests/ -q                        # expect 525 passed / 1 skipped
python scripts/check_signet_readiness.py          # must stay green
python scripts/verify_v0252_evidence.py           # 88 checks, 0 failing
python scripts/generate_v0252_release_gate.py     # safe_for_funds must stay false
python scripts/build_v025_release.py --output-dir /tmp/rb   # regenerates MANIFEST
```

Installer changes must be verified from a **pristine clone**: preflight,
apply, scope count (32 modified + 4 new), `cargo fmt --all -- --check`, then
the bridge-sm suite (currently 452/0) or, for release evidence, the full
STRATA-001..009 matrix (currently 9/9). `EXPECTED_CHANGED_FILES` lives in
`scripts/run_v0252_strata_build_matrix.py` and must be updated from the
*measured* count. The current clean 9/9 record measures 32 modified + 4 new
paths and includes `compose.yml`; do not reuse the older 31-file evidence.

---

## What "done" means

`safe_for_funds` will remain `false` after both tasks. It also gates on two
independent audits, deployed rollback witnesses, a production ceremony,
ceremony-derived fixture secrets, and a native constant-time implementation.
`V0252_PATH_TO_PRODUCTION.md` names an owner and acceptance test for each.

Those six require other people. Do not attempt to satisfy them in code.
