# RankLock v0.25.2 checkpoint

**`safe_for_funds` is `false`. Maximum mode is `observe`. This construction is
not authorized to protect funds.**

## Headline: a fund-loss bug was found and fixed

The v0.25.1 selector tapscript validated label preimages and nothing else. The
selected labels become public the instant the authorization transaction is
broadcast, so they constituted a **reusable spending capability**.

This was not theoretical. Against real Bitcoin Core regtest, an attacker who
observed a broadcast authorization was able to re-spend the same input into a
transaction paying their own address, and that transaction **confirmed on
chain**. The Taproot internal key was also derived from a hard-coded secret,
leaving a key-path spend that bypassed the authorization script entirely.

Both are fixed (see "Authorization carrier" below). Every claim in this
document that says "verified" was executed against a real `bitcoind`; nothing
here is modeled-only unless it says so.

## What was done

### 1. Baseline

The handoff archive was verified (source SHA-256
`87237d99…`, all 549 manifest entries, all 14 `SHA256SUMS` entries) and
extracted to `work/ranklock-v0.25.1`. The untouched extraction is preserved as
the first commit on `main`; all work is on `v0.25.2-qualification`.

The v0.25.1 baseline reproduces exactly: **100 test files, 423 passed, 0
failed**, with the release gate honestly fail-closed.

Environment deviation, recorded rather than hidden: this ran on CPython
3.14.6 / macOS arm64, while `requirements.lock` was tested on CPython 3.13.5 /
Linux x86_64. `check_locked_environment.py` enforces only `python>=3.11` plus
exact package versions, both satisfied.

### 2. Evidence framework

Qualification evidence is now structurally incapable of overstating itself:

- Five explicit statuses: `passed`, `failed`, `not_executed`, `unavailable`,
  `modeled_only`.
- A case cannot be constructed as `passed` without at least one recorded,
  zero-exit, non-timed-out command behind it.
- Every command records argv, cwd, environment digest, exit code, duration and
  **separate** stdout/stderr hashes, so a zero exit cannot hide error output.
- A report must cover exactly the canonical case set — no silently dropped
  case, no invented case ID.
- The verifier re-hashes every referenced log **from disk**, so a log edited
  after its report was written is rejected.
- The release gate reads *only* the verifier's output. It never reads a raw
  matrix report's own `all_passed`, and refuses to run at all if the verifier
  flagged an inconsistency.

Both tamper classes are covered by regression tests: flipping a status to
`passed` without commands, and editing a log after the fact.

### 3. Authorization carrier (the security fix)

- `selector_validation_tapscript` now begins with
  `PUSH32(authorizer) OP_CHECKSIGVERIFY`. The signature is the topmost witness
  item, so it is checked before any of the 512 hash comparisons.
- The signature is over the BIP341 script-path sighash, committing to version,
  locktime, every input outpoint and sequence, every spent amount and
  scriptPubKey, and every output — therefore also the fee.
- The Taproot output now commits under the shared unspendable
  `NUMS_INTERNAL_KEY`, removing the key-path bypass.
- Witness policy is now v2 (`RLWP2502`); the magic bump makes a v1 policy fail
  loudly rather than be silently accepted under the new rules.

Verified against real Core: the honest transaction is accepted, while output
redirection, fee mutation and the pre-fix unsigned witness shape are all
rejected with `Invalid Schnorr signature`.

**Consequence:** the tapscript changed, so Taproot outputs, txids and every
committee/split-scalar conformance artifact were regenerated. The handoff's
`inputs/` copies describe the old, vulnerable carrier and no longer match, by
design.

### 4. Slot-conflict semantics (CORE-014)

An authenticated conflicting binding now drives the slot to terminal
`retry-rejected` instead of leaving it `burned`. Only a validly signed
preauthorization reaches the ledger, so a conflict means one one-shot slot was
bound to two different transactions. Afterwards neither the conflicting request
nor the original honest one can drive the slot forward. A conflict arriving
*after* a terminal outcome is audit-only — released information cannot be
recalled.

### 5. Crash durability and reproducibility

Previous coverage reopened a ledger object in the same interpreter, which
exercises SQLite reads but not durability. `tests/test_crash_durability.py`
now SIGKILLs a child process between the committed burn and the response
write — uncatchable, so nothing can tidy up on the way out — and inspects the
database from a fresh process. A killed burn stays burned, still blocks a
conflicting binding (terminally, per CORE-014), and replays deterministically
with exactly one burn event.

EVID-007 is closed by `scripts/verify_v0252_deterministic_build.py`: two
independent builds produce byte-identical archives across all four artifacts.
Its scope note is explicit that this is same-machine determinism;
cross-machine reproducibility additionally needs a hash-locked dependency set.

### 6. Strata handoff repair

The supplied bundle **could not preflight at the pinned commit at all**. Two
installer defects, both reproduced directly:

1. The `ACK no CSV wait` anchor matched twice in `game_graph.rs`.
   Disambiguated against the counterproof-ACK branch its label names.
2. The `retry.rs` use-tree anchor expected 8-space indentation where the
   pinned source uses 4, so it matched zero times.

Formatting then still failed with 36 hunks. The installer now runs
`cargo fmt --all` after applying — safe only because the pinned base is
rustfmt-clean, which is verified and **asserted at runtime**: if formatting
touches anything outside the declared scope the installer fails rather than
silently widening the patch.

## Acceptance matrix status

Executed against real Bitcoin Core (development binary — see the blocker
below), each negative case pinned to its specific rejection reason so none can
later pass vacuously:

| Case | Result | Rejection reason pinned |
|---|---|---|
| CORE-004/006/007 | passed | `OP_VERIFY` |
| CORE-012 | passed | `Witness program hash mismatch` |
| CORE-024 | passed | `min relay fee not met` |
| CORE-025 | passed | accepted |
| CORE-028 | passed | `Invalid Schnorr signature` |
| CORE-019 | passed | orphaned, then cleanly reconsidered |
| CORE-029 | passed | restart: no duplicate release, no regression |
| CORE-030 | passed | oversize/truncated input bounded-rejected |
| CORE-002/003 | passed | full two-phase protocol, 6 confirmations |
| CORE-013/015 | passed | exact retries create no second response |

Pinning those reasons was not cosmetic: it caught that CORE-024 would
otherwise have passed on an invalid signature rather than on the fee floor.

| Phase | passed | failed | not_executed | unavailable | |
|---|---|---|---|---|---|
| CORE-001..030 | 17 | 0 | 7 | 1 | (+5 `modeled_only`)
| STRATA-001..009 | 4 | 0 | 0 | 5 | |
| STRATA-010..020 | — | — | 11 | — | |

Five CORE rows are `modeled_only`: covered by the package suite but not driven through a live node. Per the acceptance matrix only `PASS` closes a release fact, so this records existing coverage without inflating the gate — asserted by a regression test.

## Blockers (why the remaining cases are open)

These are recorded with their actual probe output, never asserted from memory.

1. **No hash-pinned Bitcoin Core 31.1.** The only local binary is 31.0
   (`d83bbb59…`). It is usable for development probes but can never produce
   qualification evidence — there is deliberately no
   `--allow-unpinned-bitcoind` flag. CORE-001 is `unavailable`.
2. **The Strata dependency graph is not resolvable here.** `cargo --offline`
   cannot reach the pinned `mosaic` git rev, and the full workspace also needs
   a FoundationDB client library. STRATA-005..009 are `unavailable`.
3. **Per-scenario protocol negatives are not wired into the matrix.**
   Remaining CORE rows are per-scenario burn/anchor/release negatives (wrong
   slot, wrong context, wrong witness) and the Strata ACK/NACK graph
   (CORE-021..023, 026/027). The *positive* two-phase path is executed end to
   end. CORE-014/016/017 are closed: they are slot-ledger durability
   properties rather than consensus properties, so the correct evidence is a
   real process kill, and the matrix now executes those suites directly.
   Only CORE-005 and CORE-009 remain as unbuilt protocol negatives.
4. **STRATA-010..020 need the compiled bridge.** A production-shaped
   exporter now exists (`src/ranklock/strata_exporter.py`), replacing the
   unsafe fixture, but the ACK/NACK paths cannot be driven until blocker 2
   is resolved.

## Gates that engineering cannot close

Per `04_EXTERNAL_GATES.md`, these require genuinely independent parties and
must not be self-attested: a real production setup ceremony (active-MPC or an
independently administered split-scalar ceremony); native constant-time
implementation with erasure evidence; independently operated rollback
witnesses; independent cryptography, implementation, Bitcoin and operations
audits; and a governance-signed deployment policy with staged rollout.

Even a fully green local matrix leaves `safe_for_funds` false. That is the
correct behavior, not a limitation to work around.

## Known scope note

CORE-003's adaptive slot-1 point is derived from slot-0's *released* material
(seed and labels), so it is adaptive by dependency and ordering. It is **not**
the BN254 projective output of executing the retained DFB program, because the
regtest harness uses synthetic slot artifacts. Recorded here rather than
claimed as full adaptive execution.
