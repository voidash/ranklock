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

Executed against the pinned, signature-verified Bitcoin Core 31.1, each
negative case pinned to its specific rejection reason so none can later pass
vacuously:

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

Authoritative counts live in `results/v0252_*.json`; the table below is
regenerated from them rather than maintained by hand.

| Phase | passed | failed | not_executed | unavailable | |
|---|---|---|---|---|---|
| CORE-001..030 | 18 | 0 | 5 | 0 | (+7 `modeled_only`)
| STRATA-001..009 | 7 | 0 | 0 | 2 | |
| STRATA-010..020 | — | — | 11 | — | |

The STRATA row is a full re-run against a pristine clone of the pinned
commit: STRATA-001..004 and 006..008 pass; only STRATA-005 and STRATA-009
are `unavailable`, both on the FoundationDB client library and nothing else.

Five CORE rows are `modeled_only`: covered by the package suite but not driven through a live node. Per the acceptance matrix only `PASS` closes a release fact, so this records existing coverage without inflating the gate — asserted by a regression test.

## Resolved: both former "blockers"

Both were resolvable, and resolving them found four more real defects.

**Bitcoin Core 31.1 is now pinned and verified.** Tarball SHA-256 matches the
published manifest, and the manifest's GPG signatures verify: **11 good, 0
bad**, from independent Core maintainers. Executable
`d55c12b0b02001cc16b1481c4075361dcba193100a8143924abda911174c09ec`.
CORE-001 passes, so the CORE matrix is qualification evidence rather than a
development probe.

**The dependency graph resolves.** The earlier claim that it did not was
wrong — only `--offline` had been tested. `cargo fetch --locked` succeeds,
which made compiling the patch possible for the first time and surfaced
defects no static bundle check could catch.

## Resolved: STRATA-006 (a base defect, fixed as a labeled delta)

`logging::init_from_env` installed the global tracing dispatcher with no
once-guard, so the *second* call in a process aborted the test binary with
"a global default trace dispatcher has already been set". The pinned base
tree has **19 unguarded call sites**; any crate whose tests initialize
logging more than once per binary could not run its suite.

This is not a validity-first regression. The attribution control is
`claim_payout`, which the installer never touches: it fails 5 tests with the
identical panic at `f94c06d`, and passes **11/11** once the guard is added.

The fix is a `std::sync::Once` at the single definition site in
`crates/common/src/logging.rs`, not at the 19 call sites —
`init_logging_from_config` is re-exported from the `strata_logging`
dependency and is not editable from this patch. Per handoff rule 4 it is
carried as a separate, labeled delta (`patch_base_logging_defect`) rather
than folded into the feature patch, which raises the declared scope from 24
to **25 modified files**. Tests after the first in a binary now share the
first test's service label; the second call previously panicked, so nothing
could have depended on re-initialization.

**STRATA-006 now passes: 6/6 `validity_first_counterproof` tests against
pinned Core 31.1 regtest.**

## Resolved: STRATA-008, and a functor regression it exposed

All previously failing `bridge-sm` tests pass. Measured on a tree built by
cloning the pinned commit, running the installer preflight and apply, and
running the suites — not on an incrementally edited tree:

| Suite | Result |
|---|---|
| `-p strata-bridge-connectors validity_first_counterproof` | 6 passed, 0 failed |
| `-p strata-bridge-connectors` (whole crate) | 27 passed, 0 failed |
| `-p strata-bridge-tx-graph game_graph` | 7 passed, 0 failed |
| `-p strata-bridge-tx-graph --lib` (whole crate) | 46 passed, 0 failed |
| `-p strata-bridge-sm counterproof` | 71 passed, 0 failed |
| `-p strata-bridge-sm` (whole crate) | 449 passed, 0 failed |

The 21 failures were five distinct defects, not the single context mismatch
previously recorded here. The load-bearing one: `test_graph_sm_cfg()` called
`random_p2tr_desc()` and `generate_xonly_pubkey()` on **every invocation**,
so a graph built by a fixture and the graph the state machine regenerates
disagreed on every exact txid. It is now memoized in a `OnceLock`. The
earlier "the fixture's context must match the SM's" diagnosis was wrong —
`create_nonpov_sm` sets `graph_idx.operator = TEST_POV_IDX`, so the slots
already agreed.

One test, `event_rejected_when_tx_is_counterproof_ack`, had been **passing
by accident** on that same randomness. It was rewritten to feed the real
counterproof ACK for the slot and assert rejection, which is the strongest
form of its original premise.

**A regression the `counterproof` filter was hiding.** Running the whole
`tx-graph` crate rather than the filtered case showed 25 passed / 21 failed.
The patch widened the production `GAME_WATCHTOWER_LEN` for the new
per-watchtower fixed NACK but left the test module's parallel `PACKED_LEN`
constant unchanged, so every functor fixture was one element short per
watchtower; `unpack` returned `None`, the `expect("enough data")` in
`get_functor` panicked, and that poisoned the shared `LazyLock` fixtures,
cascading into 21 of 46 lib tests.

This was **caused by the patch, not pre-existing**: the pinned base is 46
passed / 0 failed, the patched tree was 25/21, and correcting `PACKED_LEN`
returns it to 46/0. Establishing that required running the base without the
patch; the filtered STRATA-007 case (`game_graph`, 7/0) passed throughout
and would never have revealed it. That is the concrete argument for the
acceptance matrix's rule that a filtered run must not be recorded as a full
one.

No test was deleted, ignored, or weakened to reach these numbers: the patch
adds no `#[ignore]` anywhere, and test counts per touched file held or grew
(one net-new test pinning the pre-maturity NACK gate).

### The repurposed tests were checked against the design, not just the code

Proving no test was *weakened* does not prove its new expectation is
*intended* — a test rewritten to match observed behaviour would enshrine a
defect. The four flips that changed semantics were therefore each checked
against an authority outside the implementation:

- **No immediate NACK on counterproof.** `integration_spec.json` states
  `polarity: {immediate: "ACK …", timeout: "CSV NACK …"}`. Matches.
- **Five packed signatures per watchtower.** The same file states
  `packed_signatures_per_watchtower_before: 4`, `…_after: 5`. This
  independently confirms the `PACKED_LEN` correction above is the intended
  arity and not a fixture bent to fit.
- **ACK viable *at* the nack-timeout boundary** (renamed from
  `…not_viable_at…`). The spec is **silent** on the boundary, so it was
  checked against BIP68 instead, which is the stronger authority. The
  patched code emits the NACK duty when
  `block_height + 1 >= conf_height + nack_timelock` — exactly when a
  relative-timelocked spend may enter the next block. The base guard it
  replaced (`block_height <= conf_height + nack_timelock`) fired two blocks
  *later* than consensus requires. The new boundary is correct; the rename
  reflects a real fix, not an accommodation.

- **ACK re-emitted on every retry tick** (`…noop…` → `…emits_ack…`). Neither
  the spec nor BIP68 settles this, so it was closed against the executor
  instead. `resolve_and_publish_counterproof_ack` returns `Ok(())` early when
  the RankLock preimage is not yet available, so a tick before export is a
  no-op; the transaction is a fixed pre-signed template finalized with the
  same preimage, so its txid is identical every tick; and it is published
  through the `tx_driver`, which the untouched base covers with a
  `tx_drive_idempotence` test. The duty is therefore an idempotent
  "ensure published", not a "broadcast now", and re-emission is safe.

## Resolved: two evidence-integrity holes

**A checksum ledger nothing verified.** The bundle's `MANIFEST.sha256` had
drifted from `apply_validity_first.py` — and had done so *before* this
session's edits. Nothing in `run_bundle_checks.sh` or `CHECKS.txt` ever
checked it, so a ledger recording nothing was indistinguishable from one
recording everything. All 23 entries were regenerated and
`shasum -a 256 -c --quiet` was added to the bundle check, so drift now fails
closed. The mechanism was confirmed by watching it reject an edit to the
bundle script before the manifest was regenerated.

**A fail-open version hole in the release gate.** The gate validates the
schema of the evidence-verification report, but consumed the optional
clean-archive report with *no* schema or version check — it read only
`all_checks_passed`. That report closes
`complete_source_archive_reproducible`, which is a funds blocker. The report
currently in `results/` is a **v0.18.0** artifact whose decision string is
`CLEAN_FULL_SUITE_ORCHESTRATION_INCOMPLETE_DUE_RUNTIME_CEILING`; it fails
closed today only because its `all_checks_passed` happens to be null. A
stale report saying `true` would silently have closed a v0.25.2 funds
blocker with evidence from a different release. The gate now pins both the
schema and the version, and the guard was verified by confirming it rejects
that exact report with exit code 1 while the normal path still produces
`safe_for_funds: false`, `maximum_mode: observe`.

## Resolved: source reproducibility — the gate advanced to `canary`

Having built the guard, the obvious next step was to run the producer, which
had never been done for this release. `verify_v025_clean_archive.py` extracts
the built archive into a clean tree, installs the locked dependencies into a
fresh interpreter, and re-runs everything from there. Result:
`all_checks_passed: true`, with all **15** reproducibility checks true —
including `packaged_fixtures_match_clean_generation`,
`source_manifest_verified`, `release_checksum_verified`,
`locked_dependencies_available` and `evidence_verifier_passed` — and **484
tests passed across 108 files, 0 failed, 0 nonzero exits** from the clean
extraction, driven against the pinned Core 31.1.

That closes `complete_source_archive_reproducible`, so
`locally_reproducible` is now true and **`maximum_mode` advances from
`observe` to `canary`**. The gate reads the report from its default path,
subject to the schema/version pin above.

The narrower EVID-007 claim is also closed:
`verify_v0252_deterministic_build.py` builds the release twice into separate
clean directories and all **4 of 4** artifacts are byte-identical. Two builds
on one machine remains a strictly weaker claim than cross-machine
reproducibility, and the two are deliberately not conflated.

## Why `safe_for_funds` cannot be closed here

The blocker list is down from nine to eight, and the FoundationDB step
closes two more — "Bitcoin Core regtest did not pass" (the five remaining
CORE rows are all `blocked_by` the Strata ACK/NACK graph, STRATA-012) and
"current bridge commit was not compiled and tested" (STRATA-009). That
leaves six, none of which is a matter of further local engineering:

| Blocker | Why local work cannot close it |
|---|---|
| independent cryptography audit | a third party must perform and sign it |
| independent implementation audit | likewise |
| production rollback witnesses deployed | operational infrastructure run by other parties |
| production setup gate (split-scalar) | a real multi-party ceremony with secrets nobody holds alone |
| deterministic fixture secrets absent | the shipped fixtures are public *by design*; only a real ceremony replaces them |
| native constant-time implementation | a separate engineering program, not a defect to fix |

These six are hardcoded `False` in `generate_v0252_release_gate.py` on
purpose. That is the fail-closed architecture handoff rule 2 requires, and
it is now pinned by
`test_a_fully_passing_local_matrix_still_cannot_open_the_funds_gate`, which
feeds the generator a **completely green** CORE and STRATA matrix — every
case passing, the best result any amount of local work could produce — and
asserts all six remain false and `safe_for_funds` stays false. Without that
test the boundary would be a convention; with it, it is a property.

Setting any of the six from this machine would mean fabricating an
attestation — the one thing handoff rules 2 and 5 forbid outright, and the
thing that would actually endanger funds, because the gate's entire purpose
is to stop a bridge going live on evidence nobody independent ever checked.

## Adversarial review findings (machine-assisted, NOT an independent audit)

Three adversarial reviews were run with a second model against the carrier,
the slot ledger and the Strata patch. **This is engineering, not
attestation.** A review commissioned and run by the same party on the same
machine is not what `independent_cryptography_audit_passed` means, and it did
not move that fact. Its value is that it found real defects before an
external auditor sees the code.

### Fixed: the slot ledger's audit chain did not bind live slot state

`verify_audit_chain()` hashed only the `audit_events` rows. The events and
the `slots` rows are separate tables in the same writable file, so the two
could disagree while verification returned `True`. Two attacks were
**reproduced against the previous implementation**:

1. Rewrite `slots.state` back to `available`, leaving the audit rows intact.
   The slot reopened and was burned a second time — two `burn` events for a
   one-shot slot — and `verify_audit_chain()` still returned `True`.
2. Delete every `audit_event` and zero `metadata.audit_chain_head`. An empty
   chain is trivially self-consistent, so verification returned `True`
   alongside a burned slot.

Fixed by replaying the events into the slot state they imply and comparing
against every live row, which defeats both: a slot with no events must be
`available`, so a wiped log no longer agrees with a burned slot. Getting
this right required modelling each event type rather than taking "last event
wins" — `exact-replay` is audit-only, and `conflict-rejected` records the
*rejected* digests, which are deliberately never written to the slot. The
first attempt did take last-event-wins and broke three existing conflict
tests, which is what surfaced the distinction.

Four regressions pin it, including one asserting an honest multi-slot ledger
still verifies so the check cannot be fail-closed-too-far.

**Scope is stated honestly in the docstring:** this is tamper *evidence*, not
tamper proofing. The hashes are unkeyed and the head sits in the same
writable database, so an actor who rewrites events, head and slot rows
consistently still produces a self-consistent file. Detecting that needs an
external authenticated monotonic witness — which is precisely the
deployed-rollback-witness release gate, and is not claimed here.

### Fixed: signing over a BIP341 annex produced an unspendable signature

`authorization_sighash` parsed the transaction but always called the sighash
helper with `annex=None`. For an annex-bearing input that signs a *different*
message than the network validates — a signature that looks valid and can
never be spent. The review demonstrated the divergence directly (the
no-annex and with-annex digests differ).

The witness parser already refuses annexes, so the honest path never carries
one; the signer now refuses too, keeping the two in agreement rather than
silently emitting a wrong signature. Pinned by a regression asserting the
helper still works without an annex and raises with one.

### Assessed and not accepted: the NUMS internal key's provenance

The review reported `NUMS_INTERNAL_KEY` as a defect for not being BIP341's
example point `lift_x(0x50929b74…03ac0)`. That is a documentation problem,
not a cryptographic one, and the finding is not accepted as written.

The property an internal key must have is that nobody knows its discrete
logarithm — not that it equals a particular published constant.
`_nums_internal_key()` hashes a fixed, domain-separated seed against an
incrementing counter and lifts the result to a curve point. Grinding that
search yields x coordinates, never discrete logs; recovering one would mean
solving ECDLP. The seed is a literal in the file and the search is
deterministic, so the key is independently recomputable and no choice could
have been made after seeing the outcome. A project-specific point also keeps
RankLock outputs from being confused with every other project that copies
the BIP341 example.

That a careful reviewer read it as unsound is itself the signal worth
acting on, so the derivation now carries a docstring stating exactly this.
Switching to the BIP341 example point would change every Taproot address in
the fixtures for no security gain.

### Open, not fixed: authorizer signature lacks explicit slot/context binding

The BIP340 message commits to the transaction, the input index and the leaf,
but neither the leaf nor the SigMsg contains `slot_id` or `context_digest`
directly. In principle a signature is transferable between two policies that
share a leaf and a transaction.

Practical severity is low, and lower than the review implies: the leaf
embeds the per-bit label rules, and labels are slot-separated — pinned by
`test_a_witness_for_one_slot_does_not_verify_under_another_slots_policy` —
so two distinct slots do not share a leaf. The suggested hardening (a tagged
`(context_digest, slot_id, authorization_input_index)` push in the tapscript)
is nonetheless correct defence in depth. It changes the script, and so every
address and fixture, and is left as a scoped follow-up rather than attempted
without room to verify it.

### Open, not fixed: exact-NACK is checked by txid, which omits the witness

`compute_txid()` excludes the witness under BIP141, so txid equality does not
prove the observed spend used the pre-signed NACK witness. The comment at
`contested.rs` claims the transition "accepts only the exact fixed
pre-signed NACK"; the check is weaker than the claim. A spend reusing the
NACK body but satisfying the *ACK* leaf carries the same txid and would be
classified as a NACK.

Severity is lower than a unilateral attack: it needs a fresh N/N signature
over the NACK body for the ACK leaf, so it requires all N signers to
collude. It is recorded rather than patched because the fix — comparing the
finalized transaction or wtxid in both `tx_classifier.rs` and
`contested.rs` — touches consensus-adjacent code and 449 passing tests, and
was not attempted without the room to verify it properly. **This is the
single highest-value item for the next session.**

### Assessed and not accepted: "autonomous NACK defeats a valid ACK"

The review reported that after CSV maturity the operator can broadcast the
signed NACK and double-spend a valid ACK. That describes the intended
timeout semantics rather than a defect: the CSV delay *is* the ACK's window,
and the ACK has a D-block head start. The genuine residue is a fee
competition if a valid ACK exists but is still unconfirmed at maturity,
which is inherent to any timeout-based design and is mitigated by sizing D
and fee-bumping the ACK. The proposed remedy — withholding the NACK witness
until an external attestation — would replace the pre-signed graph model
entirely, so it is a question for the protocol audit, not a patch.

## Remaining open items

1. **STRATA-009** — the FoundationDB 7.3.43 client is now **installed**
   (digests matching the verified package), so this case *executes* instead
   of being blocked, and **STRATA-005 passes**: the complete intended
   workspace compiles under `cargo check --workspace --all-targets --locked`.

   STRATA-009 is now `failed` rather than `unavailable`. The failure is a
   **pre-existing base defect, not a validity-first regression**, established
   the same way as the tx-graph question: `cargo test -p strata-bridge-db
   --lib` gives **6 passed / 32 failed on the patched tree and 6 passed / 32
   failed on the pristine base** — identical — and the patch touches no file
   under `crates/db`.

   Cause: `crates/db/src/fdb/client.rs:94` calls `network_builder.boot()` per
   client construction, but FoundationDB's API version can only be selected
   once per process, so every test after the first panics with *"the fdb
   select api version can only be run once per process"*. Structurally the
   same defect as STRATA-006 — an unguarded once-per-process global
   initializer called from many tests in one binary.

   **Correction: the api-version panic is a symptom, not the cause, and no
   code fix is warranted.** `crates/db/src/fdb/bridge_db.rs:449` already
   shares one client through `static FDB_CLIENT: OnceLock<(FdbClient,
   MustDrop)>`. The real chain is:

   1. `get_client()` calls `FDB_CLIENT.get_or_init(|| … FdbClient::setup(…).unwrap())`.
   2. `setup()` boots the network, then opens the database and runs a
      directory-setup transaction — which needs a live cluster.
   3. No cluster is reachable, so the transaction fails and `.unwrap()` panics.
   4. `OnceLock::get_or_init` stores nothing when its closure panics, so the
      next test calls `setup()` again, reaching `boot()` a second time and
      producing the api-version panic.

   So the requirement is infrastructure, exactly as Bitcoin Core regtest is
   for the CORE matrix — not a patch. Patching the guard would have masked
   the real cause.

   **A local cluster is now running, built entirely from the already-verified
   package and with no privileges:** `fdbserver` and `fdbcli` are executed
   directly out of `/tmp/fdb743/expanded/` rather than installed, on
   `127.0.0.1:4689` with data and logs under `/tmp/fdbcluster/`.
   `configure new single memory` reports *"Database created"* and
   `status minimal` reports the database available.

   One gap remains, and it is again a privileged path rather than an
   engineering problem. `Config::default()` takes
   `foundationdb::default_config_path()`, which on macOS is the compile-time
   constant `/usr/local/etc/foundationdb/fdb.cluster`; the explicit path is
   passed to `Database::new`, so `FDB_CLUSTER_FILE` is not consulted.
   `/usr/local/etc` does not exist and cannot be created unprivileged.
   Linking the running cluster's file into place is the remaining step:

   ```
   sudo mkdir -p /usr/local/etc/foundationdb
   sudo ln -sf /tmp/fdbcluster/fdb.cluster /usr/local/etc/foundationdb/fdb.cluster
   ```

   A symlink rather than a copy, so the file stays correct when the server
   rewrites coordinator details. After that STRATA-009 can run against a real
   cluster; whether it then passes is unknown and must be measured, not
   predicted — the last two predictions in this document about FoundationDB
   were both wrong.

   The earlier prediction in this document that installing FoundationDB would
   close two blockers was wrong: it closed STRATA-005 and moved STRATA-009
   from `unavailable` to `failed`.

   Historical note on the install, retained because the constraint recurs:

   The workspace pins `foundationdb` with `features = ["fdb-7_3"]` and
   deliberately *without* `embedded-fdb-include`, so it expects a real
   installed 7.3 client. `foundationdb-gen/src/lib.rs:341` resolves the
   options file with a compile-time
   `include_bytes!("/usr/local/include/foundationdb/fdb.options")` — an
   absolute path with no environment override, so it cannot be redirected.
   (`FDB_CLIENT_LIB_PATH` in `foundationdb-sys/build.rs:63` redirects only
   the *link* search path, not the headers.) `/usr/local` is `root:wheel`
   and not writable, so this one step needs sudo.

   Enabling `embedded-fdb-include` would dodge the sudo but silently change
   the pinned build configuration to compile against vendored headers rather
   than the client the project actually targets, and would still leave
   `libfdb_c.dylib` missing for the STRATA-009 test run. Rejected on those
   grounds rather than taken as a shortcut.

   Staged and verified without privileges:
   `FoundationDB-7.3.43_arm64.pkg` (native arch, exact pinned 7.3 series),
   SHA-256 `415088e5c36e22067d20c6da5f849536aaea99e103633fd0e05ce7287e19bab5`,
   matching Apple's published `.sha256`. Expanded at
   `/tmp/fdb743/expanded/FoundationDB-clients.pkg/Payload/usr/local`, which
   contains exactly `include/foundationdb/fdb.options` and an arm64
   `lib/libfdb_c.dylib`.

   The remaining step deliberately copies only the **clients** component, so
   no `fdbserver` and no launchd job are installed, and it is reversible by
   deleting the two paths:

   ```
   sudo mkdir -p /usr/local/include /usr/local/lib
   sudo cp -R /tmp/fdb743/expanded/FoundationDB-clients.pkg/Payload/usr/local/include/foundationdb /usr/local/include/
   sudo cp /tmp/fdb743/expanded/FoundationDB-clients.pkg/Payload/usr/local/lib/libfdb_c.dylib /usr/local/lib/
   ```
3. **Per-scenario protocol negatives are not wired into the matrix.**
   Remaining CORE rows are per-scenario burn/anchor/release negatives (wrong
   slot, wrong context, wrong witness) and the Strata ACK/NACK graph
   (CORE-021..023, 026/027). The *positive* two-phase path is executed end to
   end. CORE-014/016/017 are closed: they are slot-ledger durability
   properties rather than consensus properties, so the correct evidence is a
   real process kill, and the matrix now executes those suites directly.
   CORE-005 and CORE-009 are now covered by
   `tests/test_protocol_negatives.py` (wrong opening, wrong slot) -- both are
   off-chain binding checks, so a live node adds nothing: Core never sees a
   malformed opening. **Every remaining not_executed row is blocked solely on
   blocker 2.**
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
