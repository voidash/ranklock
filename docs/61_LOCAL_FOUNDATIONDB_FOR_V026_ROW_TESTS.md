# Running the v0.26 row-spec tests against a live FoundationDB

Reproduces the live-execution run of 2026-08-24. Nothing here is installed
system-wide and nothing requires `sudo`.

## Why the tests were failing

Three separate causes: two environmental, one a genuine code defect that has
since been fixed.

1. **No server.** `libfdb_c.dylib` 7.3.43 (arm64) is installed at
   `/usr/local/lib`, but no `fdbserver` binary exists on the host. The client
   links and loads; there is simply nothing to connect to.

2. **The default cluster file is a dangling symlink.**
   `/usr/local/etc/foundationdb/fdb.cluster` is a root-owned symlink to
   `/tmp/fdbcluster/fdb.cluster`. That target was created on 2026-08-16 and
   macOS cleared `/tmp` since. `Config::default()` resolves
   `foundationdb::default_config_path()` to the symlink, so every test inherits
   the dangling path.

3. **No per-test keyspace isolation.** This was misdiagnosed in the first
   version of this document as an API-version limit; that was wrong, and the
   correction matters because it points at a different defect.

   The `the fdb select api version can only be run once per process` panics
   seen before a cluster existed were a *cascade*, not an independent cause.
   `get_client()` wraps setup in a `OnceLock`, but `OnceLock::get_or_init`
   re-runs its closure when the closure panics. With a dangling cluster file the
   first caller panicked inside `FdbClient::setup`, leaving the cell
   uninitialised, so every later test re-entered setup and hit the genuine
   once-per-process guard. Fix cause 2 and that message disappears entirely.

   What remains is a real and separate defect. `get_client()` builds **one**
   client under **one** random root directory and shares it across every test.
   All tests therefore write into a single keyspace. The proptest blocks are
   seeded deterministically per test, so different tests generate overlapping
   key values — and with the default parallel harness one test reads a row
   another test has just overwritten. Observed directly: `deposit_state_roundtrip`
   read back a `DepositSM` carrying its own `deposit_idx` (`2397917207`) but a
   different test's `operator_table`.

   Serial execution masks this because each case completes its write-then-read
   without interleaving. Measured on 2026-08-24 against a healthy cluster:
   `--test-threads=1` gives 69 passed / 0 failed; the default parallel harness
   gives 58 passed / **11 failed**.

   **Fixed 2026-08-24.** The fix is per-test keyspace isolation, not a
   `OnceLock` guard — a guard would have changed nothing, because the cell was
   already guarded. `FdbApiBuilder::build` and `NetworkAutoStop` are what is
   genuinely once-per-process; `Database::new` and the directory layer are not.
   `FdbClient::additional_in_root` therefore opens a further client in its own
   root directory without re-selecting the API version, and a `get_client!()`
   macro hands each test a keyspace keyed by its own name, so collisions between
   tests are impossible rather than improbable. `process_client()` still boots
   the network exactly once.

   The suite now passes with the default parallel harness, and does so in about
   16 seconds instead of 125 — isolation removed the reason for serial
   execution, and serial execution was most of the runtime.

A fourth condition bit during setup and is worth recording because it will
recur: the host disk was **100% full** (4.2 GiB free of 461 GiB). FoundationDB's
ratekeeper stops the database when free space falls below
`MIN_AVAILABLE_SPACE_RATIO`, default `0.05`. At roughly 0.9% the cluster came up
and then went unavailable with repeated `RkTlogMinFreeSpaceZero` trace events.
The knobs below work around it for a throwaway dev cluster; they are not
appropriate for anything else.

## Procedure

Pick a scratch directory `$D` outside the repository.

1. **Fetch the server matching the installed client.** Check the client version
   first and use the same one; mixing versions silently fails to connect.

   ```sh
   strings /usr/local/lib/libfdb_c.dylib | grep -E '^7\.[0-9]+\.[0-9]+$' | sort -u
   ```

   Download `FoundationDB-<version>_arm64.pkg` and its `.sha256` from
   `https://github.com/apple/foundationdb/releases/download/<version>/`, then
   verify the digest against the published file before expanding anything.

2. **Extract without installing.** `pkgutil --expand` writes nothing outside
   `$D`:

   ```sh
   pkgutil --expand fdb.pkg expanded
   cd expanded/FoundationDB-server.pkg  && cat Payload | gunzip -dc | (cd $D/server  && cpio -id)
   cd expanded/FoundationDB-clients.pkg && cat Payload | gunzip -dc | (cd $D/clients && cpio -id)
   ```

   This yields `$D/server/usr/local/libexec/fdbserver` and
   `$D/clients/usr/local/bin/fdbcli`.

3. **Write a cluster file** at `$D/fdb.cluster` containing exactly:

   ```text
   ranklock:localdev@127.0.0.1:4689
   ```

4. **Restore the dangling symlink target** so `Config::default()` resolves.
   `/tmp/fdbcluster` is user-writable, so this needs no `sudo` and touches
   nothing root-owned — the symlink itself is left alone:

   ```sh
   mkdir -p /tmp/fdbcluster
   cp $D/fdb.cluster /tmp/fdbcluster/fdb.cluster
   ```

5. **Start a single process**, with the free-space knobs only if the disk is
   near full:

   ```sh
   $D/server/usr/local/libexec/fdbserver \
     -p 127.0.0.1:4689 -d $D/data -L $D/logs -C $D/fdb.cluster \
     --knob_min_available_space_ratio=0.0 --knob_min_available_space=1048576 &
   ```

6. **Create the database** (memory engine keeps the data in RAM):

   ```sh
   $D/clients/usr/local/bin/fdbcli -C $D/fdb.cluster --exec "configure new single memory"
   ```

7. **Run the suite.** Parallel is correct as of the cause-3 fix; no
   `--test-threads=1` is needed:

   ```sh
   cargo test -p strata-bridge-db --lib
   ```

## Result on 2026-08-24

| Stage | Result | Wall clock |
|---|---|---|
| No cluster (parallel) | 35 passed, 33 failed | — |
| Cluster, serial | 69 passed, 0 failed | ~125 s |
| Cluster, parallel, before the cause-3 fix | 58 passed, **11 failed** | ~93 s |
| Cluster, parallel, after the cause-3 fix | 69 passed, 0 failed | ~16 s |

The parallel result was reproduced across four consecutive runs. The pre-cluster
failures all trace to cause 1 or 2; the 11 parallel failures traced to cause 3.

## What this establishes, and what it does not

It establishes that `strata-bridge-db` executes against a real FoundationDB on
this host, and that the `v026_admissions_v3` subspace opens, packs its 32-byte
digest key, addresses a row, and returns `Ok(None)` for an absent key
(`v026_v3_observation_read_path_executes_against_live_fdb`).

It does **not** establish that a v0.26 observation of any version has been
durably written and read back live. No test in this crate constructs a
`StructurallyVerifiedFundingBlockedV1/V2/V3`, because doing so requires
observing a complete live graph. The V1, V2 and V3 observation tests remain
pure codec and classifier tests. Live write-path coverage for v0.26 rows is
still absent.

It authorizes nothing. Rows stay inert, every blocker count is unchanged, and
`safe_for_funds` remains `false`.

## Teardown

Kill the `fdbserver` process and delete `$D`. `/tmp/fdbcluster/fdb.cluster` may
be left in place; macOS will clear it again, which returns the host to the state
that produced the original failures.
