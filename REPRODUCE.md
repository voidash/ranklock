# Reproducing RankLock v0.25.1

## Environment

The package requires CPython 3.11 or newer. The tested dependency versions are
pinned in `requirements.lock`.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
```

When dependencies are already provisioned offline, use `--no-deps` and run
`scripts/check_locked_environment.py` to verify the exact versions.

## One-command local reproduction

```bash
./scripts/reproduce_v025.sh
```

The script performs:

1. locked dependency verification and bytecode compilation;
2. the complete per-file suite over all 100 test files;
3. fresh deterministic generation of the compact full-size committee fixture;
4. fresh deterministic generation of the full-size split-scalar fixture;
5. the static Bitcoin transaction/witness policy audit;
6. canonical artifact, signature, txid, wtxid and manifest verification;
7. the base-pinned Strata handoff's 10 static/fixture checks;
8. a Bitcoin Core 31.1 regtest attempt that records an explicit unavailable
   result rather than silently passing when `bitcoind` is absent;
9. a fail-closed release-gate result.

Expected source-suite result:

```text
100 files
423 passed
0 failed
```

## Supplying Bitcoin Core

Use an independently verified Bitcoin Core 31.1 executable:

```bash
RANKLOCK_BITCOIND=/absolute/path/to/bitcoind \
RANKLOCK_BITCOIND_SHA256=<sha256-of-that-executable> \
./scripts/reproduce_v025.sh
```

The Core runner checks the numeric release version and refuses to execute the
CLI qualification path without an explicitly pinned executable SHA-256. Preserve
the official signed release/archive verification separately; the executable hash
is an additional local identity pin, not a substitute for release signatures.

## Clean-archive verification

```bash
python scripts/verify_v025_clean_archive.py \
  /path/to/ranklock-v0.25.1-reproducible-source.zip \
  --output /path/to/ranklock-v0.25.1-clean-archive-verification.json
```

This installs the package into a clean target, verifies the source manifest,
runs all tests, regenerates both full-size modes, compares every load-bearing
artifact byte-for-byte, reruns the static policy audit and verifies the Strata
handoff manifest.

## Public-fixture warning

The conformance generators intentionally use deterministic public entropy so
that artifact bytes can be reproduced. Files under
`artifacts/v025-committee-conformance` and
`artifacts/v025-split-scalar-conformance` are unsafe for funded deployment.

A successful reproduction establishes source completeness, deterministic
format, functional correctness and executable negative tests. It does not
create external Core, Rust, operations, constant-time or audit attestations.
