# RankLock v0.25.2 — path from `canary` to `safe_for_funds`

Current gate: `safe_for_funds: false`, `maximum_mode: canary`,
8 funds blockers. This document turns those 8 into named work items with an
owner and an acceptance test for each, so nothing here is a wall — every row
is a task someone can start.

Nothing in this document may be self-attested. Handoff rules 2 and 5 forbid
setting `safe_for_funds` from local tests and forbid fabricating audit,
ceremony, rollback-witness or governance attestations. The six external
facts are hardcoded `False` in `scripts/generate_v0252_release_gate.py` for
that reason, and
`tests/test_generate_v0252_release_gate.py::test_a_fully_passing_local_matrix_still_cannot_open_the_funds_gate`
pins it: a *completely green* CORE and STRATA matrix still leaves all six
false. Do not "fix" that test.

---

## Tier 1 — one command, closes 2 blockers

**Owner: whoever holds local admin. Effort: one minute.**

Blockers closed: `Bitcoin Core regtest did not pass`,
`current bridge commit was not compiled and tested`.

The FoundationDB 7.3.43 client is staged and checksum-verified against
Apple's published `.sha256`
(`415088e5c36e22067d20c6da5f849536aaea99e103633fd0e05ce7287e19bab5`,
native arm64). Clients component only — no `fdbserver`, no launchd job:

```
sudo mkdir -p /usr/local/include /usr/local/lib
sudo cp -R /tmp/fdb743/expanded/FoundationDB-clients.pkg/Payload/usr/local/include/foundationdb /usr/local/include/
sudo cp /tmp/fdb743/expanded/FoundationDB-clients.pkg/Payload/usr/local/lib/libfdb_c.dylib /usr/local/lib/
```

Reversible by deleting those two paths.

*Why it cannot be engineered around:* `foundationdb-gen/src/lib.rs:341`
resolves the options file with a compile-time
`include_bytes!("/usr/local/include/foundationdb/fdb.options")` — an
absolute path with no environment override. `FDB_CLIENT_LIB_PATH`
(`foundationdb-sys/build.rs:63`) redirects only the link search path.
Enabling `embedded-fdb-include`, or `[patch]`-ing the dependency, would
compile — but STRATA-009 asserts *"the complete intended workspace test
suite passes"*, and a modified dependency graph is no longer the intended
workspace. That would be a false pass, which is worse than an honest
`unavailable`.

**Acceptance:** re-run
`scripts/run_v0252_strata_build_matrix.py <pristine-clone>`; STRATA-005 and
STRATA-009 move from `unavailable` to `passed`. Then run the Strata E2E so
STRATA-010..020 execute, which unblocks the five remaining CORE rows
(CORE-021/022/023/026/027 are each `blocked_by` the Strata ACK/NACK graph,
STRATA-012).

---

## Tier 1b — the STRATA-010..020 execution phase: scoped, with a trap

**Owner: engineering. Effort: hours to days, not minutes.**

Blocker closed: `Bitcoin Core regtest did not pass` (its five outstanding
CORE rows are each `blocked_by` STRATA-012).

This is **not** a test harness to write. `compose.yml` brings up thirteen
services: `foundationdb`, `asm-runner`, `asm-params-init`, three
`secret-service` (each with TLS material), three `strata-bridge`, three
`mosaic`, and `bitcoind`. Driving the eleven cases means operating a real
multi-operator deployment.

### The trap: the stack is pinned to Bitcoin Core 30, not 31.1

`compose.yml` uses `bitcoin/bitcoin:30`. Every CORE row in this
qualification is executed against **signature-verified Core 31.1**, and
`verify_v0252_evidence.py` cross-checks *"Core matrix and Strata E2E matrix
used the same pinned bitcoind executable"*.

Running the stack as shipped therefore produces E2E evidence on a different
consensus and policy version, which the verifier will reject **after** the
build rather than before it. Repoint the stack at 31.1 first, and record
that repoint as a deviation. Left undetected this would have burned hours
and then produced unusable evidence.

Also note `foundationdb/foundationdb:7.3.75` against the 7.3.43 client
installed on this host — same minor series, but worth confirming rather
than assuming.

### Build constraints found by probing, not by reading

- `docker/asm-runner/Dockerfile` hardcodes `FROM --platform=linux/amd64`,
  so that image is emulated on an arm64 host **regardless** of the VM's
  architecture. The `bitcoin` and `foundationdb` images do publish arm64,
  so only part of the stack is forced into emulation.
- `mosaic` builds from an external repository
  (`github.com/alpenlabs/mosaic.git` at a pinned commit), so the build needs
  network access to a third-party host.
- A `bridge-base:latest` image must exist before `strata-bridge` builds.
- Colima **reuses an existing VM profile and silently ignores `--arch`**.
  Switching architecture needs `colima delete` first, which destroys any
  other images in that VM — use `--profile <name>` rather than deleting
  someone else's environment.
- Budget disk deliberately: a full workspace build in Docker wants 20-30 GB,
  and this host repeatedly hit 100% during native builds alone.

### A cheaper alternative worth evaluating first

Every service that matters is a binary this workspace already produces
(`bin/strata-bridge`, `bin/secret-service`), the host already runs a real
FoundationDB cluster and verified Core 31.1, and the workspace compiles
natively. Running the bridge natively rather than in Docker would avoid the
emulation, the external `mosaic` fetch and the Core 30 mismatch in one move.
It has not been attempted; `asm-runner` and `mosaic` are the two pieces that
would need resolving, since neither is a binary of this workspace.

## Tier 2 — an engineering programme, not a defect

### `native constant-time implementation is absent`

**Owner: the implementation team. Effort: months.**

The BN254 / DFB / label-commitment stack is Python. Production key handling
needs a native implementation with no secret-dependent branches or memory
access. This is new work with its own review cycle, not a bug to fix; it is
listed as a blocker because shipping funds custody on a variable-time
implementation is a real attack surface, not a paperwork gap.

**Acceptance:** native implementation plus a timing-variance test suite, and
`native_constant_time_implementation` sourced from that suite's report
rather than hardcoded.

---

## Tier 3 — external attestations (4 blockers)

**None of these can be produced on the machine that runs the gate.** That is
the point of them. Each needs a deliverable signed by a key the RankLock
operators do not control.

| Blocker | Owner | Deliverable |
|---|---|---|
| `independent cryptography audit is absent` | external cryptography firm | signed report over the protocol: two-phase authorization, DFB label commitments, split-scalar setup, the BIP340/BIP341 carrier binding |
| `independent implementation audit is absent` | external security firm, different from the above | signed report over the code as shipped, including the Rust validity-first patch and the slot ledger |
| `production rollback witnesses are not deployed` | ≥N independent operators | witnesses running on separately controlled infrastructure, each publishing signed attestations; independence is the property being bought, so common ownership or a shared host voids it |
| `production setup gate is open for split-scalar-n-of-n` | ceremony participants + governance | a real multi-party ceremony whose transcript is signed by every participant |

### `deterministic fixture secrets are present`

Follows from the ceremony rather than standing alone. The repo ships
deterministic conformance fixtures whose setup secrets are **public by
design** — handoff rule 1: *never fund any deterministic conformance
fixture*. This flips only when a production build carries ceremony-derived
secrets and no fixture secrets. Do not close it by deleting fixtures: they
are what makes the reproducibility evidence checkable.

---

## How the attestations should reach the gate

Deliberately **not implemented here.** The correct mechanism is an
attestation bundle carrying detached signatures over each report's digest,
verified against auditor and participant public keys registered *out of
band*, with the gate reading a fact as true only when a signature verifies
against a pre-registered key.

Building that path now, with no real keys to register, would mean shipping
untested machinery whose only function is to set `safe_for_funds: true` —
the exact bypass rule 2 exists to prevent, and it would have to be audited
before it could be trusted anyway. The hardcoded `False` is the safe
default: it fails closed, and it is honest about the fact that no such
evidence exists yet.

---

## What is already closed

For contrast, so the remaining list is not mistaken for the whole picture:

- Bitcoin Core 31.1 pinned and signature-verified (11 good GPG signatures)
- A **fund-loss vulnerability** found and fixed — the selector tapscript
  validated labels only, and labels become public on broadcast; proven
  exploitable against real Core regtest, where an attacker redirected the
  output and the transaction confirmed. Fixed with `OP_CHECKSIGVERIFY` over
  the BIP341 sighash plus a NUMS internal key.
- CORE matrix 18 passed / 0 failed, negatives pinned to their specific
  rejection reasons
- STRATA 7 passed / 0 failed / 2 unavailable
- Rust: connectors 27/0, tx-graph 46/0, bridge-sm 449/0
- Clean-archive reproduction: 15/15 checks, 484 tests from a clean
  extraction — this is what moved the gate to `canary`
- Deterministic build: 4/4 byte-identical artifacts
- Evidence verifier: 79 integrity checks, 0 failing
