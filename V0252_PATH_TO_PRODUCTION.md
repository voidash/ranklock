# RankLock v0.25.2 — path from `canary` to `safe_for_funds`

Current gate: `safe_for_funds: false`, `maximum_mode: canary`,
7 funds blockers. This document turns those 7 into named work items with an
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

## Tier 1 — local build baseline complete

The FoundationDB 7.3.43 client and a reachable local cluster allowed the
complete serialized workspace to execute. The pinned Strata tree now passes
STRATA-001..009, closing `current bridge commit was not compiled and tested`.
The current rerun uses the measured 32-modified/4-new installer, not the older
31-file deployment baseline.

`Bitcoin Core regtest did not pass` remains open because five CORE rows depend
on the unexecuted Strata ACK/NACK graph. Only the Tier 1b service-boundary run
can close it; more build-only tests cannot.

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

### Deployment baseline now pins Core 31.1; the producer is still absent

The installer now replaces the old `bitcoin/bitcoin:30` tag with
`bitcoin/bitcoin:31.1` at registry index digest
`sha256:da25cedc66b1daefff9f412ee196c901a899c3fa68a33b20849c3e08b5c40d63`.
It also requires a host RankLock export root and mounts it read-only into all
three bridge nodes. A pristine install passes `docker compose config` with
those mounts and image identity intact.

That is consumer wiring, not an E2E producer. No deployed process invokes
`export_ack_from_verified_unlock`, so an empty or fixture-populated mount does
not satisfy the execution matrix. The old Core-version trap is closed; the
proof-verifying sidecar/service boundary remains the actual blocker.

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
emulation and the external `mosaic` fetch.
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
- CORE matrix 18 passed / 0 failed / 7 modeled-only / 5 not-executed,
  negatives pinned to their specific rejection reasons
- STRATA build matrix 9 passed / 0 failed; E2E matrix 0 passed / 11
  not-executed
- Rust: bridge-sm 452/0; complete serialized workspace 952/0
- Clean-archive reproduction: 15/15 checks and 525 tests across 111 files from
  a clean extraction, with generator-dependent public artifacts reproduced
  byte-for-byte — this is what moves the gate to `canary`
- Deterministic build: 4/4 byte-identical artifacts
- Evidence verifier remains fail-closed and additionally requires pinned
  binary/commit identity for every phase containing passed cases
