# RankLock v0.25.2 — threat model and security argument

**Audience: the independent cryptography and implementation auditors.**

**Status of this document.** Written by an AI agent from the code, not by the
protocol's designers. Every mechanism described below was read out of the
implementation and, where marked *verified*, executed against the pinned
Bitcoin Core 31.1. Where a claim rests on reading rather than execution it is
marked **[unverified — confirm with the designers]**. Treat those as
questions, not assertions. A spec that quietly guesses is worse than none,
because it launders a guess into a requirement.

`safe_for_funds` is `false`. Nothing here asks you to accept otherwise.

---

## 1. What the system is for

RankLock gates the release of a secret — a 32-byte positive-lock preimage —
on a two-phase authorization protocol, and binds that release to one exact
Bitcoin transaction. The Strata bridge consumes the preimage as the ACK
branch of a validity-first counterproof: if the preimage appears, the ACK
spends; if it does not, a CSV-timelocked NACK spends after a delay.

The asset at risk is whatever the bridge's game graph controls. RankLock's
job is to make the ACK happen **exactly when it should and never otherwise**.

## 2. Adversary model

Assumed capabilities, in rough order of importance:

- **A2 — network adversary.** Sees every broadcast transaction the instant it
  hits the mempool, can rebroadcast, can attempt RBF and CPFP, and can race
  their own transaction against an honest one.
- **A3 — a bridge operator.** Runs a watchtower and holds their share of the
  pre-signed graph. Can withhold, delay, or broadcast anything they hold.
- **A4 — local write access to the RankLock host.** Can modify the slot
  ledger database directly, or roll it back to an earlier snapshot.
- **A5 — chain reorganization**, up to the depth the deployment tolerates.

Explicitly **out of scope**: a quorum of N/N signers colluding (that quorum
can spend by definition), and compromise of the authorizer's signing key.

## 3. Security properties claimed

**P1 — Authorization is not transferable.** *(verified)*

The v0.25.1 carrier failed this and it was a fund-loss bug. The tapscript
validated label preimages only; labels become public on broadcast, so they
were a reusable spending capability. Against real regtest, an attacker
re-spent the input to their own address and **the transaction confirmed**.

The fix: the leaf now begins `PUSH32(authorizer_pubkey) OP_CHECKSIGVERIFY`,
checked before any of the 512 hash comparisons, over the BIP341 script-path
sighash under `SIGHASH_DEFAULT`. That message commits to version, locktime,
every input outpoint and sequence, every spent amount and scriptPubKey, and
every output — therefore also the fee. Verified: honest transaction accepted;
output redirection, fee mutation, and the pre-fix unsigned witness all
rejected with `Invalid Schnorr signature`.

The internal key is an unspendable NUMS point, removing the key-path bypass.
It is domain-separated hash-to-point over a literal seed, not BIP341's
example point — sound, because grinding a seed yields x coordinates, never
discrete logs. **An adversarial reviewer misread this as a defect; please
form your own view.**

**P2 — A consumed slot never reopens.** *(verified for crash; partial for A4)*

A one-shot slot burns durably (WAL + `synchronous=FULL`) before anything is
released. Verified by SIGKILL between commit and response: the burn survives,
still blocks a conflicting binding, and replays deterministically with
exactly one burn event.

**Known limit against A4.** `verify_audit_chain()` now replays the audit log
into the slot state it implies and compares every live row, which detects a
rewound slot and a truncated log — both were reproduced against the previous
implementation, where a rewritten row allowed a *second burn on a one-shot
slot* while verification still returned `True`.

This is tamper **evidence**, not tamper proofing. Hashes are unkeyed and the
chain head lives in the same writable database, so an adversary who rewrites
events, head and rows *consistently* still produces a self-consistent file.
Detecting that requires an external authenticated monotonic witness — which
is the deployed-rollback-witness release gate, still open. **A4 is therefore
only partially mitigated, by design, and this is the property most worth your
attention.**

**P3 — The ACK wins when the preimage exists.** **[unverified]**

The intended argument: the ACK is spendable immediately, the NACK only after
`nack_timelock` blocks, so an honest ACK has a D-block head start.

The residual risk, which an adversarial review raised and I judged to be
intended semantics rather than a defect: at maturity, A3 can broadcast the
NACK and CPFP it. If a valid ACK exists but is unconfirmed — low fee, mempool
congestion — the NACK can win the race. **Whether D is sized correctly for
that, and whether ACK fee-bumping is operationally guaranteed, is a design
question I could not settle from the code. Please treat P3 as open.**

**P4 — ACK/NACK resolution is witness-bound.** *(locally verified; live E2E pending)*

The imported handoff claimed this property after fixing only the ACK side.
That was wrong. `process_counterproof_nackd` and the NACK classifier still
compared `compute_txid()`, which excludes witness data under BIP141. The
comment promised the exact pre-signed transaction while the code established
only the unsigned body.

The local implementation now closes both directions:

- ACK events carry the complete transaction. The transition first checks the
  expected ACK txid, then requires the witness to reveal the preimage committed
  by the slot's ACK leaf.
- The NACK classifier unpacks the persisted N/N signatures, reconstructs the
  finalized fixed NACK for every slot, and compares the complete
  `Transaction`. `process_counterproof_nackd` independently reconstructs and
  compares it again at the state-transition boundary.
- Malformed persisted signature layouts fail closed instead of panicking or
  accepting a witness-blind match.

Two adversarial regressions take a genuine finalized NACK, flip a witness byte,
assert that its `txid` is unchanged and its `wtxid` changed, then prove that
both classification and direct transition reject it. The pristine installer
reproduction passes 452 bridge-sm tests and the complete workspace passes 952.

The executable P4 deltas are also inside the standalone integration bundle's
tamper-evident boundary. Its manifest now covers all 27 distributable files;
the bundle check compares the complete file set before verifying hashes, so an
unlisted replacement delta cannot bypass the checksum check.

This is still local implementation evidence. STRATA-010..020 have not run, so
no claim is made that a production-shaped observer has classified and consumed
these transactions through the deployed services.

**P6 — The exporter cannot tell a real unlock from setup entropy.**
*(verified, architectural)*

`StrataAckExporter.export_unlock` checks `SHA256(payload) == commitment` and
enforces one context per commitment, but has no way to know the payload came
from a successful BABE unlock rather than being recomputed from setup
entropy. `derive_setup_payload` produces the identical value from entropy
alone, and its own docstring says whoever reproduces it "can reconstruct the
ACK preimage without any proof and unilaterally drive the bridge to ACK".

This is defensible layering — the cryptographic gate is `unlock_positive_lock`
one call upstream, and the exporter is publication plumbing. But it means
**setup entropy is a standing ACK-forgery capability for the lifetime of the
graph**, and nothing downstream of setup can detect its misuse. Auditors
should treat setup-entropy handling as fund-critical, not as configuration.

**P5 — Domain separation across slots and contexts.** **[partial]**

The signed message commits to the transaction, input index and leaf, but
neither the leaf nor the SigMsg contains `slot_id` or `context_digest`
directly. In practice leaves differ per slot because they embed
slot-separated label rules — pinned by a regression test — so the exposure is
limited. Explicit binding is nonetheless the correct hardening and is not yet
applied.

## 3b. The proof-to-ACK library and consumer mount exist; the producer does not

**(verified by call-graph inspection and unit tests)**

`export_ack_from_verified_unlock` now implements the missing library boundary.
It accepts no caller-supplied payload: it calls `unlock_positive_lock`, which
verifies the statement/proof binding and certified projective output, then
passes only that returned payload to the exporter. Direct `export_unlock`
calls fail closed unless the caller explicitly sets
`allow_unverified_payload=True`.

The proof-gated boundary also no longer accepts an independent
`session_context`. Setup derives the positive-lock session from the complete
`AckContext`, and release derives the same value internally. This closes a
split-brain redirect in which a valid unlock for one statement could otherwise
be published under a different bridge/counterproof/ACK tuple sharing the same
partial setup-commitment path. The regression leaves the ledger unused and
publishes no preimage under the substituted context.

That closes the former absence in the library, but it does not make an E2E
system. The verified exporter function is still called only from tests; no
production command or service invokes it. The installer now connects the
consumer side: all three bridge containers receive
`STRATA_RANKLOCK_DIR=/var/lib/strata/ranklock`, with a required host export
root mounted read-only, and compose pins the verified Core 31.1 image by
multi-architecture digest. `docker compose config` resolves all three mounts
as read-only. Therefore the proof-to-unlock-to-file path and its deployed
consumer exist, but the proof-verifying producer is still absent.

The exporter storage boundary is also locally hardened. Its root and SQLite
ledger must be private, real files owned by the process user; setup
commitments and unlocks are write-once; a proof-gated export must match the
commitment already published for graph setup; and concurrent filename
collisions cannot overwrite a released preimage. If bytes become visible but
directory durability reporting fails, the context binding remains released
and the API requires an exact retry instead of falsely marking the visible
secret as an ordinary failed publication. This is host hardening, not an
external monotonic witness, and does not close A4.

Setup entropy also remains a direct capability: `derive_setup_payload` can
recompute the ACK preimage without a proof, and the explicit development
override can publish it. Production provisioning must remove that route, not
merely promise that operators will avoid it.

STRATA-010..020 are consequently both unexecuted and deployment-blocked. The
next local task is to wire the verified exporter into a production-shaped
sidecar/service boundary and drive the recorded
ACK/NACK/restart/reorg/concurrency cases without a fixture shortcut.

## 4. What has been executed, and what that does not cover

Executed against pinned Core 31.1: CORE matrix 18 passed / 0 failed with each
negative pinned to its specific rejection reason (this caught CORE-024
passing on an invalid signature rather than the fee floor). Strata workspace
952 passed / 0 failed. Python 525 passed / 1 skipped. Verifier: 88 integrity
checks, 0 failing, logs re-hashed from disk.

**Not executed: the entire ACK/NACK execution phase (STRATA-010..020).** No
end-to-end evidence exists that a valid unlock produces an ACK the slash path
accepts, or that its absence produces a NACK and a contested payout. Five
CORE rows (021/022/023, 026/027) depend on it. Of those, only CORE-022 has
adjacent coverage, via the connector's `timeout_nack_spend` against real
Core. **The behavioural core of the system is unproven.**

## 5. Questions I could not answer from the code

1. Is `nack_timelock` sized against a worst-case fee market, and who
   guarantees the ACK is fee-bumped? (P3)
2. What reorg depth is the deployment expected to tolerate, and what does the
   slot ledger do when a release-bearing block is reorged out past that?
3. What is the intended N for rollback witnesses, and what makes their
   operators independent in practice?
4. Is the deterministic conformance fixture ever built into an artifact that
   could reach production, or is exclusion enforced mechanically?

## 6. Suggested review priorities

1. **P2 against A4** — the tamper-evidence boundary is real and documented.
2. **Proof-to-ACK deployment and P6** — the verified library path is not yet
   the only deployed producer, and setup entropy remains a release capability.
3. **P3** — the ACK/NACK race, the one place I could not distinguish design
   intent from defect.
4. **P1** — the fix is verified, but it is the property that already failed
   once, so it deserves adversarial attention rather than trust.
5. **P4** — independently confirm the new full-transaction reconstruction and
   the two same-txid/different-witness regressions.
