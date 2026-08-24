# Post-format Rust deltas and non-deployable v0.26 research patches

The three `p4-*` diffs are applied by `apply_validity_first.py` after the anchor
edits are formatted. The `v026-*` diffs are preserved research artifacts
and are deliberately **not** applied by that installer: they remain
non-fundable, need a separate upstream ASM change, and do not implement active
runtime admission.

## `v026-rust-research.diff` — RESEARCH ONLY, NOT LANDED

This patch applies after the current v0.25 installer state, not directly to the
pristine Strata base. It contains the side-by-side v0.26 NUMS connectors,
transaction templates, canonical local assembler, six real-Core branch,
conflict, and relay-policy cases, and durable funding-blocked V1/V2 observation
lanes. `git apply --check -p1` succeeds against the exact
installer-applied f94c checkout.

The patch retains sixteen activation blockers and has no active P2P, funding,
signing, duty, or broadcast path. Atomic selection consumes every
counterproof reserve and returns each non-selected reserve to its setup-bound
beneficiary. Live observation write capabilities are not deserializable. Do
not add it to the installer or call it
deployable until the canonical wire/evidence profile, presign/erasure proof,
stake reservation, ASM activation, terminal economics, and admission verifier
exist.

## `v026-threshold-v3-research.diff` — THRESHOLD-V3 PREREQUISITE

This patch applies after `v026-rust-research.diff`. It adds the content-bound
threshold-v3 key registry, bond and resolution connectors, atomic bonded
Owner/CP/ACK/Timeout/Slash graph, immutable funding-blocked V3 observation,
and selected-commitment ACK-witness first-writer-wins storage. Its SHA-256 is
`97325e484e069331b40a62ca35d1552c7d802373846feb636974c6aded31de47`.

The registry admits 2..4 alternatives, 2..64 participants, and at most 64
participant-by-alternative release cells. The limit is shared with the
subject-bound proof relation and prevents the formerly accepted 64-by-64
profile from entering an SP1 guest with multi-billion-cycle cost. The graph,
observations, and ACK-witness rows remain funding-blocked. This patch does not
provide setup authority, presign/erasure evidence, active runtime admission,
or a production proof path.

## `v026-subject-bound-counterproof-guest.diff` — BUILT, EXECUTED, CONFIRMATION GATED

This follow-on patch applies after `v026-threshold-v3-research.diff`; it is not
standalone or installer-applied. Its SHA-256 is
`55f175889422d165c0e48770e57c6114f8ea2110555f9cc36381bf5c2d8c8a02`.
It adds a feature-gated subject-bound counterproof relation, a distinct
program/guest source identity, and a separate build output name. The legacy
counterproof input/output API remains available.

The operator-signed BridgeProof transaction commits at output 1 to a canonical
complete P1/ACK manifest. The relation first executes the existing invalid- or
heavier-chain counterproof checks, then verifies the exact Contest proof input,
reconstructs the selected two-leaf threshold-v3 R output (including its NUMS
internal key and timeout leaf), decodes the witness-free ACK template, and
recomputes the ACK txid and BIP341 sighash. Its public output also includes the
verified BridgeProof txid so a future runtime can require equality with the
actually observed on-chain transaction instead of accepting an off-chain
operator-signed decoy.

Native Rust tests execute the real BridgeProof Taproot signing path, reject
cross-setup relabelling and ancestry drift, and compare reconstructed R bytes
to the production connector. The subject relation passed 9 native tests and
the unchanged legacy relation passed 33 regression tests.

The guest was built three times with `cargo-prove`/SP1 6.2.0 at commit
`3772ff9` and `rustc 1.93.0-dev` (LLVM 21.1.8). A source-touch rebuild proved
that the outer builder tracks feature-gated guest sources. All three final
subject ELF hashes were byte-identical:
`1db3e54249b8e9d2609097ac144f982d80e2fa01ce2913a6a6d1a93b27339f5e`.
The program vkey and predicate hashes are respectively
`d9f2c01fdcfd8cde39391e0cad3d5ccd15da430fa5db26e96716cbab70216c75`
and
`256fda1a6b600d02a7dd780ac69864c11af4f5ba69bc55b781c0b61f87a00153`.
All nine rebuilt artifacts are retained under
`results/v026-subject-bound-sp1/` and content-bound by the generated V11
threshold result.

Real SP1 execution returned byte-identical public outputs to the native
relation for the minimum and admitted frontier:

- 2 alternatives by 3 participants: 23,633,673 cycles / 23,496,238 gas;
- 2 by 32: 74,348,051 cycles / 76,946,196 gas;
- 4 by 16: 82,346,560 cycles / 84,443,876 gas.

The worst admitted case retains 17,653,440 cycles below SP1's reserved
100,000,000-cycle limit. This qualifies guest execution cost, not production
proving memory, network execution, proof-generation latency, or service quota.

A real `SP1_PROVER=cpu` Groth16 run against the exact subject ELF was then
allowed to run until the workstation reached its predeclared 15 GiB free-disk
safety cutoff. It accumulated at least 2,859 wall seconds and 37,366 CPU
seconds, reached an observed process footprint of at least 40 GiB and system
swap usage of at least 41,239 MiB, and emitted two insecure-RNG warnings. The
run was terminated without producing a receipt; swap reclamation restored
free disk from the cutoff to 48 GiB. The strict attempt record and raw 423-byte
log are retained as `local-groth16-cpu-attempt-v1.json` and
`bridge_counterproof_subject_v1_SP1_v6.2.4.local-groth16.log`, with SHA-256
`97b496b5a02450d7494894001f3a6e188001898220b4840d43f1d8b88dd77a13`
and
`294ecc0f72afd006c6a557d1caffabcb72c657f6bb8090c2b06af22f728ff85d`.
This is evidence of a local capacity failure, not evidence for or against the
cryptographic validity of a receipt that was never created.

The current-source legacy counterproof ELF was also rebuilt as
`6faedd5c1631c9c85c8ee807aacd69d6f3c530febf6bdd678dc1ecab44558749`,
which differs from the published rc4 ELF
`9ae1d4ef5816b598cf9b02be659d3bae6535151834f1fd77a5f4b572a60be8b7`.
The new subject predicate must therefore remain a new versioned identity; it
must not overwrite or masquerade as the deployed legacy artifact.

No production SP1 proof was generated or verified. A feature-gated production
verifier is pinned to the subject program vkey, SP1 6.2.4 metadata, Groth16
verifying key, VK root, and success policy. It mints a private live capability
only after algebraic verification, and a second private capability requires
the authenticated operator/game/BridgeProof txid/ACK subject to equal exact
caller-supplied transaction and graph identities. Four regressions cover wrong
metadata, malformed algebraic proof bytes, and identity relabelling. The local
capacity failure left no valid receipt for a positive algebraic-verification
run.

The patch now also adds a separate opt-in bridge-executor confirmation gate.
It accepts only the non-serializable txid-bound receipt capability, requires
Bitcoin Core to return the exact full transaction, independently checks the
containing block's Merkle root, requires the reported block hash to be active
at its height, enforces a nonzero minimum confirmation count, and repeats the
transaction and active-height reads before returning a live capability. Two
real-Core regressions reject mempool-only state, insufficient depth, block
invalidation, and a same-txid/different-witness substitution. This is a
point-in-time, reorg-sensitive observation; it is not persisted or reusable
across an irreversible action.

The executor also has a fail-closed composition helper for the next boundary.
It consumes the live confirmation and one observer-verified threshold-v3 ACK
witness selection, requires every receipt-authenticated ACK field and the
witness-stripped finalized transaction to match, rechecks Bitcoin before the
database operation, adopts only an exact create/replay under the immutable
selected-commitment CAS, rejects a conflicting first writer, and rechecks
Bitcoin afterward. Two pure regressions cover every subject field and CAS
outcome. This is not an enforced runtime path: no valid receipt exercises the
composed positive path, the lower-level witness store remains independently
callable, and the durable witness row is inert.

No runtime duty supplies a valid receipt or consumes the confirmed capability
before threshold release, no setup ceremony authorizes the manifest, and no
deterministic final Groth16/BABE artifact exists. Funding and theorem claims
remain false.

### Reproduction order

Against the exact pinned base, apply the installer and then these research
patches in order:

1. `v026-rust-research.diff`
2. `v026-threshold-v3-research.diff`
3. `v026-subject-bound-counterproof-guest.diff`

A fresh disposable checkout reconstructed the critical source bytes exactly,
passed all relevant Cargo checks, and passed the 9 subject-relation tests. Do
not reorder the patches or treat any of them as installer-applied.

## `v026-slash-asm.diff` — UPSTREAM RESEARCH, NOT PINNED

This patch applies to ASM commit
`9d2eb77585ceb3ca414aa7a9113a1cb1b7f7307c`. It introduces a distinct type-6
Slash-v2 header and strict `[L,S,K]` parser, leaving legacy type 4 unchanged.
The isolated ASM tests passed, but Strata still pins the original ASM commit;
mixed-version activation would be unsafe. Apply only in a coordinated upstream
review and update every ASM dependency pin together.

## Installer-applied P4 deltas

The installer's `--check` mode exercises the complete P4 sequence in a
disposable detached worktree, so those patches are preflighted without
modifying the requested checkout.

## `p4-complete.diff` — LANDED

This delta is now applied by `apply_validity_first.py` and is part of the
deliverable. The file is kept because the installer applies it directly.

The historical P4 landing was verified from a pristine clone at 32 modified +
4 new, `cargo fmt --all -- --check` clean, and
`strata-bridge-sm` **452 passed / 0 failed** including
`an_ack_txid_without_the_committed_preimage_is_rejected`.

## `p4-nack-witness.diff` and `p4-nack-classifier.diff` — LANDED

The ACK delta did not close P4 completely: NACK routing and transition still
compared only the witness-excluding txid. These two deltas reconstruct the
finalized fixed NACK from the state signatures and compare the complete
transaction at both boundaries. They add separate classifier and transition
regressions whose malicious transaction keeps the same txid while changing
the witness and wtxid.

### Regenerating a post-format delta

Each delta must be generated against the exact installer state immediately
before that delta is applied. Do not run the normal installer to create the
baseline: it applies every existing P4 delta and makes regeneration circular.

1. Create two disposable checkouts at the pinned base.
2. In both, run the anchor-edit phase and `format_touched`, with the post-format
   P4 calls disabled in a disposable copy of the installer.
3. If regenerating a later delta, apply every earlier post-format delta to both
   checkouts in installer order.
4. Make the intended change in only the work checkout and run `cargo fmt` on
   the touched workspace.
5. Generate a unified patch with `a/<path>` and `b/<path>` labels (or equivalent
   Git-style paths), then verify it using `git apply --check -p1` against the
   untouched baseline.
6. Run the real installer's complete disposable preflight from another pristine
   checkout before accepting the replacement.

A diff against the pristine Strata base includes the entire anchor installer
and cannot apply mid-stream. A long-lived scratch checkout is also unsafe as a
baseline because unrelated formatting or edits can leak into the patch.

### Current verification

The canonical STRATA-001..009 runner applied all three P4 diffs from a
pristine pinned checkout and passed 9/9 cases. The complete serialized
workspace result was 952 passed / 0 failed. The current bundle adds the
read-only economic kill-witness module and its `tx-graph` export, so the current
declared scope is 33 modified + 5 new. The NACK hardening itself still touches
files already inside the earlier boundary; `compose.yml` remains the deployment
wiring delta.
