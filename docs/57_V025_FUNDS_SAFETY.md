# RankLock v0.25.1 funds-safety qualification

## Security objective

For two one-shot slots tied to the same hidden scalar, the retained artifacts
and release transcripts should reveal no information beyond the authorized
outputs and declared positive-lock side information. Internal labels must be
unforgeable and slot/context bound. Group-linear values derived from authorized
outputs are acknowledged; they must not become a third accepted protocol use.

v0.25.1 does not replace the conditional cryptographic theorem from v0.24.1. It
adds the operational mechanisms required to make that theorem meaningful in a
Bitcoin bridge deployment.

## Phase-one invariant

Before any selected label share is emitted, every participant must persist a
unique binding to:

```text
context digest
activation digest
slot id
canonical point
precommitted stripped transaction digest
authorization request digest
```

An exact retry returns byte-identical shares. Any alternative binding is a
terminal conflict. Reorg observations never restore `available` state.

## Phase-two invariant

Program-seed shares are not part of phase one. A participant prepares them only
when:

- phase one is already durably burned;
- the signed confirmation request continues the same point and transaction;
- Core reports the exact txid/wtxid in the claimed block with the configured
  confirmation depth;
- the witness parses canonically and satisfies the signed hash rules;
- a second Core read returns the same inclusion;
- the current ledger checkpoint is accepted by every configured rollback
  witness.

Any exception finalizes the slot as `abort`. Terminal success is anchored before
the seed-share response file is atomically created.

## Setup alternatives

### Active-MPC compact mode

This is the only route that preserves the 1,044,952-byte object while avoiding a
trusted dealer. It remains an external implementation obligation: the exact
fused generator, including deltas, masks, labels, nonce domains, scalar and
positive-lock material, must run inside an actively secure protocol.

### Split-scalar N-of-N mode

Each participant chooses a scalar share independently, proves knowledge of it,
generates a separate two-slot object and locks an independent ACK preimage. The
aggregate output is the sum of participant outputs. A corrupt participant does
not learn the aggregate scalar and cannot create ACK alone, but can refuse to
complete setup or release. Retained material grows approximately linearly with
participants.

## Bitcoin script and policy envelope

Each slot carries 512 64-byte selector items. The exact tapscript consumes each
item, hashes it and checks membership in the committed zero/one label pair. The
conformance script is 37,889 bytes. The serialized conformance transaction is
71,305 bytes but only 71,587 weight units because most data is witness. The
static audit checks the standard per-item and transaction-weight envelope.

This audit is necessary but insufficient. Bitcoin Core remains the source of
truth for consensus and relay policy.

## Active-MPC attestation boundary

A compact-mode funding attestation is accepted only when the signed MPC statement
binds the exact deployment digest, context, chain genesis, ceremony certificate,
artifact, backend implementation, security reference, reproducible build, malicious-
security report, transcript replay report and secret-erasure report. The MPC verifier
must be distinct from every setup participant and from the ceremony verifier. Before
issuing a funding attestation it must obtain a stable live Bitcoin Core view of the
ceremony anchor and post-cutoff beacon. The attestation commits to that exact Core
observation and expires within 3,600 seconds. A conformance test or a ceremony
certificate alone cannot mint this evidence.

## Mandatory external gates

A funded deployment requires independently produced evidence for all of:

1. Bitcoin Core 31.1 regtest covering valid release, malformed witness, alternate
   point/context, replay, timeout, reorg, restart, fee and CPFP behavior.
2. Compilation and execution of the base-pinned current Strata bridge patch and
   its complete Rust test matrix.
3. Either the exact active-MPC compact ceremony or a production split-scalar
   ceremony with independently administered participants.
4. Native constant-time parsing, cryptography, secret erasure and denial-of-
   service hardening.
5. Independently administered rollback witnesses with hardware-backed keys,
   authenticated time/chain sources and disaster-recovery exercises.
6. Independent cryptographic, Bitcoin, implementation and operational audits.
7. Governance-signed deployment policy and unexpired role attestations bound to
   the exact source archive, retained object, generator hash, bridge commit and
   context.

Until then, `safe_for_funds` must remain false and the maximum local deployment
mode is canary.
