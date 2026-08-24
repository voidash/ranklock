# RankLock v0.26 funds-safety handoff

## Current funds verdict

```text
deployed v0.25 graph safe under one release withholder: no
strict v0.26 abstract topology modeled:                  yes
maximal abstract terminal traces enumerated:             5
semantic worlds mapped:                                  7
terminal protected-value theorem:                        no
side-by-side Rust graph assembled:                       research slice only
real Bitcoin Core branch/conflict cases:                 6 passed
stake exclusivity:                                       explicitly disproved
runtime/admission integration:                           no
safe for funds:                                          no
```

Start the v0.26 review at:

1. `review/v026-funds-safety/index.html`
2. `docs/58_V026_FUNDS_SAFETY_PROTOCOL.md`
3. `results/v026_timeout_economics.json`
4. `results/v026_rust_graph_core.json`
5. `docs/05_ATTACK_LEDGER.md`, attack A-027
6. `docs/08_RESEARCH_BACKLOG.md`, task P0-GRAPH-3

The deployed graph remains broken: a valid counterproof plus one shared N-of-N
release withholder can reach mature NACKs and owner payout while avoiding the
canonical Slash. The v0.26 research graph replaces that topology with atomic
shared selection: every counterproof and the owner branch consume every
counterproof reserve, return each non-selected reserve to its setup-bound
beneficiary, and allocate the deposit to recovery on selection. It also uses
exclusive ACK/timeout resolution and ACK-created Slash authorization. Its
local Script and conflict behavior is reproduced in Bitcoin Core, but it
retains sixteen unconditional
activation blockers. A real competing stake spend is accepted by Core and
prevents Slash, so this work must not be presented as funds-safe.

The abstract economics artifact now performs deterministic live-UTXO
enumeration instead of inferring terminal safety from pairwise conflicts. It
finds five maximal local traces and maps seven semantic worlds; for each
alternative, `valid + withheld` and `invalid + absent` resolve to the identical
timeout trace. The committed atomic-reserve policy now satisfies its declared
local disposition rules and leaves zero abandoned counterproof reserves. That
result is explicitly named `AbstractDeclaredPolicySatisfiedV1`, carries four
immutable authority/execution blockers, and can never assert a protected-value
theorem or funding eligibility. The Python policy is not yet a canonical
projection of the Rust graph.

The frozen `StructurallyVerifiedFundingBlockedV1` observation format and its
fifteen-code subspace remain byte-compatible. Because the graph now has a
sixteenth weight/confirmed-parent blocker, current observations use the
separate `StructurallyVerifiedFundingBlockedV2` envelope and FDB subspace. Both
persist only a local txid manifest and exact blocker set; neither exposes
funding, signing, duty, broadcast, or P2P admission capability. Their live
FoundationDB tests did not complete in the local environment, so reproduced
evidence is limited to strict codecs and pure replay/conflict classification.
The next safe design work is to authenticate terminal principal baselines,
per-principal allowances, the service-fee schedule, and by-horizon
CSV/reorg/fee evidence. Canonical wire and active admission remain downstream
of that economic authority.

---

# RankLock v0.24.1 historical handoff

## Current decision

The reproducibility gap from v0.24 has been repaired. The canonical next target
is production qualification, not further storage optimization.

```text
retained object below one MiB:                 yes
complete source and test tree:                 yes
deterministic two-run equality:                required by reproduce script
conditional security harness:                  executable
safe for funds:                                no
```

## Start here

1. `V0241_CHECKPOINT.md`
2. `REPRODUCE.md`
3. `results/v0241_reproducibility.json`
4. `results/v0241_security_qualification.json`
5. `results/v0241_independent_verification.json`
6. `docs/56_V024_SECURITY_QUALIFICATION.md`
7. `src/ranklock/authorized_labels.py`
8. `src/ranklock/adaptive_sealing.py`
9. `src/ranklock/security_qualification.py`
10. `STATUS.json`

## Immediate production milestone

Implement the exact v0.24.1 generator inside an actively secure
`n-1`-corrupt setup protocol and connect its authorization record to a durable,
Bitcoin-enforced one-shot state machine. The acceptance test must include
crash/restart, concurrent use, reorg, alternate context, malformed witness,
timeout and fee/CPFP cases.

Do not use the public deterministic fixture or any single-process fresh fixture
with funds.
