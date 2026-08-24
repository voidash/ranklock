# Claims and Evidence Policy

## v0.26 funds-safety research claim boundary

### Supported

- “The deployed v0.25 validity-first graph is unsafe under one shared N-of-N
  release withholder; an executable Rust analyzer produces the owner-payout/no-
  slash counterexample.”
- “An EXACT Python model checks the strict shared-selection value/conflict
  topology and remains non-authorizing.”
- “The same abstract model enumerates five maximal local traces and seven
  semantic worlds for its two-alternative fixture, binds both no-ACK worlds to
  the same timeout trace, and assigns every counterproof reserve in every
  branch without calling that a protected-value theorem.”
- “A side-by-side Rust research slice implements typed `C/P/S/R/L`
  connectors, six exact transaction templates, and a private-field
  `V026Graph` assembler with an independently reconstructed transaction
  projection and spender matrix.”
- “Six real Bitcoin Core cases independently accept both counterproof
  alternatives, the mature owner branch, ACK, first-valid CSV timeout, and an
  ACK-descended Slash; reproduce their intended shared-input conflicts; and
  show that the measured 10,690-WU counterproof requires a confirmed Contest
  parent under the tested v3 policy.”
- “A valid competing live-key stake spend is accepted and prevents Slash;
  stake exclusivity is not established.”
- “The assembler retains sixteen activation blockers and always reports
  `funding_eligible = false`.”
- “The frozen `StructurallyVerifiedFundingBlockedV1` observation remains
  byte-compatible for the historical fifteen-blocker profile. A separate
  `StructurallyVerifiedFundingBlockedV2` lane persists the current exact
  sixteen-blocker set and local txid manifest; neither exposes active admission.
  Their codecs and pure replay/conflict classifiers are reproduced, while live
  FoundationDB execution is unverified.”
- “The threshold-v3 graph and its live admission path each carry seventeen
  activation blockers — the sixteen-blocker set plus
  `threshold-ack-witness-adoption-unimplemented`.”
- “A separate `V026AdmissionRowSpecV3` lane persists the seventeen-blocker
  observation in its own FoundationDB subspace, keyed by the content-derived
  funded-setup digest rather than a `GraphIdx`. The frozen fifteen-blocker V1
  and sixteen-blocker V2 bytes are unchanged and are not read by the V3
  decoder, which refuses every other envelope version. Its codec, key packing,
  and fail-closed negatives are reproduced. The row is inert and exposes no
  active admission.”
- “The V3 observation read path executes against a real FoundationDB: the
  `v026_admissions_v3` subspace opens, the 32-byte digest key addresses a row,
  and an absent key returns `None`. The complete `strata-bridge-db` suite passes
  live at 69 tests under the default parallel harness, reproduced across
  repeated runs. No v0.26 observation of any version has been
  durably written and read back live, because no test constructs a
  `StructurallyVerifiedFundingBlocked*`; the V1, V2 and V3 observation tests
  remain pure codec and classifier tests. See
  `61_LOCAL_FOUNDATIONDB_FOR_V026_ROW_TESTS.md`.”
- “The subject-bound counterproof research slice pins a versioned SP1 verifier,
  binds the receipt to the exact BridgeProof transaction id, and exposes a
  non-serializable, non-cloneable, point-in-time Bitcoin Core confirmation
  capability. Two real-Core regressions cover mempool/depth/reorg rejection and
  same-txid/different-witness rejection.”
- “One valid production Groth16 receipt exists. A fulfilled Succinct reserved
  request was recovered offline, imported without a host round trip, and
  verified by `SubjectBoundSp1Groth16VerifierV1` against the pinned program id
  and SP1 circuit version `v6.1.0`. The receipt is persisted and re-verifies on
  reload. No runtime path consumes it and funding remains disabled.”
- “A fail-closed executor helper compares every receipt-authenticated ACK field
  and the witness-stripped finalized transaction, rechecks Bitcoin before and
  after selected-commitment witness CAS, accepts only exact create/replay, and
  rejects conflicts. Two pure regressions cover binding and outcome handling;
  no valid receipt exercises the composed path and no runtime duty enforces it.”

### Not supported

Do not say:

- “RankLock v0.26 is safe for funds.”
- “The v0.26 graph is integrated into runtime admission, P2P, persistence, or
  bridge duties.”
- “The research NUMS roles or output indices are the canonical wire profile.”
- “All exact graph signatures were presigned and one honest share, nonce tree,
  derivation path, and every backup were erased.”
- “Stake is exclusively reserved, the Slash-v2 ASM profile is activated, or
  fee-package/reorg liveness is qualified.”
- “The valid-plus-withholding and invalid-plus-absent timeout worlds have been
  economically reconciled.”
- “Local pairwise conflicts prove terminal wealth preservation.”
- “`AbstractDeclaredPolicySatisfiedV1` is a protected-value theorem.” It is
  only a result over caller-declared policy inputs, always carries four
  qualification blockers, and cannot authorize funds.
- “The subject-bound counterproof is positively verified end to end.” A valid
  production receipt now verifies standalone, which closes only the
  deterministic final Groth16 execution/verification evidence gate. Runtime
  consumption, canonical-chain binding, economic qualification, and ceremony
  remain open, so end-to-end verification is not established.
- “The threshold runtime consumes the canonical-chain confirmation capability.”
  No release, ACK, admission, P2P, or funding path consumes it.
- “The confirmed ACK CAS helper is the only way to write an ACK witness.” The
  lower-level store remains independently callable and its durable row is an
  inert value, not receipt or chain authority.
- “Receipt verification plus chain confirmation is sufficient to fund.” Setup
  authority, versioned runtime integration, deterministic final proof
  qualification, presign/erasure, and the remaining graph/economic blockers
  are still open.

### Required wording

Call `results/v026_timeout_economics.json` **EXACT abstract graph and terminal-policy evidence** and
`results/v026_rust_graph_core.json` **REPRODUCED research graph/Core evidence**.
Call `results/v026_threshold_graph_v3_admission_gap.json` **REPRODUCED
threshold-v3 blocker and persistence-gap evidence**, and
`results/v026_subject_bound_sp1_network_receipt_recovery.json` **EXACT
network-receipt recovery evidence**. State that all four are non-authorizing and
that safe-for-funds remains false.

## v0.22 current claim boundary

### Supported

- “RankLock contains a real, full-dimension Duty-Free-Bits affine-switch execution pinned to `alpenlabs/duty-free-bits@e2b45be8ceaea0d51e4e7a9ef862b91b59ff255e`.”
- “The canonical join payload is 449,779 bytes and has SHA-256 `7e6d94ced9b0d663c32941f2687e90e4f7629b370044b298eadfbde1690540e0`.”
- “Standalone decoding requires a separately serialized 228,083-byte final output-mask state under the implemented interface.”
- “The emitted 677,862-byte standalone bundle, when reparsed and combined with future input-label files, reproduces all 3,077 Embryo outputs and the final BN254 point `[r]A`.”
- “All 256 conditional Jacobian maps and the five-element curve check pass in the deterministic fixture.”
- “The source suite passes 285 tests across 75 independently executed files.”
- “Two join payloads plus the historical 748-byte manifest fit in 900,306 bytes, but two standalone bundles require 1,356,472 bytes.”
- “The breakthrough target remains unmet.”

### Not supported

Do not say:

- “The 449,779-byte join payload is a self-contained public evaluator artifact.”
- “Two complete DFB/Embryo slots fit below one MiB.”
- “The final output masks can be omitted.”
- “Application-level mask fusion is secure.”
- “Adaptive, auxiliary-input, two-instance DFB security is proved.”
- “The active malicious MPC ceremony has been executed.”
- “Authenticated Bitcoin label release, complete BABE bytes, or Bitcoin Core regtest is done.”
- “RankLock is production cryptography or a same-security Strata/Mosaic replacement.”

### Required wording

Use “join payload” for 449,779 bytes, “standalone output-mask state” for 228,083 bytes, and “standalone bundle” for 677,862 bytes. Treat the v0.21 511,219-byte slot and 1,023,186-byte two-slot envelope as historical paper-derived accounting.

> The versioned sections below are retained as historical claim records. Statements such as “DFB is not implemented” apply only to their named snapshots and are superseded by this v0.22 section.

## Claims currently supported

- “RankLock v0.14 is a reproducible research package with 123 passing tests, built on the parallel agent’s validated v0.13.2 field-bridge baseline.”
- “The package contains executable attacks against late-bound AIR, late-bound permutation, split-brain memory composition, known-challenge KZG batching, and unbound dual-field CRT composition.”
- “The corresponding phase/shared-commitment fixes pass in the formal exponent-space KZG model.”
- “BN254-Fq multiplication can be represented exactly with three 85-bit limbs over BLS12-381 Fr.”
- “Fixed-point evaluation/interpolation reduces the 3×85 convolution from nine to five native nonlinear products without adding range lookups in the logical model.”
- “For canonical `x,y,z`, exact integer multiplication needs only a nonnegative 254-bit internal quotient; the quotient's separate `< q` slack proof is redundant in the executable model.”
- “For BN254 Fr × BLS12-381 Fr CRT exactness, 254 quotient bits are certified by the current residual bound, while 255 bits are not certified by that bound.”
- “At the current 25,889-product arithmetic subtotal, the rank-5 model uses 129,445 native multiplication constraints, 1,967,564 logical lookup events, and 440,113 linear relation events before parser, hash, PCS, and conditional-disclosure costs.”
- “The transparent constraint backend reproduces the rank-5, 2×127, and CRT owner-side event inventories and rejects targeted witness tampering.”
- “The 2×127 and dual-field CRT counts are executable arithmetic/constraint models with explicitly unresolved backend or composition costs.”
- “In the formal memory-proof model, delaying AIR openings to the permutation second beacon reduces 72 KZG openings to four safely batched evaluation-point groups after a third value-binding beacon.”
- “The resulting dynamic KZG-WE conjunction uses four formal headers and four decryption pairings; it is not a static lock.”
- “Two reusable standard KZG-WE headers under one randomizer reveal the randomizer base in the algebraic model.”
- “A future input can be lifted into a fixed relation only when cryptographic authentication prevents witness substitution; the package demonstrates both cases.”

- “A formal pairing-friendly candidate compresses 132 selected-byte authentication into one aggregate BLS equation and one inner-product relation; this is a relation model, not a secure LVA-WE instantiation.”
- “Two affine authentication tokens for one coordinate and session reveal the token slope and allow every byte token for that coordinate to be forged in the algebraic model.”

- “The affine input-token interface is a vector-OLE relation; the repository models a one-shot composition and the literal `(lambda+n) log p` leading expression, but does not implement Duty-Free Bits.”
- “Reusing one affine VOLE sender state for two receiver vectors recovers its affine coefficients in the executable model.”

## Claims not supported

Do not say:

- “The breakthrough has been achieved.”
- “The Duty-Free-Bits projective input layer has been implemented or concretely measured in RankLock.”
- “The 8,288-byte leading expression is the actual communication size.”
- “The BLS/inner-product input-authentication candidate already gives a secure or sub-megabyte projective input layer.”
- “RankLock is secure.”
- “RankVM replaces Mosaic.”
- “The artifact is sub-megabyte.”
- “The static conditional lock has been constructed.”
- “The 2025 LVA-WE framework has already been shown to meet RankLock’s complete cost/security target.”
- “The construction has malicious setup security.”
- “The current KZG or KZG-WE model is computationally secure or binding.”
- “The transparent constraint ledger is a proof system.”
- “The full verifier costs 25,889 multiplications.”
- “The complete non-native bridge costs exactly five constraints per Fq multiplication.”
- “The logical lookup count equals physical proof rows.”
- “The dual-field CRT route is sound end to end.”
- “Rank-5 convolution or dual-field non-native arithmetic is new.”
- “The system is ready for funds, testnet deployment, or production.”

## Required wording

Use qualifiers such as:

- “formal exponent-space model”;
- “known arithmetic subtotal”;
- “exact executable witness model”;
- “reproduced transparent constraint trace”;
- “logical tuple/range estimate under a 16-bit chunk model”;
- “upper bound excluding parser/hash/PCS/conditional-disclosure costs”;
- “provisional route decision pending a real backend”;
- “novelty hypothesis pending theorem-level review”;
- “executable research prototype, not a secure implementation.”

## v0.15 supported claims

Accurate:

- “A real 132-byte secp256k1 OT/projective-input execution uses 257,418 public and interactive bytes in the reference online backend.”
- “Actual BN254 KZG-opening witness encryption uses a 112-byte ciphertext in the reference implementation.”
- “Moving future values into the witness of one fixed linear relation removes the post-statement encapsulator and yields a 48-byte ciphertext.”
- “The exact 132-byte plus 64-scalar fixed-linear serialization model is 134,604 bytes after setup-proof batching.”
- “Direct one-coordinate-per-event compilation is killed for the current gadget: 8.27 MiB for multiplication-only and 159.82 MiB for all current logical events.”
- “The breakthrough target remains unmet.”

Inaccurate:

- “Duty-Free Bits VOLE is implemented.” The current backend is an online binary-OT measurement baseline.
- “RankVM invalidity has a static 134 KB lock.” The static trace predicate is toy linear.
- “The recursive Groth16 route is a breakthrough construction.” It is a formal candidate with missing proof and PPE-WE backends.
- “The parallel v0.15 checkpoint passed.” It had two failing tests.
- “Mosaic has been replaced.”

## v0.16 supported claims — historical; superseded where v0.17 differs

Accurate:

- “In the public algebraic source-group model, expanding hidden-scalar verifier bases requires at
  least the public coefficient rank of those bases.”
- “This rank statement is not a universal computational lower bound and does not cover private
  PCG seeds, obfuscation, multilinear maps, or hardware.”
- “A real BN254 low-rank fixed-G2 PPE prototype stores one scaled anchor per coefficient-rank
  direction and decrypts with one pairing per anchor.”
- “The executable 11-term / 2-anchor serialization envelope is 1,719 bytes and two decryption
  pairings.”
- “Changing one future G1 witness element fails decryption, and substituting one scaled anchor
  fails the generalized Schnorr setup proof.”
- “Publishing a satisfying target decomposition over the scaled anchors reveals the lock session
  and breaks secrecy.”
- “A valid common-scalar anchor proof does not prove ciphertext correctness; malicious
  ciphertext/share-consistency activation remains open.”
- “KZG/PLONK-style identity targets and Groth16-style future G2 proof elements are distinct
  blockers for the current lock interface.”
- “The breakthrough target remains unmet.”

Inaccurate:

- “All public correlation generators are impossible.” The result is a scoped algebraic rank
  lower bound.
- “PCGs cannot help RankLock.” They may help distributed setup with private party seeds; they do
  not directly provide one public cold-start seed.
- “RankLock has a 1.7 KB complete invalidity lock.” The 1,719-byte object is an 11-term / 2-anchor
  wrapper-shape envelope with a synthesized relation target.
- “PLONK or KZG directly supplies the conditional lock.” Their usual normalized target is the
  identity and carries no lock entropy.
- “The generalized Schnorr proof gives malicious setup security.” It proves common-scalar anchor
  generation only.
- “The target-separated wrapper has been constructed.” It is the next primary target.


## v0.17 supported claims

Accurate:

- “A real BN254 split-basis PPE prototype shows that identity normalization is not a universal blocker; the load-bearing condition is statement-session separation from the scaled witness-anchor span.”
- “Publishing a setup-scaled statement-side basis can reveal the accepting session without the witness.”
- “A real BN254 one-sided final equation uses only future G1 elements and a rank-two fixed G2 basis.”
- “The reference one-sided proof system itself is not implemented in this repository.”
- “All audited public Fiat–Shamir challenges enter nonlinear prover work, so the existing prover cannot run unchanged with those challenges hidden.”
- “A canonical shared proof object closes an executable transcript/pairing split-brain interface.”
- “The accepting BN254 pairing session can derive a real secp256k1 fault scalar without retaining an encrypted payload.”
- “The exact activation NP relation is executable, but its zero-knowledge proof is not implemented.”
- “Under explicit proxy assumptions, the reference static-plus-future-proof envelope is 1,036,471 bytes, leaving 12,105 bytes below one MiB.”
- “The byte envelope is not a complete cryptographic construction and is killed if the real point/transcript/LVA gadget exceeds its threshold.”
- “The breakthrough target remains unmet.”

Inaccurate:

- “Every identity-target pairing equation is unusable for conditional disclosure.” KZG-opening WE is a counterexample to that rule.
- “The one-sided SNARK is implemented.” Only the final equation and parameterized profile are present.
- “The wrapper is below one MiB in real serialized cryptography.” The result uses planning proxies.
- “The activation problem is solved.” Only the visible NP relation and ceremony state machine are implemented.
- “The derived committee key implements BIP327.” The current aggregation is MuSig-style research code and not claimed BIP327-conformant.
- “RankLock is a production or same-security Mosaic replacement.”
