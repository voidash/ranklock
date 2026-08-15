# 54 — RankLock v0.22.1 security audit

**Date:** 2026-08-11  
**Scope:** the v0.22 real DFB/Embryo implementation, not the full RankLock protocol.

## Executive verdict

v0.22 established a valuable **correctness and serialization milestone**, but its
artifact did not instantiate the privacy theorem claimed by Duty-Free Bits.  The
first audit pass found two concrete mismatches:

1. the port omitted the `mu * p` statistical smudging required by DFB Theorem 5.2;
2. the x- and y-coordinate switch systems reused one Free-XOR delta and the same
   nonce schedule, although DFB defines legal CCRH queries as nonce-unique and
   Theorem 5.3 applies the affine garbling independently per input component.

Both of those implementation mismatches are corrected in this checkpoint.  The
90-prime BN254 fixture now uses per-component statistical lifting, independent
coordinate deltas, disjoint coordinate nonce namespaces, and an explicit
canonical-field range check.

A deeper pass then found a third, still-open mismatch: the reference-compatible
body sampler does **not** sample uniformly from each odd CRT group.  Its worst
90-prime case has total-variation distance about 17.16%, while the DFB proof
requires uniform group elements.  Consequently, v0.22.1 is still a correctness
and security-audit fixture—not a selective-security implementation.

This also does **not** make RankLock secure or production ready.  The decisive
remaining gates include uniform body pads, conservative whole-vector statistical
parameters, slot-level nonce separation, adaptive privacy, authenticated
one-label-per-bit Bitcoin release, one-shot enforcement, active malicious MPC
generation, two-instance same-scalar composition, output-mask fusion, and
end-to-end Bitcoin transaction-graph validation.

## Finding RL-SEC-001 — missing statistical smudging

**Original severity:** critical  
**Status in v0.22.1:** corrected for the executable fixture

DFB lifts an affine map over `F_p` into the CRT ring `Z_M`.  The raw integer
`a*x+b` exposes its quotient by `p`; the theorem therefore samples `mu` and uses

```text
b' = b + mu*p
```

before CRT garbling.  The original v0.22 port reduced `a` and `b` directly modulo
each small CRT prime and reconstructed the unsmudged integer.  This means its
correctness result was real, but the selective privacy theorem did not apply.

The v0.22.1 generator now:

- verifies `M >= p^2 * 2^rho`;
- samples an independent `mu` for every affine output;
- garbles `b + mu*p` over the CRT primes;
- rejects noncanonical target-field inputs;
- reconstructs the integer lift and only then reduces modulo BN254.

### Concrete parameter correction

For the BN254 base field:

```text
first 80 primes: 44 full statistical bits
first 90 primes: 132 full statistical bits
fixture target:  128 bits
```

The paper's 80-prime concrete profile is therefore compatible with a roughly
40-bit statistical setting, but not a 128-bit statistical setting for this exact
field modulus.

## Finding RL-SEC-002 — cross-coordinate CCRH reuse

**Original severity:** critical/high  
**Status in v0.22.1:** corrected

The v0.22 generator sampled a single global delta and called the x and y affine
systems with identical nonce layouts.  Consequently, the combined execution
issued repeated nonce identifiers under one fixed CCRH construction.  This is
outside the paper's legal-query condition and outside the component-wise
independent composition described by Theorem 5.3.

v0.22.1 now assigns each coordinate:

- a fresh 128-bit Free-XOR delta;
- a disjoint `2^48` nonce namespace;
- independently sampled input masks and statistical masks.

This correction has no serialized-size cost.

## Finding RL-SEC-003 — adaptive privacy remains unproved

**Severity:** critical  
**Status:** open

The DFB paper explicitly defines its main privacy notion selectively: the input
is independent of the public garbled program.  RankLock publishes the artifact
first and learns the Bitcoin proof input later.  That requires an adaptive,
auxiliary-input theorem for the exact switch system.

The paper mentions a generic adaptive transform that encrypts the garbled program
and sends a key online.  That does not satisfy RankLock's no-online-authority
requirement.  Adaptive results for Half-Gates and tri-state circuits are useful
proof templates, but they do not automatically prove this distinct DFB switch
system.

Required target:

```text
adaptive + arbitrary auxiliary input + q=2 independent instances
+ same hidden scalar + authenticated labels + abort/replay semantics
```

Until this theorem or a replacement construction is complete, the security flag
must remain false.

## Finding RL-SEC-004 — authenticated one-label-per-bit release is absent

**Severity:** critical  
**Status:** open

The executable evaluator accepts label byte strings.  It does not prove that the
Bitcoin transaction released exactly one valid label for every canonical input
bit, nor that labels are bound to the exact game, deposit, proof, operator, slot,
and transaction.

The existing `BoundedSlotLedger` models burn-before-evaluate semantics, but it is
not wired into the real DFB evaluator or enforced by Bitcoin consensus.  The real
system still needs:

- canonical BN254 parsing before label release;
- one label per bit, never both;
- slot/game/deposit/transaction domain separation;
- burn on malformed input, crash, abort, and timeout;
- reorg and cross-fork analysis;
- Bitcoin Core regtest execution.

## Finding RL-SEC-005 — malicious setup is modeled, not executed

**Severity:** critical  
**Status:** open

DFB privacy assumes a correctly generated garbling.  RankLock additionally needs
correct generation when all but one ceremony participant are malicious and no
participant remains online.  v0.21/v0.22 model signed activation and an active-MPC
ideal guarantee, but the exact DFB/Embryo generator has not been executed inside
an actively secure dishonest-majority MPC.

A concrete implementation must show that a corrupt majority can abort but cannot:

- bias or reuse deltas, nonces, `mu` masks, PRF keys, or Embryo masks;
- publish malformed affine coefficients;
- activate a program different from the one signed by the honest participant;
- retain a trapdoor that distinguishes future inputs or recovers the fault key.

## Finding RL-SEC-006 — two-instance same-scalar composition is open

**Severity:** high/critical  
**Status:** open

Independent tapes remove the obvious correlation bug, but they are not themselves
a composition proof.  The adversary receives two programs tied to the same hidden
scalar and may choose the second input after seeing the first transcript and its
auxiliary Bitcoin state.  A hybrid proof must show that this shared high-level
secret does not invalidate simulation.

## Finding RL-SEC-007 — exceptional elliptic-curve inputs

**Severity:** medium/high  
**Status:** open proof/engineering obligation

The conditional-addition polynomial from DFB Appendix B is stated for
`input_x != phi_x`.  The fixture deliberately searches for a nonexceptional
point.  A direct test at `input = phi` returns an incorrect conditional map.
For fixed hidden masks and an independently sampled input the collision probability
is negligible (at most about `256/p`), but adaptive inputs, retries, and public
failure behavior require explicit treatment.

The protocol needs either:

- a complete addition formula with the same low-degree/size properties;
- a setup-time argument that the hidden exceptional set cannot be targeted;
- or a failure path proved not to leak and compatible with one-shot Bitcoin use.

## Finding RL-SEC-008 — deterministic fixture is not secret

**Severity:** informational for tests; critical if deployed unchanged

The fixture intentionally uses public deterministic seeds and publishes its hidden
scalar.  It exists to reproduce bytes and correctness.  It must never be used as
a funded artifact.  Production generation requires entropy contributed by the
active MPC ceremony and an auditable derivation transcript.

## Finding RL-SEC-009 — side channels and implementation hardening

**Severity:** high for production  
**Status:** open

The Python BN254, PRF, big-integer, and parsing paths are variable-time and
unaudited.  The portable AES path in the reference implementation is also not a
production constant-time target.  None of this affects the deterministic
correctness experiment; all of it matters for ceremony participants and any
machine holding secret setup state.

## Finding RL-SEC-010 — nonuniform finite-field body pads

**Severity:** critical for a privacy claim  
**Status:** open

The DFB proof requires hash output used on non-control-friendly wires to sample a
**uniform group element**.  The current reference-compatible implementation instead
slices `w = ceil(log2 p)` rounded to a nibble and later reduces the raw value modulo
the small CRT prime.  For odd `p`, this is generally biased.

For the 90-prime profile the worst case is `p = 181`, `w = 8`:

```text
256 = 1 * 181 + 75
75 residues have two preimages
106 residues have one preimage
total-variation distance from uniform: 0.1715728591 (17.16%)
```

The evaluator's view exposes `a + pad_hot mod p`, so the hidden pad must satisfy
the paper's uniform-group requirement.  This bias is not a cosmetic benchmark
issue and is nowhere near a 128-bit error.  A faithful implementation needs exact
rejection sampling or another proved uniform hash-to-`Z_p` map.  That changes hash
work and artifact bytes, so the existing deterministic artifact remains correctness
evidence only.

## Finding RL-SEC-011 — whole-vector statistical accounting

**Severity:** medium/high for concrete claims  
**Status:** accounting corrected; stronger profile not yet executed

The 90-prime primorial provides 132 full smudging bits for one affine-output
component.  A conservative hybrid over two slots and all `2 * 3,077 = 6,154`
components loses `log2(6154) ~= 12.59` bits, giving an upper-bound frontier of
about **119.4 bits**, not 128 bits, even when using all 132 available bits.

For a conservative 128-bit whole-q=2 bound, use at least the first 91 primes
(largest 467), which supports 141 full bits.  Exact join accounting becomes:

```text
one 91-prime join program:                 514,257 bytes
q=2 join programs + 748-byte manifest:   1,029,262 bytes
remaining below one MiB:                    19,314 bytes
```

This is an accounting result, not an executed 91-prime artifact.

## Finding RL-SEC-012 — nonce separation must extend across slots

**Severity:** critical for q=2  
**Status:** open

v0.22.1 separates x and y inside one artifact, but two independently generated
slots still need a slot-level nonce/domain prefix.  Resetting the same fixed-key
CCRH nonce schedule in slot 2 puts the joint transcript outside the paper's legal
query condition, which forbids repeated nonce identifiers.  The signed manifest
must bind a unique slot namespace and the evaluator must derive every nonce from
that namespace.  Independent randomness alone is not a substitute for this domain
separation.

## Finding RL-SEC-013 — random-oracle/PRF instantiation boundary

**Severity:** medium/high  
**Status:** open hardening/proof obligation

The Embryo paper assumes both a random oracle and a secure PRF.  The Python fixture
uses domain-separated SHA-256 directly for both roles.  This is a reasonable
deterministic research heuristic, but it is not a separately analyzed standard-model
PRF instantiation.  A production design should select a conventional keyed PRF,
define exact domains and encodings, and include it in the proof and MPC circuit.

## Corrected storage frontier

The **executed 90-prime correction profile** produces the following bytes.  It
supports 132 full smudging bits per affine component, but it is not a faithful
privacy instantiation because uniform body pads, whole-vector accounting, and
slot-level nonce separation remain unresolved.

```text
one 90-prime join program:              508,395 bytes
one standalone decode state:            262,699 bytes
one standalone artifact:                771,094 bytes

q=2 join programs + 748-byte manifest: 1,017,538 bytes
remaining below one MiB:                  31,038 bytes

q=2 standalone + manifest:             1,542,936 bytes
over one MiB:                             494,360 bytes
```

For the conservative 128-bit whole-`q=2` statistical target identified in
RL-SEC-011, the 91-prime accounting leaves only **19,314 bytes** below one MiB.
That 91-prime profile has not yet been executed, and neither margin includes the
cost of a uniform hash-to-`Z_p` repair, BABE, authenticated Bitcoin label release,
or the transaction graph.  The former 148,270-byte margin applied only to the
80-prime/44-bit profile.

## What is now established

- exact DFB join generation, canonical serialization and parsing;
- real late-bound x/y input labels;
- real CRT evaluation and final Embryo `[r]A` correctness;
- DFB Theorem-5.2-style integer lifting with a 90-prime smudging domain;
- independent x/y deltas and nonce namespaces;
- exact 90-prime execution accounting and 91-prime whole-`q=2` target accounting;
- focused tests for smudging, range rejection, component independence, parser
  behavior, and arithmetic correctness.

## What is not established

- uniform hash-to-`Z_p` body pads matching the DFB proof;
- conservative 128-bit whole-q=2 statistical distance;
- slot-level nonce domain separation;
- adaptive DFB privacy;
- malicious active-MPC generation of this exact artifact;
- authenticated Bitcoin label release;
- one-shot enforcement under reorgs and aborts;
- q=2 same-scalar composition;
- sound output-mask fusion;
- complete exceptional-point handling;
- end-to-end BABE/Groth16 security;
- Bitcoin Core regtest or production readiness.

## Decision

```text
REAL EXECUTION:                         PASS
SELECTIVE DFB INSTANTIATION MATCH:      FAIL (NONUNIFORM BODY PADS)
90-PRIME PER-COMPONENT SMUDGING:         132-BIT FRONTIER
WHOLE-Q=2 128-BIT STATISTICAL TARGET:    FAIL (ABOUT 119.4-BIT BOUND)
ADAPTIVE PRIVACY:                       OPEN
MALICIOUS SETUP:                        OPEN
BITCOIN INPUT AUTHENTICATION:           OPEN
Q=2 COMPOSITION:                        OPEN
SUB-MIB COMPLETE ARTIFACT:              FAIL
PRODUCTION / TEAM ANNOUNCEMENT CLAIM:   RESEARCH MILESTONE ONLY
```
