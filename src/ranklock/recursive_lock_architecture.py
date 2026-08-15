from __future__ import annotations

"""Executable architecture certificate for the RankLock recursive-lock route.

The large RankVM relation is moved into a transparent BLS12-381-Fr
STARK/FRI proof.  A small Groth16 circuit over the same scalar field verifies
that transparent proof.  The final object is a constant-size pairing product
equation (PPE), and the only future public statement is a 256-bit
domain-separated digest packed into two canonical 128-bit field elements.

This is the architectural breakthrough reduction: the conditional-disclosure
primitive no longer sees the R-row relation.  It sees one Groth16 PPE with two
projective scalars.

The module does *not* implement a production PPE witness-encryption scheme or
a STARK/Groth16 backend.  Those assumptions and implementation gaps are
explicit in every report.
"""

from dataclasses import dataclass
from hashlib import sha256
from math import ceil
from typing import Sequence

from .bls12_381_g1 import BLS12_381_SCALAR_FIELD

MIB = 1 << 20
G1_COMPRESSED_BYTES = 48
G2_COMPRESSED_BYTES = 96
SCALAR_BYTES = 32
CONTEXT_DIGEST_BITS = 256
CONTEXT_LIMB_BITS = 128

# v0.13.2's known 25,889-product field-bridge subtotal.
CURRENT_NATIVE_MULTIPLICATIONS = 129_445
CURRENT_LOGICAL_LOOKUPS = 1_967_564
CURRENT_LINEAR_RELATIONS = 440_113
CURRENT_LOGICAL_EVENTS = (
    CURRENT_NATIVE_MULTIPLICATIONS
    + CURRENT_LOGICAL_LOOKUPS
    + CURRENT_LINEAR_RELATIONS
)


class RecursiveLockError(ValueError):
    pass


def next_power_of_two(value: int) -> int:
    if value <= 0:
        return 1
    return 1 << (value - 1).bit_length()


def two_adicity(value: int) -> int:
    if value <= 0:
        raise RecursiveLockError("two-adicity input must be positive")
    count = 0
    while value & 1 == 0:
        value >>= 1
        count += 1
    return count


def split_context_digest(digest: bytes) -> tuple[int, int]:
    if len(digest) != 32:
        raise RecursiveLockError("context digest must be 32 bytes")
    integer = int.from_bytes(digest, "big")
    high = integer >> CONTEXT_LIMB_BITS
    low = integer & ((1 << CONTEXT_LIMB_BITS) - 1)
    return high, low


def join_context_digest(limbs: Sequence[int]) -> bytes:
    if len(limbs) != 2:
        raise RecursiveLockError("context digest requires two limbs")
    high, low = (int(value) for value in limbs)
    bound = 1 << CONTEXT_LIMB_BITS
    if not 0 <= high < bound or not 0 <= low < bound:
        raise RecursiveLockError("non-canonical context limb")
    return ((high << CONTEXT_LIMB_BITS) | low).to_bytes(32, "big")


def ranklock_context_digest(
    *,
    program_hash: bytes,
    statement: bytes,
    transparent_vk_hash: bytes,
    wrapper_vk_hash: bytes,
    deployment_id: bytes,
) -> bytes:
    fields = (
        (b"program", program_hash),
        (b"statement", statement),
        (b"transparent-vk", transparent_vk_hash),
        (b"wrapper-vk", wrapper_vk_hash),
        (b"deployment", deployment_id),
    )
    digest = sha256(b"ranklock/context/v1\x00")
    for label, value in fields:
        digest.update(len(label).to_bytes(2, "big"))
        digest.update(label)
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.digest()


@dataclass(frozen=True, slots=True)
class TransparentTraceProfile:
    logical_events: int = CURRENT_LOGICAL_EVENTS
    blowup_log2: int = 3
    query_count: int = 48
    folding_arity: int = 4

    def __post_init__(self) -> None:
        if self.logical_events <= 0:
            raise RecursiveLockError("logical event count must be positive")
        if self.blowup_log2 < 0:
            raise RecursiveLockError("negative blowup")
        if self.query_count <= 0:
            raise RecursiveLockError("query count must be positive")
        if self.folding_arity <= 1 or self.folding_arity & (
            self.folding_arity - 1
        ):
            raise RecursiveLockError("folding arity must be a power of two")

    @property
    def trace_rows(self) -> int:
        return next_power_of_two(self.logical_events)

    @property
    def evaluation_domain(self) -> int:
        return self.trace_rows << self.blowup_log2

    @property
    def domain_log2(self) -> int:
        return self.evaluation_domain.bit_length() - 1

    @property
    def fri_layers(self) -> int:
        arity_log2 = self.folding_arity.bit_length() - 1
        return ceil(self.domain_log2 / arity_log2)

    @property
    def field_two_adicity(self) -> int:
        return two_adicity(BLS12_381_SCALAR_FIELD - 1)

    @property
    def radix2_domain_fits(self) -> bool:
        return self.domain_log2 <= self.field_two_adicity

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-transparent-trace-profile-v1",
            "logical_events": self.logical_events,
            "trace_rows": self.trace_rows,
            "blowup_log2": self.blowup_log2,
            "evaluation_domain": self.evaluation_domain,
            "evaluation_domain_log2": self.domain_log2,
            "BLS12_381_Fr_two_adicity": self.field_two_adicity,
            "radix2_domain_fits": self.radix2_domain_fits,
            "query_count_assumption": self.query_count,
            "folding_arity_assumption": self.folding_arity,
            "fri_layers": self.fri_layers,
            "cost_class": {
                "prover_native_field_and_hash": "near-linear / quasilinear in R",
                "verifier_native_field_and_hash": "polylogarithmic in R",
                "prover_group_crypto": "zero for transparent layer",
                "verifier_group_crypto": "zero for transparent layer",
            },
            "measurement_boundary": (
                "Query count, hash arithmetization, physical rows, proof bytes and "
                "timings remain backend measurements; this profile only certifies "
                "field/domain compatibility and asymptotic placement."
            ),
        }


@dataclass(frozen=True, slots=True)
class Groth16PPEKey:
    """Groth16 verifier key represented in pairing-exponent space.

    For group generators g1, g2 and e(g1, g2)=gt, each integer stores the
    corresponding exponent.  This is a formal equation model, not a group
    implementation.
    """

    alpha: int
    beta: int
    gamma: int
    delta: int
    input_coefficients: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.input_coefficients) != 3:
            raise RecursiveLockError(
                "two public inputs require IC_0, IC_1 and IC_2"
            )
        if self.delta % BLS12_381_SCALAR_FIELD == 0:
            raise RecursiveLockError("delta exponent must be nonzero")

    def projective_input(self, public_inputs: Sequence[int]) -> int:
        if len(public_inputs) != 2:
            raise RecursiveLockError("Groth16 wrapper exposes two inputs")
        modulus = BLS12_381_SCALAR_FIELD
        return (
            self.input_coefficients[0]
            + int(public_inputs[0]) * self.input_coefficients[1]
            + int(public_inputs[1]) * self.input_coefficients[2]
        ) % modulus


@dataclass(frozen=True, slots=True)
class Groth16PPEProof:
    a: int
    b: int
    c: int


def groth16_ppe_residual(
    key: Groth16PPEKey,
    public_inputs: Sequence[int],
    proof: Groth16PPEProof,
) -> int:
    """Return zero exactly when the formal Groth16 pairing equation accepts."""

    modulus = BLS12_381_SCALAR_FIELD
    vk_x = key.projective_input(public_inputs)
    return (
        int(proof.a) * int(proof.b)
        - int(key.alpha) * int(key.beta)
        - vk_x * int(key.gamma)
        - int(proof.c) * int(key.delta)
    ) % modulus


def formal_accepting_proof(
    key: Groth16PPEKey,
    public_inputs: Sequence[int],
    *,
    a: int,
    b: int,
) -> Groth16PPEProof:
    """Complete a PPE tuple in the exponent model.

    This helper tests equation composition only.  It is not a Groth16 prover
    and does not imply that a false transparent statement can be proved.
    """

    modulus = BLS12_381_SCALAR_FIELD
    vk_x = key.projective_input(public_inputs)
    numerator = (
        int(a) * int(b)
        - int(key.alpha) * int(key.beta)
        - vk_x * int(key.gamma)
    ) % modulus
    c = numerator * pow(int(key.delta) % modulus, -1, modulus) % modulus
    return Groth16PPEProof(int(a) % modulus, int(b) % modulus, c)


@dataclass(frozen=True, slots=True)
class ProjectiveMaterialBudget:
    cap_bytes: int = MIB
    fixed_protocol_overhead_bytes: int = 64 << 10
    public_scalar_count: int = 2
    conservative_component_bytes: int = G2_COMPRESSED_BYTES

    @property
    def groth16_verifying_key_bytes(self) -> int:
        # alpha in G1, beta/gamma/delta in G2, and IC_0..IC_m in G1.
        return (
            G1_COMPRESSED_BYTES
            + 3 * G2_COMPRESSED_BYTES
            + (self.public_scalar_count + 1) * G1_COMPRESSED_BYTES
        )

    @property
    def available_projective_bytes(self) -> int:
        return (
            self.cap_bytes
            - self.fixed_protocol_overhead_bytes
            - self.groth16_verifying_key_bytes
        )

    @property
    def max_components_per_public_scalar(self) -> int:
        if self.available_projective_bytes < 0:
            return -1
        return self.available_projective_bytes // (
            self.public_scalar_count * self.conservative_component_bytes
        )

    @property
    def max_components_per_digest_bit(self) -> int:
        if self.available_projective_bytes < 0:
            return -1
        return self.available_projective_bytes // (
            CONTEXT_DIGEST_BITS * self.conservative_component_bytes
        )

    def size_for_scalar_projective_lock(
        self, components_per_scalar: int
    ) -> int:
        return (
            self.fixed_protocol_overhead_bytes
            + self.groth16_verifying_key_bytes
            + self.public_scalar_count
            * int(components_per_scalar)
            * self.conservative_component_bytes
        )

    def size_for_bit_projective_fallback(
        self, components_per_bit: int
    ) -> int:
        return (
            self.fixed_protocol_overhead_bytes
            + self.groth16_verifying_key_bytes
            + CONTEXT_DIGEST_BITS
            * int(components_per_bit)
            * self.conservative_component_bytes
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-projective-material-budget-v1",
            "cap_bytes": self.cap_bytes,
            "fixed_protocol_overhead_bytes": self.fixed_protocol_overhead_bytes,
            "groth16_verifying_key_bytes": self.groth16_verifying_key_bytes,
            "public_scalar_count": self.public_scalar_count,
            "conservative_component_bytes": self.conservative_component_bytes,
            "available_projective_bytes": self.available_projective_bytes,
            "max_components_per_public_scalar": (
                self.max_components_per_public_scalar
            ),
            "max_components_per_digest_bit_fallback": (
                self.max_components_per_digest_bit
            ),
            "example_scalar_projective_1024_components_each_bytes": (
                self.size_for_scalar_projective_lock(1024)
            ),
            "example_bit_projective_32_components_each_bytes": (
                self.size_for_bit_projective_fallback(32)
            ),
            "examples_fit_cap": {
                "scalar_projective_1024_each": (
                    self.size_for_scalar_projective_lock(1024)
                    <= self.cap_bytes
                ),
                "bit_projective_32_each": (
                    self.size_for_bit_projective_fallback(32)
                    <= self.cap_bytes
                ),
            },
        }


@dataclass(frozen=True, slots=True)
class RouteDecision:
    name: str
    proof_size: str
    native_work: str
    expensive_group_work: str
    retained_or_static_material: str
    conditional_release: str
    decision: str
    reason: str

    def document(self) -> dict[str, str]:
        return {
            "name": self.name,
            "proof_size": self.proof_size,
            "native_work": self.native_work,
            "expensive_group_work": self.expensive_group_work,
            "retained_or_static_material": self.retained_or_static_material,
            "conditional_release": self.conditional_release,
            "decision": self.decision,
            "reason": self.reason,
        }


def architectural_breakthrough_report() -> dict[str, object]:
    trace = TransparentTraceProfile()
    budget = ProjectiveMaterialBudget()
    routes = (
        RouteDecision(
            "direct KZG over full relation",
            "constant/logarithmic",
            "linear field arithmetic",
            "Theta(R) prover MSM",
            "at least relation-sized proving material",
            "pairing equation available",
            "KILL",
            "moves the width bottleneck into linear group work",
        ),
        RouteDecision(
            "direct IPA over full R1CS",
            "logarithmic",
            "linear sparse-matrix projection",
            "Theta(R) prover and verifier generator MSM",
            "Theta(R) generator vector or derivation",
            "inner-product equation available",
            "KILL",
            "real binding negative control still has two linear verifier walls",
        ),
        RouteDecision(
            "transparent STARK/FRI only",
            "polylogarithmic",
            "near-linear prover; polylog verifier",
            "none",
            "polylog verifier data",
            "missing",
            "INCOMPLETE",
            "solves proof width but does not release the locked secret",
        ),
        RouteDecision(
            "STARK/FRI -> Groth16(BLS12-381) -> projective PPE lock",
            "polylog transparent proof plus 192-byte wrapper proof",
            "near-linear transparent prover; polylog wrapper circuit",
            "polylog(R) wrapper proving work; constant final verifier pairings",
            "polylog wrapper key plus constant-width projective PPE material",
            "one constant-size PPE with two projective context scalars",
            "SELECT UNDER EXPLICIT PPE-CD ASSUMPTION",
            (
                "the conditional mechanism sees only a constant-size wrapper "
                "equation; relation width remains in native field/hash work"
            ),
        ),
    )
    return {
        "schema": "ranklock-recursive-lock-breakthrough-v1",
        "status": "ARCHITECTURAL_BREAKTHROUGH_REDUCTION",
        "breakthrough_statement": (
            "Compress the full RankVM relation with a transparent proof over "
            "BLS12-381 Fr, recursively verify it in Groth16 over BLS12-381, "
            "and lock against the resulting PPE.  Hash the entire future "
            "statement into two canonical 128-bit public scalars.  The lock "
            "width is therefore two, not R."
        ),
        "field_alignment": {
            "transparent_field": "BLS12-381 Fr",
            "wrapper_curve": "BLS12-381",
            "wrapper_circuit_field": "BLS12-381 Fr",
            "final_predicate": "BLS12-381 Groth16 pairing product equation",
            "two_adicity": trace.field_two_adicity,
            "current_domain_log2": trace.domain_log2,
            "current_domain_fits": trace.radix2_domain_fits,
        },
        "current_trace_profile": trace.document(),
        "projective_material_budget": budget.document(),
        "route_decisions": [route.document() for route in routes],
        "target_check": {
            "public_cold_start": True,
            "online_authority": False,
            "large_relation_native_work": "near-linear / quasilinear",
            "large_relation_group_work": "none in transparent layer",
            "recursive_group_work": "polylogarithmic in R",
            "final_pairing_verifier": "constant-size PPE",
            "future_projective_coordinates": 2,
            "projective_material_under_one_MiB": (
                budget.size_for_scalar_projective_lock(1024) <= MIB
            ),
        },
        "remaining_assumptions_and_gaps": [
            (
                "instantiate a maliciously secure projective conditional-"
                "disclosure or witness-encryption primitive for the Groth16 PPE"
            ),
            (
                "implement and benchmark the BLS12-381-Fr transparent proof "
                "and its Groth16 verifier circuit"
            ),
            (
                "run verifiable distributed setup for the wrapper and lock, "
                "with n-1 corrupt-party secrecy and abort handling"
            ),
            (
                "prove end-to-end context binding, simulation/extractability "
                "and selective-failure resistance"
            ),
        ],
        "claim_boundary": (
            "The relation-width bottleneck is removed at the architecture "
            "level.  This report is not a production-security claim and does "
            "not claim an implemented PPE witness-encryption primitive."
        ),
    }
