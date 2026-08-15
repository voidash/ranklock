from __future__ import annotations

"""Groth16 rerandomization and density-sound projective-liveness analysis.

For a valid proof ``(A,B,C)`` and public nonzero ``u`` plus arbitrary ``v``:

    A' = u^-1 A
    B' = u B + u v delta
    C' = C + v A

is another valid proof for the same statement.  Because ``A'`` is uniform over nonidentity
G1 when ``u`` is uniform, an A-only malicious projective artifact can be analyzed by the
density of its bad input set.

If ``t`` post-commitment audit points all miss a bad set of density epsilon and ``q``
independent runtime rerandomizations all hit it, the joint failure probability is

    (1-epsilon)^t * epsilon^q.

Its maximum is attained at epsilon=q/(t+q).  For t=q=20 the bound is exactly 2^-40.
This theorem does *not* instantiate the required audit: Embryo/DFB input encodings are
one-time affine encodings, so revealing multiple selected encodings for one live artifact
is unsafe.  A zero-knowledge proof of committed evaluation or a reusable encoding remains
required.
"""

from dataclasses import dataclass
from hashlib import sha256
import math

from .babe_positive_lock import (
    PositiveGroth16Proof,
    PositiveGroth16VerifyingKey,
    verify_positive_groth16,
)
from .bn254_real import CURVE_ORDER, add, compress_g1, compress_g2, decompress_g1, decompress_g2, multiply


class RerandomizationError(ValueError):
    pass


def rerandomize_groth16(
    proof: PositiveGroth16Proof,
    vk: PositiveGroth16VerifyingKey,
    *,
    u: int,
    v: int,
) -> PositiveGroth16Proof:
    u %= CURVE_ORDER
    v %= CURVE_ORDER
    if u == 0:
        raise RerandomizationError("Groth16 rerandomization scalar u must be nonzero")
    inv_u = pow(u, -1, CURVE_ORDER)
    a = decompress_g1(proof.a_g1)
    b = decompress_g2(proof.b_g2)
    c = decompress_g1(proof.c_g1)
    delta = decompress_g2(vk.delta_g2)
    rerand_a = multiply(a, inv_u, group="g1")
    rerand_b = add(
        multiply(b, u, group="g2"),
        multiply(delta, u * v, group="g2"),
        group="g2",
    )
    rerand_c = add(c, multiply(a, v, group="g1"), group="g1")
    return PositiveGroth16Proof(
        compress_g1(rerand_a),
        compress_g2(rerand_b),
        compress_g1(rerand_c),
    )


def derive_rerandomization(beacon: bytes, attempt: int) -> tuple[int, int]:
    beacon = bytes(beacon)
    if not beacon:
        raise RerandomizationError("rerandomization beacon is empty")

    def scalar(label: bytes, *, nonzero: bool) -> int:
        for counter in range(2**32):
            value = int.from_bytes(
                sha256(
                    b"ranklock/groth16-rerandomization/v1\x00"
                    + len(beacon).to_bytes(4, "big")
                    + beacon
                    + attempt.to_bytes(8, "big")
                    + label
                    + counter.to_bytes(4, "big")
                ).digest(),
                "big",
            ) % CURVE_ORDER
            if value or not nonzero:
                return value
        raise RerandomizationError("hash-to-scalar exhausted")

    return scalar(b"u", nonzero=True), scalar(b"v", nonzero=False)


@dataclass(frozen=True, slots=True)
class DensityAuditParameters:
    audit_queries: int
    runtime_attempts: int
    schema: str = "ranklock-density-audit-parameters-v1"

    def __post_init__(self) -> None:
        if self.audit_queries <= 0 or self.runtime_attempts <= 0:
            raise RerandomizationError("audit/runtime counts must be positive")

    @property
    def worst_case_bad_density(self) -> float:
        return self.runtime_attempts / (self.audit_queries + self.runtime_attempts)

    @property
    def joint_audit_and_runtime_failure_upper_bound(self) -> float:
        t, q = self.audit_queries, self.runtime_attempts
        epsilon = q / (t + q)
        return (1.0 - epsilon) ** t * epsilon**q

    @property
    def combined_failure_upper_bound(self) -> float:
        return self.joint_audit_and_runtime_failure_upper_bound

    @property
    def soundness_bits(self) -> float:
        return -math.log2(self.combined_failure_upper_bound)

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "audit_queries": self.audit_queries,
            "runtime_attempts": self.runtime_attempts,
            "worst_case_bad_density": self.worst_case_bad_density,
            "joint_failure_upper_bound": self.combined_failure_upper_bound,
            "soundness_bits": self.soundness_bits,
        }


def balanced_density_parameters(target_bits: int) -> DensityAuditParameters:
    if target_bits <= 0:
        raise RerandomizationError("target soundness must be positive")
    # With t=q=n the exact maximum is 2^(-2n).
    n = (target_bits + 1) // 2
    return DensityAuditParameters(n, n)


def rerandomized_liveness_checkpoint() -> dict[str, object]:
    parameters = balanced_density_parameters(40)
    return {
        "schema": "ranklock-rerandomized-projective-liveness-checkpoint-v1",
        "groth16_public_rerandomization_implemented": True,
        "artifact_interface_restricted_to_A_only": True,
        "joint_density_bound": parameters.document(),
        "forty_bit_balanced_schedule": {
            "audit_queries": parameters.audit_queries,
            "runtime_attempts": parameters.runtime_attempts,
        },
        "one_time_affine_encoding_reuse_safe": False,
        "zero_knowledge_committed_evaluation_audit_required": True,
        "multiple_runtime_encodings_for_one_live_artifact_instantiated": False,
        "assumptions": [
            "artifact is committed before independent audit/runtime beacons",
            "artifact evaluation is deterministic and depends only on canonical A",
            "audit and runtime A values are independent uniform rerandomizations",
            "audit relation is proven without revealing reusable affine labels",
        ],
        "decision": "PROMISING_DENSITY_THEOREM_AUDIT_AND_MULTI_QUERY_ENCODING_OPEN",
        "breakthrough_target_met": False,
    }
