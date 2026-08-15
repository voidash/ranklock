from __future__ import annotations

"""Public certification layer for Embryo's private scalar multiplication.

For public ``A``, public ``[r]delta`` and claimed output ``Z``, the equation

    e(Z, delta) = e(A, [r]delta)

certifies that ``Z=[r]A`` in the prime-order BN254 source group.  This prevents a
malicious projective artifact from returning an undetected *wrong* point.  It cannot
force a malformed or selectively aborting artifact to produce an output, so setup
liveness still needs proof-carrying generation, cut-and-choose, or another mechanism.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Iterable

from .babe_positive_lock import PositiveGroth16Proof, PositiveGroth16VerifyingKey
from .bn254_real import (
    CURVE_ORDER,
    FQ12,
    G1,
    compress_g1,
    decompress_g1,
    decompress_g2,
    multiply,
    neg,
    pairing_product,
)


class ProjectiveFailure(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ScalarOutputCertificate:
    input_a_g1: bytes
    output_r_a_g1: bytes
    delta_g2: bytes
    r_delta_g2: bytes
    schema: str = "ranklock-scalar-output-certificate-v1"

    def verify(self) -> bool:
        try:
            residual = pairing_product(
                (
                    (decompress_g1(self.output_r_a_g1), decompress_g2(self.delta_g2)),
                    (neg(decompress_g1(self.input_a_g1)), decompress_g2(self.r_delta_g2)),
                )
            )
            return residual == FQ12.one()
        except (ValueError, ZeroDivisionError, OverflowError):
            return False


@dataclass(frozen=True, slots=True)
class CertifiedEvaluation:
    output_r_a_g1: bytes
    certificate: ScalarOutputCertificate
    schema: str = "ranklock-certified-projective-evaluation-v1"

    def __post_init__(self) -> None:
        if self.output_r_a_g1 != self.certificate.output_r_a_g1:
            raise ProjectiveFailure("certificate/output split brain")
        if not self.certificate.verify():
            raise ProjectiveFailure("projective scalar output is invalid")


Evaluator = Callable[[bytes], bytes | None]


def evaluate_and_certify(
    evaluator: Evaluator,
    *,
    input_a_g1: bytes,
    vk: PositiveGroth16VerifyingKey,
    r_delta_g2: bytes,
) -> CertifiedEvaluation:
    try:
        output = evaluator(bytes(input_a_g1))
    except Exception as exc:  # noqa: BLE001 - fail-closed boundary
        raise ProjectiveFailure("projective evaluator raised an exception") from exc
    if output is None:
        raise ProjectiveFailure("projective evaluator produced no output")
    certificate = ScalarOutputCertificate(
        input_a_g1=bytes(input_a_g1),
        output_r_a_g1=bytes(output),
        delta_g2=vk.delta_g2,
        r_delta_g2=bytes(r_delta_g2),
    )
    return CertifiedEvaluation(bytes(output), certificate)


@dataclass(slots=True)
class HonestScalarEvaluator:
    scale: int

    def __call__(self, input_a_g1: bytes) -> bytes:
        scale = self.scale % CURVE_ORDER
        if scale == 0:
            raise ProjectiveFailure("zero scale")
        return compress_g1(multiply(decompress_g1(input_a_g1), scale, group="g1"))


@dataclass(slots=True)
class SparseFaultEvaluator:
    """Evaluator correct except on an explicitly chosen sparse set of A encodings."""

    scale: int
    bad_inputs: frozenset[bytes]
    fault_mode: str = "abort"

    def __call__(self, input_a_g1: bytes) -> bytes | None:
        input_a_g1 = bytes(input_a_g1)
        if input_a_g1 in self.bad_inputs:
            if self.fault_mode == "abort":
                return None
            if self.fault_mode == "wrong":
                return compress_g1(multiply(G1, 1, group="g1"))
            if self.fault_mode == "malformed":
                return b"\xff" * 32
            raise ProjectiveFailure("unknown sparse-fault mode")
        return HonestScalarEvaluator(self.scale)(input_a_g1)


def black_box_probe(
    evaluator: Evaluator,
    probe_inputs: Iterable[bytes],
    *,
    vk: PositiveGroth16VerifyingKey,
    r_delta_g2: bytes,
) -> tuple[int, int]:
    total = passed = 0
    for input_a in probe_inputs:
        total += 1
        try:
            evaluate_and_certify(
                evaluator,
                input_a_g1=input_a,
                vk=vk,
                r_delta_g2=r_delta_g2,
            )
            passed += 1
        except ProjectiveFailure:
            pass
    return passed, total


def self_certifying_embryo_checkpoint() -> dict[str, object]:
    return {
        "schema": "ranklock-self-certifying-embryo-checkpoint-v1",
        "public_certificate": "e(Z, delta) == e(A, r_delta)",
        "wrong_output_detected": True,
        "malformed_output_detected": True,
        "selective_abort_prevented": False,
        "finite_black_box_probes_imply_universal_correctness": False,
        "remaining_requirement": (
            "prove committed artifact generation/evaluation, or otherwise prevent selective abort"
        ),
        "breakthrough_target_met": False,
    }
