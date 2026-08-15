from __future__ import annotations

"""Additive-share projectivization with fallback cut-and-choose.

This module isolates a concrete way to make BABE/Embryo compatible with an
n-1-corrupt setup *without* asking one monolithic malicious garbler to know the
aggregate hidden scalar.

For contributor i, let r_i be its private BN254 scalar share and publish
R_i=[r_i]delta in G2.  The aggregate positive-lock scalar is

    r = sum_i r_i mod q,
    [r]delta = sum_i R_i.

A one-shot projective artifact for contributor i maps a future Groth16 A point
onto Z_i=[r_i]A.  Every returned Z_i is publicly certified by

    e(Z_i, delta) = e(A, R_i).

The evaluator sums certified outputs to obtain [r]A.  Hence a corrupt
contributor can reveal or otherwise compromise *its own* r_i without revealing
r as long as one honest r_h remains hidden.  What a corrupt contributor can do
is make its static artifact selectively fail.  We address only that liveness
problem here with commit-then-random-partition cut-and-choose over independent,
one-shot copies.

If N committed copies are partitioned after commitment into t fully opened
(audited) copies and q unopened live fallback copies, then an adversary whose
malformed copies would be rejected when opened can both pass the audit and make
all q live copies malformed only when the live set is exactly its q bad copies.
The worst-case probability is therefore 1/binom(t+q,q).  This is substantially
stronger than treating each copy as an independent 1/2 cut-and-choose trial.

Scope / non-claims:
* This is a combinatorial and algebraic composition theorem, not an Embryo
  implementation.
* It assumes an opened Embryo copy can be checked perfectly against its
  contributor share/generator transcript.
* It assumes each live copy is one-shot and independently encoded.
* It does not by itself prove maliciously secure distributed generation of the
  DFB artifact, Bitcoin graph correctness, or a complete RankLock replacement.
"""

from dataclasses import dataclass
from math import comb, log2
from typing import Iterable

from .babe_positive_lock import PositiveGroth16VerifyingKey
from .bn254_real import (
    CURVE_ORDER,
    FQ12,
    Point,
    add,
    compress_g1,
    compress_g2,
    decompress_g1,
    decompress_g2,
    multiply,
    neg,
    pairing_product,
)


class AdditiveProjectiveError(ValueError):
    pass


def aggregate_g1(encodings: Iterable[bytes]) -> bytes:
    acc: Point | None = None
    for encoded in encodings:
        point = decompress_g1(bytes(encoded))
        acc = point if acc is None else add(acc, point, group="g1")
    if acc is None:
        raise AdditiveProjectiveError("no G1 shares to aggregate")
    return compress_g1(acc)


def aggregate_g2(encodings: Iterable[bytes]) -> bytes:
    acc: Point | None = None
    for encoded in encodings:
        point = decompress_g2(bytes(encoded))
        acc = point if acc is None else add(acc, point, group="g2")
    if acc is None:
        raise AdditiveProjectiveError("no G2 shares to aggregate")
    return compress_g2(acc)


def certify_share_output(
    *,
    input_a_g1: bytes,
    output_r_i_a_g1: bytes,
    delta_g2: bytes,
    r_i_delta_g2: bytes,
) -> bool:
    """Certify Z_i=[r_i]A without revealing r_i."""

    try:
        residual = pairing_product(
            (
                (decompress_g1(output_r_i_a_g1), decompress_g2(delta_g2)),
                (neg(decompress_g1(input_a_g1)), decompress_g2(r_i_delta_g2)),
            )
        )
        return residual == FQ12.one()
    except (ValueError, ZeroDivisionError, OverflowError):
        return False


def aggregate_certified_outputs(
    *,
    input_a_g1: bytes,
    outputs_r_i_a_g1: Iterable[bytes],
    vk: PositiveGroth16VerifyingKey,
    r_i_delta_g2: Iterable[bytes],
) -> tuple[bytes, bytes]:
    outputs = tuple(bytes(value) for value in outputs_r_i_a_g1)
    anchors = tuple(bytes(value) for value in r_i_delta_g2)
    if not outputs or len(outputs) != len(anchors):
        raise AdditiveProjectiveError("share output/anchor count mismatch")
    for output, anchor in zip(outputs, anchors, strict=True):
        if not certify_share_output(
            input_a_g1=input_a_g1,
            output_r_i_a_g1=output,
            delta_g2=vk.delta_g2,
            r_i_delta_g2=anchor,
        ):
            raise AdditiveProjectiveError("projective share failed pairing certification")
    aggregate_output = aggregate_g1(outputs)
    aggregate_anchor = aggregate_g2(anchors)
    if not certify_share_output(
        input_a_g1=input_a_g1,
        output_r_i_a_g1=aggregate_output,
        delta_g2=vk.delta_g2,
        r_i_delta_g2=aggregate_anchor,
    ):
        raise AdditiveProjectiveError("aggregate projective output failed certification")
    return aggregate_output, aggregate_anchor


@dataclass(frozen=True, slots=True)
class FallbackCutAndChoose:
    audit_copies: int
    live_copies: int
    artifact_bytes_per_copy: int = 500 * 1024
    schema: str = "ranklock-fallback-cut-and-choose-v1"

    def __post_init__(self) -> None:
        if self.audit_copies < 1 or self.live_copies < 1:
            raise AdditiveProjectiveError("audit/live copy counts must be positive")
        if self.artifact_bytes_per_copy <= 0:
            raise AdditiveProjectiveError("artifact byte count must be positive")

    @property
    def total_copies(self) -> int:
        return self.audit_copies + self.live_copies

    @property
    def worst_case_undetected_total_live_failure_probability(self) -> float:
        # To pass perfect opening checks and make every live copy malformed,
        # the adversary can have exactly q malformed copies and the random live
        # subset must equal that set.  More malformed copies necessarily place
        # at least one malformed copy in the opened set.
        return 1.0 / comb(self.total_copies, self.live_copies)

    @property
    def soundness_bits(self) -> float:
        return log2(comb(self.total_copies, self.live_copies))

    @property
    def retained_bytes_per_contributor(self) -> int:
        # Conservative ceremony storage: count all committed copies.  Audited
        # copies can be discarded after activation, but setup bandwidth/storage
        # still pays for them.
        return self.total_copies * self.artifact_bytes_per_copy

    @property
    def post_activation_live_bytes_per_contributor(self) -> int:
        return self.live_copies * self.artifact_bytes_per_copy

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "audit_copies": self.audit_copies,
            "live_copies": self.live_copies,
            "total_copies": self.total_copies,
            "soundness_bits": self.soundness_bits,
            "undetected_all_live_failure_probability": (
                self.worst_case_undetected_total_live_failure_probability
            ),
            "setup_bytes_per_contributor": self.retained_bytes_per_contributor,
            "post_activation_live_bytes_per_contributor": (
                self.post_activation_live_bytes_per_contributor
            ),
        }


def minimum_balanced_schedule(target_bits: int, *, artifact_bytes: int = 500 * 1024) -> FallbackCutAndChoose:
    if target_bits <= 0:
        raise AdditiveProjectiveError("target soundness must be positive")
    n = 2
    while True:
        q = n // 2
        t = n - q
        schedule = FallbackCutAndChoose(t, q, artifact_bytes)
        if schedule.soundness_bits >= target_bits:
            return schedule
        n += 1


def contributor_share_fixture(
    vk: PositiveGroth16VerifyingKey,
    *,
    input_a_g1: bytes,
    scales: Iterable[int],
) -> tuple[tuple[bytes, ...], tuple[bytes, ...], bytes, bytes]:
    """Build exact algebraic fixtures for tests and result generation."""

    a = decompress_g1(input_a_g1)
    delta = decompress_g2(vk.delta_g2)
    outputs: list[bytes] = []
    anchors: list[bytes] = []
    total = 0
    for raw_scale in scales:
        scale = int(raw_scale) % CURVE_ORDER
        if scale == 0:
            raise AdditiveProjectiveError("zero contributor scale")
        total = (total + scale) % CURVE_ORDER
        outputs.append(compress_g1(multiply(a, scale, group="g1")))
        anchors.append(compress_g2(multiply(delta, scale, group="g2")))
    if total == 0:
        raise AdditiveProjectiveError("aggregate scale is zero")
    return (
        tuple(outputs),
        tuple(anchors),
        compress_g1(multiply(a, total, group="g1")),
        compress_g2(multiply(delta, total, group="g2")),
    )


def additive_projective_checkpoint() -> dict[str, object]:
    schedules = {
        str(bits): minimum_balanced_schedule(bits).document()
        for bits in (40, 64, 80, 128)
    }
    return {
        "schema": "ranklock-additive-projective-checkpoint-v1",
        "algebraic_share_composition": "sum_i [r_i]A = [sum_i r_i]A",
        "public_share_certificate": "e([r_i]A, delta) = e(A, [r_i]delta)",
        "one_honest_share_secrecy_strategy": True,
        "malicious_contributor_own_share_leakage_is_not_aggregate_scalar_leakage": True,
        "runtime_wrong_output_detected": True,
        "runtime_fallback_is_one_query_per_copy": True,
        "balanced_cut_and_choose_schedules": schedules,
        "remaining_assumptions": [
            "opened Embryo copies admit perfect deterministic generation checks",
            "each contributor's one-shot copies are independently encoded and committed before partition randomness",
            "one honest contributor samples and erases an unpredictable scalar share",
            "privacy of the honest contributor's Embryo copies holds against the evaluator and corrupt contributors",
            "full distributed activation binds all share anchors and graph/session context",
        ],
        "decision": "PROMISING_MALICIOUS_SETUP_COMPOSITION_NOT_COMPLETE_DFB_INSTANTIATION",
        "breakthrough_target_met": False,
    }
