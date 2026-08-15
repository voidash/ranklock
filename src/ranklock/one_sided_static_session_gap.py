from __future__ import annotations

"""Audit the static-session gap in the one-sided RankLock wrapper.

The v0.18 wrapper now has a concrete, sub-megabyte arithmetic envelope, but its
last pairing equation is identity-normalised::

    e(Q, [s]G2) = e(R + alpha^{-1} Q, G2).

A direct split-basis lock scales the fixed G2 anchors by a hidden ``r`` and uses
an accepting pairing value as a KDF session.  For the equation above the scaled
residual is still the public identity ``1_GT``.  It therefore contains no
conditional entropy.  The small byte envelope is only a *size pass* until a
real fixed-relation LVA witness lift (or another entropy-bearing compiler) is
constructed.

The module also captures a tempting repair and its failure.  Publicly shifting
future G1 proof elements can turn an identity PPE into a non-identity target,
but every such public affine shift over the scaled fixed-G2 anchor span exposes
the scaled target to everybody.  This is a scoped algebraic barrier, not a
universal impossibility theorem.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .bn254_real import (
    CURVE_ORDER,
    FQ12,
    G1,
    G2,
    Point,
    add,
    compress_g1,
    multiply,
    neg,
    pairing_product,
)
from .one_sided_scalar_verifier import scalar_verifier_frontier
from .one_sided_wrapper_frontier import OneSidedFinalPairingEquation


class StaticSessionGapError(ValueError):
    pass


def _field(value: int) -> int:
    return int(value) % CURVE_ORDER


def _sum_g1(points: Sequence[Point]) -> Point:
    result = multiply(G1, 0, group="g1")
    for point in points:
        result = add(result, point, group="g1")
    return result


def _gt_digest(value: FQ12, *, context: bytes) -> bytes:
    return sha256(
        b"ranklock/one-sided-static-session/v1\x00"
        + len(context).to_bytes(4, "big")
        + bytes(context)
        + value.to_bytes()
    ).digest()


@dataclass(frozen=True, slots=True)
class IdentitySessionAudit:
    trapdoor_s: int
    challenge_alpha: int
    scale_r: int
    q_scalar: int
    context: bytes = b"ranklock-v0.18-one-sided-wrapper"
    schema: str = "ranklock-one-sided-identity-session-audit-v1"

    def __post_init__(self) -> None:
        fields = (
            ("trapdoor", "trapdoor_s", self.trapdoor_s),
            ("challenge", "challenge_alpha", self.challenge_alpha),
            ("scale", "scale_r", self.scale_r),
            ("Q scalar", "q_scalar", self.q_scalar),
        )
        for label, attribute, value in fields:
            canonical = _field(value)
            if canonical == 0:
                raise StaticSessionGapError(f"{label} is zero")
            object.__setattr__(self, attribute, canonical)
        if not self.context:
            raise StaticSessionGapError("audit context is empty")

    @property
    def equation(self) -> OneSidedFinalPairingEquation:
        return OneSidedFinalPairingEquation(self.trapdoor_s, self.challenge_alpha)

    @property
    def witness(self) -> tuple[bytes, bytes]:
        return self.equation.accepting_witness(self.q_scalar)

    @property
    def direct_residual(self) -> FQ12:
        q_raw, r_raw = self.witness
        # The helper's public accepts path already performs canonical parsing.
        from .bn254_real import decompress_g1

        q = decompress_g1(q_raw)
        r = decompress_g1(r_raw)
        right = add(
            r,
            multiply(q, self.equation.alpha_inverse, group="g1"),
            group="g1",
        )
        return pairing_product(
            (
                (q, multiply(G2, self.trapdoor_s, group="g2")),
                (neg(right), G2),
            )
        )

    @property
    def scaled_residual(self) -> FQ12:
        q_raw, r_raw = self.witness
        from .bn254_real import decompress_g1

        q = decompress_g1(q_raw)
        r = decompress_g1(r_raw)
        right = add(
            r,
            multiply(q, self.equation.alpha_inverse, group="g1"),
            group="g1",
        )
        return pairing_product(
            (
                (
                    q,
                    multiply(
                        multiply(G2, self.trapdoor_s, group="g2"),
                        self.scale_r,
                        group="g2",
                    ),
                ),
                (
                    neg(right),
                    multiply(G2, self.scale_r, group="g2"),
                ),
            )
        )

    @property
    def session_digest(self) -> bytes:
        return _gt_digest(self.scaled_residual, context=self.context)

    @property
    def public_identity_digest(self) -> bytes:
        return _gt_digest(FQ12.one(), context=self.context)

    @property
    def direct_lock_has_entropy(self) -> bool:
        return self.scaled_residual != FQ12.one()

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "equation_accepts": self.equation.accepts(self.witness),
            "direct_residual_is_identity": self.direct_residual == FQ12.one(),
            "scaled_residual_is_identity": self.scaled_residual == FQ12.one(),
            "session_digest_equals_public_identity_digest": (
                self.session_digest == self.public_identity_digest
            ),
            "direct_lock_has_entropy": self.direct_lock_has_entropy,
            "failure": (
                "Scaling both fixed G2 anchors preserves the accepting residual 1_GT. "
                "A KDF of that residual is a public constant, not conditional disclosure."
            ),
        }


@dataclass(frozen=True, slots=True)
class PublicAffineShiftBarrier:
    """Public-shift attack for a low-rank fixed-G2 pairing relation.

    Fixed bases are ``B_i = sum_j a[i,j] U_j``.  Public shifts ``D_i`` change an
    identity relation into target ``T = product_i e(D_i, B_i)``.  If setup
    publishes ``r U_j`` for direct decryption, anybody computes::

        T^r = product_j e(sum_i a[i,j] D_i, r U_j).

    Thus the apparent non-identity target does not add secrecy.
    """

    anchors_g2: tuple[Point, ...]
    coefficients: tuple[tuple[int, ...], ...]
    public_shifts_g1: tuple[Point, ...]
    scale_r: int
    schema: str = "ranklock-public-affine-target-barrier-v1"

    def __post_init__(self) -> None:
        if not self.anchors_g2 or not self.coefficients or not self.public_shifts_g1:
            raise StaticSessionGapError("affine-shift barrier has empty dimensions")
        if len(self.coefficients) != len(self.public_shifts_g1):
            raise StaticSessionGapError("shift/coefficient row count differs")
        width = len(self.anchors_g2)
        if any(len(row) != width for row in self.coefficients):
            raise StaticSessionGapError("affine-shift coefficient matrix is ragged")
        scale = _field(self.scale_r)
        if scale == 0:
            raise StaticSessionGapError("affine-shift scale is zero")
        object.__setattr__(self, "scale_r", scale)
        object.__setattr__(
            self,
            "coefficients",
            tuple(tuple(_field(value) for value in row) for row in self.coefficients),
        )

    @property
    def term_bases_g2(self) -> tuple[Point, ...]:
        bases: list[Point] = []
        for row in self.coefficients:
            terms = tuple(
                multiply(anchor, coefficient, group="g2")
                for anchor, coefficient in zip(
                    self.anchors_g2, row, strict=True
                )
                if coefficient
            )
            result = multiply(G2, 0, group="g2")
            from .bn254_real import add as add_point

            for term in terms:
                result = add_point(result, term, group="g2")
            bases.append(result)
        return tuple(bases)

    @property
    def target(self) -> FQ12:
        return pairing_product(tuple(zip(self.public_shifts_g1, self.term_bases_g2, strict=True)))

    @property
    def target_to_scale(self) -> FQ12:
        # Ground truth T^r, calculated without exposing r.
        return self.target ** self.scale_r

    @property
    def public_reconstruction(self) -> FQ12:
        aggregates: list[Point] = []
        for anchor_index in range(len(self.anchors_g2)):
            aggregates.append(
                _sum_g1(
                    tuple(
                        multiply(
                            shift,
                            self.coefficients[row_index][anchor_index],
                            group="g1",
                        )
                        for row_index, shift in enumerate(self.public_shifts_g1)
                        if self.coefficients[row_index][anchor_index]
                    )
                )
            )
        scaled_anchors = tuple(
            multiply(anchor, self.scale_r, group="g2")
            for anchor in self.anchors_g2
        )
        return pairing_product(tuple(zip(aggregates, scaled_anchors, strict=True)))

    @property
    def leaks_scaled_target(self) -> bool:
        return self.public_reconstruction == self.target_to_scale

    @classmethod
    def for_one_sided_equation(
        cls,
        equation: OneSidedFinalPairingEquation,
        *,
        scale_r: int,
        q_shift: int = 7,
        r_shift: int = 11,
    ) -> "PublicAffineShiftBarrier":
        shifts = (
            multiply(G1, _field(q_shift), group="g1"),
            multiply(G1, _field(r_shift), group="g1"),
        )
        return cls(
            equation.fixed_g2_anchors,
            equation.coefficient_matrix,
            shifts,
            scale_r,
        )

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "anchor_rank_upper_bound": len(self.anchors_g2),
            "shift_terms": len(self.public_shifts_g1),
            "target_is_nonidentity": self.target != FQ12.one(),
            "public_reconstruction_equals_target_to_r": self.leaks_scaled_target,
            "public_shift_encodings": [
                compress_g1(point).hex() for point in self.public_shifts_g1
            ],
            "failure": (
                "Any public affine target shift over the fixed-G2 witness-anchor span "
                "has a public decomposition against the published scaled anchors."
            ),
        }


def one_sided_static_session_checkpoint() -> dict[str, object]:
    audit = IdentitySessionAudit(
        trapdoor_s=17,
        challenge_alpha=23,
        scale_r=29,
        q_scalar=31,
    )
    barrier = PublicAffineShiftBarrier.for_one_sided_equation(
        audit.equation,
        scale_r=29,
    )
    size = scalar_verifier_frontier()
    envelope = size["integrated_envelope"]
    return {
        "schema": "ranklock-one-sided-static-session-checkpoint-v1",
        "size_gate": {
            "decision": "PASS",
            "activation_plus_future_proof_bytes": envelope[
                "activation_plus_future_proof_bytes"
            ],
            "margin_to_one_MiB_bytes": envelope["margin_to_one_MiB_bytes"],
            "warning": (
                "This is a concrete arithmetic/transcript envelope but still uses the "
                "uninstantiated fixed-relation LVA-WE coordinate-key model."
            ),
        },
        "direct_identity_session": audit.document(),
        "public_affine_target_repair": barrier.document(),
        "cryptographic_gate": {
            "decision": "FAIL",
            "constructed_static_witness_lift": False,
            "required_new_object": (
                "An extractable fixed-relation LVA witness-encryption compiler, or a "
                "witness-dependent target token that is unavailable from public affine "
                "proof shifts and whose accepting session is fixed at activation."
            ),
            "acceptable_repair_classes": [
                "real LVA-WE gadget composition for the full typed one-sided verifier",
                "predictable/target-token argument with a proof-only hidden session",
                "a different proof backend with a basis-separated fixed statement session",
            ],
        },
        "overall_decision": "CONDITIONAL_SIZE_PASS__STATIC_SESSION_NOT_CONSTRUCTED",
    }
