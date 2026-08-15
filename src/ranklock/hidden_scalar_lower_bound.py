from __future__ import annotations

"""Executable generic-bilinear-group barrier for delayed hidden scalar multiplication.

BABE/Argo-style conditional disclosure eventually needs to evaluate ``P -> [r]P``
for a *future* source-group point ``P`` while the scalar ``r`` was chosen during
setup and remains hidden.  This module records a simple algebraic generic-group
barrier:

* setup may publish arbitrary source-group encodings whose exponents depend on
  ``r`` but not on the future point ``P``;
* evaluation may add source-group elements and multiply them by public scalars;
* the future input contributes the independent formal discrete logarithm ``p``;
* pairings may multiply G1 and G2 exponents, but their output remains in GT.

Under those operations, the mixed monomial ``r*p`` is reachable in GT as
``e(P, [r]G2)`` but not in G1.  A map from GT back to G1, an online holder of
``r``, or a nonlinear source-group mechanism such as garbling/obfuscation is
therefore necessary.

This is an executable algebraic-model argument, not a computational lower bound
against every possible cryptographic assumption.
"""

from dataclasses import dataclass
from typing import Iterable, Literal, Mapping

Group = Literal["G1", "G2", "GT"]
Monomial = tuple[int, int]  # (degree in hidden setup scalar r, degree in future point log p)


class AlgebraicBarrierError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FormalGroupExpression:
    group: Group
    terms: tuple[tuple[Monomial, int], ...]

    def __post_init__(self) -> None:
        canonical: dict[Monomial, int] = {}
        for monomial, coefficient in self.terms:
            if len(monomial) != 2 or min(monomial) < 0:
                raise AlgebraicBarrierError("malformed formal monomial")
            coefficient = int(coefficient)
            if coefficient:
                canonical[tuple(monomial)] = canonical.get(tuple(monomial), 0) + coefficient
        canonical = {m: c for m, c in canonical.items() if c}
        object.__setattr__(self, "terms", tuple(sorted(canonical.items())))

    @classmethod
    def monomial(
        cls, group: Group, *, r_degree: int = 0, p_degree: int = 0, coefficient: int = 1
    ) -> "FormalGroupExpression":
        return cls(group, (((int(r_degree), int(p_degree)), int(coefficient)),))

    @classmethod
    def zero(cls, group: Group) -> "FormalGroupExpression":
        return cls(group, ())

    @property
    def support(self) -> frozenset[Monomial]:
        return frozenset(monomial for monomial, _coefficient in self.terms)

    def _check(self, other: "FormalGroupExpression") -> None:
        if self.group != other.group:
            raise AlgebraicBarrierError("cross-group source addition is undefined")

    def __add__(self, other: "FormalGroupExpression") -> "FormalGroupExpression":
        self._check(other)
        return FormalGroupExpression(self.group, self.terms + other.terms)

    def __sub__(self, other: "FormalGroupExpression") -> "FormalGroupExpression":
        self._check(other)
        return self + other.scale(-1)

    def scale(self, public_scalar: int) -> "FormalGroupExpression":
        # The scalar is public and may not contain r or the hidden discrete log p.
        scalar = int(public_scalar)
        return FormalGroupExpression(
            self.group,
            tuple((monomial, coefficient * scalar) for monomial, coefficient in self.terms),
        )

    def contains(self, monomial: Monomial) -> bool:
        return tuple(monomial) in self.support


def pairing(
    left: FormalGroupExpression, right: FormalGroupExpression
) -> FormalGroupExpression:
    if left.group != "G1" or right.group != "G2":
        raise AlgebraicBarrierError("formal pairing requires G1 x G2")
    products: list[tuple[Monomial, int]] = []
    for (r_left, p_left), c_left in left.terms:
        for (r_right, p_right), c_right in right.terms:
            products.append(((r_left + r_right, p_left + p_right), c_left * c_right))
    return FormalGroupExpression("GT", tuple(products))


@dataclass(frozen=True, slots=True)
class HiddenScalarBarrierCertificate:
    setup_r_degree_bound: int
    source_g1_support: frozenset[Monomial]
    source_g2_support: frozenset[Monomial]
    target: Monomial = (1, 1)

    @property
    def target_reachable_in_g1(self) -> bool:
        return self.target in self.source_g1_support

    @property
    def target_reachable_in_gt(self) -> bool:
        # Pair the future point p in G1 with r in G2.
        return (0, 1) in self.source_g1_support and (1, 0) in self.source_g2_support

    @property
    def barrier_holds(self) -> bool:
        return not self.target_reachable_in_g1 and self.target_reachable_in_gt

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-hidden-scalar-barrier-v1",
            "setup_r_degree_bound": self.setup_r_degree_bound,
            "target_monomial": list(self.target),
            "target_reachable_in_g1": self.target_reachable_in_g1,
            "target_reachable_in_gt": self.target_reachable_in_gt,
            "barrier_holds": self.barrier_holds,
            "interpretation": (
                "pairing exposes r*p only in GT; source-group linear operations cannot return it to G1"
            ),
        }


def hidden_scalar_barrier(
    *, setup_r_degree_bound: int = 8
) -> HiddenScalarBarrierCertificate:
    """Return the source-group closure under the stated algebraic model.

    We intentionally grant setup arbitrary powers ``r^0, ..., r^d`` in both
    source groups.  The future point contributes ``p`` in G1.  Source-group
    addition and public scaling preserve the linear span of these monomials, so
    no mixed ``r*p`` term appears in G1.
    """

    if setup_r_degree_bound < 1:
        raise AlgebraicBarrierError("setup degree bound must include r")
    setup = frozenset((degree, 0) for degree in range(setup_r_degree_bound + 1))
    g1 = setup | frozenset({(0, 1)})
    g2 = setup
    return HiddenScalarBarrierCertificate(setup_r_degree_bound, g1, g2)


def hypothetical_gt_to_g1(
    expression: FormalGroupExpression,
) -> FormalGroupExpression:
    """A deliberately unavailable map used to pinpoint the missing primitive."""

    if expression.group != "GT":
        raise AlgebraicBarrierError("inverse-pairing map expects GT")
    return FormalGroupExpression("G1", expression.terms)


def demonstrate_hidden_scalar_barrier() -> dict[str, object]:
    certificate = hidden_scalar_barrier()
    future_point = FormalGroupExpression.monomial("G1", p_degree=1)
    hidden_scalar_g2 = FormalGroupExpression.monomial("G2", r_degree=1)
    gt_product = pairing(future_point, hidden_scalar_g2)
    impossible_without_map = FormalGroupExpression.monomial("G1", r_degree=1, p_degree=1)
    mapped = hypothetical_gt_to_g1(gt_product)
    return {
        **certificate.document(),
        "pairing_output_support": [list(value) for value in sorted(gt_product.support)],
        "desired_source_support": [list(value) for value in sorted(impossible_without_map.support)],
        "hypothetical_inverse_map_recovers_target": mapped.support == impossible_without_map.support,
    }
