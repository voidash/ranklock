from __future__ import annotations

"""Formal pairing-product normal form for the terminal RankFold check.

The construction shows exactly what a linearly-verifiable proof must provide:
three polynomial openings and one terminal multiplication equation.  A and C
use ordinary KZG commitments in G1; B uses a dual KZG commitment in G2 so its
opened value can directly participate in ``e([a]_1,[b]_2)`` without a separate
cross-group consistency proof.

This module is an exponent-space model.  It establishes algebraic shape and
catches sign/statement mistakes; it is not a secure pairing implementation or a
complete trace proof.
"""

from dataclasses import dataclass
from typing import Sequence

from .field import BN254_BASE_FIELD, polynomial_evaluate
from .kzg_we_model import GroupElement, generator, pairing


class PpeNormalFormError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PairingTerm:
    left: GroupElement
    right: GroupElement
    coefficient: int = 1

    def __post_init__(self) -> None:
        if self.left.group != "G1" or self.right.group != "G2":
            raise PpeNormalFormError("PPE term must be G1 x G2")
        if self.left.modulus != self.right.modulus:
            raise PpeNormalFormError("PPE term fields differ")

    def evaluate(self) -> GroupElement:
        return pairing(self.left, self.right).scale(self.coefficient)


@dataclass(frozen=True, slots=True)
class PairingProductEquation:
    terms: tuple[PairingTerm, ...]
    label: str

    def __post_init__(self) -> None:
        if not self.terms:
            raise PpeNormalFormError("empty pairing-product equation")
        modulus = self.terms[0].left.modulus
        if any(term.left.modulus != modulus for term in self.terms):
            raise PpeNormalFormError("PPE terms use different fields")

    @property
    def modulus(self) -> int:
        return self.terms[0].left.modulus

    def residual(self) -> GroupElement:
        result = GroupElement("GT", 0, self.modulus)
        for term in self.terms:
            result = result + term.evaluate()
        return result

    def verify(self) -> bool:
        return self.residual().is_identity


@dataclass(frozen=True, slots=True)
class FormalKzgSrs:
    tau: int
    modulus: int = BN254_BASE_FIELD

    @property
    def g1(self) -> GroupElement:
        return generator("G1", self.modulus)

    @property
    def g2(self) -> GroupElement:
        return generator("G2", self.modulus)

    @property
    def tau_g1(self) -> GroupElement:
        return self.g1.scale(self.tau)

    @property
    def tau_g2(self) -> GroupElement:
        return self.g2.scale(self.tau)

    def commit_g1(self, coefficients: Sequence[int]) -> GroupElement:
        return self.g1.scale(polynomial_evaluate(coefficients, self.tau, self.modulus))

    def commit_g2(self, coefficients: Sequence[int]) -> GroupElement:
        return self.g2.scale(polynomial_evaluate(coefficients, self.tau, self.modulus))

    def opening_g1(self, coefficients: Sequence[int], point: int) -> tuple[int, GroupElement]:
        value, quotient_at_tau = _opening_exponents(coefficients, point, self.tau, self.modulus)
        return value, self.g1.scale(quotient_at_tau)

    def opening_g2(self, coefficients: Sequence[int], point: int) -> tuple[int, GroupElement]:
        value, quotient_at_tau = _opening_exponents(coefficients, point, self.tau, self.modulus)
        return value, self.g2.scale(quotient_at_tau)


def _opening_exponents(
    coefficients: Sequence[int], point: int, tau: int, modulus: int
) -> tuple[int, int]:
    coefficients = tuple(int(value) % modulus for value in coefficients)
    if not coefficients:
        raise PpeNormalFormError("polynomial is empty")
    point %= modulus
    value = polynomial_evaluate(coefficients, point, modulus)
    # Synthetic division of f(X)-f(point) by X-point, little-endian.
    descending = list(reversed(coefficients))
    if len(descending) == 1:
        quotient = ()
    else:
        quotient_desc = [descending[0]]
        for coefficient in descending[1:-1]:
            quotient_desc.append((coefficient + point * quotient_desc[-1]) % modulus)
        remainder = (descending[-1] + point * quotient_desc[-1]) % modulus
        if remainder != value:
            raise PpeNormalFormError("synthetic division invariant failed")
        quotient = tuple(reversed(quotient_desc))
    quotient_at_tau = polynomial_evaluate(quotient or (0,), tau, modulus)
    return value, quotient_at_tau


def kzg_opening_equation_g1(
    *,
    commitment: GroupElement,
    value: int,
    opening: GroupElement,
    point: int,
    srs: FormalKzgSrs,
    label: str,
) -> PairingProductEquation:
    return PairingProductEquation(
        (
            PairingTerm(commitment - srs.g1.scale(value), srs.g2, 1),
            PairingTerm(opening, srs.tau_g2 - srs.g2.scale(point), -1),
        ),
        label,
    )


def kzg_opening_equation_g2(
    *,
    commitment: GroupElement,
    value: int,
    opening: GroupElement,
    point: int,
    srs: FormalKzgSrs,
    label: str,
) -> PairingProductEquation:
    if commitment.group != "G2" or opening.group != "G2":
        raise PpeNormalFormError("dual KZG commitment/opening must be in G2")
    return PairingProductEquation(
        (
            PairingTerm(srs.tau_g1 - srs.g1.scale(point), opening, 1),
            PairingTerm(srs.g1, commitment - srs.g2.scale(value), -1),
        ),
        label,
    )


def terminal_product_equation(
    *,
    a: int,
    b: int,
    c: int,
    current_claim: int,
    equality_weight: int,
    srs: FormalKzgSrs,
) -> PairingProductEquation:
    modulus = srs.modulus
    eq = equality_weight % modulus
    rhs = (current_claim + eq * c) % modulus
    return PairingProductEquation(
        (
            PairingTerm(srs.g1.scale(a * eq), srs.g2.scale(b), 1),
            PairingTerm(srs.g1.scale(rhs), srs.g2, -1),
        ),
        "rankfold-terminal-product",
    )


@dataclass(frozen=True, slots=True)
class RankFoldTerminalPpeProof:
    point: int
    a: int
    b: int
    c: int
    commitment_a: GroupElement
    commitment_b: GroupElement
    commitment_c: GroupElement
    opening_a: GroupElement
    opening_b: GroupElement
    opening_c: GroupElement

    def equations(
        self,
        *,
        current_claim: int,
        equality_weight: int,
        srs: FormalKzgSrs,
    ) -> tuple[PairingProductEquation, ...]:
        return (
            kzg_opening_equation_g1(
                commitment=self.commitment_a,
                value=self.a,
                opening=self.opening_a,
                point=self.point,
                srs=srs,
                label="open-A",
            ),
            kzg_opening_equation_g2(
                commitment=self.commitment_b,
                value=self.b,
                opening=self.opening_b,
                point=self.point,
                srs=srs,
                label="open-B-dual",
            ),
            kzg_opening_equation_g1(
                commitment=self.commitment_c,
                value=self.c,
                opening=self.opening_c,
                point=self.point,
                srs=srs,
                label="open-C",
            ),
            terminal_product_equation(
                a=self.a,
                b=self.b,
                c=self.c,
                current_claim=current_claim,
                equality_weight=equality_weight,
                srs=srs,
            ),
        )

    def verify(
        self,
        *,
        current_claim: int,
        equality_weight: int,
        srs: FormalKzgSrs,
    ) -> bool:
        return all(
            equation.verify()
            for equation in self.equations(
                current_claim=current_claim,
                equality_weight=equality_weight,
                srs=srs,
            )
        )


def build_terminal_ppe_proof(
    *,
    polynomial_a: Sequence[int],
    polynomial_b: Sequence[int],
    polynomial_c: Sequence[int],
    point: int,
    srs: FormalKzgSrs,
) -> RankFoldTerminalPpeProof:
    a, opening_a = srs.opening_g1(polynomial_a, point)
    b, opening_b = srs.opening_g2(polynomial_b, point)
    c, opening_c = srs.opening_g1(polynomial_c, point)
    return RankFoldTerminalPpeProof(
        point=point % srs.modulus,
        a=a,
        b=b,
        c=c,
        commitment_a=srs.commit_g1(polynomial_a),
        commitment_b=srs.commit_g2(polynomial_b),
        commitment_c=srs.commit_g1(polynomial_c),
        opening_a=opening_a,
        opening_b=opening_b,
        opening_c=opening_c,
    )
