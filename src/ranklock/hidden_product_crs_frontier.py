from __future__ import annotations

"""Frontier for challenge-oblivious one-sided proof generation.

After the concrete outer-point ledger kills the generic public-Fiat--Shamir
parser, the obvious escape is to move verifier randomness into preprocessing so
no proof-point encoding is hashed inside the conditional relation.

The published one-sided prover, however, contains products of affine functions
of two early challenges over the full trace.  If setup merely publishes source-
group encodings of challenge monomials and the prover is restricted to public
scalar linear combinations, a generic degree-``d`` polynomial in ``v`` hidden
variables needs

    binomial(d + v, v)

independent source-group directions.  Pairings do not repair this for proof
messages that must return to G1: they move products to GT and there is no
standard efficient GT-to-G1 map.

This module makes that scoped algebraic barrier executable.  It does not rule
out functional encryption, multilinear maps, obfuscation, an online helper, or
a purpose-built proof whose challenge dependence has lower algebraic rank.
"""

from dataclasses import dataclass
from math import comb
from typing import Mapping

from .outer_curve_candidate import COMPRESSED_G1_BYTES


class HiddenProductFrontierError(ValueError):
    pass


def monomial_count(total_degree: int, variables: int) -> int:
    degree = int(total_degree)
    variable_count = int(variables)
    if degree < 0 or variable_count <= 0:
        raise HiddenProductFrontierError("invalid monomial geometry")
    return comb(degree + variable_count, variable_count)


def multiply_bivariate_affine_factors(
    factors: tuple[tuple[int, int, int], ...],
    modulus: int,
) -> dict[tuple[int, int], int]:
    """Expand ``prod_i(c_i + a_i X + b_i Y)`` exactly over a prime field."""

    if modulus <= 2:
        raise HiddenProductFrontierError("modulus must exceed two")
    coefficients: dict[tuple[int, int], int] = {(0, 0): 1}
    for constant, x_coefficient, y_coefficient in factors:
        next_coefficients: dict[tuple[int, int], int] = {}
        for (x_degree, y_degree), value in coefficients.items():
            for shift, multiplier in (
                ((0, 0), constant),
                ((1, 0), x_coefficient),
                ((0, 1), y_coefficient),
            ):
                key = (x_degree + shift[0], y_degree + shift[1])
                next_coefficients[key] = (
                    next_coefficients.get(key, 0) + value * multiplier
                ) % modulus
        coefficients = {
            key: value for key, value in next_coefficients.items() if value % modulus
        }
    return coefficients


def coefficient_support_dimension(
    coefficients: Mapping[tuple[int, ...], int],
) -> int:
    return sum(1 for value in coefficients.values() if int(value) != 0)


@dataclass(frozen=True, slots=True)
class HiddenProductCRSScenario:
    name: str
    rows: int
    hidden_challenges: int = 2
    encoded_group_bytes: int = COMPRESSED_G1_BYTES
    schema: str = "ranklock-hidden-product-crs-scenario-v1"

    def __post_init__(self) -> None:
        if self.rows <= 0 or self.hidden_challenges <= 0:
            raise HiddenProductFrontierError("invalid hidden-product scenario")
        if self.encoded_group_bytes <= 0:
            raise HiddenProductFrontierError("invalid group encoding size")

    @property
    def generic_total_degree(self) -> int:
        # A product of ``rows`` affine factors has total degree ``rows``.
        return self.rows

    @property
    def required_source_group_directions(self) -> int:
        return monomial_count(self.generic_total_degree, self.hidden_challenges)

    @property
    def raw_source_group_bytes(self) -> int:
        return self.required_source_group_directions * self.encoded_group_bytes

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "name": self.name,
            "rows": self.rows,
            "hidden_challenges": self.hidden_challenges,
            "generic_total_degree": self.generic_total_degree,
            "required_source_group_directions": self.required_source_group_directions,
            "compressed_group_bytes_each": self.encoded_group_bytes,
            "raw_source_group_bytes": self.raw_source_group_bytes,
            "raw_source_group_MiB": self.raw_source_group_bytes / (1 << 20),
            "raw_source_group_GiB": self.raw_source_group_bytes / (1 << 30),
        }


@dataclass(frozen=True, slots=True)
class HiddenProductPrimitiveTarget:
    name: str = "projective hidden-product evaluation"
    public_material: str = "polylogarithmic or low-template-rank in trace length"
    prover_work: str = "O(n) ordinary field work plus polylog expensive operations"
    output_group: str = "G1, not only GT"
    setup_security: str = "malicious n-1-corrupt distributed activation"
    public_cold_start: bool = True
    online_secret_holder: bool = False
    constructed: bool = False
    schema: str = "ranklock-hidden-product-primitive-target-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "name": self.name,
            "public_material": self.public_material,
            "prover_work": self.prover_work,
            "output_group": self.output_group,
            "setup_security": self.setup_security,
            "public_cold_start": self.public_cold_start,
            "online_secret_holder": self.online_secret_holder,
            "constructed": self.constructed,
        }


def hidden_product_crs_report() -> dict[str, object]:
    scenarios = (
        HiddenProductCRSScenario(
            "sparse RankVM arithmetic subtotal",
            25_889,
        ),
        HiddenProductCRSScenario(
            "3x85 rank-5 nonlinear subtotal",
            129_445,
        ),
    )

    # Small exact witness that the generic bivariate product reaches full
    # triangular support.  Large scenarios use the exact combinatorial formula.
    modulus = 2**127 - 1
    factors = tuple((1, 2**index + 1, 3**index + 1) for index in range(8))
    expanded = multiply_bivariate_affine_factors(factors, modulus)
    expected_support = monomial_count(len(factors), 2)

    return {
        "schema": "ranklock-hidden-product-crs-frontier-v1",
        "evidence_class": (
            "EXACT symbolic small-case expansion plus algebraic-span dimension formula"
        ),
        "small_exact_experiment": {
            "factors": len(factors),
            "support_dimension": coefficient_support_dimension(expanded),
            "generic_triangular_dimension": expected_support,
            "full_generic_support_observed": (
                coefficient_support_dimension(expanded) == expected_support
            ),
        },
        "scenarios": [scenario.document() for scenario in scenarios],
        "scoped_barrier": (
            "Publishing ordinary source-group encodings of hidden challenge monomials "
            "requires one algebraic direction per generic coefficient. The first two-"
            "challenge grand product is consequently quadratic in trace length."
        ),
        "pairing_boundary": (
            "A bilinear pairing can multiply one G1 and one G2 encoding into GT, but the "
            "one-sided proof needs a new G1 commitment and standard bilinear groups provide "
            "no efficient GT-to-G1 map."
        ),
        "killed_route": (
            "prepublish all hidden-challenge powers/monomials and run the published prover "
            "by source-group linear combinations"
        ),
        "not_ruled_out": [
            "a proof protocol whose challenge dependence has certified low tensor rank",
            "functional encryption or obfuscation for hidden product evaluation",
            "multilinear maps",
            "an online private-state helper",
            "a public-transcript proof with a native hybrid group/scalar binding gadget",
        ],
        "new_primitive_target": HiddenProductPrimitiveTarget().document(),
        "breakthrough_target_met": False,
    }
