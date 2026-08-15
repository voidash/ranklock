from __future__ import annotations

"""Algebraic rank bounds for public expansion of hidden-scalar correlations.

The model is deliberately narrow and exact.  Let ``B_1, ..., B_n`` be fixed source-group
bases represented by coefficient rows over algebraically independent anchors, and let ``r`` be
a hidden setup scalar.  A public algebraic expander receives ``k`` source-group seed elements
whose hidden-scalar coefficient vectors are ``s_1, ..., s_k``.  Group addition and
multiplication by public scalars can only output vectors in ``span(s_1, ..., s_k)``.
Consequently, emitting all desired ``r B_i`` requires at least the rank of the desired
coefficient matrix.

Pairings can create products in ``GT`` but, in the ordinary bilinear-group interface, there is
no algebraic map from ``GT`` back to ``G1`` or ``G2``.  They therefore do not lower this
source-group rank bound.  This is an algebraic-model result, not a universal computational
impossibility theorem: obfuscation-like primitives, multilinear maps, hardware, or a verifier
whose bases already have low public coefficient rank are outside the lower bound.
"""

from dataclasses import dataclass
from typing import Sequence

from .bn254_real import CURVE_ORDER


class CorrelationRankError(ValueError):
    pass


def _canonical_matrix(
    matrix: Sequence[Sequence[int]], *, modulus: int = CURVE_ORDER
) -> tuple[tuple[int, ...], ...]:
    if modulus <= 2:
        raise CorrelationRankError("modulus must exceed two")
    rows = tuple(tuple(int(value) % modulus for value in row) for row in matrix)
    if not rows:
        raise CorrelationRankError("coefficient matrix is empty")
    width = len(rows[0])
    if width == 0:
        raise CorrelationRankError("coefficient matrix has zero columns")
    if any(len(row) != width for row in rows):
        raise CorrelationRankError("coefficient matrix is ragged")
    return rows


def matrix_rank(
    matrix: Sequence[Sequence[int]], *, modulus: int = CURVE_ORDER
) -> int:
    """Return the exact row rank over the prime field ``F_modulus``."""

    rows = [list(row) for row in _canonical_matrix(matrix, modulus=modulus)]
    row_count = len(rows)
    column_count = len(rows[0])
    pivot_row = 0
    for column in range(column_count):
        pivot = next(
            (index for index in range(pivot_row, row_count) if rows[index][column]),
            None,
        )
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        inverse = pow(rows[pivot_row][column], -1, modulus)
        rows[pivot_row] = [value * inverse % modulus for value in rows[pivot_row]]
        for index in range(row_count):
            if index == pivot_row:
                continue
            factor = rows[index][column]
            if factor:
                rows[index] = [
                    (left - factor * right) % modulus
                    for left, right in zip(rows[index], rows[pivot_row], strict=True)
                ]
        pivot_row += 1
        if pivot_row == row_count:
            break
    return pivot_row


def independent_base_matrix(width: int) -> tuple[tuple[int, ...], ...]:
    if width <= 0:
        raise CorrelationRankError("independent width must be positive")
    return tuple(
        tuple(1 if row == column else 0 for column in range(width))
        for row in range(width)
    )


def structured_coefficient_matrix(
    term_count: int,
    anchor_count: int,
    *,
    modulus: int = CURVE_ORDER,
) -> tuple[tuple[int, ...], ...]:
    """Return a deterministic full-column-rank Vandermonde-shaped matrix."""

    if anchor_count <= 0:
        raise CorrelationRankError("anchor count must be positive")
    if term_count < anchor_count:
        raise CorrelationRankError("term count must be at least the anchor count")
    return tuple(
        tuple(pow(term + 1, column, modulus) for column in range(anchor_count))
        for term in range(term_count)
    )


@dataclass(frozen=True, slots=True)
class CorrelationRankCertificate:
    term_count: int
    coefficient_columns: int
    coefficient_rank: int
    public_seed_elements: int
    source_group_element_bytes: int = 64
    schema: str = "ranklock-public-correlation-rank-v1"

    @property
    def lower_bound_met(self) -> bool:
        return self.public_seed_elements >= self.coefficient_rank

    @property
    def minimum_seed_bytes(self) -> int:
        return self.coefficient_rank * self.source_group_element_bytes

    @property
    def proposed_seed_bytes(self) -> int:
        return self.public_seed_elements * self.source_group_element_bytes

    @property
    def direct_independent_bytes(self) -> int:
        return self.term_count * self.source_group_element_bytes

    @property
    def cryptographic_compression_ratio(self) -> float:
        if self.proposed_seed_bytes == 0:
            return float("inf")
        return self.direct_independent_bytes / self.proposed_seed_bytes

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_class": "EXACT algebraic linear-rank model",
            "term_count": self.term_count,
            "coefficient_columns": self.coefficient_columns,
            "coefficient_rank": self.coefficient_rank,
            "public_seed_elements": self.public_seed_elements,
            "lower_bound_met": self.lower_bound_met,
            "minimum_seed_bytes": self.minimum_seed_bytes,
            "proposed_seed_bytes": self.proposed_seed_bytes,
            "direct_independent_bytes": self.direct_independent_bytes,
            "cryptographic_compression_ratio": self.cryptographic_compression_ratio,
            "scope": (
                "Public algebraic source-group expansion using group addition and public-scalar "
                "multiplication. Pairings may produce GT values but do not map back to a source "
                "group. This is not a universal computational lower bound."
            ),
        }


def certify_public_correlation_expander(
    desired_coefficients: Sequence[Sequence[int]],
    *,
    public_seed_elements: int,
    source_group_element_bytes: int = 64,
    modulus: int = CURVE_ORDER,
) -> CorrelationRankCertificate:
    rows = _canonical_matrix(desired_coefficients, modulus=modulus)
    if public_seed_elements < 0:
        raise CorrelationRankError("public seed count is negative")
    return CorrelationRankCertificate(
        term_count=len(rows),
        coefficient_columns=len(rows[0]),
        coefficient_rank=matrix_rank(rows, modulus=modulus),
        public_seed_elements=int(public_seed_elements),
        source_group_element_bytes=int(source_group_element_bytes),
    )


def certify_independent_correlations(
    width: int,
    *,
    public_seed_elements: int,
    source_group_element_bytes: int = 64,
) -> CorrelationRankCertificate:
    """Certify the identity-matrix case without materializing an O(width^2) matrix."""

    if width <= 0:
        raise CorrelationRankError("independent width must be positive")
    if public_seed_elements < 0:
        raise CorrelationRankError("public seed count is negative")
    return CorrelationRankCertificate(
        term_count=int(width),
        coefficient_columns=int(width),
        coefficient_rank=int(width),
        public_seed_elements=int(public_seed_elements),
        source_group_element_bytes=int(source_group_element_bytes),
    )


def demonstrate_rank_dichotomy(
    *, independent_width: int = 128, term_count: int = 11, anchor_count: int = 2
) -> dict[str, object]:
    generic = certify_independent_correlations(
        independent_width, public_seed_elements=independent_width
    )
    generic_short = certify_independent_correlations(
        independent_width, public_seed_elements=max(0, independent_width - 1)
    )
    structured = certify_public_correlation_expander(
        structured_coefficient_matrix(term_count, anchor_count),
        public_seed_elements=anchor_count,
    )
    return {
        "schema": "ranklock-public-correlation-rank-dichotomy-v1",
        "evidence_class": "EXACT algebraic linear-rank model",
        "generic_independent": generic.document(),
        "generic_one_seed_short": generic_short.document(),
        "structured_low_rank": structured.document(),
        "decision": (
            "A polylogarithmic public source-group seed cannot expand arbitrary algebraically "
            "independent verifier correlations in this model. It can expand a verifier whose "
            "fixed-base coefficient matrix already has polylogarithmic rank."
        ),
    }
