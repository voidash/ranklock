from __future__ import annotations

"""Algebraic barrier for reusable public updates of standard KZG-WE.

Consider a static object that reuses one hidden randomizer ``r`` and lets anyone
obtain the standard KZG-WE header

    H(alpha) = r * ([tau]_2 - alpha * [1]_2)

for arbitrary future points.  Two update queries reveal

    (H(alpha_0) - H(alpha_1)) / (alpha_1 - alpha_0) = r * [1]_2.

That element makes the KZG-WE session for every future commitment/value public:

    e(C - beta*[1]_1, r*[1]_2).

Thus standard one-randomizer KZG-WE cannot be turned into a reusable public
statement updater.  A one-time projective delivery channel that reveals only one
header avoids the difference attack, but it still cannot precompute the masked
payload for an arbitrary future commitment.

This is an algebraic-family barrier, not an impossibility theorem for all
witness encryption or functional encryption constructions.
"""

from dataclasses import dataclass

from .kzg_we_conjunction import KzgOpeningStatement
from .kzg_we_model import GroupElement, pairing
from .ppe_normal_form import FormalKzgSrs


class CommitmentObliviousError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReusableHeaderOracle:
    randomizer: int
    srs: FormalKzgSrs

    def __post_init__(self) -> None:
        if int(self.randomizer) % self.srs.modulus == 0:
            raise CommitmentObliviousError("randomizer must be nonzero")

    def header(self, point: int) -> GroupElement:
        return (
            self.srs.tau_g2 - self.srs.g2.scale(int(point) % self.srs.modulus)
        ).scale(self.randomizer)


def recover_randomizer_base_from_two_updates(
    *,
    point_zero: int,
    header_zero: GroupElement,
    point_one: int,
    header_one: GroupElement,
) -> GroupElement:
    if header_zero.group != "G2" or header_one.group != "G2":
        raise CommitmentObliviousError("headers must be G2 elements")
    if header_zero.modulus != header_one.modulus:
        raise CommitmentObliviousError("header fields differ")
    modulus = header_zero.modulus
    denominator = (int(point_one) - int(point_zero)) % modulus
    if denominator == 0:
        raise CommitmentObliviousError("update points must differ")
    return (header_zero - header_one).scale(pow(denominator, -1, modulus))


def session_from_recovered_base(
    statement: KzgOpeningStatement,
    recovered_r_g2: GroupElement,
    *,
    srs: FormalKzgSrs,
) -> GroupElement:
    normalized = statement.normalized(srs)
    if recovered_r_g2.group != "G2" or recovered_r_g2.modulus != srs.modulus:
        raise CommitmentObliviousError("recovered randomizer base is malformed")
    return pairing(
        normalized.commitment - srs.g1.scale(normalized.value), recovered_r_g2
    )


def lower_bound_scope() -> dict[str, object]:
    return {
        "schema": "ranklock-commitment-oblivious-kzg-we-barrier-v1",
        "ruled_out": [
            "reusable arbitrary-point public updates with one fixed KZG-WE randomizer",
            "security from hiding r*[1]_2 when two standard headers are publicly obtainable",
        ],
        "not_ruled_out": [
            "one-time selected projective delivery revealing only one header",
            "fresh-randomizer updates with an online encapsulator",
            "stronger witness/functional encryption not algebraically equivalent to standard KZG-WE",
        ],
        "remaining_dynamic_commitment_problem": True,
    }
