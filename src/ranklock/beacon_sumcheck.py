from __future__ import annotations

"""Cost model for replacing sequential sumcheck challenges with one future beacon.

A tempting idea is to commit, before a Bitcoin beacon, to every future sumcheck
message as a polynomial in all prior challenges.  Once the beacon supplies all
challenges, the prover opens the appropriate message path.  This removes
Fiat--Shamir from the conditional verifier, but the committed message functions
are large.

For a degree-``d`` round polynomial, each of its ``d+1`` coefficients is a
polynomial of individual degree at most ``d`` in every prior challenge.  A dense
coefficient representation therefore has ``(d+1)^(i-1)`` monomials at round
``i``.  Across ``m`` rounds the total number of field coefficients is

    sum_{i=1..m} (d+1)^i.

RankFold uses degree-three round polynomials, making this essentially ``4^m`` or
quadratic in a table of size ``2^m``.  The module records this as an executable
kill result for the naive one-beacon transformation.  It does not rule out
structured commitments, folding proofs, or a different polynomial IOP.
"""

from dataclasses import dataclass
import json
from pathlib import Path


class BeaconSumcheckError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class BeaconPrecommitEstimate:
    rounds: int
    round_degree: int
    original_table_size: int
    committed_field_coefficients: int
    coefficient_bytes: int
    blowup_vs_table: float
    schema: str = "ranklock-naive-beacon-sumcheck-precommit-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "rounds": self.rounds,
            "round_degree": self.round_degree,
            "original_table_size": self.original_table_size,
            "committed_field_coefficients": self.committed_field_coefficients,
            "coefficient_bytes": self.coefficient_bytes,
            "blowup_vs_table": self.blowup_vs_table,
            "status": "KILLED_FOR_DENSE_MESSAGE_FUNCTION_PRECOMMITMENT",
            "scope": (
                "does not rule out structured/folding commitments or a different one-round IOP"
            ),
        }


def estimate_naive_beacon_precommit(
    rounds: int, *, round_degree: int = 3, field_bytes: int = 32
) -> BeaconPrecommitEstimate:
    if rounds <= 0:
        raise BeaconSumcheckError("round count must be positive")
    if round_degree < 1:
        raise BeaconSumcheckError("round degree must be positive")
    if field_bytes <= 0:
        raise BeaconSumcheckError("field byte width must be positive")
    base = round_degree + 1
    coefficients = sum(base**round_index for round_index in range(1, rounds + 1))
    table = 1 << rounds
    return BeaconPrecommitEstimate(
        rounds=rounds,
        round_degree=round_degree,
        original_table_size=table,
        committed_field_coefficients=coefficients,
        coefficient_bytes=coefficients * field_bytes,
        blowup_vs_table=coefficients / table,
    )


def write_beacon_estimate(path: Path, *, rounds: int = 15) -> None:
    estimates = {
        "schema": "ranklock-beacon-sumcheck-estimates-v1",
        "rankfold_degree_three": estimate_naive_beacon_precommit(
            rounds, round_degree=3
        ).document(),
        "degree_two_negative_control": estimate_naive_beacon_precommit(
            rounds, round_degree=2
        ).document(),
    }
    Path(path).write_text(json.dumps(estimates, indent=2, sort_keys=True) + "\n")
