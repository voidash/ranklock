from __future__ import annotations

from dataclasses import replace

from ranklock.generic_air import (
    AirConstraint,
    BoundaryConstraint,
    Current,
    GenericAirProgram,
    GenericAirTrace,
    Next,
    generic_air_cost,
    prove_generic_air,
    verify_generic_air,
)
from ranklock.ppe_normal_form import FormalKzgSrs


def test_generic_air_proves_products_transitions_and_boundaries() -> None:
    rows = 8
    all_rows = tuple(range(rows))
    transition_rows = tuple(range(rows - 1))
    a, b, c, state = Current("a"), Current("b"), Current("c"), Current("state")
    program = GenericAirProgram(
        ("a", "b", "c", "state"),
        (
            AirConstraint("product", a * b - c, all_rows),
            AirConstraint("state-step", Next("state") - state - 7, transition_rows),
        ),
        (BoundaryConstraint("state", 0, 11, "state-start"),),
    )
    trace = GenericAirTrace(
        {
            "a": tuple(index + 2 for index in range(rows)),
            "b": tuple(3 * index + 5 for index in range(rows)),
            "c": tuple((index + 2) * (3 * index + 5) for index in range(rows)),
            "state": tuple(11 + 7 * index for index in range(rows)),
        }
    )
    srs = FormalKzgSrs(tau=307)
    proof = prove_generic_air(program, trace, zeta=97, srs=srs).proof
    assert verify_generic_air(program, proof, srs=srs)
    cost = generic_air_cost(program, rows)
    assert cost["beacons"] == 1
    assert cost["proof_shape_independent_of_rows"] is True


def test_generic_air_rejects_wrong_program_or_opening() -> None:
    rows = 4
    a, b, c = Current("a"), Current("b"), Current("c")
    program = GenericAirProgram(
        ("a", "b", "c"),
        (AirConstraint("product", a * b - c, tuple(range(rows))),),
    )
    trace = GenericAirTrace({"a": (1, 2, 3, 4), "b": (5, 6, 7, 8), "c": (5, 12, 21, 32)})
    srs = FormalKzgSrs(tau=311)
    proof = prove_generic_air(program, trace, zeta=101, srs=srs).proof
    wrong = GenericAirProgram(
        ("a", "b", "c"),
        (AirConstraint("product", a * b - c - 1, tuple(range(rows))),),
    )
    assert not verify_generic_air(wrong, proof, srs=srs)
    openings = dict(proof.current_openings)
    openings["a"] = replace(openings["a"], value=openings["a"].value + 1)
    assert not verify_generic_air(program, replace(proof, current_openings=openings), srs=srs)
