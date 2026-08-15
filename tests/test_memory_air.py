from __future__ import annotations

from dataclasses import replace

import pytest

from ranklock.memory_air import (
    MemoryAccess,
    build_sorted_memory_air,
    memory_argument_cost,
    prove_memory_argument,
    verify_memory_argument,
)
from ranklock.generic_air import GenericAirError, prove_generic_air
from ranklock.ppe_normal_form import FormalKzgSrs


def _valid_accesses() -> tuple[MemoryAccess, ...]:
    return (
        MemoryAccess(1, 0, 5, 1),
        MemoryAccess(1, 1, 5, 0),
        MemoryAccess(2, 2, 7, 1),
        MemoryAccess(2, 3, 7, 0),
        MemoryAccess(1, 4, 9, 1),
        MemoryAccess(1, 5, 9, 0),
    )


def test_memory_argument_proves_permutation_order_and_read_write_semantics() -> None:
    srs = FormalKzgSrs(tau=503)
    proof, sorted_air = prove_memory_argument(
        _valid_accesses(),
        address_bits=4,
        timestamp_bits=4,
        eta=79,
        beta=83,
        zeta=97,
        srs=srs,
    )
    assert verify_memory_argument(proof, sorted_air.program, srs=srs)
    cost = memory_argument_cost(sorted_air)
    assert cost["beacons"] == 2
    assert cost["proof_shape_independent_of_rows"] is True


def test_invalid_read_is_rejected_by_sorted_air() -> None:
    accesses = list(_valid_accesses())
    accesses[1] = MemoryAccess(1, 1, 6, 0)
    sorted_air = build_sorted_memory_air(
        accesses, address_bits=4, timestamp_bits=4
    )
    with pytest.raises(GenericAirError, match="read-observes-current-value"):
        prove_generic_air(
            sorted_air.program,
            sorted_air.trace,
            zeta=101,
            srs=FormalKzgSrs(tau=509),
        )


def test_tampered_sorted_air_proof_fails_bundle() -> None:
    srs = FormalKzgSrs(tau=521)
    proof, sorted_air = prove_memory_argument(
        _valid_accesses(),
        address_bits=4,
        timestamp_bits=4,
        eta=89,
        beta=97,
        zeta=103,
        srs=srs,
    )
    openings = dict(proof.sorted_air.current_openings)
    openings["before"] = replace(openings["before"], value=openings["before"].value + 1)
    tampered = replace(proof, sorted_air=replace(proof.sorted_air, current_openings=openings))
    assert not verify_memory_argument(tampered, sorted_air.program, srs=srs)
