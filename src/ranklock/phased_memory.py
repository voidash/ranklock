from __future__ import annotations

"""Phase-correct, composition-bound sorted-memory argument.

The inherited memory bundle had two independent commitment sets:

* tuple permutation commitments for the alleged sorted access table; and
* AIR commitments for a valid sorted-memory execution.

Because the verifier never compared those commitments, a prover could use two
unrelated tables.  This module requires the permutation's right-side component
commitments to be exactly the AIR commitments for
``(address,timestamp,value,is_write)`` and uses the explicit beacon phases from
:mod:`ranklock.phased_air` and :mod:`ranklock.phased_permutation`.
"""

from dataclasses import dataclass
from typing import Sequence

from .memory_air import MemoryAccess, SortedMemoryAir, build_sorted_memory_air
from .phased_air import (
    AirCommittedState,
    PhasedAirProof,
    commit_air,
    open_committed_air,
    verify_phased_air,
)
from .phased_permutation import (
    PhasedTuplePermutationProof,
    commit_tuple_permutation_phase_two,
    open_committed_tuple_permutation,
    verify_phased_tuple_permutation,
)
from .ppe_normal_form import FormalKzgSrs
from .tuple_permutation import TuplePermutationState, commit_tuple_sequences


class PhasedMemoryError(ValueError):
    pass


ACCESS_COLUMNS = ("address", "timestamp", "value", "is_write")


@dataclass(frozen=True, slots=True)
class PhasedMemoryCommittedState:
    sorted_air: SortedMemoryAir
    permutation_phase_one: TuplePermutationState
    air_phase: AirCommittedState
    address_bits: int
    timestamp_bits: int
    schema: str = "ranklock-phased-memory-committed-state-v1"


@dataclass(frozen=True, slots=True)
class PhasedMemoryProof:
    permutation: PhasedTuplePermutationProof
    sorted_air: PhasedAirProof
    address_bits: int
    timestamp_bits: int
    schema: str = "ranklock-phased-memory-proof-v1"


def _right_commitments_match_air(
    permutation: TuplePermutationState | PhasedTuplePermutationProof,
    air: AirCommittedState | PhasedAirProof,
) -> bool:
    phase_one = (
        permutation.phase_one
        if isinstance(permutation, TuplePermutationState)
        else permutation.phase_two.phase_one
    )
    air_commitments = (
        air.phase.commitments
        if isinstance(air, AirCommittedState)
        else air.phase.commitments
    )
    if phase_one.width != len(ACCESS_COLUMNS):
        return False
    try:
        expected = tuple(air_commitments[name] for name in ACCESS_COLUMNS)
    except KeyError:
        return False
    return phase_one.right_commitments == expected


def commit_memory_argument(
    accesses: Sequence[MemoryAccess],
    *,
    address_bits: int,
    timestamp_bits: int,
    srs: FormalKzgSrs,
) -> PhasedMemoryCommittedState:
    sorted_air = build_sorted_memory_air(
        accesses,
        address_bits=address_bits,
        timestamp_bits=timestamp_bits,
        modulus=srs.modulus,
    )
    unsorted_tuples = tuple(access.tuple(srs.modulus) for access in accesses)
    sorted_tuples = tuple(
        access.tuple(srs.modulus) for access in sorted_air.sorted_accesses
    )
    permutation = commit_tuple_sequences(unsorted_tuples, sorted_tuples, srs=srs)
    air = commit_air(sorted_air.program, sorted_air.trace, srs=srs)
    state = PhasedMemoryCommittedState(
        sorted_air, permutation, air, address_bits, timestamp_bits
    )
    if not _right_commitments_match_air(permutation, air):
        raise PhasedMemoryError(
            "sorted permutation commitments differ from sorted AIR commitments"
        )
    return state


def open_memory_argument(
    state: PhasedMemoryCommittedState,
    *,
    beacon_one: bytes,
    beacon_two: bytes,
    srs: FormalKzgSrs,
) -> PhasedMemoryProof:
    if not _right_commitments_match_air(
        state.permutation_phase_one, state.air_phase
    ):
        raise PhasedMemoryError("memory commitment binding was lost")
    tuple_phase_two = commit_tuple_permutation_phase_two(
        state.permutation_phase_one, beacon_one=beacon_one, srs=srs
    )
    permutation = open_committed_tuple_permutation(
        tuple_phase_two, beacon_two=beacon_two, srs=srs
    )
    air = open_committed_air(
        state.air_phase,
        beacon=beacon_one,
        program=state.sorted_air.program,
        srs=srs,
    )
    return PhasedMemoryProof(
        permutation, air, state.address_bits, state.timestamp_bits
    )


def verify_phased_memory_argument(
    proof: PhasedMemoryProof,
    sorted_air_program,
    *,
    srs: FormalKzgSrs,
) -> bool:
    try:
        if not _right_commitments_match_air(proof.permutation, proof.sorted_air):
            return False
        return verify_phased_tuple_permutation(
            proof.permutation, srs=srs
        ) and verify_phased_air(sorted_air_program, proof.sorted_air, srs=srs)
    except (PhasedMemoryError, ValueError, KeyError, OverflowError):
        return False
