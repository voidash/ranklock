from __future__ import annotations

"""Legacy sorted-memory AIR composition.

SECURITY WARNING: this historical bundle has two independent defects:

* it uses the late-bound legacy AIR and tuple-permutation helpers; and
* it does not bind the permutation's alleged sorted table to the AIR's sorted
  trace commitments.

``tests/test_phased_memory.py`` demonstrates acceptance of an invalid access log
combined with an unrelated valid AIR.  New protocol work must use
:mod:`ranklock.phased_memory`, which enforces shared commitments and explicit
beacon phases.  The access-table and AIR-program builder in this file remains
useful infrastructure.
"""

from dataclasses import dataclass
from typing import Sequence

from .field import BN254_BASE_FIELD
from .generic_air import (
    AirConstraint,
    BoundaryConstraint,
    Current,
    GenericAirProgram,
    GenericAirProof,
    GenericAirTrace,
    Next,
    generic_air_cost,
    prove_generic_air,
    verify_generic_air,
)
from .ppe_normal_form import FormalKzgSrs
from .tuple_permutation import (
    TuplePermutationProof,
    commit_tuple_sequences,
    respond_tuple_permutation,
    tuple_permutation_cost,
    verify_tuple_permutation,
)


class MemoryAirError(ValueError):
    pass


@dataclass(frozen=True, slots=True, order=True)
class MemoryAccess:
    address: int
    timestamp: int
    value: int
    is_write: int

    def __post_init__(self) -> None:
        if self.address < 0 or self.timestamp < 0:
            raise MemoryAirError("memory address/timestamp must be non-negative")
        if self.is_write not in (0, 1):
            raise MemoryAirError("memory access write flag must be a bit")

    def tuple(self, modulus: int = BN254_BASE_FIELD) -> tuple[int, int, int, int]:
        return (
            self.address % modulus,
            self.timestamp % modulus,
            self.value % modulus,
            self.is_write,
        )


def _bits(value: int, width: int) -> tuple[int, ...]:
    if width <= 0 or not 0 <= value < 1 << width:
        raise MemoryAirError(f"value {value} does not fit {width} bits")
    return tuple((value >> index) & 1 for index in range(width))


def _bit_sum(prefix: str, width: int):
    expression = 0
    for index in range(width):
        expression = expression + (1 << index) * Current(f"{prefix}_bit_{index}")
    return expression


@dataclass(frozen=True, slots=True)
class SortedMemoryAir:
    sorted_accesses: tuple[MemoryAccess, ...]
    program: GenericAirProgram
    trace: GenericAirTrace
    address_bits: int
    timestamp_bits: int


def build_sorted_memory_air(
    accesses: Sequence[MemoryAccess],
    *,
    address_bits: int,
    timestamp_bits: int,
    modulus: int = BN254_BASE_FIELD,
) -> SortedMemoryAir:
    accesses = tuple(accesses)
    if len(accesses) < 2:
        raise MemoryAirError("memory trace must contain at least two accesses")
    if len({access.timestamp for access in accesses}) != len(accesses):
        raise MemoryAirError("memory access timestamps must be unique")
    sorted_accesses = tuple(sorted(accesses, key=lambda access: (access.address, access.timestamp)))
    rows = len(sorted_accesses)
    all_rows = tuple(range(rows))
    transition_rows = tuple(range(rows - 1))

    core_names = (
        "address",
        "timestamp",
        "value",
        "is_write",
        "before",
        "after",
        "same_address",
        "address_gap",
        "time_gap",
    )
    bit_names = tuple(
        [f"address_bit_{index}" for index in range(address_bits)]
        + [f"timestamp_bit_{index}" for index in range(timestamp_bits)]
        + [f"address_gap_bit_{index}" for index in range(address_bits)]
        + [f"time_gap_bit_{index}" for index in range(timestamp_bits)]
    )
    columns: dict[str, list[int]] = {name: [] for name in core_names + bit_names}

    previous_after_by_address: dict[int, int] = {}
    for row, access in enumerate(sorted_accesses):
        before = previous_after_by_address.get(access.address, 0)
        after = access.value % modulus if access.is_write else before
        previous_after_by_address[access.address] = after
        if row < rows - 1:
            following = sorted_accesses[row + 1]
            same = int(following.address == access.address)
            address_gap = 0 if same else following.address - access.address - 1
            time_gap = following.timestamp - access.timestamp - 1 if same else 0
            if address_gap < 0 or time_gap < 0:
                raise MemoryAirError("sorted memory order produced a negative gap")
        else:
            same = 0
            address_gap = 0
            time_gap = 0

        values = {
            "address": access.address,
            "timestamp": access.timestamp,
            "value": access.value % modulus,
            "is_write": access.is_write,
            "before": before,
            "after": after,
            "same_address": same,
            "address_gap": address_gap,
            "time_gap": time_gap,
        }
        for name, value in values.items():
            columns[name].append(value % modulus)
        for prefix, value, width in (
            ("address", access.address, address_bits),
            ("timestamp", access.timestamp, timestamp_bits),
            ("address_gap", address_gap, address_bits),
            ("time_gap", time_gap, timestamp_bits),
        ):
            for index, bit in enumerate(_bits(value, width)):
                columns[f"{prefix}_bit_{index}"].append(bit)

    constraints: list[AirConstraint] = []
    is_write = Current("is_write")
    same = Current("same_address")
    address = Current("address")
    timestamp = Current("timestamp")
    value = Current("value")
    before = Current("before")
    after = Current("after")
    address_gap = Current("address_gap")
    time_gap = Current("time_gap")

    constraints.extend(
        (
            AirConstraint("is-write-bit", is_write * (is_write - 1), all_rows),
            AirConstraint(
                "write-or-read-state-update",
                after - (is_write * value + (1 - is_write) * before),
                all_rows,
            ),
            AirConstraint(
                "read-observes-current-value",
                (1 - is_write) * (value - before),
                all_rows,
            ),
            AirConstraint(
                "address-decomposition", address - _bit_sum("address", address_bits), all_rows
            ),
            AirConstraint(
                "timestamp-decomposition",
                timestamp - _bit_sum("timestamp", timestamp_bits),
                all_rows,
            ),
            AirConstraint(
                "address-gap-decomposition",
                address_gap - _bit_sum("address_gap", address_bits),
                all_rows,
            ),
            AirConstraint(
                "time-gap-decomposition",
                time_gap - _bit_sum("time_gap", timestamp_bits),
                all_rows,
            ),
        )
    )
    for prefix, width in (
        ("address", address_bits),
        ("timestamp", timestamp_bits),
        ("address_gap", address_bits),
        ("time_gap", timestamp_bits),
    ):
        for index in range(width):
            bit = Current(f"{prefix}_bit_{index}")
            constraints.append(
                AirConstraint(f"{prefix}-bit-{index}", bit * (bit - 1), all_rows)
            )

    constraints.extend(
        (
            AirConstraint("same-address-bit", same * (same - 1), transition_rows),
            AirConstraint(
                "address-order",
                Next("address") - address - (1 - same) * (address_gap + 1),
                transition_rows,
            ),
            AirConstraint("same-address-zero-gap", same * address_gap, transition_rows),
            AirConstraint(
                "same-address-time-order",
                same * (Next("timestamp") - timestamp - time_gap - 1),
                transition_rows,
            ),
            AirConstraint("new-address-zero-time-gap", (1 - same) * time_gap, transition_rows),
            AirConstraint(
                "same-address-state-link",
                same * (Next("before") - after),
                transition_rows,
            ),
            AirConstraint(
                "new-address-initial-zero",
                (1 - same) * Next("before"),
                transition_rows,
            ),
        )
    )
    program = GenericAirProgram(
        tuple(columns),
        tuple(constraints),
        (BoundaryConstraint("before", 0, 0, "initial-memory-zero"),),
        modulus,
        schema="ranklock-sorted-memory-air-v1",
    )
    trace = GenericAirTrace(
        {name: tuple(values) for name, values in columns.items()}, modulus
    )
    return SortedMemoryAir(sorted_accesses, program, trace, address_bits, timestamp_bits)


@dataclass(frozen=True, slots=True)
class MemoryArgumentProof:
    permutation: TuplePermutationProof
    sorted_air: GenericAirProof
    address_bits: int
    timestamp_bits: int


def prove_memory_argument(
    accesses: Sequence[MemoryAccess],
    *,
    address_bits: int,
    timestamp_bits: int,
    eta: int,
    beta: int,
    zeta: int,
    srs: FormalKzgSrs,
) -> tuple[MemoryArgumentProof, SortedMemoryAir]:
    sorted_air = build_sorted_memory_air(
        accesses,
        address_bits=address_bits,
        timestamp_bits=timestamp_bits,
        modulus=srs.modulus,
    )
    unsorted_tuples = tuple(access.tuple(srs.modulus) for access in accesses)
    sorted_tuples = tuple(access.tuple(srs.modulus) for access in sorted_air.sorted_accesses)
    permutation = respond_tuple_permutation(
        commit_tuple_sequences(unsorted_tuples, sorted_tuples, srs=srs),
        eta=eta,
        beta=beta,
        zeta=zeta,
        srs=srs,
    )
    air_proof = prove_generic_air(
        sorted_air.program, sorted_air.trace, zeta=zeta, srs=srs
    ).proof
    return (
        MemoryArgumentProof(permutation, air_proof, address_bits, timestamp_bits),
        sorted_air,
    )


def verify_memory_argument(
    proof: MemoryArgumentProof,
    sorted_air_program: GenericAirProgram,
    *,
    srs: FormalKzgSrs,
) -> bool:
    return verify_tuple_permutation(proof.permutation, srs=srs) and verify_generic_air(
        sorted_air_program, proof.sorted_air, srs=srs
    )


def memory_argument_cost(
    sorted_air: SortedMemoryAir,
) -> dict[str, object]:
    air = generic_air_cost(sorted_air.program, len(sorted_air.sorted_accesses))
    permutation = tuple_permutation_cost(len(sorted_air.sorted_accesses), 4)
    return {
        "schema": "ranklock-memory-argument-cost-v1",
        "rows": len(sorted_air.sorted_accesses),
        "address_bits": sorted_air.address_bits,
        "timestamp_bits": sorted_air.timestamp_bits,
        "beacons": 2,
        "tuple_permutation": permutation,
        "sorted_air": air,
        "proof_shape_independent_of_rows": True,
        "remaining_assumptions": [
            "initial memory is zero",
            "timestamps are unique and bounded",
            "formal KZG model replaced by real binding PCS",
        ],
    }
