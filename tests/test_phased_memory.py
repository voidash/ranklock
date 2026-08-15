from __future__ import annotations

from dataclasses import replace

from ranklock.generic_air import prove_generic_air
from ranklock.memory_air import (
    MemoryAccess,
    MemoryArgumentProof,
    build_sorted_memory_air,
    verify_memory_argument,
)
from ranklock.phased_memory import (
    commit_memory_argument,
    open_memory_argument,
    verify_phased_memory_argument,
)
from ranklock.ppe_normal_form import FormalKzgSrs
from ranklock.tuple_permutation import (
    commit_tuple_sequences,
    respond_tuple_permutation,
)


def _valid_accesses() -> tuple[MemoryAccess, ...]:
    return (
        MemoryAccess(1, 0, 5, 1),
        MemoryAccess(1, 1, 5, 0),
        MemoryAccess(2, 2, 7, 1),
        MemoryAccess(2, 3, 7, 0),
        MemoryAccess(1, 4, 9, 1),
        MemoryAccess(1, 5, 9, 0),
    )


def _other_valid_accesses() -> tuple[MemoryAccess, ...]:
    return (
        MemoryAccess(3, 0, 12, 1),
        MemoryAccess(3, 1, 12, 0),
        MemoryAccess(4, 2, 15, 1),
        MemoryAccess(4, 3, 15, 0),
        MemoryAccess(3, 4, 21, 1),
        MemoryAccess(3, 5, 21, 0),
    )


def test_legacy_memory_bundle_accepts_unrelated_permutation_and_air_tables() -> None:
    srs = FormalKzgSrs(tau=809)
    # This access multiset contains a bad read.  The permutation proof merely
    # proves it equals itself; it is not linked to the unrelated valid AIR below.
    bad = list(_valid_accesses())
    bad[1] = MemoryAccess(1, 1, 6, 0)
    bad_tuples = tuple(access.tuple(srs.modulus) for access in bad)
    permutation = respond_tuple_permutation(
        commit_tuple_sequences(bad_tuples, bad_tuples, srs=srs),
        eta=43,
        beta=47,
        zeta=101,
        srs=srs,
    )
    unrelated = build_sorted_memory_air(
        _valid_accesses(), address_bits=4, timestamp_bits=4
    )
    air = prove_generic_air(
        unrelated.program, unrelated.trace, zeta=101, srs=srs
    ).proof
    forged_bundle = MemoryArgumentProof(permutation, air, 4, 4)
    assert verify_memory_argument(forged_bundle, unrelated.program, srs=srs)


def test_phased_memory_accepts_valid_trace_and_binds_shared_commitments() -> None:
    srs = FormalKzgSrs(tau=811)
    state = commit_memory_argument(
        _valid_accesses(), address_bits=4, timestamp_bits=4, srs=srs
    )
    proof = open_memory_argument(
        state,
        beacon_one=bytes.fromhex("51" * 32),
        beacon_two=bytes.fromhex("52" * 32),
        srs=srs,
    )
    assert verify_phased_memory_argument(proof, state.sorted_air.program, srs=srs)


def test_mixing_permutation_and_air_from_two_valid_tables_is_rejected() -> None:
    srs = FormalKzgSrs(tau=821)
    first = commit_memory_argument(
        _valid_accesses(), address_bits=4, timestamp_bits=4, srs=srs
    )
    second = commit_memory_argument(
        _other_valid_accesses(), address_bits=4, timestamp_bits=4, srs=srs
    )
    beacon_one = bytes.fromhex("61" * 32)
    beacon_two = bytes.fromhex("62" * 32)
    proof_first = open_memory_argument(
        first, beacon_one=beacon_one, beacon_two=beacon_two, srs=srs
    )
    proof_second = open_memory_argument(
        second, beacon_one=beacon_one, beacon_two=beacon_two, srs=srs
    )
    mixed = replace(proof_first, sorted_air=proof_second.sorted_air)
    assert not verify_phased_memory_argument(
        mixed, first.sorted_air.program, srs=srs
    )
