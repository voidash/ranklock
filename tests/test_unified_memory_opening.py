from __future__ import annotations

from dataclasses import replace

from ranklock.kzg_we_conjunction import (
    decapsulate_conjunction,
    encapsulate_conjunction,
)
from ranklock.memory_air import MemoryAccess
from ranklock.phased_memory import commit_memory_argument
from ranklock.ppe_normal_form import FormalKzgSrs
from ranklock.unified_memory_opening import (
    batch_published_openings,
    commit_unified_memory_phase_two,
    open_unified_memory,
    publish_opening_values,
    unified_opening_inventory,
    verify_unified_memory,
)


def accesses() -> tuple[MemoryAccess, ...]:
    return (
        MemoryAccess(1, 0, 5, 1),
        MemoryAccess(1, 1, 5, 0),
        MemoryAccess(2, 2, 7, 1),
        MemoryAccess(2, 3, 7, 0),
        MemoryAccess(1, 4, 9, 1),
        MemoryAccess(1, 5, 9, 0),
    )


def test_unified_second_beacon_opens_air_and_permutation_at_same_zeta() -> None:
    srs = FormalKzgSrs(tau=1051)
    committed = commit_memory_argument(
        accesses(), address_bits=4, timestamp_bits=4, srs=srs
    )
    phase_two = commit_unified_memory_phase_two(
        committed, beacon_one=bytes.fromhex("81" * 32), srs=srs
    )
    proof = open_unified_memory(
        phase_two, beacon_two=bytes.fromhex("82" * 32), srs=srs
    )
    assert proof.air.zeta == proof.permutation.zeta == proof.zeta
    assert verify_unified_memory(proof, srs=srs)


def test_complete_memory_openings_batch_to_four_points_and_decrypt() -> None:
    srs = FormalKzgSrs(tau=1061)
    committed = commit_memory_argument(
        accesses(), address_bits=4, timestamp_bits=4, srs=srs
    )
    proof = open_unified_memory(
        commit_unified_memory_phase_two(
            committed, beacon_one=bytes.fromhex("83" * 32), srs=srs
        ),
        beacon_two=bytes.fromhex("84" * 32),
        srs=srs,
    )
    publication = publish_opening_values(proof)
    batched = batch_published_openings(
        publication, beacon_three=bytes.fromhex("85" * 32), srs=srs
    )
    inventory = unified_opening_inventory(proof, batched)
    assert inventory["raw_kzg_openings"] > 20
    assert inventory["batched_kzg_openings"] == 4
    assert sorted(batched.group_sizes) == sorted(inventory["batch_group_sizes"])
    message = b"ranklock-static-authority-target"
    ciphertext = encapsulate_conjunction(
        batched.statements,
        message,
        randomizers=(107, 109, 113, 127),
        srs=srs,
    )
    assert decapsulate_conjunction(ciphertext, batched.witnesses, srs=srs) == message


def test_unified_transcript_or_opening_tampering_fails() -> None:
    srs = FormalKzgSrs(tau=1063)
    committed = commit_memory_argument(
        accesses(), address_bits=4, timestamp_bits=4, srs=srs
    )
    proof = open_unified_memory(
        commit_unified_memory_phase_two(
            committed, beacon_one=bytes.fromhex("86" * 32), srs=srs
        ),
        beacon_two=bytes.fromhex("87" * 32),
        srs=srs,
    )
    assert not verify_unified_memory(replace(proof, zeta=proof.zeta + 1), srs=srs)
    current = dict(proof.air.current_openings)
    first = next(iter(current))
    current[first] = replace(current[first], value=current[first].value + 1)
    tampered = replace(proof, air=replace(proof.air, current_openings=current))
    assert not verify_unified_memory(tampered, srs=srs)
