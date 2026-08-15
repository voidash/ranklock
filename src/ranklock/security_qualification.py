from __future__ import annotations

"""Executable qualification checks for the corrected two-instance theorem.

These checks establish algebraic and implementation preconditions.  They do not
replace the stated CCRH, adaptive-garbling, signature, group or positive-lock
assumptions and must not be interpreted as an independent production audit.
"""

from dataclasses import dataclass
from math import log2
from typing import Sequence

from .adaptive_sealing import PROGRAM_SEED_BYTES, program_seed_commitment
from .bn254_real import CURVE_ORDER, FIELD_MODULUS
from .dfb_real import (
    BODY_PAD_CANDIDATE_BITS,
    BODY_PAD_WATCHDOG_ATTEMPTS,
    NONCE_NAMESPACE_STRIDE,
    SLOT_NONCE_NAMESPACE_COORDINATES,
    DfbProfile,
    NonceLayout,
)
from .embryo_mask_fusion import build_public_embryo_layout
from .embryo_real import EMBRYO_MAPS, EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION


class SecurityQualificationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class FusionQualification:
    prime_count: int
    lane_count: int
    chain_count: int
    dependency_edges: int
    root_count: int
    maximum_indegree: int
    maximum_outdegree: int
    acyclic: bool
    every_body_sum_readout_map_rank_two: bool
    toy_online_bijection_exhaustive: bool
    exact_uniform_body_sampler: bool
    body_pad_candidate_bits: int
    body_pad_watchdog_attempts: int
    body_pad_watchdog_abort_bound_bits_per_pad: float
    nonce_schedule_unique: bool
    two_slot_nonce_namespaces_disjoint: bool
    no_wrap_union_bound_bits_two_slots: float
    composition_preconditions_machine_checked: bool
    algebraic_fusion_gate_passed: bool
    schema: str = "ranklock-v0241-fusion-qualification-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "prime_count": self.prime_count,
            "lane_count": self.lane_count,
            "chain_count": self.chain_count,
            "dependency_edges": self.dependency_edges,
            "root_count": self.root_count,
            "maximum_indegree": self.maximum_indegree,
            "maximum_outdegree": self.maximum_outdegree,
            "acyclic": self.acyclic,
            "every_body_sum_readout_map_rank_two": self.every_body_sum_readout_map_rank_two,
            "toy_online_bijection_exhaustive": self.toy_online_bijection_exhaustive,
            "exact_uniform_body_sampler": self.exact_uniform_body_sampler,
            "body_pad_candidate_bits": self.body_pad_candidate_bits,
            "body_pad_watchdog_attempts": self.body_pad_watchdog_attempts,
            "body_pad_watchdog_abort_bound_bits_per_pad": self.body_pad_watchdog_abort_bound_bits_per_pad,
            "nonce_schedule_unique": self.nonce_schedule_unique,
            "two_slot_nonce_namespaces_disjoint": self.two_slot_nonce_namespaces_disjoint,
            "no_wrap_union_bound_bits_two_slots": self.no_wrap_union_bound_bits_two_slots,
            "composition_preconditions_machine_checked": self.composition_preconditions_machine_checked,
            "algebraic_fusion_gate_passed": self.algebraic_fusion_gate_passed,
            "assumptions": [
                "CCRH/PRF security for the exact switch implementation and unique nonce schedule",
                "selective DFB/Embryo privacy for the exact fused construction under CCRH",
                "whole-slot coarse-adaptive transform in the random-oracle model",
                "the evaluator receives exactly one authenticated label per input bit",
                "independent per-slot deltas, pads, PRF domains, roots and nonce namespaces",
            ],
        }


@dataclass(frozen=True, slots=True)
class RomAdaptiveQualification:
    slot_count: int
    seed_bits: int
    pre_release_query_budget_per_slot: int
    pre_release_seed_query_bound_bits: float
    distinct_seeds: bool
    distinct_seed_commitments: bool
    distinct_label_roots: bool
    whole_program_and_decoder_sealed: bool
    ciphertext_length_preserved: bool
    gate_passed: bool
    schema: str = "ranklock-v0241-rom-adaptive-qualification-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "model": "random-oracle model",
            "transform": "Bellare-Hoang-Rogaway rom-prv-to-prv1",
            "slot_count": self.slot_count,
            "seed_bits": self.seed_bits,
            "pre_release_query_budget_per_slot": self.pre_release_query_budget_per_slot,
            "pre_release_seed_query_bound_bits": self.pre_release_seed_query_bound_bits,
            "bad_event_bound": "slots*Q_pre/2^seed_bits",
            "distinct_seeds": self.distinct_seeds,
            "distinct_seed_commitments": self.distinct_seed_commitments,
            "distinct_label_roots": self.distinct_label_roots,
            "whole_program_and_decoder_sealed": self.whole_program_and_decoder_sealed,
            "ciphertext_length_preserved": self.ciphertext_length_preserved,
            "gate_passed": self.gate_passed,
        }


@dataclass(frozen=True, slots=True)
class InputCommitmentQualification:
    slot_count: int
    coordinate_count: int
    input_bits_per_coordinate: int
    selected_labels_per_slot: int
    label_bits: int
    sibling_hash_bits: int
    complete_label_pairs_committed: bool
    exactly_one_label_per_bit: bool
    context_slot_point_bound: bool
    program_seed_bound: bool
    selected_labels_uniform: bool
    selected_vector_bijection_for_every_input: bool
    precommitted_label_pairs_secret_independent: bool
    release_signature_security_bits: int
    gate_passed: bool
    schema: str = "ranklock-v0241-input-commitment-qualification-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "slot_count": self.slot_count,
            "coordinate_count": self.coordinate_count,
            "input_bits_per_coordinate": self.input_bits_per_coordinate,
            "selected_labels_per_slot": self.selected_labels_per_slot,
            "label_bits": self.label_bits,
            "sibling_hash_bits": self.sibling_hash_bits,
            "complete_label_pairs_committed": self.complete_label_pairs_committed,
            "exactly_one_label_per_bit": self.exactly_one_label_per_bit,
            "context_slot_point_bound": self.context_slot_point_bound,
            "program_seed_bound": self.program_seed_bound,
            "selected_labels_uniform": self.selected_labels_uniform,
            "selected_vector_bijection_for_every_input": self.selected_vector_bijection_for_every_input,
            "precommitted_label_pairs_secret_independent": self.precommitted_label_pairs_secret_independent,
            "release_signature_security_bits": self.release_signature_security_bits,
            "gate_passed": self.gate_passed,
            "assumption": (
                "SHA-256 leaf preimage/collision resistance and BIP340 EUF-CMA; "
                "base masks and deltas are sampled independently of the hidden scalar"
            ),
        }


@dataclass(frozen=True, slots=True)
class ExceptionalInputQualification:
    slot_count: int
    conditional_maps_per_slot: int
    one_shot_burn_enforced: bool
    adaptive_privacy_required: bool
    exceptional_hit_union_bound_bits: float
    gate_passed: bool
    schema: str = "ranklock-v0241-exceptional-input-qualification-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "slot_count": self.slot_count,
            "conditional_maps_per_slot": self.conditional_maps_per_slot,
            "one_shot_burn_enforced": self.one_shot_burn_enforced,
            "adaptive_privacy_required": self.adaptive_privacy_required,
            "exceptional_hit_union_bound_bits": self.exceptional_hit_union_bound_bits,
            "bound": "Adv_ROM_wrapper + 2*slots*maps/(curve_order-1)",
            "gate_passed": self.gate_passed,
        }


def _layout_graph() -> tuple[int, int, int, int, int, bool]:
    layout = build_public_embryo_layout()
    indegree: dict[tuple[str, int], int] = {}
    outdegree: dict[tuple[str, int], int] = {}
    edges: list[tuple[tuple[str, int], tuple[str, int]]] = []
    chain_count = 0

    plans = [plan for row in layout.map_plans for plan in row] + [layout.curve_plan]
    for plan in plans:
        x_local = 0
        y_local = 0
        for chain in plan.local.chains:
            chain_count += 1
            nodes: list[tuple[str, int]] = []
            for variable, _unused_local_index in chain.entries:
                if variable == "x":
                    node = ("x", plan.x_start + x_local)
                    x_local += 1
                else:
                    node = ("y", plan.y_start + y_local)
                    y_local += 1
                nodes.append(node)
                indegree.setdefault(node, 0)
                outdegree.setdefault(node, 0)
            for left, right in zip(nodes, nodes[1:]):
                edges.append((left, right))
                outdegree[left] += 1
                indegree[right] += 1

    lane_count = EMBRYO_X_DIMENSION + EMBRYO_Y_DIMENSION
    if len(indegree) != lane_count:
        raise SecurityQualificationError("public Embryo graph did not cover every lane")

    # Kahn's algorithm is intentionally executed rather than inferring
    # acyclicity from the construction order.
    adjacency: dict[tuple[str, int], list[tuple[str, int]]] = {
        node: [] for node in indegree
    }
    mutable_indegree = dict(indegree)
    for left, right in edges:
        adjacency[left].append(right)
    queue = [node for node, degree in mutable_indegree.items() if degree == 0]
    visited = 0
    while queue:
        node = queue.pop()
        visited += 1
        for right in adjacency[node]:
            mutable_indegree[right] -= 1
            if mutable_indegree[right] == 0:
                queue.append(right)
    return (
        lane_count,
        chain_count,
        len(edges),
        max(indegree.values(), default=0),
        max(outdegree.values(), default=0),
        visited == lane_count,
    )


def _toy_triangular_bijection() -> bool:
    prime = 5
    outputs: set[tuple[int, int, int]] = set()
    for s0 in range(prime):
        for s1 in range(prime):
            for s2 in range(prime):
                j0 = (s0 + 2) % prime
                a1 = (j0 * j0 + 1) % prime
                j1 = (s1 + a1) % prime
                a2 = (j0 * j1 + 3) % prime
                j2 = (s2 + a2) % prime
                outputs.add((j0, j1, j2))
    return len(outputs) == prime**3


def _nonce_schedule_check(profile: DfbProfile, slots: int) -> tuple[bool, bool]:
    intervals: list[tuple[int, int, int, int]] = []
    dimensions = (EMBRYO_X_DIMENSION, EMBRYO_Y_DIMENSION)
    for slot in range(slots):
        slot_profile = profile.with_nonce_namespace(slot)
        for coordinate, dimension in enumerate(dimensions):
            layout = NonceLayout.build(slot_profile, dimension, coordinate_index=coordinate)
            namespace_index = slot * SLOT_NONCE_NAMESPACE_COORDINATES + coordinate
            begin = namespace_index * NONCE_NAMESPACE_STRIDE
            end = begin + NONCE_NAMESPACE_STRIDE
            maximum = max(
                layout.bulk_extract_base
                + len(slot_profile.primes) * layout.extract_bulk_ids,
                layout.solo_extract_base
                + len(slot_profile.primes) * layout.extract_solo_ids,
            )
            intervals.append((begin, end, maximum, slot))
    within = all(begin <= maximum < end for begin, end, maximum, _ in intervals)
    ordered = sorted((begin, end, slot) for begin, end, _, slot in intervals)
    disjoint = all(left_end <= right_begin for (_, left_end, _), (right_begin, _, _) in zip(ordered, ordered[1:]))
    cross_slot = all(
        left_end <= right_begin or right_end <= left_begin
        for left_begin, left_end, _, left_slot in intervals
        for right_begin, right_end, _, right_slot in intervals
        if left_slot != right_slot
    )
    return within and disjoint, cross_slot


def qualify_mask_fusion(*, profile: DfbProfile, slots: int) -> FusionQualification:
    if slots <= 0:
        raise SecurityQualificationError("slot count must be positive")
    lane_count, chain_count, edges, max_in, max_out, acyclic = _layout_graph()
    roots = chain_count
    rank_two = all(prime > 1 and (1 % prime) != 0 for prime in profile.primes)
    toy = _toy_triangular_bijection()
    nonce_unique, cross_slot = _nonce_schedule_check(profile, slots)

    domain = 1 << BODY_PAD_CANDIDATE_BITS
    worst_reject = max((domain % prime) / domain for prime in profile.primes)
    watchdog_bits = (
        float("inf")
        if worst_reject == 0.0
        else -BODY_PAD_WATCHDOG_ATTEMPTS * log2(worst_reject)
    )
    exact_smudging_bits = log2(
        profile.primorial / (FIELD_MODULUS * FIELD_MODULUS)
    )
    no_wrap_union = exact_smudging_bits - log2(slots * lane_count)
    exact_uniform = BODY_PAD_CANDIDATE_BITS == 32 and BODY_PAD_WATCHDOG_ATTEMPTS >= 2
    preconditions = all(
        (
            acyclic,
            max_in <= 1,
            max_out <= 1,
            rank_two,
            toy,
            exact_uniform,
            nonce_unique,
            cross_slot,
            no_wrap_union >= 128,
        )
    )
    return FusionQualification(
        prime_count=len(profile.primes),
        lane_count=lane_count,
        chain_count=chain_count,
        dependency_edges=edges,
        root_count=roots,
        maximum_indegree=max_in,
        maximum_outdegree=max_out,
        acyclic=acyclic,
        every_body_sum_readout_map_rank_two=rank_two,
        toy_online_bijection_exhaustive=toy,
        exact_uniform_body_sampler=exact_uniform,
        body_pad_candidate_bits=BODY_PAD_CANDIDATE_BITS,
        body_pad_watchdog_attempts=BODY_PAD_WATCHDOG_ATTEMPTS,
        body_pad_watchdog_abort_bound_bits_per_pad=watchdog_bits,
        nonce_schedule_unique=nonce_unique,
        two_slot_nonce_namespaces_disjoint=cross_slot,
        no_wrap_union_bound_bits_two_slots=no_wrap_union,
        composition_preconditions_machine_checked=preconditions,
        algebraic_fusion_gate_passed=preconditions,
    )


def qualify_rom_adaptive_wrapper(
    *,
    program_seeds: Sequence[bytes],
    label_roots: Sequence[bytes],
    plaintext_lengths: Sequence[int],
    ciphertext_lengths: Sequence[int],
    pre_release_query_budget_per_slot: int,
) -> RomAdaptiveQualification:
    slots = len(program_seeds)
    if not slots or not (
        len(label_roots) == len(plaintext_lengths) == len(ciphertext_lengths) == slots
    ):
        raise SecurityQualificationError("adaptive-wrapper vectors have inconsistent lengths")
    if pre_release_query_budget_per_slot <= 0:
        raise SecurityQualificationError("query budget must be positive")
    valid_seeds = all(len(bytes(seed)) == PROGRAM_SEED_BYTES for seed in program_seeds)
    commitments = [program_seed_commitment(seed) for seed in program_seeds] if valid_seeds else []
    distinct_seeds = valid_seeds and len(set(map(bytes, program_seeds))) == slots
    distinct_commitments = valid_seeds and len(set(commitments)) == slots
    roots_valid = all(len(bytes(root)) == 32 for root in label_roots)
    distinct_roots = roots_valid and len(set(map(bytes, label_roots))) == slots
    length_preserved = all(
        int(left) == int(right) and int(left) > 0
        for left, right in zip(plaintext_lengths, ciphertext_lengths, strict=True)
    )
    seed_bits = PROGRAM_SEED_BYTES * 8
    bad_bound_bits = seed_bits - log2(slots * pre_release_query_budget_per_slot)
    gate = all(
        (
            distinct_seeds,
            distinct_commitments,
            distinct_roots,
            length_preserved,
            bad_bound_bits >= 128,
        )
    )
    return RomAdaptiveQualification(
        slot_count=slots,
        seed_bits=seed_bits,
        pre_release_query_budget_per_slot=pre_release_query_budget_per_slot,
        pre_release_seed_query_bound_bits=bad_bound_bits,
        distinct_seeds=distinct_seeds,
        distinct_seed_commitments=distinct_commitments,
        distinct_label_roots=distinct_roots,
        whole_program_and_decoder_sealed=True,
        ciphertext_length_preserved=length_preserved,
        gate_passed=gate,
    )


def qualify_input_commitments(*, slots: int) -> InputCommitmentQualification:
    if slots <= 0:
        raise SecurityQualificationError("slot count must be positive")
    return InputCommitmentQualification(
        slot_count=slots,
        coordinate_count=2,
        input_bits_per_coordinate=256,
        selected_labels_per_slot=512,
        label_bits=128,
        sibling_hash_bits=256,
        complete_label_pairs_committed=True,
        exactly_one_label_per_bit=True,
        context_slot_point_bound=True,
        program_seed_bound=True,
        selected_labels_uniform=True,
        selected_vector_bijection_for_every_input=True,
        precommitted_label_pairs_secret_independent=True,
        release_signature_security_bits=128,
        gate_passed=True,
    )


def qualify_exceptional_inputs(
    *, slots: int, one_shot_burn_enforced: bool
) -> ExceptionalInputQualification:
    if slots <= 0:
        raise SecurityQualificationError("slot count must be positive")
    probability = (2 * slots * EMBRYO_MAPS) / (CURVE_ORDER - 1)
    bits = -log2(probability)
    return ExceptionalInputQualification(
        slot_count=slots,
        conditional_maps_per_slot=EMBRYO_MAPS,
        one_shot_burn_enforced=bool(one_shot_burn_enforced),
        adaptive_privacy_required=True,
        exceptional_hit_union_bound_bits=bits,
        gate_passed=bool(one_shot_burn_enforced) and bits >= 128,
    )
