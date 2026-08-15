from __future__ import annotations

"""Static projective-input + linearly-verifiable witness-encryption prototype.

Unlike :mod:`ranklock.hybrid_conditional_lock`, this construction creates its only
ciphertext *before* the future byte vector or proof witness exists.  It works because
both components are expressed as one fixed inner-product relation:

    input relation:
        sum_i (t_i P_i + v_i Q_i) = T_input

    trace relation:
        sum_j w_j R_j = T_trace

    combined relation:
        sum_i (...) + sum_j w_j R_j = T_input + T_trace.

The byte witness ``(v_i,t_i)`` is obtained later through the real one-shot OT path.
The trace relation is deliberately a generic *linear* relation; it is not yet the
RankVM invalidity relation.  The module therefore proves an important architectural
fact, not the final theorem: a fixed linearly-verifiable relation removes the
post-statement KZG encapsulator entirely and admits a constant-size ciphertext.  The
remaining research problem is compiling the real invalidity verifier into such a
relation with acceptable CRS/key size and malicious setup.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable, Sequence

from .inner_product_we import InnerProductCiphertext, InnerProductRelation
from .batched_inner_product_we import (
    BatchedInnerProductWeKey,
    decrypt_batched_inner_product_we,
    setup_batched_inner_product_we,
)
from .projective_vole_lock import (
    ProjectiveLockPublic,
    ProjectiveVoleSender,
    ProjectiveWitness,
    setup_projective_lock,
)
from .real_secp import (
    N,
    DeterministicScalars,
    Point,
    add,
    base_multiply,
    compress,
    decompress,
    multiply,
)


class StaticLinearConjunctionError(RuntimeError):
    pass


def _point_sum(points: Sequence[Point]) -> Point:
    result: Point = None
    for point in points:
        result = add(result, point)
    return result


def _input_relation(public: ProjectiveLockPublic) -> InnerProductRelation:
    bases: list[bytes] = []
    for coordinate in public.coordinates:
        bases.extend((coordinate.p, coordinate.q))
    return InnerProductRelation(
        tuple(bases),
        public.target,
        context=(b"ranklock/static-linear/input/v1\x00" + public.session_id),
    )


def input_witness(projective_witness: ProjectiveWitness) -> tuple[int, ...]:
    result: list[int] = []
    for value, scalar in zip(
        projective_witness.values,
        projective_witness.selected_scalars,
        strict=True,
    ):
        result.extend((int(scalar) % N, int(value)))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class LinearTraceRelation:
    bases: tuple[bytes, ...]
    target: bytes
    relation_id: bytes
    schema: str = "ranklock-static-linear-trace-relation-v1"

    def __post_init__(self) -> None:
        if not self.bases:
            raise StaticLinearConjunctionError("linear trace relation is empty")
        for base in self.bases:
            decompress(base)
        decompress(self.target)
        if len(self.relation_id) != 32:
            raise StaticLinearConjunctionError("trace relation id must be 32 bytes")

    @property
    def width(self) -> int:
        return len(self.bases)

    def accepts(self, witness: Sequence[int]) -> bool:
        if len(witness) != self.width:
            return False
        result = _point_sum(
            tuple(
                multiply(decompress(base), int(value) % N)
                for base, value in zip(self.bases, witness, strict=True)
            )
        )
        return result == decompress(self.target)

    @classmethod
    def derive_for_witness(
        cls,
        witness: Sequence[int],
        *,
        domain: bytes = b"ranklock-static-linear-trace-example",
    ) -> "LinearTraceRelation":
        values = tuple(int(value) % N for value in witness)
        if not values:
            raise StaticLinearConjunctionError("trace witness is empty")
        bases = tuple(
            compress(base_multiply(i + 1009)) for i in range(len(values))
        )
        target = _point_sum(
            tuple(
                multiply(decompress(base), value)
                for base, value in zip(bases, values, strict=True)
            )
        )
        if target is None:
            raise StaticLinearConjunctionError("trace relation target is infinity")
        relation_id = sha256(
            b"ranklock/static-linear/trace-id/v1\x00"
            + bytes(domain)
            + b"".join(base for base in bases)
            + compress(target)
        ).digest()
        return cls(bases, compress(target), relation_id)


@dataclass(frozen=True, slots=True)
class StaticLinearConjunctionPublic:
    projective_public: ProjectiveLockPublic
    trace_relation: LinearTraceRelation
    we_key: BatchedInnerProductWeKey
    ciphertext: InnerProductCiphertext
    schema: str = "ranklock-static-linear-conjunction-v1"

    @property
    def relation_width(self) -> int:
        return 2 * self.projective_public.input_bytes + self.trace_relation.width

    @property
    def retained_bytes(self) -> int:
        # The projective public object includes its unused zero-share ciphertext and
        # scaled points from the standalone lock.  This makes the count conservative;
        # a dedicated compiler can remove those fields.
        return (
            self.projective_public.preprocessed_bytes
            + self.we_key.encoded_bytes
            + self.ciphertext.encoded_bytes
            + 32  # relation id
        )


@dataclass(slots=True)
class StaticLinearConjunctionSetup:
    public: StaticLinearConjunctionPublic
    projective_sender: ProjectiveVoleSender


def setup_static_linear_conjunction(
    secret: bytes,
    trace_relation: LinearTraceRelation,
    *,
    input_bytes: int,
    seed: bytes = b"ranklock-static-linear-conjunction-v1",
) -> StaticLinearConjunctionSetup:
    secret = bytes(secret)
    if len(secret) != 32:
        raise StaticLinearConjunctionError("protected secret must be 32 bytes")
    # The standalone projective ciphertext protects zeros and is not used by the
    # conjunction.  Its OT setup supplies future authenticated input witnesses.
    projective_public, sender = setup_projective_lock(
        bytes(32),
        input_bytes=input_bytes,
        seed=bytes(seed) + b"/input",
    )
    input_relation = _input_relation(projective_public)
    combined_target = add(
        decompress(input_relation.target), decompress(trace_relation.target)
    )
    if combined_target is None:
        raise StaticLinearConjunctionError("combined relation target is infinity")
    combined_relation = InnerProductRelation(
        input_relation.bases + trace_relation.bases,
        compress(combined_target),
        context=(
            b"ranklock/static-linear/combined/v1\x00"
            + projective_public.session_id
            + trace_relation.relation_id
        ),
    )
    source = DeterministicScalars(bytes(seed) + b"/we")
    key, ciphertext = setup_batched_inner_product_we(
        combined_relation,
        secret,
        scalar_source=source,
    )
    return StaticLinearConjunctionSetup(
        StaticLinearConjunctionPublic(
            projective_public, trace_relation, key, ciphertext
        ),
        sender,
    )


def decrypt_static_linear_conjunction(
    public: StaticLinearConjunctionPublic,
    projective_witness: ProjectiveWitness,
    trace_witness: Sequence[int],
) -> bytes:
    if len(projective_witness.values) != public.projective_public.input_bytes:
        raise StaticLinearConjunctionError("projective witness dimensions differ")
    witness = input_witness(projective_witness) + tuple(
        int(value) % N for value in trace_witness
    )
    try:
        return decrypt_batched_inner_product_we(public.we_key, public.ciphertext, witness)
    except Exception as exc:
        raise StaticLinearConjunctionError(
            "combined projective/trace witness does not satisfy the fixed relation"
        ) from exc


def static_relation_frontier(
    *,
    input_bytes: int = 132,
    trace_width: int = 32,
) -> dict[str, object]:
    relation_width = 2 * int(input_bytes) + int(trace_width)
    # Batched key counts original/scaled bases plus one aggregate DLEQ proof.
    approximate_we_key_bytes = 130 + relation_width * (33 + 33)
    return {
        "schema": "ranklock-static-linear-relation-frontier-v1",
        "future_input_bytes": int(input_bytes),
        "input_relation_scalars": 2 * int(input_bytes),
        "trace_relation_width": int(trace_width),
        "combined_relation_width": relation_width,
        "constant_ciphertext_bytes": 48,
        "reference_we_key_bytes": approximate_we_key_bytes,
        "post_statement_encapsulator_required": False,
        "what_is_real": [
            "real secp256k1 group relation",
            "real aggregate-DLEQ-verified static inner-product WE key",
            "real one-shot OT-derived future byte witness",
            "constant-size AEAD ciphertext",
        ],
        "remaining_breakthrough_gap": (
            "compile RankVM invalidity, Fiat-Shamir/beacon binding, memory and "
            "opening checks into a linearly verifiable relation whose total "
            "relation key/CRS is acceptably small"
        ),
    }

@dataclass(frozen=True, slots=True)
class StaticLinearBenchmark:
    input_bytes: int
    trace_width: int
    relation_width: int
    retained_bytes: int
    projective_offer_bytes: int
    runtime_request_bytes: int
    runtime_response_bytes: int
    runtime_total_bytes: int
    setup_seconds: float
    request_seconds: float
    response_seconds: float
    finalize_seconds: float
    decrypt_seconds: float
    secret_recovered: bool

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-static-linear-conjunction-benchmark-v1",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
            "security_boundary": [
                "The trace predicate is a fixed linear relation, not RankVM invalidity.",
                "The binary OT is the online Chou-Orlandi measurement baseline.",
                "The relation key is linear in wrapper width but independent of execution rows.",
                "No post-statement secret holder or KZG encapsulator is used.",
            ],
        }


def benchmark_static_linear_conjunction(
    values: bytes,
    trace_witness: Sequence[int],
    *,
    seed: bytes = b"ranklock-static-linear-benchmark-v1",
) -> StaticLinearBenchmark:
    from time import perf_counter

    from .projective_vole_lock import ProjectiveVoleReceiver

    values = bytes(values)
    trace_values = tuple(int(value) % N for value in trace_witness)
    secret = sha256(
        b"ranklock/static-linear/benchmark-secret/v1\x00" + values
    ).digest()
    relation = LinearTraceRelation.derive_for_witness(
        trace_values, domain=bytes(seed) + b"/trace"
    )
    started = perf_counter()
    setup = setup_static_linear_conjunction(
        secret,
        relation,
        input_bytes=len(values),
        seed=seed,
    )
    setup_seconds = perf_counter() - started
    started = perf_counter()
    receiver = ProjectiveVoleReceiver(
        setup.public.projective_public,
        values,
        scalar_source=DeterministicScalars(bytes(seed) + b"/receiver"),
    )
    request_seconds = perf_counter() - started
    started = perf_counter()
    response = setup.projective_sender.respond(receiver.request)
    response_seconds = perf_counter() - started
    started = perf_counter()
    projective_witness = receiver.finalize(response)
    finalize_seconds = perf_counter() - started
    started = perf_counter()
    recovered = decrypt_static_linear_conjunction(
        setup.public, projective_witness, trace_values
    )
    decrypt_seconds = perf_counter() - started
    request_bytes = sum(len(item.encode()) for item in receiver.request.requests)
    response_bytes = response.encoded_bytes
    return StaticLinearBenchmark(
        input_bytes=len(values),
        trace_width=len(trace_values),
        relation_width=setup.public.relation_width,
        retained_bytes=setup.public.retained_bytes,
        projective_offer_bytes=setup.public.projective_public.offer_bytes,
        runtime_request_bytes=request_bytes,
        runtime_response_bytes=response_bytes,
        runtime_total_bytes=request_bytes + response_bytes,
        setup_seconds=setup_seconds,
        request_seconds=request_seconds,
        response_seconds=response_seconds,
        finalize_seconds=finalize_seconds,
        decrypt_seconds=decrypt_seconds,
        secret_recovered=recovered == secret,
    )
