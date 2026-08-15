from __future__ import annotations

"""Concrete OT-to-projective-input lock for RankLock's 132 future bytes.

The construction implements the algebraic interface used by the fixed authenticated-
witness route.  It is a real group/AEAD experiment, but its binary OT backend is the
Chou--Orlandi measurement baseline from :mod:`ranklock.co_ot`, not the final
malicious-receiver-secure Duty-Free-Bits instantiation.

For coordinate ``i`` and selected byte ``v_i`` the receiver obtains

    t_i = q_i + v_i b_i  (mod n).

The public points satisfy ``Q_i=-b_i P_i`` and ``U_i=q_i P_i``.  Setup samples one
secret ``s`` and publishes ``sP_i`` and ``sQ_i``.  Consequently

    sum_i (t_i sP_i + v_i sQ_i) = s sum_i U_i = sT,

which decrypts a fixed target share independent of the future byte vector.  OT message
commitments bind every possible selected scalar and prevent a malicious sender from
silently changing the authenticated witness.
"""

from dataclasses import dataclass, replace
from hashlib import sha256
from time import perf_counter
from typing import Callable, Sequence

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .co_ot import OtOffer, OtReceiver, OtRequest, OtResponse, OtSender, transcript_cost
from .real_secp import (
    G,
    N,
    DleqProof,
    DeterministicScalars,
    Point,
    SecpError,
    add,
    base_multiply,
    compress,
    decompress,
    hash_point,
    multiply,
    negate,
    prove_dleq,
    verify_dleq,
)

BYTE_BITS = 8
DEFAULT_INPUT_BYTES = 132


class ProjectiveVoleError(RuntimeError):
    pass


def _sum_points(points: Sequence[Point]) -> Point:
    result: Point = None
    for point in points:
        result = add(result, point)
    return result


def _kdf(point: Point, session_id: bytes) -> tuple[bytes, bytes, bytes]:
    if point is None or len(session_id) != 32:
        raise ProjectiveVoleError("invalid projective lock KDF input")
    encoded = compress(point)
    domain = b"ranklock/projective-vole-lock/v1\x00" + session_id
    key = sha256(domain + b"key\x00" + encoded).digest()
    nonce = sha256(domain + b"nonce\x00" + encoded).digest()[:12]
    return key, nonce, domain + b"payload"


def _scalar_bytes(value: int) -> bytes:
    value = int(value) % N
    return value.to_bytes(32, "big")


def _parse_scalar(raw: bytes) -> int:
    raw = bytes(raw)
    if len(raw) != 32:
        raise ProjectiveVoleError("selected OT scalar must be 32 bytes")
    value = int.from_bytes(raw, "big")
    if value >= N:
        raise ProjectiveVoleError("selected OT scalar is non-canonical")
    return value


def _proof_domain(session_id: bytes, coordinate: int, kind: bytes) -> bytes:
    return (
        b"ranklock/projective-vole/dleq/v1\x00"
        + session_id
        + int(coordinate).to_bytes(4, "big")
        + bytes(kind)
    )


@dataclass(frozen=True, slots=True)
class CoordinatePublic:
    p: bytes
    q: bytes
    u: bytes
    sp: bytes
    sq: bytes
    proof_sp: DleqProof
    proof_sq: DleqProof
    message0_commitments: tuple[bytes, ...]

    def __post_init__(self) -> None:
        for encoded in (self.p, self.q, self.u, self.sp, self.sq):
            decompress(encoded)
        if len(self.message0_commitments) != BYTE_BITS:
            raise ProjectiveVoleError("coordinate requires eight OT commitments")
        for encoded in self.message0_commitments:
            decompress(encoded)

    @property
    def encoded_bytes(self) -> int:
        return 5 * 33 + 2 * 64 + BYTE_BITS * 33


@dataclass(frozen=True, slots=True)
class ProjectiveLockPublic:
    session_id: bytes
    s_generator: bytes
    target: bytes
    ciphertext: bytes
    coordinates: tuple[CoordinatePublic, ...]
    offers: tuple[OtOffer, ...]
    schema: str = "ranklock-real-projective-vole-lock-v1"

    def __post_init__(self) -> None:
        if len(self.session_id) != 32:
            raise ProjectiveVoleError("session id must be 32 bytes")
        decompress(self.s_generator)
        decompress(self.target)
        if len(self.ciphertext) != 48:
            raise ProjectiveVoleError("encrypted share must be 48 bytes")
        if len(self.offers) != len(self.coordinates) * BYTE_BITS:
            raise ProjectiveVoleError("OT offer count differs from byte width")
        if tuple(offer.index for offer in self.offers) != tuple(range(len(self.offers))):
            raise ProjectiveVoleError("OT offer ordering differs")

    @property
    def input_bytes(self) -> int:
        return len(self.coordinates)

    @property
    def public_lock_bytes_excluding_offers(self) -> int:
        return (
            4
            + 32
            + 33
            + 33
            + len(self.ciphertext)
            + sum(coordinate.encoded_bytes for coordinate in self.coordinates)
        )

    @property
    def offer_bytes(self) -> int:
        return sum(len(offer.encode()) for offer in self.offers)

    @property
    def preprocessed_bytes(self) -> int:
        return self.public_lock_bytes_excluding_offers + self.offer_bytes


@dataclass(frozen=True, slots=True)
class ProjectiveReceiverRequest:
    values: bytes
    requests: tuple[OtRequest, ...]

    @property
    def encoded_bytes(self) -> int:
        return len(self.values) + sum(len(request.encode()) for request in self.requests)


@dataclass(frozen=True, slots=True)
class ProjectiveSenderResponse:
    responses: tuple[OtResponse, ...]

    @property
    def encoded_bytes(self) -> int:
        return sum(len(response.encode()) for response in self.responses)


@dataclass(frozen=True, slots=True)
class ProjectiveWitness:
    values: bytes
    selected_scalars: tuple[int, ...]

    def __post_init__(self) -> None:
        if len(self.values) != len(self.selected_scalars):
            raise ProjectiveVoleError("witness byte/scalar count differs")
        if any(not 0 <= scalar < N for scalar in self.selected_scalars):
            raise ProjectiveVoleError("witness scalar is non-canonical")

    @property
    def local_bytes(self) -> int:
        return len(self.values) + 32 * len(self.selected_scalars)


class ProjectiveVoleSender:
    def __init__(self, public: ProjectiveLockPublic, ot_senders: Sequence[OtSender]) -> None:
        self.public = public
        self._senders = tuple(ot_senders)
        if len(self._senders) != len(public.offers):
            raise ProjectiveVoleError("sender state count differs")
        self.consumed = False

    def respond(self, request: ProjectiveReceiverRequest) -> ProjectiveSenderResponse:
        if self.consumed:
            raise ProjectiveVoleError("projective sender state already consumed")
        if len(request.values) != self.public.input_bytes or len(request.requests) != len(self._senders):
            raise ProjectiveVoleError("projective request dimensions differ")
        responses = tuple(
            sender.respond(raw_request)
            for sender, raw_request in zip(self._senders, request.requests, strict=True)
        )
        self.consumed = True
        return ProjectiveSenderResponse(responses)


class ProjectiveVoleReceiver:
    def __init__(
        self,
        public: ProjectiveLockPublic,
        values: bytes,
        *,
        scalar_source: Callable[[], int],
    ) -> None:
        self.public = public
        self.values = bytes(values)
        if len(self.values) != public.input_bytes:
            raise ProjectiveVoleError("future byte vector has the wrong length")
        receivers: list[OtReceiver] = []
        for coordinate, value in enumerate(self.values):
            for bit_index in range(BYTE_BITS):
                ot_index = coordinate * BYTE_BITS + bit_index
                receivers.append(
                    OtReceiver(
                        session_id=public.session_id,
                        offer=public.offers[ot_index],
                        choice=(value >> bit_index) & 1,
                        scalar_source=scalar_source,
                    )
                )
        self._receivers = tuple(receivers)
        self.request = ProjectiveReceiverRequest(
            self.values, tuple(receiver.request for receiver in self._receivers)
        )
        self.consumed = False

    def finalize(self, response: ProjectiveSenderResponse) -> ProjectiveWitness:
        if self.consumed:
            raise ProjectiveVoleError("projective receiver state already consumed")
        if len(response.responses) != len(self._receivers):
            raise ProjectiveVoleError("projective response dimensions differ")
        selected = [
            _parse_scalar(receiver.finalize(raw_response))
            for receiver, raw_response in zip(
                self._receivers, response.responses, strict=True
            )
        ]
        scalars: list[int] = []
        for coordinate, value in enumerate(self.values):
            base = coordinate * BYTE_BITS
            coordinate_public = self.public.coordinates[coordinate]
            p = decompress(coordinate_public.p)
            q = decompress(coordinate_public.q)
            total = 0
            for bit_index in range(BYTE_BITS):
                scalar = selected[base + bit_index]
                commitment0 = decompress(
                    coordinate_public.message0_commitments[bit_index]
                )
                expected = (
                    commitment0
                    if ((value >> bit_index) & 1) == 0
                    else add(
                        commitment0,
                        negate(multiply(q, 1 << bit_index)),
                    )
                )
                if multiply(p, scalar) != expected:
                    raise ProjectiveVoleError(
                        "selected OT scalar differs from its public affine commitment"
                    )
                total = (total + scalar) % N
            scalars.append(total)
        self.consumed = True
        return ProjectiveWitness(self.values, tuple(scalars))


def verify_public_setup(public: ProjectiveLockPublic) -> bool:
    try:
        s_generator = decompress(public.s_generator)
        expected_target_points: list[Point] = []
        for index, coordinate in enumerate(public.coordinates):
            p = decompress(coordinate.p)
            expected_p = hash_point(
                b"ranklock/projective-vole/coordinate-generator/v1\x00" + public.session_id,
                index,
            )
            if p != expected_p:
                return False
            q = decompress(coordinate.q)
            u = decompress(coordinate.u)
            sp = decompress(coordinate.sp)
            sq = decompress(coordinate.sq)
            if not verify_dleq(
                coordinate.proof_sp,
                G,
                s_generator,
                p,
                sp,
                domain=_proof_domain(public.session_id, index, b"sp"),
            ):
                return False
            if not verify_dleq(
                coordinate.proof_sq,
                G,
                s_generator,
                q,
                sq,
                domain=_proof_domain(public.session_id, index, b"sq"),
            ):
                return False
            message0_points = tuple(
                decompress(value) for value in coordinate.message0_commitments
            )
            if _sum_points(message0_points) != u:
                return False
            # The branch-one commitment is derived as M0 - 2^j Q.  No extra point
            # needs to be retained, but ensure the derived points are non-infinity.
            if any(
                add(point, negate(multiply(q, 1 << bit_index))) is None
                for bit_index, point in enumerate(message0_points)
            ):
                return False
            expected_target_points.append(u)
        return _sum_points(expected_target_points) == decompress(public.target)
    except (ProjectiveVoleError, SecpError, ValueError, OverflowError):
        return False


def unlock_share(public: ProjectiveLockPublic, witness: ProjectiveWitness) -> bytes:
    if not verify_public_setup(public):
        raise ProjectiveVoleError("public projective setup is invalid")
    if len(witness.values) != public.input_bytes:
        raise ProjectiveVoleError("projective witness dimensions differ")
    terms: list[Point] = []
    for value, scalar, coordinate in zip(
        witness.values, witness.selected_scalars, public.coordinates, strict=True
    ):
        terms.append(multiply(decompress(coordinate.sp), scalar))
        terms.append(multiply(decompress(coordinate.sq), value))
    shared = _sum_points(terms)
    key, nonce, aad = _kdf(shared, public.session_id)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, public.ciphertext, aad)
    except Exception as exc:
        raise ProjectiveVoleError("projective lock decryption failed") from exc


def setup_projective_lock(
    secret_share: bytes,
    *,
    input_bytes: int = DEFAULT_INPUT_BYTES,
    seed: bytes = b"ranklock-projective-vole-default-seed",
) -> tuple[ProjectiveLockPublic, ProjectiveVoleSender]:
    secret_share = bytes(secret_share)
    if len(secret_share) != 32:
        raise ProjectiveVoleError("protected share must be 32 bytes")
    if not 1 <= input_bytes <= 4096:
        raise ProjectiveVoleError("input byte count outside local bounds")
    scalars = DeterministicScalars(seed)
    session_id = sha256(b"ranklock/projective-vole/session/v1\x00" + bytes(seed)).digest()
    s = scalars()
    s_generator = base_multiply(s)
    coordinates: list[CoordinatePublic] = []
    ot_senders: list[OtSender] = []
    u_points: list[Point] = []

    for coordinate_index in range(input_bytes):
        p = hash_point(
            b"ranklock/projective-vole/coordinate-generator/v1\x00" + session_id,
            coordinate_index,
        )
        b = scalars()
        q_point = negate(multiply(p, b))
        if q_point is None:  # pragma: no cover - nonzero b,p
            raise ProjectiveVoleError("degenerate slope point")
        randomness = tuple(scalars() for _ in range(BYTE_BITS))
        q_scalar = sum(randomness) % N
        if q_scalar == 0:
            raise ProjectiveVoleError("degenerate offset scalar")
        u = multiply(p, q_scalar)
        sp = multiply(p, s)
        sq = multiply(q_point, s)
        if any(point is None for point in (p, u, sp, sq)):
            raise ProjectiveVoleError("degenerate coordinate point")
        message0_commitments = tuple(
            compress(multiply(p, random_value)) for random_value in randomness
        )
        proof_sp = prove_dleq(
            s,
            G,
            s_generator,
            p,
            sp,
            domain=_proof_domain(session_id, coordinate_index, b"sp"),
            nonce_source=scalars,
        )
        proof_sq = prove_dleq(
            s,
            G,
            s_generator,
            q_point,
            sq,
            domain=_proof_domain(session_id, coordinate_index, b"sq"),
            nonce_source=scalars,
        )
        coordinates.append(
            CoordinatePublic(
                compress(p),
                compress(q_point),
                compress(u),
                compress(sp),
                compress(sq),
                proof_sp,
                proof_sq,
                message0_commitments,
            )
        )
        u_points.append(u)
        for bit_index, random_value in enumerate(randomness):
            index = coordinate_index * BYTE_BITS + bit_index
            m0 = random_value
            m1 = (random_value + (1 << bit_index) * b) % N
            ot_senders.append(
                OtSender(
                    session_id=session_id,
                    index=index,
                    message0=_scalar_bytes(m0),
                    message1=_scalar_bytes(m1),
                    scalar_source=scalars,
                )
            )

    target = _sum_points(u_points)
    if target is None:
        raise ProjectiveVoleError("aggregate target is infinity")
    shared = multiply(target, s)
    key, nonce, aad = _kdf(shared, session_id)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, secret_share, aad)
    public = ProjectiveLockPublic(
        session_id=session_id,
        s_generator=compress(s_generator),
        target=compress(target),
        ciphertext=ciphertext,
        coordinates=tuple(coordinates),
        offers=tuple(sender.offer for sender in ot_senders),
    )
    if not verify_public_setup(public):
        raise AssertionError("generated projective setup failed verification")
    return public, ProjectiveVoleSender(public, ot_senders)


def recover_reused_affine_state(
    value0: int, scalar0: int, value1: int, scalar1: int
) -> tuple[int, int]:
    """Recover ``(q,b)`` after two distinct values use one affine state."""

    v0, v1 = int(value0), int(value1)
    if not 0 <= v0 < 256 or not 0 <= v1 < 256 or v0 == v1:
        raise ProjectiveVoleError("reuse attack requires two distinct bytes")
    denominator = (v1 - v0) % N
    b = (int(scalar1) - int(scalar0)) * pow(denominator, -1, N) % N
    q = (int(scalar0) - v0 * b) % N
    return q, b


def synthesize_affine_scalar(q: int, b: int, value: int) -> int:
    if not 0 <= int(value) < 256:
        raise ProjectiveVoleError("byte outside range")
    return (int(q) + int(value) * int(b)) % N


@dataclass(frozen=True, slots=True)
class ProjectiveRunResult:
    input_bytes: int
    binary_ots: int
    public_lock_bytes_excluding_offers: int
    offer_bytes: int
    request_bytes: int
    response_bytes: int
    total_public_and_interactive_bytes: int
    receiver_local_witness_bytes: int
    setup_seconds: float
    public_verification_seconds: float
    request_seconds: float
    response_seconds: float
    finalize_seconds: float
    unlock_seconds: float
    share_recovered: bool

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-real-projective-vole-run-v1",
            **{name: getattr(self, name) for name in self.__dataclass_fields__},
            "security_boundary": [
                "Real secp256k1 group operations and AEAD; variable-time research implementation.",
                "Binary OT is a Chou-Orlandi measurement baseline, not the final malicious-receiver-secure DFB protocol.",
                "The OT sender is online for selection; this experiment does not yet provide public cold-start delivery.",
                "The lock releases an authenticated-input share, not the complete fault secret.",
                "Every affine state is one-shot; abort/retry requires fresh setup.",
            ],
        }


def benchmark_projective_lock(
    values: bytes,
    *,
    seed: bytes = b"ranklock-projective-benchmark-v1",
) -> ProjectiveRunResult:
    values = bytes(values)
    secret = sha256(b"ranklock-projective-benchmark-secret" + values).digest()
    started = perf_counter()
    public, sender = setup_projective_lock(secret, input_bytes=len(values), seed=seed)
    setup_seconds = perf_counter() - started
    started = perf_counter()
    verified = verify_public_setup(public)
    public_verification_seconds = perf_counter() - started
    if not verified:
        raise AssertionError("projective public setup did not verify")
    started = perf_counter()
    receiver = ProjectiveVoleReceiver(
        public,
        values,
        scalar_source=DeterministicScalars(seed + b"receiver"),
    )
    request_seconds = perf_counter() - started
    started = perf_counter()
    response = sender.respond(receiver.request)
    response_seconds = perf_counter() - started
    started = perf_counter()
    witness = receiver.finalize(response)
    finalize_seconds = perf_counter() - started
    started = perf_counter()
    recovered = unlock_share(public, witness)
    unlock_seconds = perf_counter() - started
    return ProjectiveRunResult(
        input_bytes=len(values),
        binary_ots=len(values) * BYTE_BITS,
        public_lock_bytes_excluding_offers=public.public_lock_bytes_excluding_offers,
        offer_bytes=public.offer_bytes,
        request_bytes=sum(len(item.encode()) for item in receiver.request.requests),
        response_bytes=response.encoded_bytes,
        total_public_and_interactive_bytes=(
            public.public_lock_bytes_excluding_offers
            + public.offer_bytes
            + sum(len(item.encode()) for item in receiver.request.requests)
            + response.encoded_bytes
        ),
        receiver_local_witness_bytes=witness.local_bytes,
        setup_seconds=setup_seconds,
        public_verification_seconds=public_verification_seconds,
        request_seconds=request_seconds,
        response_seconds=response_seconds,
        finalize_seconds=finalize_seconds,
        unlock_seconds=unlock_seconds,
        share_recovered=recovered == secret,
    )
