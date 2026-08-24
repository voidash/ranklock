"""Real BN254 positive-Groth16 conditional locks for the validity-first route.

The construction mirrors the algebraic core of BABE.  For a fixed Groth16 statement,
setup samples ``r`` and publishes ``[r]delta`` plus a payload masked under ``Y^r``, where

    Y = e(alpha, beta) * e(vk_x, gamma).

A future valid proof (A, B, C) and the projective scalar-multiplication output ``[r]A``
recover the same session:

    e([r]A, B) / e(C, [r]delta) = Y^r.

The algebra follows Construction 1 of BABE (ePrint 2026/065).  Its hiding proof is
in the generic bilinear group and random-oracle models and additionally invokes
Groth16 knowledge soundness.  Correct execution here is not a replacement for those
assumptions or for a qualified CRS/circuit.

``PositiveLock`` is the historical v1 format.  It publishes a plaintext hash and
therefore is not ordinary witness-encryption indistinguishable for adversarially
chosen messages.  New threshold-release code must use ``BabePositiveLockV2``, which
uses the paper's ciphertext shape without that commitment and has an explicit
versioned encoding.  Payload authenticity remains the consuming relation's job; the
v0.26 consumer verifies the recovered exact BIP340 signature.

The code uses real BN254 pairings.  It is research code, not constant-time production
cryptography, and the projective ``[r]A`` artifact is supplied as an interface rather
than constructed here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from hashlib import sha256

from .bn254_real import (
    CURVE_ORDER,
    FQ12,
    G1,
    G2,
    Point,
    add,
    compress_g1,
    compress_g2,
    decompress_g1,
    decompress_g2,
    multiply,
    neg,
    pairing_product,
)


class BabePositiveLockError(RuntimeError):
    pass


def _xor(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise BabePositiveLockError("xor length mismatch")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _hash_stream(domain: bytes, session: FQ12, length: int) -> bytes:
    session_bytes = session.to_bytes()
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            sha256(domain + session_bytes + counter.to_bytes(4, "big")).digest()
        )
        counter += 1
    return bytes(output[:length])


def _sum_g1(points: Iterable[Point]) -> Point:
    result = multiply(G1, 0, group="g1")
    for point in points:
        result = add(result, point, group="g1")
    return result


@dataclass(frozen=True, slots=True)
class PositiveGroth16VerifyingKey:
    alpha_g1: bytes
    beta_g2: bytes
    gamma_g2: bytes
    delta_g2: bytes
    ic_g1: tuple[bytes, ...]
    context: bytes
    schema: str = "ranklock-positive-groth16-vk-v1"

    def __post_init__(self) -> None:
        decompress_g1(self.alpha_g1)
        decompress_g2(self.beta_g2)
        decompress_g2(self.gamma_g2)
        decompress_g2(self.delta_g2)
        if not self.ic_g1:
            raise BabePositiveLockError("Groth16 VK has no IC points")
        for point in self.ic_g1:
            decompress_g1(point)
        if not self.context:
            raise BabePositiveLockError("Groth16 VK context is empty")

    @property
    def digest(self) -> bytes:
        h = sha256(b"ranklock/positive-groth16-vk/v1\x00")
        h.update(len(self.context).to_bytes(4, "big"))
        h.update(self.context)
        for encoded in (self.alpha_g1, self.beta_g2, self.gamma_g2, self.delta_g2):
            h.update(encoded)
        h.update(len(self.ic_g1).to_bytes(4, "big"))
        for encoded in self.ic_g1:
            h.update(encoded)
        return h.digest()

    def accumulator(self, public_inputs: Iterable[int]) -> Point:
        values = tuple(int(value) for value in public_inputs)
        if len(values) + 1 != len(self.ic_g1):
            raise BabePositiveLockError("public input count does not match Groth16 VK")
        points = [decompress_g1(self.ic_g1[0])]
        for value, encoded in zip(values, self.ic_g1[1:], strict=True):
            if not 0 <= value < CURVE_ORDER:
                raise BabePositiveLockError("public input is non-canonical")
            points.append(multiply(decompress_g1(encoded), value, group="g1"))
        return _sum_g1(points)


@dataclass(frozen=True, slots=True)
class PositiveGroth16Proof:
    a_g1: bytes
    b_g2: bytes
    c_g1: bytes
    schema: str = "ranklock-positive-groth16-proof-v1"

    def __post_init__(self) -> None:
        decompress_g1(self.a_g1)
        decompress_g2(self.b_g2)
        decompress_g1(self.c_g1)

    @property
    def digest(self) -> bytes:
        return sha256(
            b"ranklock/positive-groth16-proof/v1\x00"
            + self.a_g1
            + self.b_g2
            + self.c_g1
        ).digest()


@dataclass(frozen=True, slots=True)
class PositiveLock:
    """Historical v1 lock with a public plaintext commitment.

    ``payload_hash`` lets anyone distinguish two candidate plaintexts.  Preserve this
    type only for byte compatibility with historical research artifacts; it does not
    satisfy the BABE witness-encryption message-hiding definition.
    """

    vk_digest: bytes
    statement_digest: bytes
    r_delta_g2: bytes
    masked_payload: bytes
    payload_hash: bytes
    schema: str = "ranklock-babe-positive-lock-v1"

    def __post_init__(self) -> None:
        if len(self.vk_digest) != 32 or len(self.statement_digest) != 32:
            raise BabePositiveLockError("lock digests must be 32 bytes")
        decompress_g2(self.r_delta_g2)
        if not self.masked_payload:
            raise BabePositiveLockError("lock payload is empty")
        if len(self.payload_hash) != 32:
            raise BabePositiveLockError("payload hash must be 32 bytes")

    @property
    def encoded_bytes(self) -> int:
        return 32 + 32 + len(self.r_delta_g2) + 4 + len(self.masked_payload) + 32


_V2_MAGIC = b"RLPL"
_V2_VERSION = 2
_V2_MASK_DOMAIN = b"ranklock/babe-positive-lock/mask/v2\x00"


@dataclass(frozen=True, slots=True)
class BabePositiveLockV2:
    """Versioned BABE Construction-1 lock without a plaintext commitment."""

    vk_digest: bytes
    statement_digest: bytes
    r_delta_g2: bytes
    masked_payload: bytes
    schema: str = "ranklock-babe-positive-lock-v2"

    def __post_init__(self) -> None:
        if self.schema != "ranklock-babe-positive-lock-v2":
            raise BabePositiveLockError("unknown BABE positive-lock schema")
        if len(self.vk_digest) != 32 or len(self.statement_digest) != 32:
            raise BabePositiveLockError("lock digests must be 32 bytes")
        decompress_g2(self.r_delta_g2)
        if not self.masked_payload:
            raise BabePositiveLockError("lock payload is empty")

    @property
    def encoded(self) -> bytes:
        return (
            _V2_MAGIC
            + _V2_VERSION.to_bytes(2, "big")
            + self.vk_digest
            + self.statement_digest
            + self.r_delta_g2
            + len(self.masked_payload).to_bytes(4, "big")
            + self.masked_payload
        )

    @property
    def encoded_bytes(self) -> int:
        return len(self.encoded)

    @classmethod
    def parse(cls, raw: bytes) -> BabePositiveLockV2:
        raw = bytes(raw)
        fixed = 4 + 2 + 32 + 32 + 64 + 4
        if len(raw) < fixed + 1:
            raise BabePositiveLockError("truncated BABE positive-lock v2")
        if raw[:4] != _V2_MAGIC:
            raise BabePositiveLockError("wrong BABE positive-lock magic")
        if int.from_bytes(raw[4:6], "big") != _V2_VERSION:
            raise BabePositiveLockError("unsupported BABE positive-lock version")
        payload_length = int.from_bytes(raw[134:138], "big")
        end = fixed + payload_length
        if payload_length == 0 or end != len(raw):
            raise BabePositiveLockError("invalid BABE positive-lock payload framing")
        result = cls(
            raw[6:38],
            raw[38:70],
            raw[70:134],
            raw[138 : 138 + payload_length],
        )
        if result.encoded != raw:
            raise BabePositiveLockError("noncanonical BABE positive-lock encoding")
        return result


@dataclass(frozen=True, slots=True)
class BabePositiveLockV2SecurityAssessment:
    """Fail-closed relationship between v2 and BABE's published proof."""

    construction_reference: str = field(
        default="BABE Construction 1, ePrint 2026/065",
        init=False,
    )
    security_definition: str = field(
        default="extractable witness encryption for the deterministic Groth16 relation R-prime",
        init=False,
    )
    proof_models: tuple[str, ...] = field(
        default=("generic-bilinear-group-model", "random-oracle-model"),
        init=False,
    )
    reduction_dependencies: tuple[str, ...] = field(
        default=("Groth16 knowledge soundness",),
        init=False,
    )
    exact_ciphertext_shape_implemented: bool = field(default=True, init=False)
    plaintext_commitment_present: bool = field(default=False, init=False)
    local_equivalence_independently_reviewed: bool = field(default=False, init=False)
    complete_public_side_information_qualified: bool = field(
        default=False,
        init=False,
    )
    deterministic_non_zk_relation_qualified: bool = field(default=False, init=False)
    bn254_production_profile_approved: bool = field(default=False, init=False)
    production_hiding_theorem_established: bool = field(default=False, init=False)
    funding_eligible: bool = field(default=False, init=False)
    schema: str = field(
        default="ranklock-babe-positive-lock-v2-security-assessment-v1",
        init=False,
    )


def assess_babe_positive_lock_v2() -> BabePositiveLockV2SecurityAssessment:
    """Return the immutable claim boundary for the versioned BABE lock."""

    return BabePositiveLockV2SecurityAssessment()


def statement_digest(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    *,
    session_context: bytes,
) -> bytes:
    values = tuple(int(value) for value in public_inputs)
    h = sha256(b"ranklock/babe-positive-statement/v1\x00")
    h.update(vk.digest)
    h.update(len(session_context).to_bytes(4, "big"))
    h.update(bytes(session_context))
    h.update(len(values).to_bytes(4, "big"))
    for value in values:
        if not 0 <= value < CURVE_ORDER:
            raise BabePositiveLockError("public input is non-canonical")
        h.update(value.to_bytes(32, "big"))
    return h.digest()


def statement_session(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
) -> FQ12:
    return pairing_product(
        (
            (decompress_g1(vk.alpha_g1), decompress_g2(vk.beta_g2)),
            (vk.accumulator(public_inputs), decompress_g2(vk.gamma_g2)),
        )
    )


def verify_positive_groth16(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    proof: PositiveGroth16Proof,
) -> bool:
    try:
        left = pairing_product(
            ((decompress_g1(proof.a_g1), decompress_g2(proof.b_g2)),)
        )
        right = statement_session(vk, public_inputs) * pairing_product(
            ((decompress_g1(proof.c_g1), decompress_g2(vk.delta_g2)),)
        )
        return left == right
    except (ValueError, ZeroDivisionError, OverflowError):
        return False


def setup_positive_lock(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    payload: bytes,
    *,
    scale: int,
    session_context: bytes,
) -> PositiveLock:
    payload = bytes(payload)
    scale %= CURVE_ORDER
    if scale == 0:
        raise BabePositiveLockError("positive-lock scale must be nonzero")
    digest = statement_digest(vk, public_inputs, session_context=session_context)
    session = statement_session(vk, public_inputs) ** scale
    mask = _hash_stream(
        b"ranklock/babe-positive-lock/mask/v1\x00" + digest, session, len(payload)
    )
    return PositiveLock(
        vk_digest=vk.digest,
        statement_digest=digest,
        r_delta_g2=compress_g2(multiply(decompress_g2(vk.delta_g2), scale, group="g2")),
        masked_payload=_xor(payload, mask),
        payload_hash=sha256(
            b"ranklock/babe-positive-lock/payload/v1\x00" + digest + payload
        ).digest(),
    )


def setup_babe_positive_lock_v2(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    payload: bytes,
    *,
    scale: int,
    session_context: bytes,
) -> BabePositiveLockV2:
    """Encrypt a payload using the versioned BABE Construction-1 profile.

    Unlike v1's ``payload_hash``, the ciphertext has no public offline test for
    candidate messages.  Hiding remains conditional on BABE's GGM+ROM
    extractable-WE proof, Groth16 knowledge soundness, and the exact complete
    public side-information profile.
    """

    payload = bytes(payload)
    if not payload:
        raise BabePositiveLockError("positive-lock payload is empty")
    scale %= CURVE_ORDER
    if scale == 0:
        raise BabePositiveLockError("positive-lock scale must be nonzero")
    digest = statement_digest(vk, public_inputs, session_context=session_context)
    session = statement_session(vk, public_inputs) ** scale
    r_delta_g2 = compress_g2(multiply(decompress_g2(vk.delta_g2), scale, group="g2"))
    mask = _hash_stream(_V2_MASK_DOMAIN + digest, session, len(payload))
    masked_payload = _xor(payload, mask)
    return BabePositiveLockV2(vk.digest, digest, r_delta_g2, masked_payload)


def certify_projective_output(
    vk: PositiveGroth16VerifyingKey,
    proof: PositiveGroth16Proof,
    lock: PositiveLock | BabePositiveLockV2,
    r_a_g1: bytes,
) -> bool:
    """Publicly certify that the projective artifact returned exactly ``[r]A``."""

    try:
        residual = pairing_product(
            (
                (decompress_g1(r_a_g1), decompress_g2(vk.delta_g2)),
                (neg(decompress_g1(proof.a_g1)), decompress_g2(lock.r_delta_g2)),
            )
        )
        return residual == FQ12.one()
    except (ValueError, ZeroDivisionError, OverflowError):
        return False


def unlock_positive_lock(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    proof: PositiveGroth16Proof,
    lock: PositiveLock,
    r_a_g1: bytes,
    *,
    session_context: bytes,
) -> bytes:
    expected_statement = statement_digest(
        vk, public_inputs, session_context=session_context
    )
    if lock.vk_digest != vk.digest or lock.statement_digest != expected_statement:
        raise BabePositiveLockError("positive lock is bound to another statement")
    if not certify_projective_output(vk, proof, lock, r_a_g1):
        raise BabePositiveLockError(
            "projective scalar output failed public certification"
        )
    session = pairing_product(
        (
            (decompress_g1(r_a_g1), decompress_g2(proof.b_g2)),
            (neg(decompress_g1(proof.c_g1)), decompress_g2(lock.r_delta_g2)),
        )
    )
    mask = _hash_stream(
        b"ranklock/babe-positive-lock/mask/v1\x00" + expected_statement,
        session,
        len(lock.masked_payload),
    )
    payload = _xor(lock.masked_payload, mask)
    expected_hash = sha256(
        b"ranklock/babe-positive-lock/payload/v1\x00" + expected_statement + payload
    ).digest()
    if expected_hash != lock.payload_hash:
        raise BabePositiveLockError("Groth16 witness does not unlock the payload")
    return payload


def unlock_babe_positive_lock_v2(
    vk: PositiveGroth16VerifyingKey,
    public_inputs: Iterable[int],
    proof: PositiveGroth16Proof,
    lock: BabePositiveLockV2,
    r_a_g1: bytes,
    *,
    session_context: bytes,
) -> bytes:
    """Release a v2 payload only for an exact valid Groth16 proof and ``[r]A``."""

    inputs = tuple(int(value) for value in public_inputs)
    expected_statement = statement_digest(
        vk,
        inputs,
        session_context=session_context,
    )
    if lock.vk_digest != vk.digest or lock.statement_digest != expected_statement:
        raise BabePositiveLockError("positive lock is bound to another statement")
    if not verify_positive_groth16(vk, inputs, proof):
        raise BabePositiveLockError("Groth16 proof is invalid")
    if not certify_projective_output(vk, proof, lock, r_a_g1):
        raise BabePositiveLockError(
            "projective scalar output failed public certification"
        )
    session = pairing_product(
        (
            (decompress_g1(r_a_g1), decompress_g2(proof.b_g2)),
            (
                neg(decompress_g1(proof.c_g1)),
                decompress_g2(lock.r_delta_g2),
            ),
        )
    )
    mask = _hash_stream(
        _V2_MASK_DOMAIN + expected_statement,
        session,
        len(lock.masked_payload),
    )
    return _xor(lock.masked_payload, mask)


def honest_projective_output(proof: PositiveGroth16Proof, *, scale: int) -> bytes:
    scale %= CURVE_ORDER
    if scale == 0:
        raise BabePositiveLockError("projective scale must be nonzero")
    return compress_g1(multiply(decompress_g1(proof.a_g1), scale, group="g1"))


def deterministic_fixture(
    *,
    public_inputs: tuple[int, ...] = (17,),
    context: bytes = b"ranklock-v0.19-positive-groth16-fixture",
) -> tuple[PositiveGroth16VerifyingKey, tuple[int, ...], PositiveGroth16Proof]:
    """Construct a real pairing-valid fixture by solving the exponent equation."""

    alpha, beta, gamma, delta = 3, 5, 7, 11
    ic_scalars = (13, 19)
    if len(public_inputs) != 1:
        raise BabePositiveLockError(
            "deterministic fixture currently has one public input"
        )
    vk_x = (ic_scalars[0] + public_inputs[0] * ic_scalars[1]) % CURVE_ORDER
    a, b = 23, 29
    c = (
        (a * b - alpha * beta - vk_x * gamma) * pow(delta, -1, CURVE_ORDER)
    ) % CURVE_ORDER
    vk = PositiveGroth16VerifyingKey(
        alpha_g1=compress_g1(multiply(G1, alpha, group="g1")),
        beta_g2=compress_g2(multiply(G2, beta, group="g2")),
        gamma_g2=compress_g2(multiply(G2, gamma, group="g2")),
        delta_g2=compress_g2(multiply(G2, delta, group="g2")),
        ic_g1=tuple(
            compress_g1(multiply(G1, value, group="g1")) for value in ic_scalars
        ),
        context=bytes(context),
    )
    proof = PositiveGroth16Proof(
        a_g1=compress_g1(multiply(G1, a, group="g1")),
        b_g2=compress_g2(multiply(G2, b, group="g2")),
        c_g1=compress_g1(multiply(G1, c, group="g1")),
    )
    if not verify_positive_groth16(vk, public_inputs, proof):  # pragma: no cover
        raise AssertionError("deterministic Groth16 fixture is invalid")
    return vk, public_inputs, proof
