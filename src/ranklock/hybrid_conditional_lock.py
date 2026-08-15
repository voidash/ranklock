from __future__ import annotations

"""Concrete split-secret composition of the real projective-input lock and KZG-WE.

This module is deliberately an *attack surface isolator*, not the final RankLock
construction.  A 32-byte fault secret is XOR-shared into:

* an input share protected by :mod:`ranklock.projective_vole_lock`; and
* a trace share protected by real BN254 KZG-opening witness encryption.

The composition demonstrates that the two concrete pieces can enforce a conjunction:
a future byte vector must be translated through the one-shot projective channel and a
matching trace commitment must have a valid opening.  It also makes the remaining
failure explicit: the KZG ciphertext cannot be produced during static setup because
its statement contains the future commitment.  ``OnlineTraceEncapsulator`` therefore
holds the second secret share until the future statement exists.  That object violates
RankLock's no-online-authority target and is the exact component that a fixed-relation
LVA-WE construction must eliminate.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .bn254_real import CURVE_ORDER
from .projective_vole_lock import (
    ProjectiveLockPublic,
    ProjectiveReceiverRequest,
    ProjectiveSenderResponse,
    ProjectiveVoleReceiver,
    ProjectiveVoleSender,
    ProjectiveWitness,
    setup_projective_lock,
    unlock_share,
)
from .real_kzg_we import (
    KzgOpening,
    KzgSrs,
    KzgStatement,
    KzgWeCiphertext,
    decrypt_with_opening,
    encrypt_for_opening,
    verify_opening,
    xor_bytes,
)


class HybridLockError(RuntimeError):
    pass


def _field_hash(domain: bytes, *parts: bytes) -> int:
    digest = sha256(bytes(domain) + b"".join(len(part).to_bytes(8, "big") + part for part in parts)).digest()
    return int.from_bytes(digest, "big") % CURVE_ORDER


def _input_binding_digest(public: ProjectiveLockPublic, values: bytes) -> bytes:
    values = bytes(values)
    if len(values) != public.input_bytes:
        raise HybridLockError("input binding has the wrong byte length")
    digest = sha256(b"ranklock/hybrid/input-binding/v1\x00")
    digest.update(public.session_id)
    digest.update(public.target)
    digest.update(len(values).to_bytes(4, "big"))
    digest.update(values)
    return digest.digest()


def _trace_payload_digest(trace_values: Sequence[int]) -> bytes:
    digest = sha256(b"ranklock/hybrid/trace-values/v1\x00")
    digest.update(len(trace_values).to_bytes(8, "big"))
    for value in trace_values:
        digest.update((int(value) % CURVE_ORDER).to_bytes(32, "big"))
    return digest.digest()


@dataclass(frozen=True, slots=True)
class BoundTraceOpening:
    """Future KZG statement bound to one selected byte vector and trace payload."""

    input_binding_digest: bytes
    trace_payload_digest: bytes
    coefficients: tuple[int, ...]
    statement: KzgStatement
    opening: KzgOpening
    schema: str = "ranklock-hybrid-bound-trace-opening-v1"

    def __post_init__(self) -> None:
        if len(self.input_binding_digest) != 32 or len(self.trace_payload_digest) != 32:
            raise HybridLockError("trace binding digests must be 32 bytes")
        if not self.coefficients:
            raise HybridLockError("bound trace polynomial is empty")
        if self.statement.point != self.opening.point or self.statement.value != self.opening.value:
            raise HybridLockError("trace statement and opening differ")

    @property
    def context_scalar(self) -> int:
        return self.coefficients[0]

    @property
    def encoded_public_bytes(self) -> int:
        # Two digests, commitment, point, value.  The polynomial and opening proof are
        # evaluator witness material and are intentionally not counted here.
        return 32 + 32 + len(self.statement.commitment_g1) + 32 + 32

    @property
    def opening_witness_bytes(self) -> int:
        return len(self.opening.proof_g1)


def build_bound_trace_opening(
    *,
    srs: KzgSrs,
    projective_public: ProjectiveLockPublic,
    values: bytes,
    trace_values: Sequence[int],
    evaluation_point: int | None = None,
) -> BoundTraceOpening:
    """Commit a future trace while cryptographically including the selected bytes.

    The first polynomial coefficient is a field hash of the projective session, byte
    vector, and complete trace payload digest.  This is not a proof that ``trace_values``
    are a valid RankVM execution; it only makes split-brain substitution observable in
    the KZG statement used by this experiment.
    """

    values = bytes(values)
    trace_tuple = tuple(int(value) % CURVE_ORDER for value in trace_values)
    if not trace_tuple:
        raise HybridLockError("trace payload must be nonempty")
    input_digest = _input_binding_digest(projective_public, values)
    trace_digest = _trace_payload_digest(trace_tuple)
    context_scalar = _field_hash(
        b"ranklock/hybrid/trace-context/v1\x00", input_digest, trace_digest
    )
    coefficients = (context_scalar,) + trace_tuple
    if len(coefficients) - 1 > srs.maximum_degree:
        raise HybridLockError("bound trace exceeds KZG SRS degree")
    point = (
        _field_hash(b"ranklock/hybrid/evaluation-point/v1\x00", input_digest, trace_digest)
        if evaluation_point is None
        else int(evaluation_point) % CURVE_ORDER
    )
    if point == 0:
        point = 1
    opening = srs.open(coefficients, point)
    statement = KzgStatement(srs.commit(coefficients), opening.point, opening.value)
    result = BoundTraceOpening(
        input_digest,
        trace_digest,
        coefficients,
        statement,
        opening,
    )
    if not verify_opening(srs, result.statement, result.opening):
        raise AssertionError("generated bound trace opening did not verify")
    return result


@dataclass(frozen=True, slots=True)
class HybridStaticSetup:
    projective_public: ProjectiveLockPublic
    kzg_srs: KzgSrs
    full_secret_commitment: bytes
    schema: str = "ranklock-hybrid-static-setup-v1"

    def __post_init__(self) -> None:
        if len(self.full_secret_commitment) != 32:
            raise HybridLockError("fault-secret commitment must be 32 bytes")

    @property
    def static_bytes(self) -> int:
        return (
            self.projective_public.preprocessed_bytes
            + self.kzg_srs.encoded_bytes
            + len(self.full_secret_commitment)
        )


@dataclass(frozen=True, slots=True)
class HybridFutureCiphertext:
    trace: BoundTraceOpening
    ciphertext: KzgWeCiphertext
    schema: str = "ranklock-hybrid-future-ciphertext-v1"

    @property
    def public_bytes(self) -> int:
        return self.trace.encoded_public_bytes + self.ciphertext.encoded_bytes


class OnlineTraceEncapsulator:
    """One-shot online holder of the trace share.

    Its presence is a *failure certificate* for the breakthrough target.  The object
    checks the future byte/trace binding and only then creates statement-bound KZG-WE.
    A fixed-relation construction must remove this class entirely.
    """

    def __init__(self, trace_share: bytes, setup: HybridStaticSetup) -> None:
        self._trace_share = bytes(trace_share)
        if len(self._trace_share) != 32:
            raise HybridLockError("trace share must be 32 bytes")
        self.setup = setup
        self.consumed = False

    def encapsulate(
        self,
        trace: BoundTraceOpening,
        *,
        expected_values: bytes,
        randomness: int,
    ) -> HybridFutureCiphertext:
        if self.consumed:
            raise HybridLockError("online trace encapsulator already consumed")
        expected_digest = _input_binding_digest(
            self.setup.projective_public, bytes(expected_values)
        )
        if trace.input_binding_digest != expected_digest:
            raise HybridLockError("trace commitment is bound to another future input")
        if not verify_opening(self.setup.kzg_srs, trace.statement, trace.opening):
            raise HybridLockError("trace opening is invalid")
        ciphertext = encrypt_for_opening(
            self.setup.kzg_srs,
            trace.statement,
            self._trace_share,
            randomness=randomness,
        )
        self.consumed = True
        # Best-effort erasure in Python is not a security property; remove the only
        # reference from this object so accidental reuse is impossible.
        self._trace_share = bytes(32)
        return HybridFutureCiphertext(trace, ciphertext)


@dataclass(frozen=True, slots=True)
class HybridSetupState:
    setup: HybridStaticSetup
    projective_sender: ProjectiveVoleSender
    trace_encapsulator: OnlineTraceEncapsulator


def setup_hybrid_lock(
    full_secret: bytes,
    *,
    input_bytes: int,
    kzg_maximum_degree: int,
    seed: bytes = b"ranklock-hybrid-lock-v1",
) -> HybridSetupState:
    full_secret = bytes(full_secret)
    if len(full_secret) != 32:
        raise HybridLockError("fault secret must be 32 bytes")
    input_share = sha256(b"ranklock/hybrid/input-share/v1\x00" + bytes(seed)).digest()
    trace_share = xor_bytes((full_secret, input_share))
    public, sender = setup_projective_lock(
        input_share,
        input_bytes=input_bytes,
        seed=bytes(seed) + b"/projective",
    )
    tau = _field_hash(b"ranklock/hybrid/kzg-tau/v1\x00", bytes(seed)) or 1
    srs = KzgSrs.generate(kzg_maximum_degree, tau=tau)
    setup = HybridStaticSetup(
        public,
        srs,
        sha256(b"ranklock/hybrid/fault-secret-commitment/v1\x00" + full_secret).digest(),
    )
    return HybridSetupState(setup, sender, OnlineTraceEncapsulator(trace_share, setup))


def unlock_hybrid_lock(
    setup: HybridStaticSetup,
    projective_witness: ProjectiveWitness,
    future: HybridFutureCiphertext,
    *,
    expected_values: bytes,
) -> bytes:
    expected_values = bytes(expected_values)
    if projective_witness.values != expected_values:
        raise HybridLockError("projective witness is bound to another byte vector")
    if future.trace.input_binding_digest != _input_binding_digest(
        setup.projective_public, expected_values
    ):
        raise HybridLockError("trace statement is bound to another byte vector")
    if not verify_opening(setup.kzg_srs, future.trace.statement, future.trace.opening):
        raise HybridLockError("trace opening failed")
    input_share = unlock_share(setup.projective_public, projective_witness)
    trace_share = decrypt_with_opening(
        future.trace.statement, future.ciphertext, future.trace.opening
    )
    secret = xor_bytes((input_share, trace_share))
    commitment = sha256(
        b"ranklock/hybrid/fault-secret-commitment/v1\x00" + secret
    ).digest()
    if commitment != setup.full_secret_commitment:
        raise HybridLockError("hybrid shares do not reconstruct the committed fault secret")
    return secret


def online_authority_barrier() -> dict[str, object]:
    return {
        "schema": "ranklock-hybrid-online-encapsulator-barrier-v1",
        "concrete_components": [
            "real one-shot secp256k1 OT/projective input lock",
            "real BN254 KZG commitment and opening verification",
            "real KZG-opening witness encryption",
            "XOR conjunction of independently protected 32-byte shares",
        ],
        "breakthrough_failure": (
            "KZG-WE encryption is statement-bound. The future commitment does not exist "
            "during static setup, so OnlineTraceEncapsulator must retain a secret share."
        ),
        "required_replacement": (
            "a fixed-relation linearly-verifiable WE/compiler in which future commitments, "
            "openings, authenticated bytes, and invalidity evidence are witness variables"
        ),
        "no_online_authority_target_met": False,
    }
