from __future__ import annotations

"""Derive a Bitcoin signing key directly from an accepting pairing session.

The v0.16 lock encrypted a 32-byte fault-secret share under the pairing session.
That leaves a malicious-activation problem: a contributor can publish valid
scaled anchors and an unrelated ciphertext.  This module removes the encrypted
payload entirely.

For an accepting session ``K`` the fault scalar is

    t = HashToSecpScalar(domain, K, relation_digest, epoch, signer_id).

Setup publishes ``P = t*G_secp``.  A future satisfying witness reconstructs
``K`` from the low-rank scaled anchors, derives ``t`` and checks ``tG = P``.
There is no ciphertext to substitute and no payload share to retain.

Malicious setup still needs a public zero-knowledge activation proof for the
relation

    exists r:
      scaled_anchors_j = r * anchors_j
      P = HashToSecpScalar(statement_session^r, context) * G_secp.

The executable ``verify_activation_witness`` function specifies that relation
exactly with the setup witness visible.  A production NIZK for it is not
implemented here.  This is variable-time research code, not a signing library.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from .bn254_real import CURVE_ORDER, FQ12, G2, decompress_g2, eq_points, multiply
from .real_secp import (
    G as SECP_G,
    N as SECP_ORDER,
    Point as SecpPoint,
    add as secp_add,
    base_multiply,
    compress as compress_secp,
    decompress as decompress_secp,
    hash_scalar,
    multiply as secp_multiply,
)
from .split_basis_ppe_we import (
    SplitBasisPpeError,
    SplitBasisPpeKey,
    SplitBasisPpeRelation,
    setup_split_basis_key,
    split_basis_setup_session,
    split_basis_witness_session,
    verify_split_basis_key,
)


class DerivedFaultKeyError(RuntimeError):
    pass


def _session_bytes(session: FQ12) -> bytes:
    return session.to_bytes()


def _derive_fault_scalar(
    session: FQ12,
    relation_digest: bytes,
    epoch: bytes,
    signer_id: bytes,
) -> int:
    if len(relation_digest) != 32 or len(epoch) != 32 or not signer_id:
        raise DerivedFaultKeyError("invalid derived-fault-key context")
    return hash_scalar(
        b"ranklock/derived-fault-key/v1\x00",
        _session_bytes(session),
        bytes(relation_digest),
        bytes(epoch),
        bytes(signer_id),
    )


def _point_sum(points: Sequence[SecpPoint]) -> SecpPoint:
    result: SecpPoint = None
    for point in points:
        result = secp_add(result, point)
    return result


def _normalize_bip340_secret(secret: int) -> tuple[int, bytes]:
    secret %= SECP_ORDER
    if secret == 0:
        raise DerivedFaultKeyError("aggregate fault scalar is zero")
    point = base_multiply(secret)
    if point is None:  # pragma: no cover - guarded by nonzero scalar
        raise DerivedFaultKeyError("aggregate fault public key is infinity")
    x, y = point
    return ((SECP_ORDER - secret) % SECP_ORDER if y & 1 else secret), x.to_bytes(32, "big")


@dataclass(frozen=True, slots=True)
class DerivedFaultKeyShare:
    ppe_key: SplitBasisPpeKey
    epoch: bytes
    signer_id: bytes
    fault_public_key: bytes
    schema: str = "ranklock-derived-fault-key-share-v1"

    def __post_init__(self) -> None:
        if len(self.epoch) != 32:
            raise DerivedFaultKeyError("fault-key epoch must be 32 bytes")
        if not self.signer_id:
            raise DerivedFaultKeyError("fault-key signer id is empty")
        decompress_secp(self.fault_public_key)
        if not verify_split_basis_key(self.ppe_key):
            raise DerivedFaultKeyError("fault-key PPE key is invalid")

    @property
    def relation(self) -> SplitBasisPpeRelation:
        return self.ppe_key.relation

    @property
    def activation_statement_digest(self) -> bytes:
        transcript = bytearray(b"ranklock/derived-fault-key/activation/v1\x00")
        transcript.extend(self.relation.digest)
        transcript.extend(self.epoch)
        transcript.extend(len(self.signer_id).to_bytes(4, "big"))
        transcript.extend(self.signer_id)
        transcript.extend(self.ppe_key.base_scale_g2)
        for anchor in self.ppe_key.scaled_witness_anchors_g2:
            transcript.extend(anchor)
        transcript.extend(self.fault_public_key)
        return sha256(bytes(transcript)).digest()

    @property
    def retained_bytes(self) -> int:
        return (
            self.ppe_key.retained_bytes_without_ciphertext
            + len(self.epoch)
            + len(self.signer_id)
            + len(self.fault_public_key)
        )

    @property
    def ciphertext_bytes(self) -> int:
        return 0

    @property
    def xonly_public_key(self) -> bytes:
        point = decompress_secp(self.fault_public_key)
        assert point is not None
        return point[0].to_bytes(32, "big")


@dataclass(frozen=True, slots=True)
class DerivedFaultKeySetupWitness:
    scale: int
    fault_scalar: int
    schema: str = "ranklock-derived-fault-key-setup-witness-v1"

    def __post_init__(self) -> None:
        if not 0 < self.scale < CURVE_ORDER:
            raise DerivedFaultKeyError("setup scale is non-canonical")
        if not 0 < self.fault_scalar < SECP_ORDER:
            raise DerivedFaultKeyError("fault scalar is non-canonical")



def setup_derived_fault_key_share(
    relation: SplitBasisPpeRelation,
    *,
    epoch: bytes,
    signer_id: bytes,
    scale: int,
    proof_nonce: int,
) -> tuple[DerivedFaultKeyShare, DerivedFaultKeySetupWitness]:
    key = setup_split_basis_key(
        relation, scale=scale, proof_nonce=proof_nonce
    )
    session = split_basis_setup_session(relation, scale=scale)
    scalar = _derive_fault_scalar(session, relation.digest, bytes(epoch), bytes(signer_id))
    public = compress_secp(base_multiply(scalar))
    share = DerivedFaultKeyShare(
        key, bytes(epoch), bytes(signer_id), public
    )
    witness = DerivedFaultKeySetupWitness(int(scale) % CURVE_ORDER, scalar)
    if not verify_activation_witness(share, witness.scale):
        raise AssertionError("constructed derived fault-key activation relation failed")
    return share, witness



def recover_fault_scalar(
    share: DerivedFaultKeyShare, witness_g1: Sequence[bytes]
) -> int:
    session = split_basis_witness_session(share.ppe_key, witness_g1)
    scalar = _derive_fault_scalar(
        session,
        share.relation.digest,
        share.epoch,
        share.signer_id,
    )
    if compress_secp(base_multiply(scalar)) != share.fault_public_key:
        raise DerivedFaultKeyError("witness does not derive the committed fault key")
    return scalar



def verify_activation_witness(share: DerivedFaultKeyShare, scale: int) -> bool:
    """Evaluate the public activation NP relation with the witness exposed.

    A production deployment replaces this call with verification of a public
    zero-knowledge proof.  Keeping the exact relation executable prevents the
    setup-consistency obligation from being hidden behind prose.
    """

    try:
        scale = int(scale) % CURVE_ORDER
        if scale == 0 or not verify_split_basis_key(share.ppe_key):
            return False
        if not eq_points(
            multiply(G2, scale, group="g2"),
            decompress_g2(share.ppe_key.base_scale_g2),
        ):
            return False
        for anchor_raw, scaled_raw in zip(
            share.relation.witness_anchors_g2,
            share.ppe_key.scaled_witness_anchors_g2,
            strict=True,
        ):
            if not eq_points(
                multiply(decompress_g2(anchor_raw), scale, group="g2"),
                decompress_g2(scaled_raw),
            ):
                return False
        session = split_basis_setup_session(share.relation, scale=scale)
        scalar = _derive_fault_scalar(
            session,
            share.relation.digest,
            share.epoch,
            share.signer_id,
        )
        return compress_secp(base_multiply(scalar)) == share.fault_public_key
    except (DerivedFaultKeyError, SplitBasisPpeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True, slots=True)
class DerivedFaultKeyCommittee:
    shares: tuple[DerivedFaultKeyShare, ...]
    coefficients: tuple[int, ...]
    aggregate_public_key: bytes
    aggregate_xonly_public_key: bytes
    manifest_digest: bytes
    schema: str = "ranklock-derived-fault-key-committee-v1"

    def __post_init__(self) -> None:
        if not self.shares or len(self.shares) != len(self.coefficients):
            raise DerivedFaultKeyError("invalid fault-key committee dimensions")
        if any(not 0 < value < SECP_ORDER for value in self.coefficients):
            raise DerivedFaultKeyError("committee coefficient is non-canonical")
        decompress_secp(self.aggregate_public_key)
        if len(self.aggregate_xonly_public_key) != 32 or len(self.manifest_digest) != 32:
            raise DerivedFaultKeyError("invalid aggregate fault-key encoding")

    @property
    def retained_bytes(self) -> int:
        return (
            sum(share.retained_bytes for share in self.shares)
            + 32 * len(self.coefficients)
            + len(self.aggregate_public_key)
            + len(self.aggregate_xonly_public_key)
            + len(self.manifest_digest)
        )

    @property
    def ciphertext_bytes(self) -> int:
        return 0



def build_fault_key_committee(
    shares: Sequence[DerivedFaultKeyShare],
) -> DerivedFaultKeyCommittee:
    ordered = tuple(sorted(shares, key=lambda share: share.signer_id))
    if not ordered:
        raise DerivedFaultKeyError("fault-key committee is empty")
    if len({share.signer_id for share in ordered}) != len(ordered):
        raise DerivedFaultKeyError("duplicate fault-key signer id")
    relation_digest = ordered[0].relation.digest
    epoch = ordered[0].epoch
    if any(share.relation.digest != relation_digest for share in ordered):
        raise DerivedFaultKeyError("committee shares use different relations")
    if any(share.epoch != epoch for share in ordered):
        raise DerivedFaultKeyError("committee shares use different epochs")

    manifest = bytearray(b"ranklock/derived-fault-key/committee/v1\x00")
    manifest.extend(relation_digest)
    manifest.extend(epoch)
    for share in ordered:
        manifest.extend(len(share.signer_id).to_bytes(4, "big"))
        manifest.extend(share.signer_id)
        manifest.extend(share.fault_public_key)
        manifest.extend(share.activation_statement_digest)
    manifest_digest = sha256(bytes(manifest)).digest()
    coefficients = tuple(
        hash_scalar(
            b"ranklock/derived-fault-key/keyagg-coefficient/v1\x00",
            manifest_digest,
            index.to_bytes(4, "big"),
            share.signer_id,
            share.fault_public_key,
        )
        for index, share in enumerate(ordered)
    )
    aggregate = _point_sum(
        tuple(
            secp_multiply(decompress_secp(share.fault_public_key), coefficient)
            for share, coefficient in zip(ordered, coefficients, strict=True)
        )
    )
    if aggregate is None:
        raise DerivedFaultKeyError("aggregate fault public key is infinity")
    aggregate_encoded = compress_secp(aggregate)
    aggregate_xonly = aggregate[0].to_bytes(32, "big")
    return DerivedFaultKeyCommittee(
        ordered,
        coefficients,
        aggregate_encoded,
        aggregate_xonly,
        manifest_digest,
    )



def recover_committee_fault_scalar(
    committee: DerivedFaultKeyCommittee,
    witness_g1: Sequence[bytes],
) -> int:
    scalars = tuple(
        recover_fault_scalar(share, witness_g1) for share in committee.shares
    )
    aggregate_secret = sum(
        coefficient * scalar
        for coefficient, scalar in zip(
            committee.coefficients, scalars, strict=True
        )
    ) % SECP_ORDER
    normalized, xonly = _normalize_bip340_secret(aggregate_secret)
    if xonly != committee.aggregate_xonly_public_key:
        raise DerivedFaultKeyError("recovered aggregate scalar does not match committee key")
    return normalized



def ciphertext_free_fault_key_frontier(
    share: DerivedFaultKeyShare,
    committee: DerivedFaultKeyCommittee | None = None,
) -> dict[str, object]:
    return {
        "schema": "ranklock-ciphertext-free-fault-key-frontier-v1",
        "evidence_class": "REAL BN254 pairing sessions + real secp256k1 key derivation",
        "single_share_retained_bytes": share.retained_bytes,
        "single_share_ciphertext_bytes": share.ciphertext_bytes,
        "committee_size": 0 if committee is None else len(committee.shares),
        "committee_retained_bytes": None if committee is None else committee.retained_bytes,
        "committee_ciphertext_bytes": 0,
        "ciphertext_substitution_attack_eliminated": True,
        "fault_key_context_bound_to": [
            "pairing session",
            "relation digest",
            "32-byte epoch",
            "signer id",
        ],
        "activation_relation_executable": True,
        "activation_zero_knowledge_proof_constructed": False,
        "activation_nizk_statement": (
            "prove knowledge of the setup scale binding every G2 anchor and the "
            "hash-derived secp256k1 public key"
        ),
        "security_boundary": [
            "Hash-to-scalar is modelled with SHA-256 and must be domain-separated in production.",
            "Committee key aggregation is MuSig-style rogue-key-resistant hashing, not a proof of BIP327 conformance.",
            "Without the public activation NIZK a malicious contributor can publish a key that never unlocks.",
            "All committee shares are required for liveness; one honest hidden scale is sufficient for pre-witness key secrecy.",
        ],
        "breakthrough_target_met": False,
    }
