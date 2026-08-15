from __future__ import annotations

"""Real BN254 conditional lock for a low-rank fixed-G2 pairing-product relation.

For future G1 witness elements ``A_i``, fixed G2 term bases ``B_i``, and a fixed target
``T in GT``, the relation is

    product_i e(A_i, B_i) = T.

Assume the fixed bases have a public rank-k decomposition

    B_i = sum_j a[i,j] U_j.

Setup samples a hidden scalar ``r`` and retains only ``r U_j``.  A satisfying witness can
compute

    product_j e(sum_i a[i,j] A_i, r U_j) = T^r,

so decryption requires ``k`` pairings and O(mk) ordinary source-group linear work instead of
storing/scaling one independent G2 base per term.  A generalized Schnorr proof shows that one
scalar scaled every anchor.

This module establishes real arithmetic, exact serialization accounting, malformed-key
rejection, and the target-preimage leakage condition.  It does *not* provide the missing
knowledge-sound RankVM proof, a malicious distributed activation protocol, adaptive witness-
encryption security, or production-grade constant-time cryptography.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .bn254_real import (
    CURVE_ORDER,
    FIELD_MODULUS,
    FQ12,
    G1,
    G2,
    Point,
    add,
    compress_g1,
    compress_g2,
    decompress_g1,
    decompress_g2,
    eq_points,
    is_inf,
    multiply,
    pairing_product,
)
from .public_correlation_rank import matrix_rank


class LowRankPpeError(RuntimeError):
    pass


def _field(value: int) -> int:
    return int(value) % CURVE_ORDER


def _scalar_bytes(value: int) -> bytes:
    return _field(value).to_bytes(32, "big")


def _gt_bytes(value: FQ12) -> bytes:
    return value.to_bytes()


def _gt_from_bytes(raw: bytes) -> FQ12:
    if len(raw) != 12 * 32:
        raise LowRankPpeError("GT encoding must contain twelve Fq coefficients")
    coefficients: list[int] = []
    for offset in range(0, len(raw), 32):
        coefficient = int.from_bytes(raw[offset : offset + 32], "big")
        if coefficient >= FIELD_MODULUS:
            raise LowRankPpeError("GT encoding contains a non-canonical Fq coefficient")
        coefficients.append(coefficient)
    return FQ12(tuple(coefficients))


def _sum_g1(points: Sequence[Point]) -> Point:
    result = multiply(G1, 0, group="g1")
    for point in points:
        result = add(result, point, group="g1")
    return result


def _sum_g2(points: Sequence[Point]) -> Point:
    result = multiply(G2, 0, group="g2")
    for point in points:
        result = add(result, point, group="g2")
    return result


def _challenge_scalar(domain: bytes, transcript: bytes) -> int:
    for counter in range(256):
        candidate = int.from_bytes(
            sha256(domain + counter.to_bytes(4, "big") + transcript).digest(), "big"
        )
        if 0 < candidate < CURVE_ORDER:
            return candidate
    raise LowRankPpeError("Fiat-Shamir rejection sampling exhausted")


def _kdf(session: FQ12, relation_digest: bytes) -> tuple[bytes, bytes, bytes]:
    raw = _gt_bytes(session)
    domain = b"ranklock/low-rank-ppe-lock/kdf/v1\x00" + relation_digest
    return (
        sha256(domain + b"key\x00" + raw).digest(),
        sha256(domain + b"nonce\x00" + raw).digest()[:12],
        domain + b"payload",
    )


@dataclass(frozen=True, slots=True)
class LowRankPpeRelation:
    anchors_g2: tuple[bytes, ...]
    term_coefficients: tuple[tuple[int, ...], ...]
    target_gt: bytes
    context: bytes
    schema: str = "ranklock-low-rank-fixed-g2-ppe-relation-v1"

    def __post_init__(self) -> None:
        if not self.anchors_g2:
            raise LowRankPpeError("PPE relation has no G2 anchors")
        if not self.term_coefficients:
            raise LowRankPpeError("PPE relation has no terms")
        anchor_count = len(self.anchors_g2)
        for anchor in self.anchors_g2:
            decompress_g2(anchor)
        canonical_rows: list[tuple[int, ...]] = []
        for row in self.term_coefficients:
            if len(row) != anchor_count:
                raise LowRankPpeError("PPE coefficient matrix is ragged")
            canonical = tuple(_field(value) for value in row)
            if not any(canonical):
                raise LowRankPpeError("PPE term has the zero G2 base")
            canonical_rows.append(canonical)
        object.__setattr__(self, "term_coefficients", tuple(canonical_rows))
        if matrix_rank(canonical_rows) != anchor_count:
            raise LowRankPpeError(
                "PPE anchors are redundant for the public coefficient matrix; reduce the basis"
            )
        target = _gt_from_bytes(self.target_gt)
        if target == FQ12.one():
            raise LowRankPpeError("PPE target must be nonidentity")
        if len(self.context) == 0:
            raise LowRankPpeError("PPE relation context is empty")

    @property
    def anchor_count(self) -> int:
        return len(self.anchors_g2)

    @property
    def term_count(self) -> int:
        return len(self.term_coefficients)

    @property
    def coefficient_rank(self) -> int:
        return matrix_rank(self.term_coefficients)

    @property
    def target(self) -> FQ12:
        return _gt_from_bytes(self.target_gt)

    @property
    def coefficient_bytes(self) -> int:
        return self.term_count * self.anchor_count * 32

    @property
    def encoded_bytes(self) -> int:
        return (
            sum(len(anchor) for anchor in self.anchors_g2)
            + self.coefficient_bytes
            + len(self.target_gt)
            + len(self.context)
        )

    @property
    def digest(self) -> bytes:
        transcript = bytearray(b"ranklock/low-rank-ppe/relation/v1\x00")
        transcript.extend(len(self.context).to_bytes(4, "big"))
        transcript.extend(self.context)
        transcript.extend(self.anchor_count.to_bytes(4, "big"))
        transcript.extend(self.term_count.to_bytes(8, "big"))
        for anchor in self.anchors_g2:
            transcript.extend(anchor)
        for row in self.term_coefficients:
            for coefficient in row:
                transcript.extend(_scalar_bytes(coefficient))
        transcript.extend(self.target_gt)
        return sha256(bytes(transcript)).digest()

    def term_base(self, index: int) -> Point:
        if not 0 <= index < self.term_count:
            raise LowRankPpeError("PPE term index is out of range")
        return _sum_g2(
            tuple(
                multiply(decompress_g2(anchor), coefficient, group="g2")
                for anchor, coefficient in zip(
                    self.anchors_g2, self.term_coefficients[index], strict=True
                )
                if coefficient
            )
        )

    def aggregate_witness(self, witness_g1: Sequence[bytes]) -> tuple[Point, ...]:
        if len(witness_g1) != self.term_count:
            raise LowRankPpeError("PPE witness term count mismatch")
        points = tuple(decompress_g1(encoded) for encoded in witness_g1)
        aggregates: list[Point] = []
        for anchor_index in range(self.anchor_count):
            aggregates.append(
                _sum_g1(
                    tuple(
                        multiply(
                            point,
                            self.term_coefficients[term_index][anchor_index],
                            group="g1",
                        )
                        for term_index, point in enumerate(points)
                        if self.term_coefficients[term_index][anchor_index]
                    )
                )
            )
        return tuple(aggregates)

    def evaluate(self, witness_g1: Sequence[bytes]) -> FQ12:
        aggregates = self.aggregate_witness(witness_g1)
        return pairing_product(
            tuple(
                (aggregate, decompress_g2(anchor))
                for aggregate, anchor in zip(aggregates, self.anchors_g2, strict=True)
            )
        )

    def evaluate_direct(self, witness_g1: Sequence[bytes]) -> FQ12:
        if len(witness_g1) != self.term_count:
            raise LowRankPpeError("PPE witness term count mismatch")
        return pairing_product(
            tuple(
                (decompress_g1(witness), self.term_base(index))
                for index, witness in enumerate(witness_g1)
            )
        )

    def accepts(self, witness_g1: Sequence[bytes]) -> bool:
        try:
            return self.evaluate(witness_g1) == self.target
        except (LowRankPpeError, ValueError, ZeroDivisionError, OverflowError):
            return False


@dataclass(frozen=True, slots=True)
class SameScalarSetupProof:
    base_commitment_g2: bytes
    anchor_commitments_g2: tuple[bytes, ...]
    response: int
    schema: str = "ranklock-low-rank-ppe-same-scalar-proof-v1"

    def __post_init__(self) -> None:
        decompress_g2(self.base_commitment_g2)
        if not self.anchor_commitments_g2:
            raise LowRankPpeError("same-scalar proof has no anchor commitments")
        for commitment in self.anchor_commitments_g2:
            decompress_g2(commitment)
        if not 0 <= self.response < CURVE_ORDER:
            raise LowRankPpeError("same-scalar proof response is non-canonical")

    @property
    def encoded_bytes(self) -> int:
        return (
            len(self.base_commitment_g2)
            + sum(len(value) for value in self.anchor_commitments_g2)
            + 32
        )


@dataclass(frozen=True, slots=True)
class LowRankPpeLockKey:
    relation: LowRankPpeRelation
    base_scale_g2: bytes
    scaled_anchors_g2: tuple[bytes, ...]
    setup_proof: SameScalarSetupProof
    schema: str = "ranklock-low-rank-ppe-lock-key-v1"

    def __post_init__(self) -> None:
        decompress_g2(self.base_scale_g2)
        if len(self.scaled_anchors_g2) != self.relation.anchor_count:
            raise LowRankPpeError("scaled-anchor count does not match relation")
        for anchor in self.scaled_anchors_g2:
            decompress_g2(anchor)
        if len(self.setup_proof.anchor_commitments_g2) != self.relation.anchor_count:
            raise LowRankPpeError("proof commitment count does not match relation")

    @property
    def setup_bytes(self) -> int:
        return (
            len(self.base_scale_g2)
            + sum(len(value) for value in self.scaled_anchors_g2)
            + self.setup_proof.encoded_bytes
        )

    @property
    def retained_bytes_without_ciphertext(self) -> int:
        return self.relation.encoded_bytes + self.setup_bytes


@dataclass(frozen=True, slots=True)
class LowRankPpeCiphertext:
    payload: bytes
    schema: str = "ranklock-low-rank-ppe-ciphertext-v1"

    def __post_init__(self) -> None:
        if len(self.payload) != 48:
            raise LowRankPpeError("PPE lock payload must be 48 bytes")

    @property
    def encoded_bytes(self) -> int:
        return len(self.payload)


@dataclass(frozen=True, slots=True)
class LowRankPpeCost:
    term_count: int
    anchor_count: int
    coefficient_rank: int
    coefficient_bytes: int
    relation_bytes: int
    setup_bytes: int
    ciphertext_bytes: int
    direct_scaled_g2_bytes: int
    compressed_scaled_g2_bytes: int
    direct_pairings: int
    compressed_pairings: int
    schema: str = "ranklock-low-rank-ppe-cost-v1"

    @property
    def total_retained_bytes(self) -> int:
        return self.relation_bytes + self.setup_bytes + self.ciphertext_bytes

    @property
    def scaled_base_compression_ratio(self) -> float:
        return self.direct_scaled_g2_bytes / self.compressed_scaled_g2_bytes

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_class": "EXACT serialization accounting for the executable prototype",
            "term_count": self.term_count,
            "anchor_count": self.anchor_count,
            "coefficient_rank": self.coefficient_rank,
            "coefficient_bytes": self.coefficient_bytes,
            "relation_bytes": self.relation_bytes,
            "setup_bytes": self.setup_bytes,
            "ciphertext_bytes": self.ciphertext_bytes,
            "total_retained_bytes": self.total_retained_bytes,
            "direct_scaled_g2_bytes": self.direct_scaled_g2_bytes,
            "compressed_scaled_g2_bytes": self.compressed_scaled_g2_bytes,
            "scaled_base_compression_ratio": self.scaled_base_compression_ratio,
            "direct_pairings": self.direct_pairings,
            "compressed_pairings": self.compressed_pairings,
            "ordinary_linear_work": "O(term_count * anchor_count) G1 public-scalar work",
        }


def _setup_challenge(
    relation: LowRankPpeRelation,
    base_scale_g2: bytes,
    scaled_anchors_g2: Sequence[bytes],
    proof: SameScalarSetupProof,
) -> int:
    transcript = bytearray(relation.digest)
    transcript.extend(base_scale_g2)
    for scaled in scaled_anchors_g2:
        transcript.extend(scaled)
    transcript.extend(proof.base_commitment_g2)
    for commitment in proof.anchor_commitments_g2:
        transcript.extend(commitment)
    return _challenge_scalar(
        b"ranklock/low-rank-ppe/setup-proof/challenge/v1\x00", bytes(transcript)
    )


def verify_low_rank_ppe_key(key: LowRankPpeLockKey) -> bool:
    try:
        proof = key.setup_proof
        challenge = _setup_challenge(
            key.relation, key.base_scale_g2, key.scaled_anchors_g2, proof
        )
        left_base = multiply(G2, proof.response, group="g2")
        right_base = add(
            decompress_g2(proof.base_commitment_g2),
            multiply(decompress_g2(key.base_scale_g2), challenge, group="g2"),
            group="g2",
        )
        if not eq_points(left_base, right_base):
            return False
        for anchor, scaled, commitment in zip(
            key.relation.anchors_g2,
            key.scaled_anchors_g2,
            proof.anchor_commitments_g2,
            strict=True,
        ):
            left = multiply(decompress_g2(anchor), proof.response, group="g2")
            right = add(
                decompress_g2(commitment),
                multiply(decompress_g2(scaled), challenge, group="g2"),
                group="g2",
            )
            if not eq_points(left, right):
                return False
        return True
    except (LowRankPpeError, ValueError, ZeroDivisionError, OverflowError):
        return False


def setup_low_rank_ppe_lock(
    relation: LowRankPpeRelation,
    secret: bytes,
    *,
    scale: int,
    proof_nonce: int,
) -> tuple[LowRankPpeLockKey, LowRankPpeCiphertext]:
    secret = bytes(secret)
    if len(secret) != 32:
        raise LowRankPpeError("PPE lock secret must be 32 bytes")
    scale = _field(scale)
    proof_nonce = _field(proof_nonce)
    if scale == 0 or proof_nonce == 0:
        raise LowRankPpeError("PPE setup scalar and proof nonce must be nonzero")

    anchors = tuple(decompress_g2(anchor) for anchor in relation.anchors_g2)
    base_scale = compress_g2(multiply(G2, scale, group="g2"))
    scaled_anchors = tuple(
        compress_g2(multiply(anchor, scale, group="g2")) for anchor in anchors
    )
    provisional = SameScalarSetupProof(
        compress_g2(multiply(G2, proof_nonce, group="g2")),
        tuple(
            compress_g2(multiply(anchor, proof_nonce, group="g2"))
            for anchor in anchors
        ),
        0,
    )
    challenge = _setup_challenge(relation, base_scale, scaled_anchors, provisional)
    proof = SameScalarSetupProof(
        provisional.base_commitment_g2,
        provisional.anchor_commitments_g2,
        (proof_nonce + challenge * scale) % CURVE_ORDER,
    )
    key = LowRankPpeLockKey(relation, base_scale, scaled_anchors, proof)
    if not verify_low_rank_ppe_key(key):
        raise AssertionError("constructed PPE setup proof did not verify")

    session = relation.target ** scale
    encryption_key, nonce, aad = _kdf(session, relation.digest)
    ciphertext = LowRankPpeCiphertext(
        ChaCha20Poly1305(encryption_key).encrypt(nonce, secret, aad)
    )
    return key, ciphertext


def decrypt_low_rank_ppe_lock(
    key: LowRankPpeLockKey,
    ciphertext: LowRankPpeCiphertext,
    witness_g1: Sequence[bytes],
) -> bytes:
    if not verify_low_rank_ppe_key(key):
        raise LowRankPpeError("PPE lock setup proof is invalid")
    aggregates = key.relation.aggregate_witness(witness_g1)
    session = pairing_product(
        tuple(
            (aggregate, decompress_g2(scaled))
            for aggregate, scaled in zip(
                aggregates, key.scaled_anchors_g2, strict=True
            )
        )
    )
    encryption_key, nonce, aad = _kdf(session, key.relation.digest)
    try:
        return ChaCha20Poly1305(encryption_key).decrypt(
            nonce, ciphertext.payload, aad
        )
    except InvalidTag as exc:
        raise LowRankPpeError("PPE witness does not unlock the ciphertext") from exc


def derive_scaled_term_bases(key: LowRankPpeLockKey) -> tuple[bytes, ...]:
    if not verify_low_rank_ppe_key(key):
        raise LowRankPpeError("PPE lock setup proof is invalid")
    scaled_anchors = tuple(decompress_g2(value) for value in key.scaled_anchors_g2)
    output: list[bytes] = []
    for row in key.relation.term_coefficients:
        output.append(
            compress_g2(
                _sum_g2(
                    tuple(
                        multiply(anchor, coefficient, group="g2")
                        for anchor, coefficient in zip(
                            scaled_anchors, row, strict=True
                        )
                        if coefficient
                    )
                )
            )
        )
    return tuple(output)


def session_from_exposed_target_preimage(
    key: LowRankPpeLockKey, target_preimage_by_anchor_g1: Sequence[bytes]
) -> FQ12:
    """Demonstrate the fatal case where a target preimage is public.

    If public points ``X_j`` satisfy ``product_j e(X_j, U_j) = T``, then anybody can pair
    them with ``r U_j`` and recover ``T^r``.  A secure instantiation must therefore ensure
    that no satisfying target decomposition is public before the future proof/witness.
    """

    if len(target_preimage_by_anchor_g1) != key.relation.anchor_count:
        raise LowRankPpeError("target preimage anchor count mismatch")
    points = tuple(decompress_g1(value) for value in target_preimage_by_anchor_g1)
    claimed_target = pairing_product(
        tuple(
            (point, decompress_g2(anchor))
            for point, anchor in zip(
                points, key.relation.anchors_g2, strict=True
            )
        )
    )
    if claimed_target != key.relation.target:
        raise LowRankPpeError("supplied points are not a target preimage")
    return pairing_product(
        tuple(
            (point, decompress_g2(scaled))
            for point, scaled in zip(points, key.scaled_anchors_g2, strict=True)
        )
    )


def decrypt_from_exposed_target_preimage(
    key: LowRankPpeLockKey,
    ciphertext: LowRankPpeCiphertext,
    target_preimage_by_anchor_g1: Sequence[bytes],
) -> bytes:
    session = session_from_exposed_target_preimage(
        key, target_preimage_by_anchor_g1
    )
    encryption_key, nonce, aad = _kdf(session, key.relation.digest)
    return ChaCha20Poly1305(encryption_key).decrypt(
        nonce, ciphertext.payload, aad
    )


def relation_cost(
    key: LowRankPpeLockKey, ciphertext: LowRankPpeCiphertext
) -> LowRankPpeCost:
    relation = key.relation
    return LowRankPpeCost(
        term_count=relation.term_count,
        anchor_count=relation.anchor_count,
        coefficient_rank=relation.coefficient_rank,
        coefficient_bytes=relation.coefficient_bytes,
        relation_bytes=relation.encoded_bytes,
        setup_bytes=key.setup_bytes,
        ciphertext_bytes=ciphertext.encoded_bytes,
        direct_scaled_g2_bytes=relation.term_count * 64,
        compressed_scaled_g2_bytes=relation.anchor_count * 64,
        direct_pairings=relation.term_count,
        compressed_pairings=relation.anchor_count,
    )


def build_example_relation(
    term_coefficients: Sequence[Sequence[int]],
    witness_scalars: Sequence[int],
    *,
    anchor_scalars: Sequence[int],
    context: bytes,
) -> tuple[LowRankPpeRelation, tuple[bytes, ...], tuple[bytes, ...]]:
    """Build a deterministic real-arithmetic fixture.

    Returned target-preimage points are for the explicit leakage regression only; a deployed
    relation must not publish them before the future satisfying proof exists.
    """

    rows = tuple(tuple(_field(value) for value in row) for row in term_coefficients)
    if len(rows) != len(witness_scalars):
        raise LowRankPpeError("fixture witness length does not match term count")
    if not anchor_scalars:
        raise LowRankPpeError("fixture has no anchors")
    if any(_field(value) == 0 for value in anchor_scalars):
        raise LowRankPpeError("fixture anchor scalar is zero")
    anchors = tuple(
        compress_g2(multiply(G2, _field(value), group="g2"))
        for value in anchor_scalars
    )
    witness = tuple(
        compress_g1(multiply(G1, _field(value), group="g1"))
        for value in witness_scalars
    )

    # Compute the k aggregate G1 points first.  Pairing them with the k anchors is
    # algebraically identical to evaluating every term separately.
    # Constructing the final relation validates rank and dimensions; use a nonidentity
    # placeholder only long enough to reuse its aggregate helper.
    placeholder = pairing_product(((G1, G2),)).to_bytes()
    provisional = LowRankPpeRelation(anchors, rows, placeholder, bytes(context))
    aggregates = provisional.aggregate_witness(witness)
    target = pairing_product(
        tuple(
            (aggregate, decompress_g2(anchor))
            for aggregate, anchor in zip(aggregates, anchors, strict=True)
        )
    )
    if target == FQ12.one():
        raise LowRankPpeError("fixture accidentally produced the identity target")
    relation = LowRankPpeRelation(anchors, rows, target.to_bytes(), bytes(context))
    preimage = tuple(
        compress_g1(point) for point in aggregates if not is_inf(point)
    )
    if len(preimage) != relation.anchor_count:
        raise LowRankPpeError("fixture aggregate contains infinity; choose other scalars")
    return relation, witness, preimage
