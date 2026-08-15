from __future__ import annotations

"""Real BN254 split-basis pairing-product witness encryption.

The relation has a *witness side*

    product_i e(W_i, B_i)

and a public statement side

    product_l e(S_l, D_l),

and accepts when the two products are equal.  The future witness elements ``W_i``
are in G1.  Every witness-side G2 base has a public low-rank decomposition

    B_i = sum_j a[i,j] U_j.

Encryption samples ``r``, publishes only ``r U_j`` and masks the payload under

    (product_l e(S_l, D_l))^r.

A satisfying witness reconstructs the same session using ``k`` pairings:

    product_j e(sum_i a[i,j] W_i, r U_j).

This strictly generalises the fixed-target lock in :mod:`low_rank_ppe_lock` and
contains KZG-opening witness encryption as the one-witness-term special case.
The important security condition is not whether the normalised PPE target is the
identity.  It is whether the public statement-side pairing value has a publicly
known preimage over the *scaled witness anchor span*.  If such a decomposition is
known, the ciphertext can be opened without a witness.

This is variable-time research code.  It establishes real arithmetic, exact
serialization, the KZG special case, and scoped span-leakage attacks.  It does not
prove adaptive extractable witness-encryption security, construct the complete
RankVM relation, or provide malicious distributed activation.
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
    multiply,
    pairing_product,
)
from .public_correlation_rank import matrix_rank


class SplitBasisPpeError(RuntimeError):
    pass


def _field(value: int) -> int:
    return int(value) % CURVE_ORDER


def _scalar_bytes(value: int) -> bytes:
    return _field(value).to_bytes(32, "big")


def _gt_bytes(value: FQ12) -> bytes:
    return value.to_bytes()


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
    raise SplitBasisPpeError("Fiat-Shamir rejection sampling exhausted")


def _kdf(session: FQ12, relation_digest: bytes) -> tuple[bytes, bytes, bytes]:
    raw = _gt_bytes(session)
    domain = b"ranklock/split-basis-ppe-we/kdf/v1\x00" + relation_digest
    return (
        sha256(domain + b"key\x00" + raw).digest(),
        sha256(domain + b"nonce\x00" + raw).digest()[:12],
        domain + b"payload",
    )


@dataclass(frozen=True, slots=True)
class SplitBasisPpeRelation:
    """A fixed statement with future G1 witness terms and fixed G2 bases."""

    witness_anchors_g2: tuple[bytes, ...]
    witness_coefficients: tuple[tuple[int, ...], ...]
    statement_terms: tuple[tuple[bytes, bytes], ...]
    context: bytes
    require_minimal_witness_basis: bool = True
    schema: str = "ranklock-split-basis-ppe-relation-v1"

    def __post_init__(self) -> None:
        if not self.witness_anchors_g2:
            raise SplitBasisPpeError("split-basis relation has no witness anchors")
        if not self.witness_coefficients:
            raise SplitBasisPpeError("split-basis relation has no witness terms")
        if not self.statement_terms:
            raise SplitBasisPpeError("split-basis relation has no statement terms")
        if not self.context:
            raise SplitBasisPpeError("split-basis relation context is empty")

        for anchor in self.witness_anchors_g2:
            decompress_g2(anchor)
        anchor_count = len(self.witness_anchors_g2)
        rows: list[tuple[int, ...]] = []
        for row in self.witness_coefficients:
            if len(row) != anchor_count:
                raise SplitBasisPpeError("witness coefficient matrix is ragged")
            canonical = tuple(_field(value) for value in row)
            if not any(canonical):
                raise SplitBasisPpeError("witness term has the zero G2 base")
            rows.append(canonical)
        if self.require_minimal_witness_basis and matrix_rank(rows) != anchor_count:
            raise SplitBasisPpeError(
                "witness anchors are redundant for the public coefficient matrix"
            )
        object.__setattr__(self, "witness_coefficients", tuple(rows))

        canonical_statement: list[tuple[bytes, bytes]] = []
        for statement_g1, statement_g2 in self.statement_terms:
            decompress_g1(statement_g1)
            decompress_g2(statement_g2)
            canonical_statement.append((bytes(statement_g1), bytes(statement_g2)))
        object.__setattr__(self, "statement_terms", tuple(canonical_statement))
        if self.statement_value == FQ12.one():
            # Identity statement values make the session public and deterministic.
            raise SplitBasisPpeError("statement-side pairing value must be nonidentity")

    @property
    def witness_anchor_count(self) -> int:
        return len(self.witness_anchors_g2)

    @property
    def witness_term_count(self) -> int:
        return len(self.witness_coefficients)

    @property
    def statement_term_count(self) -> int:
        return len(self.statement_terms)

    @property
    def coefficient_rank(self) -> int:
        return matrix_rank(self.witness_coefficients)

    @property
    def coefficient_bytes(self) -> int:
        return self.witness_term_count * self.witness_anchor_count * 32

    @property
    def statement_value(self) -> FQ12:
        return pairing_product(
            tuple(
                (decompress_g1(g1), decompress_g2(g2))
                for g1, g2 in self.statement_terms
            )
        )

    @property
    def encoded_bytes(self) -> int:
        return (
            sum(len(anchor) for anchor in self.witness_anchors_g2)
            + self.coefficient_bytes
            + sum(len(g1) + len(g2) for g1, g2 in self.statement_terms)
            + len(self.context)
        )

    @property
    def digest(self) -> bytes:
        transcript = bytearray(b"ranklock/split-basis-ppe/relation/v1\x00")
        transcript.extend(len(self.context).to_bytes(4, "big"))
        transcript.extend(self.context)
        transcript.extend(self.witness_anchor_count.to_bytes(4, "big"))
        transcript.extend(self.witness_term_count.to_bytes(8, "big"))
        transcript.extend(self.statement_term_count.to_bytes(4, "big"))
        transcript.extend(bytes((1 if self.require_minimal_witness_basis else 0,)))
        for anchor in self.witness_anchors_g2:
            transcript.extend(anchor)
        for row in self.witness_coefficients:
            for coefficient in row:
                transcript.extend(_scalar_bytes(coefficient))
        for g1, g2 in self.statement_terms:
            transcript.extend(g1)
            transcript.extend(g2)
        return sha256(bytes(transcript)).digest()

    def witness_term_base(self, index: int) -> Point:
        if not 0 <= index < self.witness_term_count:
            raise SplitBasisPpeError("witness term index is out of range")
        return _sum_g2(
            tuple(
                multiply(decompress_g2(anchor), coefficient, group="g2")
                for anchor, coefficient in zip(
                    self.witness_anchors_g2,
                    self.witness_coefficients[index],
                    strict=True,
                )
                if coefficient
            )
        )

    def aggregate_witness(self, witness_g1: Sequence[bytes]) -> tuple[Point, ...]:
        if len(witness_g1) != self.witness_term_count:
            raise SplitBasisPpeError("witness term count mismatch")
        points = tuple(decompress_g1(encoded) for encoded in witness_g1)
        aggregates: list[Point] = []
        for anchor_index in range(self.witness_anchor_count):
            aggregates.append(
                _sum_g1(
                    tuple(
                        multiply(
                            point,
                            self.witness_coefficients[term_index][anchor_index],
                            group="g1",
                        )
                        for term_index, point in enumerate(points)
                        if self.witness_coefficients[term_index][anchor_index]
                    )
                )
            )
        return tuple(aggregates)

    def witness_value(self, witness_g1: Sequence[bytes]) -> FQ12:
        aggregates = self.aggregate_witness(witness_g1)
        return pairing_product(
            tuple(
                (aggregate, decompress_g2(anchor))
                for aggregate, anchor in zip(
                    aggregates, self.witness_anchors_g2, strict=True
                )
            )
        )

    def witness_value_direct(self, witness_g1: Sequence[bytes]) -> FQ12:
        if len(witness_g1) != self.witness_term_count:
            raise SplitBasisPpeError("witness term count mismatch")
        return pairing_product(
            tuple(
                (decompress_g1(encoded), self.witness_term_base(index))
                for index, encoded in enumerate(witness_g1)
            )
        )

    def accepts(self, witness_g1: Sequence[bytes]) -> bool:
        try:
            return self.witness_value(witness_g1) == self.statement_value
        except (SplitBasisPpeError, ValueError, ZeroDivisionError, OverflowError):
            return False


@dataclass(frozen=True, slots=True)
class SplitBasisSameScalarProof:
    base_commitment_g2: bytes
    anchor_commitments_g2: tuple[bytes, ...]
    response: int
    schema: str = "ranklock-split-basis-same-scalar-proof-v1"

    def __post_init__(self) -> None:
        decompress_g2(self.base_commitment_g2)
        if not self.anchor_commitments_g2:
            raise SplitBasisPpeError("same-scalar proof has no anchor commitments")
        for value in self.anchor_commitments_g2:
            decompress_g2(value)
        if not 0 <= self.response < CURVE_ORDER:
            raise SplitBasisPpeError("same-scalar response is non-canonical")

    @property
    def encoded_bytes(self) -> int:
        return (
            len(self.base_commitment_g2)
            + sum(len(value) for value in self.anchor_commitments_g2)
            + 32
        )


@dataclass(frozen=True, slots=True)
class SplitBasisPpeKey:
    relation: SplitBasisPpeRelation
    base_scale_g2: bytes
    scaled_witness_anchors_g2: tuple[bytes, ...]
    setup_proof: SplitBasisSameScalarProof
    schema: str = "ranklock-split-basis-ppe-key-v1"

    def __post_init__(self) -> None:
        decompress_g2(self.base_scale_g2)
        if len(self.scaled_witness_anchors_g2) != self.relation.witness_anchor_count:
            raise SplitBasisPpeError("scaled witness-anchor count mismatch")
        for value in self.scaled_witness_anchors_g2:
            decompress_g2(value)
        if len(self.setup_proof.anchor_commitments_g2) != self.relation.witness_anchor_count:
            raise SplitBasisPpeError("setup-proof commitment count mismatch")

    @property
    def setup_bytes(self) -> int:
        return (
            len(self.base_scale_g2)
            + sum(len(value) for value in self.scaled_witness_anchors_g2)
            + self.setup_proof.encoded_bytes
        )

    @property
    def retained_bytes_without_ciphertext(self) -> int:
        return self.relation.encoded_bytes + self.setup_bytes


@dataclass(frozen=True, slots=True)
class SplitBasisPpeCiphertext:
    payload: bytes
    schema: str = "ranklock-split-basis-ppe-ciphertext-v1"

    def __post_init__(self) -> None:
        if len(self.payload) != 48:
            raise SplitBasisPpeError("split-basis PPE payload must be 48 bytes")

    @property
    def encoded_bytes(self) -> int:
        return len(self.payload)


@dataclass(frozen=True, slots=True)
class SplitBasisPpeCost:
    witness_terms: int
    witness_anchor_rank: int
    statement_terms: int
    relation_bytes: int
    setup_bytes: int
    ciphertext_bytes: int
    direct_witness_pairings: int
    compressed_witness_pairings: int
    encryption_pairings: int
    schema: str = "ranklock-split-basis-ppe-cost-v1"

    @property
    def total_retained_bytes(self) -> int:
        return self.relation_bytes + self.setup_bytes + self.ciphertext_bytes

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_class": "EXACT serialization accounting for executable BN254 prototype",
            "witness_terms": self.witness_terms,
            "witness_anchor_rank": self.witness_anchor_rank,
            "statement_terms": self.statement_terms,
            "relation_bytes": self.relation_bytes,
            "setup_bytes": self.setup_bytes,
            "ciphertext_bytes": self.ciphertext_bytes,
            "total_retained_bytes": self.total_retained_bytes,
            "direct_witness_pairings": self.direct_witness_pairings,
            "compressed_witness_pairings": self.compressed_witness_pairings,
            "encryption_pairings": self.encryption_pairings,
            "ordinary_linear_work": "O(witness_terms * witness_anchor_rank) G1 public-scalar work",
        }


def _setup_challenge(
    relation: SplitBasisPpeRelation,
    base_scale_g2: bytes,
    scaled_anchors: Sequence[bytes],
    proof: SplitBasisSameScalarProof,
) -> int:
    transcript = bytearray(relation.digest)
    transcript.extend(base_scale_g2)
    for value in scaled_anchors:
        transcript.extend(value)
    transcript.extend(proof.base_commitment_g2)
    for value in proof.anchor_commitments_g2:
        transcript.extend(value)
    return _challenge_scalar(
        b"ranklock/split-basis-ppe/setup-proof/challenge/v1\x00",
        bytes(transcript),
    )


def verify_split_basis_key(key: SplitBasisPpeKey) -> bool:
    try:
        proof = key.setup_proof
        challenge = _setup_challenge(
            key.relation,
            key.base_scale_g2,
            key.scaled_witness_anchors_g2,
            proof,
        )
        if not eq_points(
            multiply(G2, proof.response, group="g2"),
            add(
                decompress_g2(proof.base_commitment_g2),
                multiply(decompress_g2(key.base_scale_g2), challenge, group="g2"),
                group="g2",
            ),
        ):
            return False
        for anchor, scaled, commitment in zip(
            key.relation.witness_anchors_g2,
            key.scaled_witness_anchors_g2,
            proof.anchor_commitments_g2,
            strict=True,
        ):
            if not eq_points(
                multiply(decompress_g2(anchor), proof.response, group="g2"),
                add(
                    decompress_g2(commitment),
                    multiply(decompress_g2(scaled), challenge, group="g2"),
                    group="g2",
                ),
            ):
                return False
        return True
    except (SplitBasisPpeError, ValueError, ZeroDivisionError, OverflowError):
        return False


def setup_split_basis_key(
    relation: SplitBasisPpeRelation,
    *,
    scale: int,
    proof_nonce: int,
) -> SplitBasisPpeKey:
    """Create the authenticated low-rank scaled-anchor key without a payload.

    Keeping key generation separate from payload encryption is useful for the
    ciphertext-free fault-key experiment: the accepting pairing session itself
    is hashed into a secp256k1 signing scalar, so no encrypted 32-byte share is
    retained.
    """

    scale = _field(scale)
    proof_nonce = _field(proof_nonce)
    if scale == 0 or proof_nonce == 0:
        raise SplitBasisPpeError("setup scalar and proof nonce must be nonzero")

    anchors = tuple(decompress_g2(value) for value in relation.witness_anchors_g2)
    base_scale = compress_g2(multiply(G2, scale, group="g2"))
    scaled = tuple(
        compress_g2(multiply(anchor, scale, group="g2")) for anchor in anchors
    )
    provisional = SplitBasisSameScalarProof(
        compress_g2(multiply(G2, proof_nonce, group="g2")),
        tuple(
            compress_g2(multiply(anchor, proof_nonce, group="g2"))
            for anchor in anchors
        ),
        0,
    )
    challenge = _setup_challenge(relation, base_scale, scaled, provisional)
    proof = SplitBasisSameScalarProof(
        provisional.base_commitment_g2,
        provisional.anchor_commitments_g2,
        (proof_nonce + challenge * scale) % CURVE_ORDER,
    )
    key = SplitBasisPpeKey(relation, base_scale, scaled, proof)
    if not verify_split_basis_key(key):
        raise AssertionError("constructed split-basis setup proof did not verify")
    return key


def split_basis_setup_session(
    relation: SplitBasisPpeRelation, *, scale: int
) -> FQ12:
    """Compute the statement-side accepting session while the setup scalar is live."""

    scale = _field(scale)
    if scale == 0:
        raise SplitBasisPpeError("setup scalar must be nonzero")
    return pairing_product(
        tuple(
            (
                multiply(decompress_g1(statement_g1), scale, group="g1"),
                decompress_g2(statement_g2),
            )
            for statement_g1, statement_g2 in relation.statement_terms
        )
    )


def split_basis_witness_session(
    key: SplitBasisPpeKey, witness_g1: Sequence[bytes]
) -> FQ12:
    """Compute the session exposed by a future witness and the scaled anchors."""

    if not verify_split_basis_key(key):
        raise SplitBasisPpeError("split-basis setup proof is invalid")
    aggregates = key.relation.aggregate_witness(witness_g1)
    return pairing_product(
        tuple(
            (aggregate, decompress_g2(scaled))
            for aggregate, scaled in zip(
                aggregates, key.scaled_witness_anchors_g2, strict=True
            )
        )
    )


def setup_split_basis_ppe_we(
    relation: SplitBasisPpeRelation,
    secret: bytes,
    *,
    scale: int,
    proof_nonce: int,
) -> tuple[SplitBasisPpeKey, SplitBasisPpeCiphertext]:
    secret = bytes(secret)
    if len(secret) != 32:
        raise SplitBasisPpeError("split-basis PPE secret must be 32 bytes")
    key = setup_split_basis_key(
        relation, scale=scale, proof_nonce=proof_nonce
    )

    # The encryptor knows r during setup, so it can scale the public statement-side
    # G1 terms without publishing any r-scaled statement-side G2 base.
    session = split_basis_setup_session(relation, scale=scale)
    encryption_key, nonce, aad = _kdf(session, relation.digest)
    ciphertext = SplitBasisPpeCiphertext(
        ChaCha20Poly1305(encryption_key).encrypt(nonce, secret, aad)
    )
    return key, ciphertext


def decrypt_split_basis_ppe_we(
    key: SplitBasisPpeKey,
    ciphertext: SplitBasisPpeCiphertext,
    witness_g1: Sequence[bytes],
) -> bytes:
    session = split_basis_witness_session(key, witness_g1)
    encryption_key, nonce, aad = _kdf(session, key.relation.digest)
    try:
        return ChaCha20Poly1305(encryption_key).decrypt(
            nonce, ciphertext.payload, aad
        )
    except InvalidTag as exc:
        raise SplitBasisPpeError("witness does not unlock split-basis ciphertext") from exc


def session_from_statement_span_decomposition(
    key: SplitBasisPpeKey,
    statement_base_coefficients: Sequence[Sequence[int]],
) -> FQ12:
    """Recover the session when statement G2 bases lie in the public witness-anchor span.

    ``statement_base_coefficients[l][j]`` claims

        D_l = sum_j d[l,j] U_j.

    If all decompositions verify, anyone can aggregate the public statement G1 terms by
    anchor and pair them with ``r U_j``.  This is a complete break and is the exact
    low-rank KZG leakage that occurs when both ``r[tau]`` and ``r[1]`` are published.
    """

    relation = key.relation
    if len(statement_base_coefficients) != relation.statement_term_count:
        raise SplitBasisPpeError("statement decomposition count mismatch")
    canonical_rows: list[tuple[int, ...]] = []
    for row in statement_base_coefficients:
        if len(row) != relation.witness_anchor_count:
            raise SplitBasisPpeError("statement decomposition row is ragged")
        canonical_rows.append(tuple(_field(value) for value in row))

    for (_statement_g1, statement_g2), row in zip(
        relation.statement_terms, canonical_rows, strict=True
    ):
        reconstructed = _sum_g2(
            tuple(
                multiply(decompress_g2(anchor), coefficient, group="g2")
                for anchor, coefficient in zip(
                    relation.witness_anchors_g2, row, strict=True
                )
                if coefficient
            )
        )
        if not eq_points(reconstructed, decompress_g2(statement_g2)):
            raise SplitBasisPpeError(
                "supplied coefficients do not decompose a statement G2 base"
            )

    aggregate_statement_by_anchor: list[Point] = []
    for anchor_index in range(relation.witness_anchor_count):
        aggregate_statement_by_anchor.append(
            _sum_g1(
                tuple(
                    multiply(
                        decompress_g1(statement_g1),
                        canonical_rows[term_index][anchor_index],
                        group="g1",
                    )
                    for term_index, (statement_g1, _statement_g2) in enumerate(
                        relation.statement_terms
                    )
                    if canonical_rows[term_index][anchor_index]
                )
            )
        )
    return pairing_product(
        tuple(
            (aggregate, decompress_g2(scaled))
            for aggregate, scaled in zip(
                aggregate_statement_by_anchor,
                key.scaled_witness_anchors_g2,
                strict=True,
            )
        )
    )


def decrypt_from_statement_span_decomposition(
    key: SplitBasisPpeKey,
    ciphertext: SplitBasisPpeCiphertext,
    statement_base_coefficients: Sequence[Sequence[int]],
) -> bytes:
    session = session_from_statement_span_decomposition(
        key, statement_base_coefficients
    )
    encryption_key, nonce, aad = _kdf(session, key.relation.digest)
    return ChaCha20Poly1305(encryption_key).decrypt(
        nonce, ciphertext.payload, aad
    )


def relation_cost(
    key: SplitBasisPpeKey, ciphertext: SplitBasisPpeCiphertext
) -> SplitBasisPpeCost:
    relation = key.relation
    return SplitBasisPpeCost(
        witness_terms=relation.witness_term_count,
        witness_anchor_rank=relation.witness_anchor_count,
        statement_terms=relation.statement_term_count,
        relation_bytes=relation.encoded_bytes,
        setup_bytes=key.setup_bytes,
        ciphertext_bytes=ciphertext.encoded_bytes,
        direct_witness_pairings=relation.witness_term_count,
        compressed_witness_pairings=relation.witness_anchor_count,
        encryption_pairings=relation.statement_term_count,
    )


def build_scalar_fixture(
    *,
    witness_coefficients: Sequence[Sequence[int]],
    witness_scalars: Sequence[int],
    anchor_scalars: Sequence[int],
    statement_g2_scalars: Sequence[int],
    context: bytes,
) -> tuple[SplitBasisPpeRelation, tuple[bytes, ...]]:
    """Build a satisfying real-BN254 fixture in known-exponent space.

    The helper is test-only scaffolding.  It chooses statement G1 terms so that their
    pairing product equals the witness-side product.  It does not expose those exponents
    through the relation interface.
    """

    rows = tuple(tuple(_field(value) for value in row) for row in witness_coefficients)
    witness_values = tuple(_field(value) for value in witness_scalars)
    anchors_values = tuple(_field(value) for value in anchor_scalars)
    statement_bases = tuple(_field(value) for value in statement_g2_scalars)
    if len(rows) != len(witness_values):
        raise SplitBasisPpeError("fixture witness dimensions differ")
    if not statement_bases or any(value == 0 for value in statement_bases):
        raise SplitBasisPpeError("fixture statement base scalar is zero")

    witness_exponent = 0
    for witness, row in zip(witness_values, rows, strict=True):
        base_exponent = sum(
            coefficient * anchor
            for coefficient, anchor in zip(row, anchors_values, strict=True)
        ) % CURVE_ORDER
        witness_exponent = (witness_exponent + witness * base_exponent) % CURVE_ORDER

    # Split the target exponent deterministically across all statement terms.
    statement_g1_scalars: list[int] = []
    remaining = witness_exponent
    for index, base in enumerate(statement_bases):
        if index + 1 == len(statement_bases):
            statement_g1_scalars.append(remaining * pow(base, -1, CURVE_ORDER) % CURVE_ORDER)
        else:
            value = (index + 7) % CURVE_ORDER
            statement_g1_scalars.append(value)
            remaining = (remaining - value * base) % CURVE_ORDER

    relation = SplitBasisPpeRelation(
        tuple(
            compress_g2(multiply(G2, value, group="g2"))
            for value in anchors_values
        ),
        rows,
        tuple(
            (
                compress_g1(multiply(G1, g1_value, group="g1")),
                compress_g2(multiply(G2, g2_value, group="g2")),
            )
            for g1_value, g2_value in zip(
                statement_g1_scalars, statement_bases, strict=True
            )
        ),
        bytes(context),
    )
    witness = tuple(
        compress_g1(multiply(G1, value, group="g1")) for value in witness_values
    )
    if not relation.accepts(witness):
        raise AssertionError("constructed split-basis fixture does not satisfy relation")
    return relation, witness
