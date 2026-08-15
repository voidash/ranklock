from __future__ import annotations

"""Formal KZG-opening witness encryption and conjunction/batching models.

This module implements the algebraic construction of Fleischhacker,
Hall-Andersen and Simkin in the exponent-space group model used by RankLock.
It is a correctness, statement-binding and cost model only.  It is not a
computationally secure implementation.

For one opening statement ``(C, alpha, beta)`` and opening witness ``pi``:

    header = r * ([tau]_2 - alpha * [1]_2)
    session = e(r * (C - beta * [1]_1), [1]_2)

and a valid KZG opening satisfies ``e(pi, header) = session``.

The published multi-constraint construction chooses an independent randomizer
for every opening and hashes all resulting sessions.  Its ciphertext and
pairing work are therefore linear in the number of constraints.  Same-point
KZG openings can first be randomly aggregated, but only after every individual
claimed value is bound; otherwise false values cancel in the aggregate.
"""

from dataclasses import dataclass
import hashlib
from typing import Sequence

from .kzg_we_model import GroupElement, pairing
from .ppe_normal_form import FormalKzgSrs


DOMAIN = b"ranklock/formal-kzg-we-conjunction/v1\x00"


class KzgWitnessEncryptionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class KzgOpeningStatement:
    commitment: GroupElement
    point: int
    value: int

    def validate(self, srs: FormalKzgSrs) -> None:
        if self.commitment.group != "G1":
            raise KzgWitnessEncryptionError("KZG commitment must be in G1")
        if self.commitment.modulus != srs.modulus:
            raise KzgWitnessEncryptionError("KZG statement and SRS fields differ")

    def normalized(self, srs: FormalKzgSrs) -> "KzgOpeningStatement":
        self.validate(srs)
        return KzgOpeningStatement(
            self.commitment,
            int(self.point) % srs.modulus,
            int(self.value) % srs.modulus,
        )


@dataclass(frozen=True, slots=True)
class KzgOpeningWitness:
    opening: GroupElement

    def validate(self, srs: FormalKzgSrs) -> None:
        if self.opening.group != "G1" or self.opening.modulus != srs.modulus:
            raise KzgWitnessEncryptionError("KZG opening witness must be a G1 element")


@dataclass(frozen=True, slots=True)
class KzgWeConjunctionCiphertext:
    headers: tuple[GroupElement, ...]
    encrypted_payload: bytes
    authentication_tag: bytes
    schema: str = "ranklock-formal-kzg-we-conjunction-v1"

    @property
    def constraints(self) -> int:
        return len(self.headers)


def _expand_key(seed: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(DOMAIN + b"stream" + seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _xor(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise KzgWitnessEncryptionError("XOR operands have different lengths")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _session_key(sessions: Sequence[GroupElement]) -> bytes:
    if not sessions:
        raise KzgWitnessEncryptionError("empty KZG-WE conjunction")
    if any(session.group != "GT" for session in sessions):
        raise KzgWitnessEncryptionError("KZG-WE sessions must be in GT")
    return hashlib.sha256(
        DOMAIN
        + b"session"
        + len(sessions).to_bytes(4, "big")
        + b"".join(session.encode() for session in sessions)
    ).digest()


def encapsulate_conjunction(
    statements: Sequence[KzgOpeningStatement],
    message: bytes,
    *,
    randomizers: Sequence[int],
    srs: FormalKzgSrs,
) -> KzgWeConjunctionCiphertext:
    normalized = tuple(statement.normalized(srs) for statement in statements)
    randomizers = tuple(int(value) % srs.modulus for value in randomizers)
    if not normalized or len(normalized) != len(randomizers):
        raise KzgWitnessEncryptionError("statement/randomizer count mismatch")
    if any(value == 0 for value in randomizers):
        raise KzgWitnessEncryptionError("KZG-WE randomizers must be nonzero")

    headers: list[GroupElement] = []
    sessions: list[GroupElement] = []
    for statement, randomizer in zip(normalized, randomizers, strict=True):
        residual = statement.commitment - srs.g1.scale(statement.value)
        sessions.append(pairing(residual.scale(randomizer), srs.g2))
        headers.append(
            (srs.tau_g2 - srs.g2.scale(statement.point)).scale(randomizer)
        )
    key = _session_key(sessions)
    plaintext = bytes(message)
    encrypted = _xor(plaintext, _expand_key(key, len(plaintext)))
    tag = hashlib.sha256(DOMAIN + b"tag" + key + plaintext).digest()
    return KzgWeConjunctionCiphertext(tuple(headers), encrypted, tag)


def decapsulate_conjunction(
    ciphertext: KzgWeConjunctionCiphertext,
    witnesses: Sequence[KzgOpeningWitness],
    *,
    srs: FormalKzgSrs,
) -> bytes | None:
    witnesses = tuple(witnesses)
    if not witnesses or len(witnesses) != ciphertext.constraints:
        return None
    try:
        sessions: list[GroupElement] = []
        for witness, header in zip(witnesses, ciphertext.headers, strict=True):
            witness.validate(srs)
            if header.group != "G2" or header.modulus != srs.modulus:
                return None
            sessions.append(pairing(witness.opening, header))
        key = _session_key(sessions)
        plaintext = _xor(
            ciphertext.encrypted_payload,
            _expand_key(key, len(ciphertext.encrypted_payload)),
        )
        expected = hashlib.sha256(DOMAIN + b"tag" + key + plaintext).digest()
        return plaintext if expected == ciphertext.authentication_tag else None
    except (KzgWitnessEncryptionError, ValueError, OverflowError):
        return None


def opening_statement_and_witness(
    polynomial: Sequence[int], point: int, *, srs: FormalKzgSrs
) -> tuple[KzgOpeningStatement, KzgOpeningWitness]:
    value, opening = srs.opening_g1(polynomial, point)
    return (
        KzgOpeningStatement(srs.commit_g1(polynomial), point, value),
        KzgOpeningWitness(opening),
    )


def _rho_powers(count: int, rho: int, modulus: int) -> tuple[int, ...]:
    if count <= 0:
        raise KzgWitnessEncryptionError("batch count must be positive")
    powers = [1]
    for _ in range(1, count):
        powers.append(powers[-1] * int(rho) % modulus)
    return tuple(powers)


def aggregate_same_point(
    statements: Sequence[KzgOpeningStatement],
    witnesses: Sequence[KzgOpeningWitness],
    *,
    rho: int,
    srs: FormalKzgSrs,
) -> tuple[KzgOpeningStatement, KzgOpeningWitness]:
    statements = tuple(statement.normalized(srs) for statement in statements)
    witnesses = tuple(witnesses)
    if not statements or len(statements) != len(witnesses):
        raise KzgWitnessEncryptionError("batch statement/witness count mismatch")
    point = statements[0].point
    if any(statement.point != point for statement in statements):
        raise KzgWitnessEncryptionError("simple aggregation requires one opening point")
    for witness in witnesses:
        witness.validate(srs)
    powers = _rho_powers(len(statements), rho, srs.modulus)
    commitment = srs.g1.scale(0)
    value = 0
    opening = srs.g1.scale(0)
    for coefficient, statement, witness in zip(
        powers, statements, witnesses, strict=True
    ):
        commitment = commitment + statement.commitment.scale(coefficient)
        value = (value + coefficient * statement.value) % srs.modulus
        opening = opening + witness.opening.scale(coefficient)
    return KzgOpeningStatement(commitment, point, value), KzgOpeningWitness(opening)


def aggregate_claimed_values(
    statements: Sequence[KzgOpeningStatement], *, rho: int, srs: FormalKzgSrs
) -> KzgOpeningStatement:
    """Aggregate statements without witnesses.

    This helper is intentionally usable with false individual values.  It makes
    the known-challenge cancellation attack executable: if values are chosen
    after ``rho``, distinct false values can preserve the one aggregate value.
    """

    statements = tuple(statement.normalized(srs) for statement in statements)
    if not statements:
        raise KzgWitnessEncryptionError("empty claimed-value batch")
    point = statements[0].point
    if any(statement.point != point for statement in statements):
        raise KzgWitnessEncryptionError("simple aggregation requires one opening point")
    powers = _rho_powers(len(statements), rho, srs.modulus)
    commitment = srs.g1.scale(0)
    value = 0
    for coefficient, statement in zip(powers, statements, strict=True):
        commitment = commitment + statement.commitment.scale(coefficient)
        value = (value + coefficient * statement.value) % srs.modulus
    return KzgOpeningStatement(commitment, point, value)


def conjunction_cost_inventory(constraints: int, *, group_element_bytes: int = 96) -> dict[str, object]:
    if constraints <= 0 or group_element_bytes <= 0:
        raise KzgWitnessEncryptionError("invalid conjunction cost parameters")
    return {
        "schema": "ranklock-kzg-we-conjunction-cost-v1",
        "opening_constraints": int(constraints),
        "ciphertext_group_elements": int(constraints),
        "ciphertext_header_bytes": int(constraints) * int(group_element_bytes),
        "decryption_pairings": int(constraints),
        "encryption_pairings": int(constraints),
        "asymptotic": "linear in the number of KZG opening constraints",
        "source_result": "Fleischhacker-Hall-Andersen-Simkin multi-constraint KZG-WE",
    }
