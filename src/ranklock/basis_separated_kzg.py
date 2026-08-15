from __future__ import annotations

"""Basis-separated KZG openings and statement-specific witness encryption.

Standard KZG verifies

    e(pi, [tau-z]_2) = e(C-y, [1]_2).

Trying to make its WE header reusable across future points by publishing
``r[tau]_2`` and ``r[1]_2`` is fatal: the second anchor directly exposes the
statement-side session ``e(C-y, r[1]_2)``.

This experiment introduces an independent hidden setup scalar ``rho`` and uses

    proof = [rho * q(tau)]_1
    e(proof, [tau-z]_2) = e(C-y, [rho]_2).

The witness-side header basis remains ``([tau]_2, [1]_2)``, while the statement
base is ``[rho]_2``.  Thus reusable scaled witness anchors ``r[tau]_2,r[1]_2``
do not *algebraically* expose the statement session unless a public decomposition
of ``[rho]_2`` in that basis is supplied.

This does not complete static RankLock: encryption still needs the future
``C-y`` point while the scalar ``r`` is live.  Publishing ``r[rho]_2`` removes
that timing dependence but immediately exposes the session to everybody.  The
module therefore establishes a useful basis-separation lemma and a remaining
online-encapsulation barrier, not a production PCS or a proof of extractable WE.
"""

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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
from .real_kzg_we import opening_quotient, polynomial_evaluate


class BasisSeparatedKzgError(RuntimeError):
    pass


def _field(value: int) -> int:
    return int(value) % CURVE_ORDER


def _sum_g1(points: Sequence[Point]) -> Point:
    result = multiply(G1, 0, group="g1")
    for point in points:
        result = add(result, point, group="g1")
    return result


def _gt_bytes(value: FQ12) -> bytes:
    return value.to_bytes()


def _kdf(session: FQ12, statement_digest: bytes) -> tuple[bytes, bytes, bytes]:
    raw = _gt_bytes(session)
    domain = b"ranklock/basis-separated-kzg-we/kdf/v1\x00" + statement_digest
    return (
        sha256(domain + b"key\x00" + raw).digest(),
        sha256(domain + b"nonce\x00" + raw).digest()[:12],
        domain + b"payload",
    )


@dataclass(frozen=True, slots=True)
class BasisSeparatedKzgSrs:
    commitment_g1_powers: tuple[bytes, ...]
    opening_g1_powers: tuple[bytes, ...]
    g2: bytes
    tau_g2: bytes
    rho_g2: bytes
    schema: str = "ranklock-basis-separated-kzg-srs-v1"

    def __post_init__(self) -> None:
        if len(self.commitment_g1_powers) < 2:
            raise BasisSeparatedKzgError("KZG SRS degree must be at least one")
        if len(self.commitment_g1_powers) != len(self.opening_g1_powers):
            raise BasisSeparatedKzgError("commitment/opening SRS dimensions differ")
        for encoded in self.commitment_g1_powers + self.opening_g1_powers:
            decompress_g1(encoded)
        for encoded in (self.g2, self.tau_g2, self.rho_g2):
            decompress_g2(encoded)

    @classmethod
    def generate(
        cls, maximum_degree: int, *, tau: int, rho: int
    ) -> "BasisSeparatedKzgSrs":
        if not 1 <= maximum_degree <= 1_000_000:
            raise BasisSeparatedKzgError("KZG degree outside local bounds")
        tau = _field(tau)
        rho = _field(rho)
        if tau == 0 or rho == 0:
            raise BasisSeparatedKzgError("tau and rho must be nonzero")
        commitment: list[bytes] = []
        opening: list[bytes] = []
        power = 1
        for _ in range(maximum_degree + 1):
            commitment.append(compress_g1(multiply(G1, power, group="g1")))
            opening.append(
                compress_g1(multiply(G1, rho * power % CURVE_ORDER, group="g1"))
            )
            power = power * tau % CURVE_ORDER
        return cls(
            tuple(commitment),
            tuple(opening),
            compress_g2(G2),
            compress_g2(multiply(G2, tau, group="g2")),
            compress_g2(multiply(G2, rho, group="g2")),
        )

    @property
    def maximum_degree(self) -> int:
        return len(self.commitment_g1_powers) - 1

    @property
    def encoded_bytes(self) -> int:
        return (
            sum(len(value) for value in self.commitment_g1_powers)
            + sum(len(value) for value in self.opening_g1_powers)
            + len(self.g2)
            + len(self.tau_g2)
            + len(self.rho_g2)
        )

    def _msm(self, bases: Sequence[bytes], scalars: Sequence[int]) -> bytes:
        if len(scalars) > len(bases):
            raise BasisSeparatedKzgError("polynomial exceeds SRS degree")
        terms = tuple(
            multiply(decompress_g1(base), _field(scalar), group="g1")
            for base, scalar in zip(bases, scalars, strict=False)
            if _field(scalar)
        )
        point = _sum_g1(terms)
        if point is None:
            raise BasisSeparatedKzgError("KZG MSM is infinity")
        return compress_g1(point)

    def commit(self, coefficients: Sequence[int]) -> bytes:
        if not coefficients:
            raise BasisSeparatedKzgError("polynomial is empty")
        return self._msm(self.commitment_g1_powers, coefficients)

    def open(self, coefficients: Sequence[int], point: int) -> "BasisSeparatedOpening":
        value, quotient = opening_quotient(coefficients, point)
        # q=0 is a valid KZG opening but this compressed-point research backend
        # intentionally excludes infinity encodings.  RankLock verifier traces are
        # nonconstant; callers should choose nonconstant test polynomials.
        if all(_field(value) == 0 for value in quotient):
            raise BasisSeparatedKzgError("zero quotient is unsupported by local encoding")
        return BasisSeparatedOpening(
            _field(point), value, self._msm(self.opening_g1_powers, quotient)
        )


@dataclass(frozen=True, slots=True)
class BasisSeparatedStatement:
    commitment_g1: bytes
    point: int
    value: int
    context: bytes = b""
    schema: str = "ranklock-basis-separated-kzg-statement-v1"

    def __post_init__(self) -> None:
        decompress_g1(self.commitment_g1)
        if not 0 <= self.point < CURVE_ORDER or not 0 <= self.value < CURVE_ORDER:
            raise BasisSeparatedKzgError("statement scalar is non-canonical")

    @property
    def digest(self) -> bytes:
        return sha256(
            b"ranklock/basis-separated-kzg-statement/v1\x00"
            + len(self.context).to_bytes(4, "big")
            + self.context
            + self.commitment_g1
            + self.point.to_bytes(32, "big")
            + self.value.to_bytes(32, "big")
        ).digest()


@dataclass(frozen=True, slots=True)
class BasisSeparatedOpening:
    point: int
    value: int
    proof_g1: bytes
    schema: str = "ranklock-basis-separated-kzg-opening-v1"

    def __post_init__(self) -> None:
        if not 0 <= self.point < CURVE_ORDER or not 0 <= self.value < CURVE_ORDER:
            raise BasisSeparatedKzgError("opening scalar is non-canonical")
        decompress_g1(self.proof_g1)


@dataclass(frozen=True, slots=True)
class BasisSeparatedCiphertext:
    header_tau_g2: bytes
    header_one_g2: bytes
    payload: bytes
    schema: str = "ranklock-basis-separated-kzg-ciphertext-v1"

    def __post_init__(self) -> None:
        decompress_g2(self.header_tau_g2)
        decompress_g2(self.header_one_g2)
        if len(self.payload) != 48:
            raise BasisSeparatedKzgError("ciphertext payload must be 48 bytes")

    @property
    def encoded_bytes(self) -> int:
        return len(self.header_tau_g2) + len(self.header_one_g2) + len(self.payload)

    def header_for_point(self, point: int) -> bytes:
        return compress_g2(
            add(
                decompress_g2(self.header_tau_g2),
                neg(
                    multiply(
                        decompress_g2(self.header_one_g2),
                        _field(point),
                        group="g2",
                    )
                ),
                group="g2",
            )
        )


def _commitment_minus_value(statement: BasisSeparatedStatement) -> Point:
    return add(
        decompress_g1(statement.commitment_g1),
        neg(multiply(G1, statement.value, group="g1")),
        group="g1",
    )


def verify_basis_separated_opening(
    srs: BasisSeparatedKzgSrs,
    statement: BasisSeparatedStatement,
    opening: BasisSeparatedOpening,
) -> bool:
    try:
        if opening.point != statement.point or opening.value != statement.value:
            return False
        tau_minus_z = add(
            decompress_g2(srs.tau_g2),
            neg(multiply(G2, statement.point, group="g2")),
            group="g2",
        )
        check = pairing_product(
            (
                (decompress_g1(opening.proof_g1), tau_minus_z),
                (neg(_commitment_minus_value(statement)), decompress_g2(srs.rho_g2)),
            )
        )
        return check == FQ12.one()
    except (BasisSeparatedKzgError, ValueError, ZeroDivisionError, OverflowError):
        return False


def encrypt_basis_separated_opening(
    srs: BasisSeparatedKzgSrs,
    statement: BasisSeparatedStatement,
    secret: bytes,
    *,
    randomness: int,
) -> BasisSeparatedCiphertext:
    secret = bytes(secret)
    if len(secret) != 32:
        raise BasisSeparatedKzgError("WE payload must be 32 bytes")
    r = _field(randomness)
    if r == 0:
        raise BasisSeparatedKzgError("WE randomness is zero")
    header_tau = multiply(decompress_g2(srs.tau_g2), r, group="g2")
    header_one = multiply(G2, r, group="g2")
    session = pairing_product(
        (
            (
                multiply(_commitment_minus_value(statement), r, group="g1"),
                decompress_g2(srs.rho_g2),
            ),
        )
    )
    key, nonce, aad = _kdf(session, statement.digest)
    return BasisSeparatedCiphertext(
        compress_g2(header_tau),
        compress_g2(header_one),
        ChaCha20Poly1305(key).encrypt(nonce, secret, aad),
    )


def decrypt_basis_separated_opening(
    statement: BasisSeparatedStatement,
    ciphertext: BasisSeparatedCiphertext,
    opening: BasisSeparatedOpening,
) -> bytes:
    if opening.point != statement.point or opening.value != statement.value:
        raise BasisSeparatedKzgError("opening belongs to another statement")
    session = pairing_product(
        (
            (
                decompress_g1(opening.proof_g1),
                decompress_g2(ciphertext.header_for_point(statement.point)),
            ),
        )
    )
    key, nonce, aad = _kdf(session, statement.digest)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext.payload, aad)
    except InvalidTag as exc:
        raise BasisSeparatedKzgError("basis-separated KZG-WE decryption failed") from exc


def session_from_published_scaled_rho(
    statement: BasisSeparatedStatement,
    scaled_rho_g2: bytes,
) -> FQ12:
    """Show that publishing ``r[rho]_2`` destroys witness encryption."""

    decompress_g2(scaled_rho_g2)
    return pairing_product(
        ((_commitment_minus_value(statement), decompress_g2(scaled_rho_g2)),)
    )


def decrypt_from_published_scaled_rho(
    statement: BasisSeparatedStatement,
    ciphertext: BasisSeparatedCiphertext,
    scaled_rho_g2: bytes,
) -> bytes:
    session = session_from_published_scaled_rho(
        statement, scaled_rho_g2
    )
    key, nonce, aad = _kdf(session, statement.digest)
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext.payload, aad)


def static_timing_frontier(
    srs: BasisSeparatedKzgSrs, *, proof_points: int = 1
) -> dict[str, object]:
    return {
        "schema": "ranklock-basis-separated-kzg-frontier-v1",
        "evidence_class": "EXACT interface/cost accounting plus executable attacks",
        "maximum_degree": srs.maximum_degree,
        "srs_bytes": srs.encoded_bytes,
        "reusable_witness_header_anchors": 2,
        "reusable_witness_header_bytes": 2 * 64,
        "proof_g1_elements": int(proof_points),
        "decryption_pairings": 1,
        "statement_base_publicly_decomposed_over_witness_headers": False,
        "post_statement_encapsulator_required": True,
        "why": (
            "The future point z can be applied to r[tau],r[1] without exposing "
            "the rho-separated statement session.  But the payload key still depends "
            "on the future C-y point while r is live.  Publishing r[rho] removes the "
            "online encapsulator and simultaneously makes the session public."
        ),
        "decision": "BASIS_SEPARATION_PASSES; STATIC_TIMING_REMAINS_OPEN",
    }
