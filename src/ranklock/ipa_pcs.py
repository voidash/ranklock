from __future__ import annotations

"""A real discrete-log binding IPA opening backend for RankFold.

This is a transparent reference PCS over Grumpkin.  It makes the RankFold
opening-binding assumption executable, but it deliberately exposes the next
performance wall: verification folds O(N) public generators and is therefore
not the width-free PCS needed for the final breakthrough.
"""

from dataclasses import dataclass
import hashlib
from typing import Sequence

from .field import BN254_BASE_FIELD
from .grumpkin import (
    AffinePoint,
    GRUMPKIN_SCALAR_FIELD,
    add,
    compress,
    decompress,
    hash_to_curve,
    multi_scalar_multiply,
    scalar_multiply,
)
from .rankfold import (
    InMemoryMultilinearOracle,
    RankFoldError,
    RankFoldOpening,
    RankFoldStatement,
    _commit_vector,
    _field_bytes,
    equality_table,
    evaluate_multilinear,
)

IPA_DOMAIN = b"ranklock/grumpkin-ipa/v1\x00"
PROOF_MAGIC = b"RIPA1"


class IpaError(ValueError):
    pass


def _point_add_many(*points: AffinePoint) -> AffinePoint:
    result: AffinePoint = None
    for point in points:
        result = add(result, point)
    return result


def _inner(left: Sequence[int], right: Sequence[int], modulus: int) -> int:
    if len(left) != len(right):
        raise IpaError("inner-product dimensions differ")
    return sum((int(a) * int(b)) % modulus for a, b in zip(left, right, strict=True)) % modulus


def _hash_scalar(seed: bytes, *parts: bytes) -> int:
    for counter in range(2**32):
        digest = hashlib.sha256(
            IPA_DOMAIN
            + len(seed).to_bytes(4, "big")
            + seed
            + b"".join(len(part).to_bytes(4, "big") + part for part in parts)
            + counter.to_bytes(4, "big")
        ).digest()
        value = int.from_bytes(digest, "big") % GRUMPKIN_SCALAR_FIELD
        if value != 0:
            return value
    raise RuntimeError("IPA challenge derivation exhausted")


@dataclass(frozen=True, slots=True)
class IpaParameters:
    size: int
    domain: bytes
    g: tuple[AffinePoint, ...]
    h: tuple[AffinePoint, ...]
    u: AffinePoint

    @classmethod
    def derive(cls, size: int, *, domain: bytes = b"ranklock-default-ipa") -> "IpaParameters":
        if size <= 0 or size & (size - 1):
            raise IpaError("IPA size must be a positive power of two")
        g = tuple(hash_to_curve(IPA_DOMAIN + domain + b"/G", index) for index in range(size))
        h = tuple(hash_to_curve(IPA_DOMAIN + domain + b"/H", index) for index in range(size))
        u = hash_to_curve(IPA_DOMAIN + domain + b"/U", 0)
        return cls(size, bytes(domain), g, h, u)

    @property
    def digest(self) -> bytes:
        digest = hashlib.sha256(IPA_DOMAIN + b"parameters\x00" + self.domain)
        digest.update(self.size.to_bytes(8, "big"))
        for point in (*self.g, *self.h, self.u):
            digest.update(compress(point))
        return digest.digest()


@dataclass(frozen=True, slots=True)
class IpaProof:
    left_points: tuple[AffinePoint, ...]
    right_points: tuple[AffinePoint, ...]
    final_a: int

    def __post_init__(self) -> None:
        if len(self.left_points) != len(self.right_points):
            raise IpaError("IPA proof round vectors differ")

    def serialize(self) -> bytes:
        if len(self.left_points) >= 2**16:
            raise IpaError("IPA proof has too many rounds")
        return (
            PROOF_MAGIC
            + len(self.left_points).to_bytes(2, "big")
            + b"".join(
                compress(left) + compress(right)
                for left, right in zip(self.left_points, self.right_points, strict=True)
            )
            + (self.final_a % GRUMPKIN_SCALAR_FIELD).to_bytes(32, "big")
        )

    @classmethod
    def parse(cls, raw: bytes) -> "IpaProof":
        if len(raw) < len(PROOF_MAGIC) + 2 + 32 or not raw.startswith(PROOF_MAGIC):
            raise IpaError("invalid IPA proof encoding")
        offset = len(PROOF_MAGIC)
        rounds = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        expected = len(PROOF_MAGIC) + 2 + rounds * 66 + 32
        if len(raw) != expected:
            raise IpaError("IPA proof length differs")
        left: list[AffinePoint] = []
        right: list[AffinePoint] = []
        for _ in range(rounds):
            left.append(decompress(raw[offset : offset + 33]))
            offset += 33
            right.append(decompress(raw[offset : offset + 33]))
            offset += 33
        final_a = int.from_bytes(raw[offset : offset + 32], "big")
        if final_a >= GRUMPKIN_SCALAR_FIELD:
            raise IpaError("non-canonical IPA scalar")
        return cls(tuple(left), tuple(right), final_a)


@dataclass(frozen=True, slots=True)
class IpaVerificationMetrics:
    vector_size: int
    rounds: int
    proof_bytes: int
    verifier_generator_scalar_multiplications: int
    verifier_proof_point_scalar_multiplications: int
    schema: str = "ranklock-ipa-metrics-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "vector_size": self.vector_size,
            "rounds": self.rounds,
            "proof_bytes": self.proof_bytes,
            "verifier_generator_scalar_multiplications": self.verifier_generator_scalar_multiplications,
            "verifier_proof_point_scalar_multiplications": self.verifier_proof_point_scalar_multiplications,
            "warning": (
                "The proof is logarithmic, but this reference IPA verifier still performs "
                "O(N) generator scalar multiplications. It binds RankFold openings but does "
                "not satisfy the width-free expensive-evaluation target."
            ),
        }


def ipa_metrics(size: int) -> IpaVerificationMetrics:
    if size <= 0 or size & (size - 1):
        raise IpaError("IPA size must be a positive power of two")
    rounds = size.bit_length() - 1
    proof_bytes = len(PROOF_MAGIC) + 2 + 66 * rounds + 32
    # Folding G and H requires two scalar multiplications for every generator at every
    # level; the geometric sum is < 4N.  Two proof points are also scaled per round.
    return IpaVerificationMetrics(size, rounds, proof_bytes, 4 * size - 4, 2 * rounds)


def commit_vector(parameters: IpaParameters, vector: Sequence[int]) -> AffinePoint:
    if len(vector) != parameters.size:
        raise IpaError("commitment vector has wrong length")
    return multi_scalar_multiply(parameters.g, tuple(int(value) % GRUMPKIN_SCALAR_FIELD for value in vector))


def prove_inner_product(
    parameters: IpaParameters,
    *,
    vector: Sequence[int],
    public_weights: Sequence[int],
    claimed_value: int,
    commitment: AffinePoint,
    transcript_seed: bytes,
) -> IpaProof:
    n = parameters.size
    if len(vector) != n or len(public_weights) != n:
        raise IpaError("IPA witness dimensions differ")
    modulus = GRUMPKIN_SCALAR_FIELD
    a = [int(value) % modulus for value in vector]
    b = [int(value) % modulus for value in public_weights]
    if _inner(a, b, modulus) != claimed_value % modulus:
        raise IpaError("claimed IPA opening value is false")
    if commit_vector(parameters, a) != commitment:
        raise IpaError("IPA witness does not match commitment")
    g = list(parameters.g)
    h = list(parameters.h)
    left_points: list[AffinePoint] = []
    right_points: list[AffinePoint] = []
    state = hashlib.sha256(
        IPA_DOMAIN
        + b"opening\x00"
        + parameters.digest
        + compress(commitment)
        + (claimed_value % modulus).to_bytes(32, "big")
        + transcript_seed
    ).digest()

    while len(a) > 1:
        half = len(a) // 2
        a_l, a_r = a[:half], a[half:]
        b_l, b_r = b[:half], b[half:]
        g_l, g_r = g[:half], g[half:]
        h_l, h_r = h[:half], h[half:]
        c_l = _inner(a_l, b_r, modulus)
        c_r = _inner(a_r, b_l, modulus)
        left = _point_add_many(
            multi_scalar_multiply(g_r, a_l),
            multi_scalar_multiply(h_l, b_r),
            scalar_multiply(parameters.u, c_l),
        )
        right = _point_add_many(
            multi_scalar_multiply(g_l, a_r),
            multi_scalar_multiply(h_r, b_l),
            scalar_multiply(parameters.u, c_r),
        )
        left_points.append(left)
        right_points.append(right)
        encoded_l, encoded_r = compress(left), compress(right)
        challenge = _hash_scalar(state, encoded_l, encoded_r)
        inverse = pow(challenge, -1, modulus)
        state = hashlib.sha256(state + encoded_l + encoded_r + challenge.to_bytes(32, "big")).digest()
        a = [
            (left_value * challenge + right_value * inverse) % modulus
            for left_value, right_value in zip(a_l, a_r, strict=True)
        ]
        b = [
            (left_value * inverse + right_value * challenge) % modulus
            for left_value, right_value in zip(b_l, b_r, strict=True)
        ]
        g = [
            _point_add_many(
                scalar_multiply(left_point, inverse),
                scalar_multiply(right_point, challenge),
            )
            for left_point, right_point in zip(g_l, g_r, strict=True)
        ]
        h = [
            _point_add_many(
                scalar_multiply(left_point, challenge),
                scalar_multiply(right_point, inverse),
            )
            for left_point, right_point in zip(h_l, h_r, strict=True)
        ]
    return IpaProof(tuple(left_points), tuple(right_points), a[0])


def verify_inner_product(
    parameters: IpaParameters,
    *,
    public_weights: Sequence[int],
    claimed_value: int,
    commitment: AffinePoint,
    transcript_seed: bytes,
    proof: IpaProof,
) -> bool:
    try:
        n = parameters.size
        rounds = n.bit_length() - 1
        if len(public_weights) != n or len(proof.left_points) != rounds:
            return False
        modulus = GRUMPKIN_SCALAR_FIELD
        b = [int(value) % modulus for value in public_weights]
        g = list(parameters.g)
        h = list(parameters.h)
        p = _point_add_many(
            commitment,
            multi_scalar_multiply(h, b),
            scalar_multiply(parameters.u, claimed_value % modulus),
        )
        state = hashlib.sha256(
            IPA_DOMAIN
            + b"opening\x00"
            + parameters.digest
            + compress(commitment)
            + (claimed_value % modulus).to_bytes(32, "big")
            + transcript_seed
        ).digest()
        for left, right in zip(proof.left_points, proof.right_points, strict=True):
            encoded_l, encoded_r = compress(left), compress(right)
            challenge = _hash_scalar(state, encoded_l, encoded_r)
            inverse = pow(challenge, -1, modulus)
            state = hashlib.sha256(
                state + encoded_l + encoded_r + challenge.to_bytes(32, "big")
            ).digest()
            p = _point_add_many(
                scalar_multiply(left, challenge * challenge % modulus),
                p,
                scalar_multiply(right, inverse * inverse % modulus),
            )
            half = len(b) // 2
            b_l, b_r = b[:half], b[half:]
            g_l, g_r = g[:half], g[half:]
            h_l, h_r = h[:half], h[half:]
            b = [
                (left_value * inverse + right_value * challenge) % modulus
                for left_value, right_value in zip(b_l, b_r, strict=True)
            ]
            g = [
                _point_add_many(
                    scalar_multiply(left_point, inverse),
                    scalar_multiply(right_point, challenge),
                )
                for left_point, right_point in zip(g_l, g_r, strict=True)
            ]
            h = [
                _point_add_many(
                    scalar_multiply(left_point, challenge),
                    scalar_multiply(right_point, inverse),
                )
                for left_point, right_point in zip(h_l, h_r, strict=True)
            ]
        if len(b) != 1 or len(g) != 1 or len(h) != 1:
            return False
        final_a = proof.final_a % modulus
        expected = _point_add_many(
            scalar_multiply(g[0], final_a),
            scalar_multiply(h[0], b[0]),
            scalar_multiply(parameters.u, final_a * b[0] % modulus),
        )
        return p == expected
    except (IpaError, ValueError):
        return False


class IpaMultilinearOracle(InMemoryMultilinearOracle):
    """RankFold oracle with one batched Grumpkin IPA opening."""

    def __init__(
        self,
        a: Sequence[int],
        b: Sequence[int],
        c: Sequence[int],
        *,
        context_digest: bytes,
        parameters: IpaParameters | None = None,
        modulus: int = BN254_BASE_FIELD,
    ) -> None:
        if modulus != GRUMPKIN_SCALAR_FIELD:
            raise IpaError("Grumpkin IPA only commits the BN254 base field")
        super().__init__(a, b, c, context_digest=context_digest, modulus=modulus)
        self.parameters = parameters or IpaParameters.derive(
            self.statement.padded_length,
            domain=b"rankfold/" + context_digest,
        )
        if self.parameters.size != self.statement.padded_length:
            raise IpaError("IPA parameter size differs from RankFold table")
        self.commitment_points = (
            commit_vector(self.parameters, self.a),
            commit_vector(self.parameters, self.b),
            commit_vector(self.parameters, self.c),
        )
        commitments = tuple(
            hashlib.sha256(b"ranklock/ipa-commitment/v1\x00" + compress(point)).digest()
            for point in self.commitment_points
        )
        self._statement = RankFoldStatement(
            context_digest=bytes(context_digest),
            logical_length=self.logical_length,
            padded_length=len(self.a),
            commitments=commitments,  # type: ignore[arg-type]
            modulus=modulus,
        )

    def _batch_challenges(
        self, point: Sequence[int], values: tuple[int, int, int]
    ) -> tuple[int, int, int]:
        seed = hashlib.sha256(
            IPA_DOMAIN
            + b"batch\x00"
            + self.statement.digest
            + b"".join(_field_bytes(value, self.modulus) for value in point)
            + b"".join(_field_bytes(value, self.modulus) for value in values)
            + b"".join(compress(commitment) for commitment in self.commitment_points)
        ).digest()
        return tuple(_hash_scalar(seed, index.to_bytes(4, "big")) for index in range(3))  # type: ignore[return-value]

    def open(self, point: Sequence[int]) -> RankFoldOpening:
        if len(point) != self.statement.rounds:
            raise RankFoldError("opening point has wrong dimension")
        values = (
            evaluate_multilinear(self.a, point, self.modulus),
            evaluate_multilinear(self.b, point, self.modulus),
            evaluate_multilinear(self.c, point, self.modulus),
        )
        challenges = self._batch_challenges(point, values)
        combined_vector = tuple(
            sum(challenge * vector[index] for challenge, vector in zip(challenges, (self.a, self.b, self.c), strict=True))
            % self.modulus
            for index in range(len(self.a))
        )
        combined_commitment = _point_add_many(
            *(
                scalar_multiply(commitment, challenge)
                for commitment, challenge in zip(self.commitment_points, challenges, strict=True)
            )
        )
        combined_value = sum(
            challenge * value for challenge, value in zip(challenges, values, strict=True)
        ) % self.modulus
        weights = equality_table(point, self.modulus)
        transcript_seed = hashlib.sha256(
            IPA_DOMAIN + b"rankfold-opening\x00" + self.statement.digest
        ).digest()
        proof = prove_inner_product(
            self.parameters,
            vector=combined_vector,
            public_weights=weights,
            claimed_value=combined_value,
            commitment=combined_commitment,
            transcript_seed=transcript_seed,
        )
        return RankFoldOpening(values[0], values[1], values[2], proof.serialize())

    def verify(self, point: Sequence[int], opening: RankFoldOpening) -> bool:
        try:
            if len(point) != self.statement.rounds:
                return False
            values = (
                opening.a % self.modulus,
                opening.b % self.modulus,
                opening.c % self.modulus,
            )
            challenges = self._batch_challenges(point, values)
            combined_commitment = _point_add_many(
                *(
                    scalar_multiply(commitment, challenge)
                    for commitment, challenge in zip(
                        self.commitment_points, challenges, strict=True
                    )
                )
            )
            combined_value = sum(
                challenge * value for challenge, value in zip(challenges, values, strict=True)
            ) % self.modulus
            proof = IpaProof.parse(opening.proof)
            transcript_seed = hashlib.sha256(
                IPA_DOMAIN + b"rankfold-opening\x00" + self.statement.digest
            ).digest()
            return verify_inner_product(
                self.parameters,
                public_weights=equality_table(point, self.modulus),
                claimed_value=combined_value,
                commitment=combined_commitment,
                transcript_seed=transcript_seed,
                proof=proof,
            )
        except (IpaError, RankFoldError, ValueError):
            return False
