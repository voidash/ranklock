from __future__ import annotations

"""A transparent reference implementation of the RankFold multiplication argument.

The module proves a batch of pointwise field multiplication constraints

    c_i = a_i * b_i

by combining an outer random multilinear residual evaluation with a degree-three
sumcheck.  The verifier work is logarithmic in the padded batch size *apart from*
the multilinear polynomial-commitment opening.  ``InMemoryMultilinearOracle``
is intentionally only a transparent reference oracle; replacing it with a
binding succinct PCS (and then turning acceptance into conditional disclosure)
is the load-bearing open cryptographic step.
"""

from dataclasses import dataclass
import hashlib
import json
from math import ceil, log2
from typing import Protocol, Sequence

from .field import BN254_BASE_FIELD
from .rank_ir import RankDecomposition

FIELD_BYTES = 32
SUMCHECK_DEGREE = 3
DOMAIN = b"ranklock/rankfold/v1\x00"


class RankFoldError(ValueError):
    """Malformed statement, table, or proof."""


def _field(value: int, modulus: int) -> int:
    return int(value) % modulus


def _field_bytes(value: int, modulus: int) -> bytes:
    value = _field(value, modulus)
    width = max(FIELD_BYTES, (modulus.bit_length() + 7) // 8)
    return value.to_bytes(width, "big")


def _next_power_of_two(value: int) -> int:
    if value <= 0:
        raise RankFoldError("constraint count must be positive")
    return 1 << (value - 1).bit_length()


def _hash_to_field(seed: bytes, modulus: int, *, label: bytes, index: int) -> int:
    """Deterministically rejection-sample one field element from SHA-256."""

    if modulus <= 3:
        raise RankFoldError("RankFold requires a field of characteristic greater than three")
    ceiling = 1 << 256
    limit = ceiling - (ceiling % modulus)
    for attempt in range(2**32):
        digest = hashlib.sha256(
            DOMAIN
            + len(seed).to_bytes(8, "big")
            + seed
            + len(label).to_bytes(4, "big")
            + label
            + int(index).to_bytes(8, "big")
            + attempt.to_bytes(4, "big")
        ).digest()
        candidate = int.from_bytes(digest, "big")
        if candidate < limit:
            return candidate % modulus
    raise RuntimeError("hash-to-field rejection sampler exhausted")


def _commit_vector(
    values: Sequence[int], *, modulus: int, logical_length: int, label: bytes
) -> bytes:
    digest = hashlib.sha256()
    digest.update(DOMAIN)
    digest.update(b"vector-commitment\x00")
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(int(modulus).to_bytes(FIELD_BYTES, "big"))
    digest.update(int(logical_length).to_bytes(8, "big"))
    digest.update(len(values).to_bytes(8, "big"))
    for value in values:
        digest.update(_field_bytes(value, modulus))
    return digest.digest()


def _encode_round(evaluations: Sequence[int], modulus: int) -> bytes:
    if len(evaluations) != SUMCHECK_DEGREE + 1:
        raise RankFoldError("a RankFold round must contain four evaluations")
    return b"".join(_field_bytes(value, modulus) for value in evaluations)


def _interpolate_degree_three(evaluations: Sequence[int], point: int, modulus: int) -> int:
    """Evaluate the unique degree-at-most-three polynomial through x=0,1,2,3."""

    if len(evaluations) != 4:
        raise RankFoldError("degree-three interpolation requires four evaluations")
    point %= modulus
    # Fixed Lagrange denominators for nodes 0,1,2,3: -6, 2, -2, 6.
    denominators = (-6, 2, -2, 6)
    result = 0
    for index, value in enumerate(evaluations):
        numerator = 1
        for node in range(4):
            if node != index:
                numerator = numerator * (point - node) % modulus
        result = (
            result
            + int(value) * numerator * pow(denominators[index] % modulus, -1, modulus)
        ) % modulus
    return result


def evaluate_multilinear(values: Sequence[int], point: Sequence[int], modulus: int) -> int:
    """Evaluate a multilinear table using little-endian variable ordering.

    Adjacent entries differ in variable zero.  This is the ordering used by the
    sumcheck folding loop and by the trace compiler.
    """

    expected = 1 << len(point)
    if len(values) != expected:
        raise RankFoldError("multilinear table length does not match evaluation point")
    layer = [_field(value, modulus) for value in values]
    for challenge in point:
        challenge %= modulus
        layer = [
            (left + challenge * (right - left)) % modulus
            for left, right in zip(layer[0::2], layer[1::2], strict=True)
        ]
    if len(layer) != 1:
        raise AssertionError("multilinear folding did not terminate")
    return layer[0]


def equality_table(point: Sequence[int], modulus: int) -> tuple[int, ...]:
    """Return ``eq(point, x)`` on all Boolean vertices x."""

    weights = [1]
    for coordinate in point:
        coordinate %= modulus
        zero = (1 - coordinate) % modulus
        # Add the new coordinate as the most-significant bit so variable zero
        # remains the adjacent/least-significant coordinate.
        weights = [weight * zero % modulus for weight in weights] + [
            weight * coordinate % modulus for weight in weights
        ]
    return tuple(weights)


def equality_evaluation(left: Sequence[int], right: Sequence[int], modulus: int) -> int:
    if len(left) != len(right):
        raise RankFoldError("equality-polynomial points have different dimensions")
    result = 1
    for a, b in zip(left, right, strict=True):
        a %= modulus
        b %= modulus
        coordinate = ((1 - a) * (1 - b) + a * b) % modulus
        result = result * coordinate % modulus
    return result


@dataclass(frozen=True, slots=True)
class RankFoldStatement:
    context_digest: bytes
    logical_length: int
    padded_length: int
    commitments: tuple[bytes, bytes, bytes]
    modulus: int = BN254_BASE_FIELD
    schema: str = "ranklock-rankfold-statement-v1"

    def __post_init__(self) -> None:
        if len(self.context_digest) != 32:
            raise RankFoldError("context digest must be 32 bytes")
        if self.logical_length <= 0:
            raise RankFoldError("logical length must be positive")
        if self.padded_length != _next_power_of_two(self.logical_length):
            raise RankFoldError("padded length must be the next power of two")
        if len(self.commitments) != 3 or any(len(value) != 32 for value in self.commitments):
            raise RankFoldError("RankFold requires three 32-byte table commitments")
        if self.modulus <= 3:
            raise RankFoldError("RankFold requires an odd field larger than three")

    @property
    def rounds(self) -> int:
        return self.padded_length.bit_length() - 1

    @property
    def digest(self) -> bytes:
        document = {
            "schema": self.schema,
            "context_digest": self.context_digest.hex(),
            "logical_length": self.logical_length,
            "padded_length": self.padded_length,
            "commitments": [value.hex() for value in self.commitments],
            "modulus": str(self.modulus),
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(DOMAIN + b"statement\x00" + payload).digest()


@dataclass(frozen=True, slots=True)
class RankFoldOpening:
    a: int
    b: int
    c: int
    proof: bytes = b""

    def normalized(self, modulus: int) -> "RankFoldOpening":
        return RankFoldOpening(self.a % modulus, self.b % modulus, self.c % modulus, bytes(self.proof))


@dataclass(frozen=True, slots=True)
class RankFoldProof:
    statement_digest: bytes
    rounds: tuple[tuple[int, int, int, int], ...]
    opening: RankFoldOpening
    transcript_digest: bytes
    schema: str = "ranklock-rankfold-proof-v1"

    def __post_init__(self) -> None:
        if len(self.statement_digest) != 32 or len(self.transcript_digest) != 32:
            raise RankFoldError("proof digests must be 32 bytes")
        if any(len(values) != 4 for values in self.rounds):
            raise RankFoldError("each sumcheck round must contain four field elements")

    def encoded_bytes(self, modulus: int) -> int:
        # This counts the transparent sumcheck transcript and opening values.
        # A real PCS opening proof is additive and deliberately reported separately.
        return 64 + len(self.rounds) * 4 * FIELD_BYTES + 3 * FIELD_BYTES + len(self.opening.proof)


class MultilinearOpeningOracle(Protocol):
    """Binding interface needed by the RankFold verifier."""

    @property
    def statement(self) -> RankFoldStatement: ...

    def open(self, point: Sequence[int]) -> RankFoldOpening: ...

    def verify(self, point: Sequence[int], opening: RankFoldOpening) -> bool: ...


class InMemoryMultilinearOracle:
    """Transparent, non-succinct reference oracle.

    Verification recomputes the multilinear evaluations from complete local
    vectors.  It is useful for testing the RankFold transcript, but is *not* the
    polynomial commitment required by the final construction.
    """

    def __init__(
        self,
        a: Sequence[int],
        b: Sequence[int],
        c: Sequence[int],
        *,
        context_digest: bytes,
        modulus: int = BN254_BASE_FIELD,
    ) -> None:
        if not (len(a) == len(b) == len(c)):
            raise RankFoldError("multiplication tables have different lengths")
        logical_length = len(a)
        padded_length = _next_power_of_two(logical_length)
        self.modulus = modulus
        self.logical_length = logical_length
        self.a = tuple(_field(value, modulus) for value in a) + (0,) * (
            padded_length - logical_length
        )
        self.b = tuple(_field(value, modulus) for value in b) + (0,) * (
            padded_length - logical_length
        )
        self.c = tuple(_field(value, modulus) for value in c) + (0,) * (
            padded_length - logical_length
        )
        commitments = (
            _commit_vector(self.a, modulus=modulus, logical_length=logical_length, label=b"a"),
            _commit_vector(self.b, modulus=modulus, logical_length=logical_length, label=b"b"),
            _commit_vector(self.c, modulus=modulus, logical_length=logical_length, label=b"c"),
        )
        self._statement = RankFoldStatement(
            context_digest=bytes(context_digest),
            logical_length=logical_length,
            padded_length=padded_length,
            commitments=commitments,
            modulus=modulus,
        )

    @property
    def statement(self) -> RankFoldStatement:
        return self._statement

    def open(self, point: Sequence[int]) -> RankFoldOpening:
        if len(point) != self.statement.rounds:
            raise RankFoldError("opening point has wrong dimension")
        return RankFoldOpening(
            evaluate_multilinear(self.a, point, self.modulus),
            evaluate_multilinear(self.b, point, self.modulus),
            evaluate_multilinear(self.c, point, self.modulus),
            b"in-memory-reference-oracle",
        )

    def verify(self, point: Sequence[int], opening: RankFoldOpening) -> bool:
        try:
            expected = self.open(point).normalized(self.modulus)
            actual = opening.normalized(self.modulus)
        except (RankFoldError, ValueError):
            return False
        # The proof marker has no security meaning; compare it only to catch accidental
        # cross-oracle serialization mistakes in the reference harness.
        return actual == expected


class _Transcript:
    def __init__(self, statement: RankFoldStatement) -> None:
        self.modulus = statement.modulus
        self.state = hashlib.sha256(DOMAIN + b"transcript\x00" + statement.digest).digest()

    def challenge(self, label: bytes, index: int) -> int:
        result = _hash_to_field(self.state, self.modulus, label=label, index=index)
        self.state = hashlib.sha256(
            DOMAIN
            + b"challenge\x00"
            + self.state
            + len(label).to_bytes(4, "big")
            + label
            + int(index).to_bytes(8, "big")
            + _field_bytes(result, self.modulus)
        ).digest()
        return result

    def absorb(self, label: bytes, payload: bytes) -> None:
        self.state = hashlib.sha256(
            DOMAIN
            + b"absorb\x00"
            + self.state
            + len(label).to_bytes(4, "big")
            + label
            + len(payload).to_bytes(8, "big")
            + payload
        ).digest()


def _derive_outer_point(transcript: _Transcript, rounds: int) -> tuple[int, ...]:
    return tuple(transcript.challenge(b"outer-residual-point", index) for index in range(rounds))


def _round_polynomial(
    a: Sequence[int],
    b: Sequence[int],
    c: Sequence[int],
    equality: Sequence[int],
    modulus: int,
) -> tuple[int, int, int, int]:
    """Compute p(0),p(1),p(2),p(3) using ten multiplications per pair."""

    if not (len(a) == len(b) == len(c) == len(equality)) or len(a) % 2:
        raise RankFoldError("sumcheck layers must have equal even lengths")
    coefficients = [0, 0, 0, 0]
    for index in range(0, len(a), 2):
        a0, a_at_1 = a[index], a[index + 1]
        b0, b_at_1 = b[index], b[index + 1]
        c0, c_at_1 = c[index], c[index + 1]
        e0, e_at_1 = equality[index], equality[index + 1]
        da = (a_at_1 - a0) % modulus
        db = (b_at_1 - b0) % modulus
        dc = (c_at_1 - c0) % modulus
        de = (e_at_1 - e0) % modulus

        d0 = (a0 * b0 - c0) % modulus
        d1 = (a0 * db + da * b0 - dc) % modulus
        d2 = da * db % modulus

        coefficients[0] = (coefficients[0] + e0 * d0) % modulus
        coefficients[1] = (coefficients[1] + e0 * d1 + de * d0) % modulus
        coefficients[2] = (coefficients[2] + e0 * d2 + de * d1) % modulus
        coefficients[3] = (coefficients[3] + de * d2) % modulus

    evaluations = []
    for point in range(4):
        value = 0
        power = 1
        for coefficient in coefficients:
            value = (value + coefficient * power) % modulus
            power = power * point % modulus
        evaluations.append(value)
    return tuple(evaluations)  # type: ignore[return-value]


def _fold(values: Sequence[int], challenge: int, modulus: int) -> list[int]:
    return [
        (left + challenge * (right - left)) % modulus
        for left, right in zip(values[0::2], values[1::2], strict=True)
    ]


def prove_rankfold(oracle: InMemoryMultilinearOracle) -> RankFoldProof:
    """Create a RankFold proof from the transparent reference oracle.

    The function intentionally permits invalid multiplication tables and returns
    a transcript that the verifier will reject.  This makes negative tests and
    attack experiments explicit rather than hiding them behind prover asserts.
    """

    statement = oracle.statement
    modulus = statement.modulus
    transcript = _Transcript(statement)
    outer_point = _derive_outer_point(transcript, statement.rounds)

    a = list(oracle.a)
    b = list(oracle.b)
    c = list(oracle.c)
    eq = list(equality_table(outer_point, modulus))
    current_claim = 0
    round_messages: list[tuple[int, int, int, int]] = []
    final_point: list[int] = []

    for round_index in range(statement.rounds):
        evaluations = _round_polynomial(a, b, c, eq, modulus)
        # An honest prover for a valid relation has this equality.  For an invalid
        # relation the first mismatch is left in the proof and the verifier rejects.
        round_messages.append(evaluations)
        transcript.absorb(b"sumcheck-round", _encode_round(evaluations, modulus))
        challenge = transcript.challenge(b"sumcheck-challenge", round_index)
        final_point.append(challenge)
        current_claim = _interpolate_degree_three(evaluations, challenge, modulus)
        a = _fold(a, challenge, modulus)
        b = _fold(b, challenge, modulus)
        c = _fold(c, challenge, modulus)
        eq = _fold(eq, challenge, modulus)

    opening = oracle.open(final_point).normalized(modulus)
    transcript.absorb(
        b"opening-values",
        _field_bytes(opening.a, modulus)
        + _field_bytes(opening.b, modulus)
        + _field_bytes(opening.c, modulus)
        + hashlib.sha256(opening.proof).digest(),
    )
    return RankFoldProof(
        statement_digest=statement.digest,
        rounds=tuple(round_messages),
        opening=opening,
        transcript_digest=transcript.state,
    )


def verify_rankfold(
    statement: RankFoldStatement,
    proof: RankFoldProof,
    oracle: MultilinearOpeningOracle,
) -> bool:
    """Verify the logarithmic RankFold transcript plus one oracle opening."""

    try:
        if proof.statement_digest != statement.digest:
            return False
        if oracle.statement != statement:
            return False
        if len(proof.rounds) != statement.rounds:
            return False
        modulus = statement.modulus
        transcript = _Transcript(statement)
        outer_point = _derive_outer_point(transcript, statement.rounds)
        current_claim = 0
        final_point: list[int] = []

        for round_index, raw_evaluations in enumerate(proof.rounds):
            evaluations = tuple(_field(value, modulus) for value in raw_evaluations)
            if (evaluations[0] + evaluations[1]) % modulus != current_claim:
                return False
            transcript.absorb(b"sumcheck-round", _encode_round(evaluations, modulus))
            challenge = transcript.challenge(b"sumcheck-challenge", round_index)
            final_point.append(challenge)
            current_claim = _interpolate_degree_three(evaluations, challenge, modulus)

        opening = proof.opening.normalized(modulus)
        if not oracle.verify(final_point, opening):
            return False
        eq_value = equality_evaluation(outer_point, final_point, modulus)
        final_relation = eq_value * (opening.a * opening.b - opening.c) % modulus
        if current_claim != final_relation:
            return False
        transcript.absorb(
            b"opening-values",
            _field_bytes(opening.a, modulus)
            + _field_bytes(opening.b, modulus)
            + _field_bytes(opening.c, modulus)
            + hashlib.sha256(opening.proof).digest(),
        )
        return transcript.state == proof.transcript_digest
    except (RankFoldError, ValueError, OverflowError):
        return False


def product_tables(
    decomposition: RankDecomposition,
    left: Sequence[int],
    right: Sequence[int] | None = None,
) -> tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]:
    """Expose one certified low-rank module as pointwise product tables."""

    if len(left) != decomposition.left_dimension:
        raise RankFoldError("left input dimension differs from rank template")
    right_values = left if decomposition.quadratic else right
    if right_values is None or len(right_values) != decomposition.right_dimension:
        raise RankFoldError("right input dimension differs from rank template")
    a: list[int] = []
    b: list[int] = []
    c: list[int] = []
    for term in decomposition.terms:
        left_value = term.left.evaluate(left)
        right_value = term.right.evaluate(right_values)
        a.append(left_value)
        b.append(right_value)
        c.append(left_value * right_value % decomposition.modulus)
    return tuple(a), tuple(b), tuple(c)


@dataclass(frozen=True, slots=True)
class RankFoldEstimate:
    constraints: int
    padded_constraints: int
    rounds: int
    sumcheck_field_elements: int
    transcript_bytes_excluding_pcs: int
    conservative_soundness_error_numerator: int
    conservative_soundness_error_denominator: int
    conservative_soundness_bits: float
    reference_prover_multiplications_upper_bound: int
    verifier_multiplications_excluding_pcs_upper_bound: int
    pcs_openings: int = 3
    schema: str = "ranklock-rankfold-estimate-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "constraints": self.constraints,
            "padded_constraints": self.padded_constraints,
            "padding_factor": self.padded_constraints / self.constraints,
            "rounds": self.rounds,
            "sumcheck_field_elements": self.sumcheck_field_elements,
            "transcript_bytes_excluding_pcs": self.transcript_bytes_excluding_pcs,
            "pcs_openings": self.pcs_openings,
            "conservative_soundness_error": (
                f"{self.conservative_soundness_error_numerator}/"
                f"{self.conservative_soundness_error_denominator}"
            ),
            "conservative_soundness_bits": self.conservative_soundness_bits,
            "reference_prover_multiplications_upper_bound": (
                self.reference_prover_multiplications_upper_bound
            ),
            "verifier_multiplications_excluding_pcs_upper_bound": (
                self.verifier_multiplications_excluding_pcs_upper_bound
            ),
            "warning": (
                "The estimate excludes the binding PCS opening proof and the conditional-"
                "disclosure mechanism; both remain open construction components."
            ),
        }


def estimate_rankfold(
    constraints: int, *, modulus: int = BN254_BASE_FIELD
) -> RankFoldEstimate:
    padded = _next_power_of_two(constraints)
    rounds = padded.bit_length() - 1
    # Four evaluations per round plus the three final MLE values.  Challenges are Fiat-Shamir.
    field_elements = 4 * rounds + 3
    transcript_bytes = 64 + field_elements * FIELD_BYTES
    # Outer multilinear residual test contributes <= m/p; degree-three sumcheck contributes
    # <= 3m/p.  Union-bound them as 4m/p.  m=0 is a direct check.
    numerator = max(1, 4 * rounds)
    soundness_bits = log2(modulus / numerator)
    # Coefficient-form round construction: ten multiplications per pair, four folds per pair,
    # plus a conservative equality-table budget and constant round interpolation overhead.
    prover_mults = 16 * max(0, padded - 1) + 12 * rounds
    # Conservative verifier accounting: cubic interpolation and equality evaluation.
    verifier_mults = 20 * rounds + 2
    return RankFoldEstimate(
        constraints=constraints,
        padded_constraints=padded,
        rounds=rounds,
        sumcheck_field_elements=field_elements,
        transcript_bytes_excluding_pcs=transcript_bytes,
        conservative_soundness_error_numerator=numerator,
        conservative_soundness_error_denominator=modulus,
        conservative_soundness_bits=soundness_bits,
        reference_prover_multiplications_upper_bound=prover_mults,
        verifier_multiplications_excluding_pcs_upper_bound=verifier_mults,
    )


class AcceptAllOpeningOracle:
    """Deliberately insecure oracle used to demonstrate the PCS-binding gap."""

    def __init__(self, statement: RankFoldStatement) -> None:
        self._statement = statement

    @property
    def statement(self) -> RankFoldStatement:
        return self._statement

    def open(self, point: Sequence[int]) -> RankFoldOpening:
        return RankFoldOpening(0, 0, 0, b"unbound")

    def verify(self, point: Sequence[int], opening: RankFoldOpening) -> bool:
        return len(point) == self.statement.rounds


def forge_with_unbound_openings(statement: RankFoldStatement) -> RankFoldProof:
    """Forge an accepting transcript when openings are not bound to commitments.

    Every round polynomial is identically zero, and the attacker chooses final
    openings satisfying the terminal relation.  This is impossible once a sound
    PCS binds A, B, and C, but it is a useful executable kill-switch against any
    proposal that treats hashes of the trace as sufficient.
    """

    transcript = _Transcript(statement)
    _derive_outer_point(transcript, statement.rounds)
    rounds: list[tuple[int, int, int, int]] = []
    for round_index in range(statement.rounds):
        message = (0, 0, 0, 0)
        rounds.append(message)
        transcript.absorb(b"sumcheck-round", _encode_round(message, statement.modulus))
        transcript.challenge(b"sumcheck-challenge", round_index)
    opening = RankFoldOpening(0, 0, 0, b"unbound")
    transcript.absorb(
        b"opening-values",
        _field_bytes(0, statement.modulus) * 3 + hashlib.sha256(opening.proof).digest(),
    )
    return RankFoldProof(
        statement_digest=statement.digest,
        rounds=tuple(rounds),
        opening=opening,
        transcript_digest=transcript.state,
    )
