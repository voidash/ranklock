from __future__ import annotations

"""Vector-OLE delivery model for affine RankLock input authentication.

Duty-Free Bits (ePrint 2026/476) gives a non-interactive reduction from vector
OLE over a large prime field to 1-out-of-2 OTs, secure against a malicious
receiver, with communication ``O((lambda+n) log p)`` bits.  This module does
not implement that protocol.  It models the interface RankLock needs and the
security-critical state lifecycle around it.

For fresh per-deposit vectors ``a,b`` and selected byte vector ``v``, vector OLE
returns only

    t_i = a_i + v_i*b_i mod p.

The evaluator locally derives the BLS-like token ``t_i*H(tag)`` and aggregate
public key ``[t_i]_2``.  Learning one ``t_i`` does not reveal another value's
key.  Reusing the same affine sender state for two receiver vectors does reveal
``a_i,b_i`` wherever the inputs differ, so the sender state is strictly
one-shot and must be burned after abort or completion.
"""

from dataclasses import dataclass
import hashlib
import random
from typing import Sequence

from .algebraic_input_auth import (
    AggregateInputWitness,
    CoordinatePublicKey,
    InputToken,
    aggregate_tokens,
)
from .nonnative_field import BLS12_381_SCALAR_FIELD
from .kzg_we_model import generator


class VoleInputAuthError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VoleDelivery:
    inputs: tuple[int, ...]
    affine_outputs: tuple[int, ...]
    session_id: bytes


@dataclass(frozen=True, slots=True)
class RecoveredAffineCoordinate:
    base: int
    slope: int

    def at(self, value: int, modulus: int) -> int:
        return (self.base + int(value) * self.slope) % modulus


@dataclass(frozen=True, slots=True)
class VoleInputAuthCost:
    coordinates: int
    input_bits_per_coordinate: int
    security_bits: int
    field_bits: int
    asymptotic_leading_expression_bits: int
    asymptotic_leading_expression_bytes_ceiling: int
    public_basis_bytes: int
    receiver_output_scalar_bytes: int
    eliminated_naive_token_catalog_bytes: int
    schema: str = "ranklock-vole-input-auth-cost-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "coordinates": self.coordinates,
            "input_bits_per_coordinate": self.input_bits_per_coordinate,
            "security_bits": self.security_bits,
            "field_bits": self.field_bits,
            "asymptotic_leading_expression_bits": self.asymptotic_leading_expression_bits,
            "asymptotic_leading_expression_bytes_ceiling": self.asymptotic_leading_expression_bytes_ceiling,
            "public_basis_bytes": self.public_basis_bytes,
            "receiver_output_scalar_bytes": self.receiver_output_scalar_bytes,
            "eliminated_naive_token_catalog_bytes": self.eliminated_naive_token_catalog_bytes,
            "source_bound": "Duty-Free Bits: O((lambda+n) log p) bits plus base OTs",
            "warning": (
                "The leading expression is not a concrete protocol byte count: big-O constants, "
                "base OTs, authentication, framing, malicious checks and distributed setup are excluded."
            ),
            "required_lifecycle": [
                "fresh affine sender state per deposit/session",
                "at most one receiver vector per state",
                "burn state on abort, retry, or completion",
            ],
            "remaining_work": [
                "instantiate the actual Duty-Free-Bits vector-OLE protocol",
                "bind OLE receiver bits to the bridge's selected bytes",
                "distribute sender state with one-honest-party security",
                "compose the aggregate BLS and inner-product gadgets in real LVA-WE",
            ],
        }


@dataclass(slots=True)
class OneShotAffineVoleSender:
    bases: tuple[int, ...]
    slopes: tuple[int, ...]
    session_id: bytes
    tag_scalar: int
    modulus: int = BLS12_381_SCALAR_FIELD
    consumed: bool = False

    def __post_init__(self) -> None:
        self.bases = tuple(int(x) % self.modulus for x in self.bases)
        self.slopes = tuple(int(x) % self.modulus for x in self.slopes)
        self.session_id = bytes(self.session_id)
        self.tag_scalar %= self.modulus
        if not self.bases or len(self.bases) != len(self.slopes):
            raise VoleInputAuthError("base/slope vectors must be nonempty and equal length")
        if len(self.session_id) != 32:
            raise VoleInputAuthError("session id must be 32 bytes")
        if self.tag_scalar == 0 or any(slope == 0 for slope in self.slopes):
            raise VoleInputAuthError("tag and slopes must be nonzero")

    @classmethod
    def generate(
        cls,
        coordinates: int,
        *,
        session_context: bytes,
        seed: int = 0x564F4C4552414E4B,
        modulus: int = BLS12_381_SCALAR_FIELD,
    ) -> "OneShotAffineVoleSender":
        if coordinates <= 0:
            raise VoleInputAuthError("coordinate count must be positive")
        context = bytes(session_context)
        session_id = hashlib.sha256(
            b"ranklock/vole-input-auth/session/v1\x00" + context
        ).digest()
        tag_scalar = int.from_bytes(
            hashlib.sha256(
                b"ranklock/vole-input-auth/tag/v1\x00" + context
            ).digest(),
            "big",
        ) % modulus or 1
        rng = random.Random(seed)
        bases = tuple(rng.randrange(1, modulus) for _ in range(coordinates))
        slopes = tuple(rng.randrange(1, modulus) for _ in range(coordinates))
        return cls(bases, slopes, session_id, tag_scalar, modulus)

    @property
    def coordinates(self) -> int:
        return len(self.bases)

    @property
    def public_keys(self) -> tuple[CoordinatePublicKey, ...]:
        g2 = generator("G2", self.modulus)
        return tuple(
            CoordinatePublicKey(g2.scale(a), g2.scale(b))
            for a, b in zip(self.bases, self.slopes, strict=True)
        )

    @property
    def tag_point(self):
        return generator("G1", self.modulus).scale(self.tag_scalar)

    def evaluate_once(self, inputs: Sequence[int]) -> VoleDelivery:
        if self.consumed:
            raise VoleInputAuthError("affine VOLE sender state is already consumed")
        if len(inputs) != self.coordinates:
            raise VoleInputAuthError("receiver vector has wrong width")
        values = tuple(int(value) for value in inputs)
        if any(not 0 <= value <= 255 for value in values):
            raise VoleInputAuthError("receiver inputs must be bytes")
        outputs = tuple(
            (a + value * b) % self.modulus
            for a, b, value in zip(self.bases, self.slopes, values, strict=True)
        )
        self.consumed = True
        return VoleDelivery(values, outputs, self.session_id)

    def unsafe_evaluate_for_attack(self, inputs: Sequence[int]) -> VoleDelivery:
        """Evaluate without consuming state; only for the two-query regression."""
        was_consumed = self.consumed
        self.consumed = False
        delivery = self.evaluate_once(inputs)
        self.consumed = was_consumed
        return delivery


def delivery_to_aggregate_witness(
    delivery: VoleDelivery,
    *,
    sender: OneShotAffineVoleSender,
) -> AggregateInputWitness:
    if delivery.session_id != sender.session_id:
        raise VoleInputAuthError("delivery belongs to another session")
    if len(delivery.affine_outputs) != sender.coordinates:
        raise VoleInputAuthError("delivery output width differs")
    tokens = tuple(
        InputToken(i, value, sender.tag_point.scale(secret))
        for i, (value, secret) in enumerate(
            zip(delivery.inputs, delivery.affine_outputs, strict=True)
        )
    )
    return aggregate_tokens(tokens, sender.public_keys)


def recover_coordinate_from_two_deliveries(
    first: VoleDelivery,
    second: VoleDelivery,
    coordinate: int,
    *,
    modulus: int = BLS12_381_SCALAR_FIELD,
) -> RecoveredAffineCoordinate:
    if first.session_id != second.session_id:
        raise VoleInputAuthError("deliveries use different sessions")
    if not 0 <= coordinate < len(first.inputs) or len(first.inputs) != len(second.inputs):
        raise VoleInputAuthError("coordinate outside delivery range")
    x0, x1 = first.inputs[coordinate], second.inputs[coordinate]
    if x0 == x1:
        raise VoleInputAuthError("coordinate inputs are equal")
    y0, y1 = first.affine_outputs[coordinate], second.affine_outputs[coordinate]
    slope = (y1 - y0) * pow((x1 - x0) % modulus, -1, modulus) % modulus
    base = (y0 - x0 * slope) % modulus
    return RecoveredAffineCoordinate(base, slope)


def vole_input_auth_cost(
    coordinates: int = 132,
    *,
    input_bits_per_coordinate: int = 8,
    security_bits: int = 128,
    field_bits: int = 255,
    scalar_bytes: int = 32,
    g2_bytes: int = 96,
    naive_token_catalog_bytes: int = 1_622_016,
) -> VoleInputAuthCost:
    if min(
        coordinates,
        input_bits_per_coordinate,
        security_bits,
        field_bits,
        scalar_bytes,
        g2_bytes,
    ) <= 0:
        raise VoleInputAuthError("cost parameters must be positive")
    leading_bits = (security_bits + coordinates) * field_bits
    return VoleInputAuthCost(
        coordinates=coordinates,
        input_bits_per_coordinate=input_bits_per_coordinate,
        security_bits=security_bits,
        field_bits=field_bits,
        asymptotic_leading_expression_bits=leading_bits,
        asymptotic_leading_expression_bytes_ceiling=(leading_bits + 7) // 8,
        public_basis_bytes=2 * coordinates * g2_bytes,
        receiver_output_scalar_bytes=coordinates * scalar_bytes,
        eliminated_naive_token_catalog_bytes=naive_token_catalog_bytes,
    )
