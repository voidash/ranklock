from __future__ import annotations

"""Formal algebraic authentication for projectively delivered RankLock inputs.

This module models a candidate fixed-relation input layer for the LVA-WE route.
It is *not* a secure BLS implementation.  Group elements expose their exponents
through :mod:`ranklock.kzg_we_model`; the code is only an executable algebraic
and cost model.

For one session tag ``H`` and coordinate ``i``, setup samples affine secret-key
coefficients ``a_i,b_i`` and publishes

    A_i = [a_i]_2,  B_i = [b_i]_2.

The token for byte value ``v`` is the BLS-like signature

    sigma_{i,v} = [H * (a_i + v*b_i)]_1.

The corresponding public key is computed from public data as

    pk_{i,v} = A_i + v*B_i.

Selected tokens aggregate into one signature and one public key.  A fixed
witness-encryption relation can combine:

1. a BLS signature gadget proving the aggregate signature authenticates the
   fixed session tag under the aggregate public key; and
2. an inner-product gadget proving that the aggregate public key is exactly
   ``sum_i A_i + v_i B_i`` for the same byte witnesses consumed by RankVM.

The model also demonstrates a critical one-time-use condition: two tokens for
one coordinate under the same tag reveal the affine signature slope and allow
all 256 tokens for that coordinate to be forged.
"""

from dataclasses import dataclass
import hashlib
import random
from typing import Iterable, Sequence

from .field import BN254_BASE_FIELD
from .kzg_we_model import GroupElement, generator, pairing


class AlgebraicInputAuthError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CoordinatePublicKey:
    base: GroupElement
    slope: GroupElement

    def __post_init__(self) -> None:
        if self.base.group != "G2" or self.slope.group != "G2":
            raise AlgebraicInputAuthError("coordinate public keys must be in G2")
        if self.base.modulus != self.slope.modulus:
            raise AlgebraicInputAuthError("coordinate public-key fields differ")

    def at(self, value: int) -> GroupElement:
        if not 0 <= int(value) <= 255:
            raise AlgebraicInputAuthError("input value must be one byte")
        return self.base + self.slope.scale(int(value))


@dataclass(frozen=True, slots=True)
class InputToken:
    coordinate: int
    value: int
    signature: GroupElement

    def __post_init__(self) -> None:
        if self.coordinate < 0:
            raise AlgebraicInputAuthError("coordinate must be nonnegative")
        if not 0 <= int(self.value) <= 255:
            raise AlgebraicInputAuthError("token value must be one byte")
        if self.signature.group != "G1":
            raise AlgebraicInputAuthError("input token signature must be in G1")


@dataclass(frozen=True, slots=True)
class AggregateInputWitness:
    values: tuple[int, ...]
    signature: GroupElement
    aggregate_public_key: GroupElement


@dataclass(frozen=True, slots=True)
class InputAuthCost:
    coordinates: int
    cardinality: int
    contributors: int
    naive_catalog_group_elements: int
    naive_catalog_bytes: int
    selected_token_bytes: int
    public_basis_group_elements: int
    public_basis_bytes: int
    aggregate_witness_group_elements: int
    lva_signature_gadgets: int
    lva_inner_product_gadgets: int
    schema: str = "ranklock-algebraic-input-auth-cost-v1"

    def document(self) -> dict[str, int | str | bool | list[str]]:
        return {
            "schema": self.schema,
            "coordinates": self.coordinates,
            "cardinality": self.cardinality,
            "contributors": self.contributors,
            "naive_catalog_group_elements": self.naive_catalog_group_elements,
            "naive_catalog_bytes": self.naive_catalog_bytes,
            "selected_token_bytes": self.selected_token_bytes,
            "public_basis_group_elements": self.public_basis_group_elements,
            "public_basis_bytes": self.public_basis_bytes,
            "aggregate_witness_group_elements": self.aggregate_witness_group_elements,
            "lva_signature_gadgets": self.lva_signature_gadgets,
            "lva_inner_product_gadgets": self.lva_inner_product_gadgets,
            "ciphertext_size_conclusion": (
                "O(1) at the gadget level is prior-art-supported; exact compiler/CRS cost remains unknown"
            ),
            "one_time_delivery_required": True,
            "not_counted": [
                "projective/oblivious delivery wrapper",
                "malicious distributed token generation proof",
                "trace-proof gadgets",
                "WE encryption key and CRS",
                "real pairing and group-operation costs",
            ],
        }


@dataclass(slots=True)
class AlgebraicInputAuthority:
    """One formal issuer for a fixed session tag.

    Production RankLock would distribute the affine coefficients across setup
    contributors and prove token-table correctness.  This single-issuer object
    is only the algebraic reference model.
    """

    tag_scalar: int
    secret_bases: tuple[int, ...]
    secret_slopes: tuple[int, ...]
    modulus: int = BN254_BASE_FIELD

    def __post_init__(self) -> None:
        if self.modulus <= 257:
            raise AlgebraicInputAuthError("group order is too small")
        self.tag_scalar %= self.modulus
        if self.tag_scalar == 0:
            raise AlgebraicInputAuthError("session tag point must be nonidentity")
        if not self.secret_bases or len(self.secret_bases) != len(self.secret_slopes):
            raise AlgebraicInputAuthError("base/slope vectors must be nonempty and equal length")
        self.secret_bases = tuple(int(x) % self.modulus for x in self.secret_bases)
        self.secret_slopes = tuple(int(x) % self.modulus for x in self.secret_slopes)
        if any(x == 0 for x in self.secret_slopes):
            raise AlgebraicInputAuthError("coordinate slopes must be nonzero")

    @classmethod
    def generate(
        cls,
        coordinates: int,
        *,
        session_context: bytes,
        modulus: int = BN254_BASE_FIELD,
        seed: int = 0x52414E4B4C4F434B,
    ) -> "AlgebraicInputAuthority":
        if coordinates <= 0:
            raise AlgebraicInputAuthError("coordinate count must be positive")
        digest = hashlib.sha256(
            b"ranklock/algebraic-input-auth/tag/v1\x00" + bytes(session_context)
        ).digest()
        tag = int.from_bytes(digest, "big") % modulus or 1
        rng = random.Random(seed)
        bases = tuple(rng.randrange(1, modulus) for _ in range(coordinates))
        slopes = tuple(rng.randrange(1, modulus) for _ in range(coordinates))
        return cls(tag, bases, slopes, modulus)

    @property
    def coordinates(self) -> int:
        return len(self.secret_bases)

    @property
    def tag_point(self) -> GroupElement:
        return generator("G1", self.modulus).scale(self.tag_scalar)

    @property
    def public_keys(self) -> tuple[CoordinatePublicKey, ...]:
        g2 = generator("G2", self.modulus)
        return tuple(
            CoordinatePublicKey(g2.scale(a), g2.scale(b))
            for a, b in zip(self.secret_bases, self.secret_slopes, strict=True)
        )

    def token(self, coordinate: int, value: int) -> InputToken:
        if not 0 <= coordinate < self.coordinates:
            raise AlgebraicInputAuthError("coordinate outside authority range")
        if not 0 <= int(value) <= 255:
            raise AlgebraicInputAuthError("value must be one byte")
        secret = (
            self.secret_bases[coordinate]
            + int(value) * self.secret_slopes[coordinate]
        ) % self.modulus
        signature = self.tag_point.scale(secret)
        return InputToken(coordinate, int(value), signature)

    def select(self, values: Sequence[int]) -> tuple[InputToken, ...]:
        if len(values) != self.coordinates:
            raise AlgebraicInputAuthError("selected vector has wrong width")
        return tuple(self.token(i, int(value)) for i, value in enumerate(values))


def aggregate_tokens(
    tokens: Sequence[InputToken],
    public_keys: Sequence[CoordinatePublicKey],
) -> AggregateInputWitness:
    if not tokens or len(tokens) != len(public_keys):
        raise AlgebraicInputAuthError("token/public-key vectors must be nonempty and equal length")
    modulus = tokens[0].signature.modulus
    signature = GroupElement("G1", 0, modulus)
    aggregate_key = GroupElement("G2", 0, modulus)
    values: list[int] = []
    seen: set[int] = set()
    for expected, (token, key) in enumerate(zip(tokens, public_keys, strict=True)):
        if token.coordinate != expected or token.coordinate in seen:
            raise AlgebraicInputAuthError("tokens must contain each coordinate exactly once in order")
        if token.signature.modulus != modulus or key.base.modulus != modulus:
            raise AlgebraicInputAuthError("token aggregate mixes fields")
        seen.add(token.coordinate)
        signature = signature + token.signature
        aggregate_key = aggregate_key + key.at(token.value)
        values.append(token.value)
    return AggregateInputWitness(tuple(values), signature, aggregate_key)


def verify_signature_gadget(
    witness: AggregateInputWitness,
    *,
    tag_point: GroupElement,
) -> bool:
    if tag_point.group != "G1":
        raise AlgebraicInputAuthError("tag point must be in G1")
    g2 = generator("G2", tag_point.modulus)
    return pairing(witness.signature, g2) == pairing(tag_point, witness.aggregate_public_key)


def expected_aggregate_key(
    values: Sequence[int], public_keys: Sequence[CoordinatePublicKey]
) -> GroupElement:
    if not values or len(values) != len(public_keys):
        raise AlgebraicInputAuthError("value/public-key vectors differ")
    modulus = public_keys[0].base.modulus
    result = GroupElement("G2", 0, modulus)
    for value, key in zip(values, public_keys, strict=True):
        result = result + key.at(int(value))
    return result


def verify_inner_product_gadget(
    witness: AggregateInputWitness,
    *,
    public_keys: Sequence[CoordinatePublicKey],
) -> bool:
    """Formal check represented by one LVA-WE inner-product gadget."""

    return witness.aggregate_public_key == expected_aggregate_key(
        witness.values, public_keys
    )


def verify_authenticated_input(
    witness: AggregateInputWitness,
    *,
    tag_point: GroupElement,
    public_keys: Sequence[CoordinatePublicKey],
) -> bool:
    return verify_signature_gadget(witness, tag_point=tag_point) and verify_inner_product_gadget(
        witness, public_keys=public_keys
    )


def forge_fresh_signature_only_witness(
    values: Sequence[int],
    *,
    tag_point: GroupElement,
    attacker_secret: int,
) -> AggregateInputWitness:
    """Forge the signature gadget while intentionally violating input binding."""

    modulus = tag_point.modulus
    secret = int(attacker_secret) % modulus or 1
    pk = generator("G2", modulus).scale(secret)
    sig = tag_point.scale(secret)
    return AggregateInputWitness(tuple(int(v) for v in values), sig, pk)


def recover_affine_signature_slope(
    first: InputToken, second: InputToken
) -> GroupElement:
    """Recover ``H*b_i`` from two values for one coordinate and one tag."""

    if first.coordinate != second.coordinate:
        raise AlgebraicInputAuthError("tokens belong to different coordinates")
    if first.signature.modulus != second.signature.modulus:
        raise AlgebraicInputAuthError("tokens use different fields")
    delta = (second.value - first.value) % first.signature.modulus
    if delta == 0:
        raise AlgebraicInputAuthError("tokens use the same value")
    return (second.signature - first.signature).scale(
        pow(delta, -1, first.signature.modulus)
    )


def forge_token_from_two(
    first: InputToken,
    second: InputToken,
    target_value: int,
) -> InputToken:
    if not 0 <= int(target_value) <= 255:
        raise AlgebraicInputAuthError("target value must be one byte")
    slope = recover_affine_signature_slope(first, second)
    signature = first.signature + slope.scale(int(target_value) - first.value)
    return InputToken(first.coordinate, int(target_value), signature)


def input_auth_cost(
    coordinates: int = 132,
    *,
    cardinality: int = 256,
    contributors: int = 1,
    g1_bytes: int = 48,
    g2_bytes: int = 96,
) -> InputAuthCost:
    if coordinates <= 0 or cardinality <= 1 or contributors <= 0:
        raise AlgebraicInputAuthError("cost dimensions must be positive")
    if g1_bytes <= 0 or g2_bytes <= 0:
        raise AlgebraicInputAuthError("group encodings must be positive")
    catalog_elements = coordinates * cardinality * contributors
    return InputAuthCost(
        coordinates=coordinates,
        cardinality=cardinality,
        contributors=contributors,
        naive_catalog_group_elements=catalog_elements,
        naive_catalog_bytes=catalog_elements * g1_bytes,
        selected_token_bytes=coordinates * contributors * g1_bytes,
        public_basis_group_elements=2 * coordinates * contributors,
        public_basis_bytes=2 * coordinates * contributors * g2_bytes,
        aggregate_witness_group_elements=2,
        lva_signature_gadgets=1,
        lva_inner_product_gadgets=1,
    )
