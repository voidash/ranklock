from __future__ import annotations

"""Dual-field CRT proof model for BN254 base-field multiplication.

Instead of representing one BN254 Fq element with limbs in a single proof
field, represent the *same canonical integer* in two coprime native fields.  For
canonical ``x,y,z,k < q`` the relation

    x*y = z + k*q

has absolute residual strictly below ``q^2``.  If it holds modulo two coprime
moduli whose product exceeds ``q^2``, it holds over the integers.

Using BN254 Fr and BLS12-381 Fr gives a product about 2.3956 times ``q^2``.
The nonlinear arithmetic is one multiplication in each native field.  The
load-bearing remaining requirement is a binding proof that both residue traces
come from the same canonical byte strings.

This module proves the arithmetic lemma exactly and inventories the costs.  It
does not implement the dual PCS or conditional-disclosure conjunction.
"""

from dataclasses import dataclass
from math import gcd
import random
from typing import Sequence

from .field import BN254_BASE_FIELD
from .nonnative_field import BN254_SCALAR_FIELD, BLS12_381_SCALAR_FIELD


class CrtFieldError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CrtFieldConfig:
    foreign_modulus: int = BN254_BASE_FIELD
    native_moduli: tuple[int, int] = (
        BN254_SCALAR_FIELD,
        BLS12_381_SCALAR_FIELD,
    )

    def __post_init__(self) -> None:
        left, right = self.native_moduli
        if min(self.foreign_modulus, left, right) <= 2:
            raise CrtFieldError("moduli must exceed two")
        if gcd(left, right) != 1:
            raise CrtFieldError("CRT native moduli must be coprime")
        if self.crt_modulus <= self.residual_abs_exclusive_bound:
            raise CrtFieldError("CRT product does not dominate multiplication residual")

    @property
    def crt_modulus(self) -> int:
        return self.native_moduli[0] * self.native_moduli[1]

    @property
    def residual_abs_exclusive_bound(self) -> int:
        # For x,y,z,k in [0,q), both x*y and z+k*q are in [0,q^2).
        return self.foreign_modulus**2

    @property
    def safety_ratio(self) -> float:
        return self.crt_modulus / self.residual_abs_exclusive_bound

    def bounded_quotient_residual_abs_exclusive_bound(
        self, quotient_bits: int
    ) -> int:
        """Uniform residual bound for ``0 <= quotient < 2^bits``.

        With canonical ``x,y,z < q``, the positive residual is below ``q^2``
        and the negative residual magnitude is below ``2^bits * q``.
        """

        bits = int(quotient_bits)
        if bits <= 0:
            raise CrtFieldError("quotient bit bound must be positive")
        return max(self.foreign_modulus**2, (1 << bits) * self.foreign_modulus)

    def bounded_quotient_safety_ratio(self, quotient_bits: int) -> float:
        return self.crt_modulus / self.bounded_quotient_residual_abs_exclusive_bound(
            quotient_bits
        )

    def bounded_quotient_is_crt_exact(self, quotient_bits: int) -> bool:
        return (
            self.crt_modulus
            >= self.bounded_quotient_residual_abs_exclusive_bound(quotient_bits)
        )

    @property
    def maximum_crt_exact_quotient_bits(self) -> int:
        """Largest power-of-two quotient range certified by the CRT bound."""

        ratio_floor = self.crt_modulus // self.foreign_modulus
        bits = ratio_floor.bit_length() - 1
        while bits > 0 and not self.bounded_quotient_is_crt_exact(bits):
            bits -= 1
        return bits

    @property
    def minimum_honest_quotient_bits(self) -> int:
        return (self.foreign_modulus - 2).bit_length()

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-dual-field-crt-config-v1",
            "foreign_modulus": str(self.foreign_modulus),
            "native_moduli": [str(value) for value in self.native_moduli],
            "native_moduli_bits": [value.bit_length() for value in self.native_moduli],
            "crt_modulus_bits": self.crt_modulus.bit_length(),
            "foreign_square_bits": self.residual_abs_exclusive_bound.bit_length(),
            "crt_over_foreign_square_ratio": self.safety_ratio,
            "coprime": True,
            "exact_residual_uniqueness": True,
            "minimum_honest_quotient_bits": self.minimum_honest_quotient_bits,
            "maximum_crt_exact_quotient_bits": self.maximum_crt_exact_quotient_bits,
            "bounded_quotient_254_safety_ratio": self.bounded_quotient_safety_ratio(254),
        }


def canonical_bytes(value: int, config: CrtFieldConfig, *, width: int = 32) -> bytes:
    value = int(value)
    if not 0 <= value < config.foreign_modulus:
        raise CrtFieldError("foreign value is noncanonical")
    if value >= 1 << (8 * width):
        raise CrtFieldError("foreign value does not fit canonical byte width")
    return value.to_bytes(width, "big")


def decode_canonical(data: bytes, config: CrtFieldConfig, *, width: int = 32) -> int:
    data = bytes(data)
    if len(data) != width:
        raise CrtFieldError("canonical byte string has wrong length")
    value = int.from_bytes(data, "big")
    if value >= config.foreign_modulus:
        raise CrtFieldError("canonical byte string is outside foreign field")
    return value


def residues(value: int, config: CrtFieldConfig) -> tuple[int, int]:
    value = int(value)
    if not 0 <= value < config.foreign_modulus:
        raise CrtFieldError("foreign value is noncanonical")
    return tuple(value % modulus for modulus in config.native_moduli)  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class CrtEncodedValue:
    canonical: bytes
    residues: tuple[int, int]

    @classmethod
    def encode(cls, value: int, config: CrtFieldConfig) -> "CrtEncodedValue":
        return cls(canonical_bytes(value, config), residues(value, config))

    def decode(self, config: CrtFieldConfig) -> int:
        value = decode_canonical(self.canonical, config)
        if self.residues != residues(value, config):
            raise CrtFieldError("dual-field residues do not match canonical bytes")
        return value


@dataclass(frozen=True, slots=True)
class CrtMulWitness:
    x: CrtEncodedValue
    y: CrtEncodedValue
    z: CrtEncodedValue
    quotient: CrtEncodedValue


def build_mul_witness(x: int, y: int, config: CrtFieldConfig = CrtFieldConfig()) -> CrtMulWitness:
    x = int(x)
    y = int(y)
    if not 0 <= x < config.foreign_modulus or not 0 <= y < config.foreign_modulus:
        raise CrtFieldError("foreign operands must be canonical")
    product = x * y
    z = product % config.foreign_modulus
    quotient = (product - z) // config.foreign_modulus
    if not 0 <= quotient < config.foreign_modulus:
        raise AssertionError("foreign quotient is outside canonical range")
    return CrtMulWitness(
        CrtEncodedValue.encode(x, config),
        CrtEncodedValue.encode(y, config),
        CrtEncodedValue.encode(z, config),
        CrtEncodedValue.encode(quotient, config),
    )


def verify_mul_witness(
    witness: CrtMulWitness, config: CrtFieldConfig = CrtFieldConfig()
) -> bool:
    try:
        x = witness.x.decode(config)
        y = witness.y.decode(config)
        z = witness.z.decode(config)
        quotient = witness.quotient.decode(config)
        q = config.foreign_modulus
        for index, modulus in enumerate(config.native_moduli):
            if (
                witness.x.residues[index] * witness.y.residues[index]
                - witness.z.residues[index]
                - witness.quotient.residues[index] * (q % modulus)
            ) % modulus != 0:
                return False
        residual = x * y - z - quotient * q
        # This explicit integer check is test/model evidence.  The theorem uses:
        # residual divisible by m1*m2 and |residual| < m1*m2.
        if abs(residual) >= config.crt_modulus:
            return False
        return residual == 0
    except (CrtFieldError, ValueError, OverflowError):
        return False


def congruences_imply_exact(
    *, x: int, y: int, z: int, quotient: int, config: CrtFieldConfig
) -> bool:
    """Executable statement of the CRT uniqueness lemma."""

    values = (int(x), int(y), int(z), int(quotient))
    if any(not 0 <= value < config.foreign_modulus for value in values):
        return False
    residual = values[0] * values[1] - values[2] - values[3] * config.foreign_modulus
    congruent = all(residual % modulus == 0 for modulus in config.native_moduli)
    if not congruent:
        return False
    if abs(residual) >= config.crt_modulus:
        return False
    return residual == 0


def bounded_quotient_congruences_imply_exact(
    *,
    x: int,
    y: int,
    z: int,
    quotient: int,
    quotient_bits: int,
    config: CrtFieldConfig = CrtFieldConfig(),
) -> bool:
    """CRT uniqueness with canonical operands/output and a bounded quotient.

    This is the executable theorem statement used by the reduced-quotient CRT
    inventory.  It deliberately rejects bit widths not certified by the simple
    residual bound.
    """

    bits = int(quotient_bits)
    if not config.bounded_quotient_is_crt_exact(bits):
        return False
    x_i, y_i, z_i, quotient_i = map(int, (x, y, z, quotient))
    if any(
        not 0 <= value < config.foreign_modulus for value in (x_i, y_i, z_i)
    ):
        return False
    if not 0 <= quotient_i < (1 << bits):
        return False
    residual = x_i * y_i - z_i - quotient_i * config.foreign_modulus
    if not all(residual % modulus == 0 for modulus in config.native_moduli):
        return False
    if abs(residual) >= config.crt_modulus:
        return False
    return residual == 0


@dataclass(frozen=True, slots=True)
class CrtScheduleEstimate:
    foreign_products: int
    native_multiplications_total: int
    native_multiplications_per_field: int
    fresh_canonical_bytes_if_inputs_reused: int
    byte_lookup_events_if_byte_range_table: int
    proof_fields: int
    config: CrtFieldConfig
    schema: str = "ranklock-dual-field-crt-schedule-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "foreign_products": self.foreign_products,
            "native_multiplications_total": self.native_multiplications_total,
            "native_multiplications_per_field": self.native_multiplications_per_field,
            "native_multiplications_per_foreign_product": 2,
            "fresh_canonical_bytes_if_inputs_reused": self.fresh_canonical_bytes_if_inputs_reused,
            "byte_lookup_events_if_byte_range_table": self.byte_lookup_events_if_byte_range_table,
            "proof_fields": self.proof_fields,
            "config": self.config.document(),
            "excluded_costs": [
                "cross-field byte/commitment consistency proof",
                "dual PCS commitments and openings",
                "conditional-disclosure conjunction across both proof systems",
                "parser, hash and complete verifier trace",
            ],
        }


def estimate_schedule(
    foreign_products: int, config: CrtFieldConfig = CrtFieldConfig()
) -> CrtScheduleEstimate:
    if foreign_products <= 0:
        raise CrtFieldError("foreign product count must be positive")
    # If x and y are previous canonical trace values, each multiplication creates
    # only z and quotient: two fresh 32-byte values.
    fresh_bytes = int(foreign_products) * 64
    return CrtScheduleEstimate(
        foreign_products=int(foreign_products),
        native_multiplications_total=2 * int(foreign_products),
        native_multiplications_per_field=int(foreign_products),
        fresh_canonical_bytes_if_inputs_reused=fresh_bytes,
        byte_lookup_events_if_byte_range_table=fresh_bytes,
        proof_fields=2,
        config=config,
    )


def randomized_self_test(
    config: CrtFieldConfig = CrtFieldConfig(), *, cases: int = 500, seed: int = 17
) -> None:
    rng = random.Random(seed)
    edge = (0, 1, 2, config.foreign_modulus - 2, config.foreign_modulus - 1)
    for x in edge:
        for y in edge:
            if not verify_mul_witness(build_mul_witness(x, y, config), config):
                raise AssertionError("CRT edge multiplication failed")
    for _ in range(cases):
        x = rng.randrange(config.foreign_modulus)
        y = rng.randrange(config.foreign_modulus)
        if not verify_mul_witness(build_mul_witness(x, y, config), config):
            raise AssertionError("CRT random multiplication failed")


@dataclass(frozen=True, slots=True)
class UnboundCrtMulWitness:
    """Two independent native-field tuples with no common-value binding."""

    field_tuples: tuple[tuple[int, int, int, int], tuple[int, int, int, int]]


def verify_unbound_congruences(
    witness: UnboundCrtMulWitness, config: CrtFieldConfig = CrtFieldConfig()
) -> bool:
    """Deliberately incomplete verifier used to demonstrate split-field attacks."""

    try:
        if len(witness.field_tuples) != len(config.native_moduli):
            return False
        for (x, y, z, quotient), modulus in zip(
            witness.field_tuples, config.native_moduli, strict=True
        ):
            if (
                int(x) * int(y)
                - int(z)
                - int(quotient) * (config.foreign_modulus % modulus)
            ) % modulus != 0:
                return False
        return True
    except (ValueError, OverflowError):
        return False
