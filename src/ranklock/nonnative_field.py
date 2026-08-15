from __future__ import annotations

"""Exact non-native field multiplication over a pairing scalar field.

RankLock's verifier arithmetic is over the BN254 base field Fq, while readily
available KZG implementations commit polynomials over a pairing curve's scalar
field Fr.  The fields need not match: represent every Fq value in small integer
limbs and constrain the integer identity

    x * y = z + quotient * q,

where z = x*y mod q.  With three 85-bit limbs, every convolution/carry equation
is far below a 254/255-bit native modulus, so a native-field equality cannot hide
an integer wrap.  The only nonlinear terms are the 3x3 limb products.

This module is an exact integer model and a constraint-cost estimator.  It is
not yet an AIR or a production range-check implementation.
"""

from dataclasses import dataclass
from math import ceil
import random
from typing import Iterable

from .field import BN254_BASE_FIELD

# BN254 scalar field, used by BN254 KZG.
BN254_SCALAR_FIELD = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

# BLS12-381 scalar field, an alternative ~128-bit-security KZG field.
BLS12_381_SCALAR_FIELD = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)


class NonNativeFieldError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LimbConfig:
    foreign_modulus: int
    native_modulus: int
    limb_bits: int
    limbs: int

    def __post_init__(self) -> None:
        if self.foreign_modulus <= 2 or self.native_modulus <= 2:
            raise NonNativeFieldError("field moduli must exceed two")
        if self.limb_bits <= 0 or self.limbs < 2:
            raise NonNativeFieldError("invalid limb geometry")
        if self.base**self.limbs <= self.foreign_modulus:
            raise NonNativeFieldError("limb geometry cannot represent the foreign field")
        if not self.safe_no_wrap:
            raise NonNativeFieldError("limb convolution can wrap the native field")

    @property
    def base(self) -> int:
        return 1 << self.limb_bits

    @property
    def foreign_bits(self) -> int:
        return self.foreign_modulus.bit_length()

    @property
    def native_bits(self) -> int:
        return self.native_modulus.bit_length()

    @property
    def nonlinear_products_per_mul(self) -> int:
        return self.limbs * self.limbs

    @property
    def nonlinear_products_per_square(self) -> int:
        return self.limbs * (self.limbs + 1) // 2

    @property
    def coefficient_abs_bound(self) -> int:
        """Conservative |d_k| bound before carry terms.

        Each coefficient contains at most ``limbs`` x*y products and at most
        ``limbs`` quotient*constant-modulus limb products, plus one output limb.
        """

        limb_max = self.base - 1
        return 2 * self.limbs * limb_max * limb_max + limb_max

    @property
    def carry_abs_bound(self) -> int:
        bound = 0
        for _ in range(2 * self.limbs - 1):
            bound = ceil((self.coefficient_abs_bound + bound) / self.base)
        return bound

    @property
    def equation_abs_bound(self) -> int:
        # |d_k + carry_k - B*carry_{k+1}| before knowing it is zero.
        return (
            self.coefficient_abs_bound
            + self.carry_abs_bound
            + self.base * self.carry_abs_bound
        )

    @property
    def safe_no_wrap(self) -> bool:
        # If the canonical signed representative is strictly smaller than the
        # modulus, congruence to zero implies integer equality to zero.
        return self.equation_abs_bound < self.native_modulus

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-nonnative-limb-config-v1",
            "foreign_modulus": str(self.foreign_modulus),
            "native_modulus": str(self.native_modulus),
            "foreign_bits": self.foreign_bits,
            "native_bits": self.native_bits,
            "limb_bits": self.limb_bits,
            "limbs": self.limbs,
            "capacity_bits": self.limb_bits * self.limbs,
            "nonlinear_products_per_mul": self.nonlinear_products_per_mul,
            "nonlinear_products_per_square": self.nonlinear_products_per_square,
            "coefficient_abs_bound_bits": self.coefficient_abs_bound.bit_length(),
            "carry_abs_bound_bits": self.carry_abs_bound.bit_length(),
            "equation_abs_bound_bits": self.equation_abs_bound.bit_length(),
            "safe_no_wrap": self.safe_no_wrap,
        }


def decompose(value: int, config: LimbConfig) -> tuple[int, ...]:
    value = int(value)
    if not 0 <= value < config.base**config.limbs:
        raise NonNativeFieldError("value does not fit limb geometry")
    limbs: list[int] = []
    for _ in range(config.limbs):
        limbs.append(value % config.base)
        value //= config.base
    if value:
        raise AssertionError("limb decomposition left a remainder")
    return tuple(limbs)


def reconstruct(limbs: Iterable[int], config: LimbConfig) -> int:
    values = tuple(int(value) for value in limbs)
    if len(values) != config.limbs:
        raise NonNativeFieldError("limb count differs from configuration")
    if any(not 0 <= value < config.base for value in values):
        raise NonNativeFieldError("limb outside canonical range")
    return sum(value * config.base**index for index, value in enumerate(values))


def _convolution(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    result = [0] * (len(left) + len(right) - 1)
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[i + j] += a * b
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ForeignMulWitness:
    x_limbs: tuple[int, ...]
    y_limbs: tuple[int, ...]
    z_limbs: tuple[int, ...]
    quotient_limbs: tuple[int, ...]
    carries: tuple[int, ...]

    @property
    def limbs(self) -> int:
        return len(self.x_limbs)


def build_mul_witness(x: int, y: int, config: LimbConfig) -> ForeignMulWitness:
    x = int(x)
    y = int(y)
    if not 0 <= x < config.foreign_modulus or not 0 <= y < config.foreign_modulus:
        raise NonNativeFieldError("foreign operands must be canonical")
    product = x * y
    z = product % config.foreign_modulus
    quotient = (product - z) // config.foreign_modulus
    if not 0 <= quotient < config.foreign_modulus:
        raise AssertionError("foreign multiplication quotient is outside Fq range")

    x_limbs = decompose(x, config)
    y_limbs = decompose(y, config)
    z_limbs = decompose(z, config)
    quotient_limbs = decompose(quotient, config)
    modulus_limbs = decompose(config.foreign_modulus, config)
    lhs = _convolution(x_limbs, y_limbs)
    qp = _convolution(quotient_limbs, modulus_limbs)

    carries = [0]
    for k in range(2 * config.limbs - 1):
        rhs_coefficient = qp[k] + (z_limbs[k] if k < config.limbs else 0)
        numerator = lhs[k] - rhs_coefficient + carries[-1]
        if numerator % config.base:
            raise AssertionError("foreign multiplication carry is not integral")
        carries.append(numerator // config.base)
    if carries[-1] != 0:
        raise AssertionError("foreign multiplication terminal carry is nonzero")
    return ForeignMulWitness(
        x_limbs, y_limbs, z_limbs, quotient_limbs, tuple(carries)
    )


def verify_mul_witness(witness: ForeignMulWitness, config: LimbConfig) -> bool:
    try:
        n = config.limbs
        if any(
            len(values) != n
            for values in (
                witness.x_limbs,
                witness.y_limbs,
                witness.z_limbs,
                witness.quotient_limbs,
            )
        ):
            return False
        if len(witness.carries) != 2 * n:
            return False
        for values in (
            witness.x_limbs,
            witness.y_limbs,
            witness.z_limbs,
            witness.quotient_limbs,
        ):
            if any(not 0 <= int(value) < config.base for value in values):
                return False
        if witness.carries[0] != 0 or witness.carries[-1] != 0:
            return False
        if any(abs(int(value)) > config.carry_abs_bound for value in witness.carries):
            return False

        x = reconstruct(witness.x_limbs, config)
        y = reconstruct(witness.y_limbs, config)
        z = reconstruct(witness.z_limbs, config)
        quotient = reconstruct(witness.quotient_limbs, config)
        if any(value >= config.foreign_modulus for value in (x, y, z, quotient)):
            return False

        modulus_limbs = decompose(config.foreign_modulus, config)
        lhs = _convolution(witness.x_limbs, witness.y_limbs)
        qp = _convolution(witness.quotient_limbs, modulus_limbs)
        for k in range(2 * n - 1):
            rhs_coefficient = qp[k] + (witness.z_limbs[k] if k < n else 0)
            equation = (
                lhs[k]
                - rhs_coefficient
                + witness.carries[k]
                - config.base * witness.carries[k + 1]
            )
            if equation != 0:
                return False
            if abs(equation) >= config.native_modulus:
                return False
        return x * y == z + quotient * config.foreign_modulus
    except (NonNativeFieldError, ValueError, OverflowError):
        return False


def candidate_configs(
    *,
    foreign_modulus: int = BN254_BASE_FIELD,
    native_modulus: int = BN254_SCALAR_FIELD,
    maximum_limbs: int = 8,
) -> tuple[LimbConfig, ...]:
    candidates: list[LimbConfig] = []
    foreign_bits = foreign_modulus.bit_length()
    for limbs in range(2, maximum_limbs + 1):
        minimum_bits = ceil(foreign_bits / limbs)
        for limb_bits in range(minimum_bits, max(minimum_bits, native_modulus.bit_length()) + 1):
            try:
                config = LimbConfig(
                    foreign_modulus, native_modulus, limb_bits, limbs
                )
            except NonNativeFieldError:
                continue
            candidates.append(config)
            break
    return tuple(
        sorted(
            candidates,
            key=lambda config: (
                config.nonlinear_products_per_mul,
                config.limbs * config.limb_bits,
                config.limb_bits,
            ),
        )
    )


def best_config(
    *,
    foreign_modulus: int = BN254_BASE_FIELD,
    native_modulus: int = BN254_SCALAR_FIELD,
) -> LimbConfig:
    candidates = candidate_configs(
        foreign_modulus=foreign_modulus, native_modulus=native_modulus
    )
    if not candidates:
        raise NonNativeFieldError("no safe limb configuration found")
    return candidates[0]


@dataclass(frozen=True, slots=True)
class NonNativeScheduleEstimate:
    foreign_products: int
    config: LimbConfig
    native_nonlinear_products_upper_bound: int
    fresh_quotient_range_bits: int
    fresh_signed_carry_values: int
    schema: str = "ranklock-nonnative-schedule-estimate-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "foreign_products": self.foreign_products,
            "config": self.config.document(),
            "native_nonlinear_products_upper_bound": self.native_nonlinear_products_upper_bound,
            "multiplicative_blowup": self.config.nonlinear_products_per_mul,
            "fresh_quotient_range_bits": self.fresh_quotient_range_bits,
            "fresh_signed_carry_values": self.fresh_signed_carry_values,
            "scope": (
                "upper bound treats every foreign product as a generic multiplication; "
                "squaring symmetry and constant multipliers can reduce it"
            ),
        }


def estimate_schedule(foreign_products: int, config: LimbConfig) -> NonNativeScheduleEstimate:
    if foreign_products <= 0:
        raise NonNativeFieldError("foreign product count must be positive")
    return NonNativeScheduleEstimate(
        foreign_products=int(foreign_products),
        config=config,
        native_nonlinear_products_upper_bound=(
            int(foreign_products) * config.nonlinear_products_per_mul
        ),
        fresh_quotient_range_bits=(
            int(foreign_products) * config.limbs * config.limb_bits
        ),
        fresh_signed_carry_values=(
            int(foreign_products) * (2 * config.limbs - 2)
        ),
    )


def randomized_self_test(config: LimbConfig, *, cases: int = 100, seed: int = 1) -> None:
    rng = random.Random(seed)
    edge_values = (0, 1, 2, config.foreign_modulus - 2, config.foreign_modulus - 1)
    for x in edge_values:
        for y in edge_values:
            witness = build_mul_witness(x, y, config)
            if not verify_mul_witness(witness, config):
                raise AssertionError("edge-case non-native witness failed")
    for _ in range(cases):
        x = rng.randrange(config.foreign_modulus)
        y = rng.randrange(config.foreign_modulus)
        witness = build_mul_witness(x, y, config)
        if not verify_mul_witness(witness, config):
            raise AssertionError("random non-native witness failed")
