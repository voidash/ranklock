from __future__ import annotations

"""Two-limb split-product foreign multiplication over BLS12-381 Fr.

A naive two-limb coefficient equation is unsafe because the middle coefficient
can exceed the native modulus.  This construction avoids that wrap by:

1. using two 127-bit limbs, so each individual limb product is below
   BLS12-381 Fr;
2. splitting every exact limb product into low/high radix-2^127 chunks;
3. normalizing both ``x*y`` and ``quotient*q + z`` as four bounded radix digits;
4. requiring the normalized digits to be identical.

It uses four native nonlinear products per foreign multiplication—one fewer than
the rank-5 3x85 route—but it introduces many more range lookups.  The
module provides exact witness checks and a logical constraint inventory, not a
real PCS implementation.
"""

from dataclasses import dataclass
import random

from .field import BN254_BASE_FIELD
from .field_bridge import (
    CANONICAL_BYTE_WIDTH,
    CanonicalGeometry,
    CanonicalLimbWitness,
    FieldBridgeError,
    RangeLookupModel,
    build_canonical_limb_witness,
    verify_canonical_limb_witness,
)
from .nonnative_field import BLS12_381_SCALAR_FIELD


class SplitLimbError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SplitLimbConfig:
    foreign_modulus: int = BN254_BASE_FIELD
    native_modulus: int = BLS12_381_SCALAR_FIELD
    limb_bits: int = 127
    limbs: int = 2

    def __post_init__(self) -> None:
        if self.limbs != 2:
            raise SplitLimbError("split-product construction currently requires two limbs")
        if self.limb_bits != 127:
            raise SplitLimbError("split-product construction currently requires 127-bit limbs")
        if self.base**2 <= self.foreign_modulus:
            raise SplitLimbError("two limbs do not cover the foreign field")
        if self.base**2 >= self.native_modulus:
            raise SplitLimbError("an individual limb product can wrap the native field")

    @property
    def base(self) -> int:
        return 1 << self.limb_bits

    @property
    def geometry(self) -> CanonicalGeometry:
        return CanonicalGeometry(
            self.foreign_modulus,
            self.limb_bits,
            self.limbs,
            CANONICAL_BYTE_WIDTH,
        )

    @property
    def modulus_limbs(self) -> tuple[int, int]:
        return _decompose_two(self.foreign_modulus, self)

    def document(self) -> dict[str, object]:
        return {
            "schema": "ranklock-split-limb-config-v1",
            "foreign_modulus": str(self.foreign_modulus),
            "native_modulus": str(self.native_modulus),
            "foreign_bits": self.foreign_modulus.bit_length(),
            "native_bits": self.native_modulus.bit_length(),
            "limb_bits": self.limb_bits,
            "limbs": self.limbs,
            "capacity_bits": 2 * self.limb_bits,
            "individual_product_bits_exclusive": 2 * self.limb_bits,
            "individual_products_below_native_modulus": True,
            "native_nonlinear_products_per_foreign_mul": 4,
        }


def _decompose_two(value: int, config: SplitLimbConfig) -> tuple[int, int]:
    value = int(value)
    if not 0 <= value < config.base**2:
        raise SplitLimbError("value does not fit two-limb geometry")
    return value % config.base, value // config.base


@dataclass(frozen=True, slots=True)
class ProductSplit:
    low: int
    high: int

    def value(self, base: int) -> int:
        return int(self.low) + base * int(self.high)


def _build_product_split(left: int, right: int, config: SplitLimbConfig) -> ProductSplit:
    product = int(left) * int(right)
    if not 0 <= product < config.base**2:
        raise SplitLimbError("limb product exceeds split range")
    if product >= config.native_modulus:
        raise SplitLimbError("limb product wraps native field")
    return ProductSplit(product % config.base, product // config.base)


def _verify_product_split(
    split: ProductSplit, left: int, right: int, config: SplitLimbConfig
) -> bool:
    try:
        if not 0 <= int(split.low) < config.base:
            return False
        if not 0 <= int(split.high) < config.base:
            return False
        product = int(left) * int(right)
        if product >= config.native_modulus:
            return False
        reconstructed = split.value(config.base)
        # The modular equation is the circuit relation.  The explicit integer
        # equality records why it is exact under the range bounds.
        if (product - reconstructed) % config.native_modulus != 0:
            return False
        return product == reconstructed
    except (ValueError, OverflowError):
        return False


@dataclass(frozen=True, slots=True)
class SplitLimbMulWitness:
    x: CanonicalLimbWitness
    y: CanonicalLimbWitness
    z: CanonicalLimbWitness
    quotient: CanonicalLimbWitness
    xy_splits: tuple[ProductSplit, ProductSplit, ProductSplit, ProductSplit]
    quotient_modulus_splits: tuple[
        ProductSplit, ProductSplit, ProductSplit, ProductSplit
    ]
    normalized_digits: tuple[int, int, int, int]
    product_carries: tuple[int, int]
    reduction_carries: tuple[int, int, int]


_INDEX_PAIRS = ((0, 0), (0, 1), (1, 0), (1, 1))


def _normalize_product(
    splits: tuple[ProductSplit, ProductSplit, ProductSplit, ProductSplit],
    config: SplitLimbConfig,
) -> tuple[tuple[int, int, int, int], tuple[int, int]]:
    p00, p01, p10, p11 = splits
    digit0 = p00.low
    raw1 = p00.high + p01.low + p10.low
    digit1, carry2 = raw1 % config.base, raw1 // config.base
    raw2 = p01.high + p10.high + p11.low + carry2
    digit2, carry3 = raw2 % config.base, raw2 // config.base
    raw3 = p11.high + carry3
    if raw3 >= config.base:
        raise AssertionError("product normalization has a terminal carry")
    return (digit0, digit1, digit2, raw3), (carry2, carry3)


def _normalize_reduction(
    splits: tuple[ProductSplit, ProductSplit, ProductSplit, ProductSplit],
    z_limbs: tuple[int, int],
    config: SplitLimbConfig,
) -> tuple[tuple[int, int, int, int], tuple[int, int, int]]:
    p00, p01, p10, p11 = splits
    raw0 = p00.low + z_limbs[0]
    digit0, carry1 = raw0 % config.base, raw0 // config.base
    raw1 = p00.high + p01.low + p10.low + z_limbs[1] + carry1
    digit1, carry2 = raw1 % config.base, raw1 // config.base
    raw2 = p01.high + p10.high + p11.low + carry2
    digit2, carry3 = raw2 % config.base, raw2 // config.base
    raw3 = p11.high + carry3
    if raw3 >= config.base:
        raise AssertionError("reduction normalization has a terminal carry")
    return (digit0, digit1, digit2, raw3), (carry1, carry2, carry3)


def build_split_limb_mul_witness(
    x: int, y: int, config: SplitLimbConfig = SplitLimbConfig()
) -> SplitLimbMulWitness:
    x = int(x)
    y = int(y)
    if not 0 <= x < config.foreign_modulus or not 0 <= y < config.foreign_modulus:
        raise SplitLimbError("foreign operands must be canonical")
    product = x * y
    z = product % config.foreign_modulus
    quotient = product // config.foreign_modulus
    if not 0 <= quotient < config.foreign_modulus:
        raise AssertionError("foreign multiplication quotient is noncanonical")

    geometry = config.geometry
    x_bound = build_canonical_limb_witness(x, geometry)
    y_bound = build_canonical_limb_witness(y, geometry)
    z_bound = build_canonical_limb_witness(z, geometry)
    quotient_bound = build_canonical_limb_witness(quotient, geometry)

    x_limbs = x_bound.value_limbs
    y_limbs = y_bound.value_limbs
    q_limbs = config.modulus_limbs
    quotient_limbs = quotient_bound.value_limbs

    xy_splits = tuple(
        _build_product_split(x_limbs[i], y_limbs[j], config)
        for i, j in _INDEX_PAIRS
    )
    quotient_splits = tuple(
        _build_product_split(quotient_limbs[i], q_limbs[j], config)
        for i, j in _INDEX_PAIRS
    )
    product_digits, product_carries = _normalize_product(xy_splits, config)
    reduction_digits, reduction_carries = _normalize_reduction(
        quotient_splits, z_bound.value_limbs, config
    )
    if product_digits != reduction_digits:
        raise AssertionError("split-product and reduction digits differ")

    return SplitLimbMulWitness(
        x_bound,
        y_bound,
        z_bound,
        quotient_bound,
        xy_splits,  # type: ignore[arg-type]
        quotient_splits,  # type: ignore[arg-type]
        product_digits,
        product_carries,
        reduction_carries,
    )


def verify_split_limb_mul_witness(
    witness: SplitLimbMulWitness,
    config: SplitLimbConfig = SplitLimbConfig(),
) -> bool:
    try:
        geometry = config.geometry
        bound_values = (witness.x, witness.y, witness.z, witness.quotient)
        if not all(
            verify_canonical_limb_witness(value, geometry) for value in bound_values
        ):
            return False
        if len(witness.xy_splits) != 4 or len(witness.quotient_modulus_splits) != 4:
            return False
        if len(witness.normalized_digits) != 4:
            return False
        if len(witness.product_carries) != 2 or len(witness.reduction_carries) != 3:
            return False
        if any(not 0 <= int(value) < config.base for value in witness.normalized_digits):
            return False

        for split, (i, j) in zip(witness.xy_splits, _INDEX_PAIRS, strict=True):
            if not _verify_product_split(
                split, witness.x.value_limbs[i], witness.y.value_limbs[j], config
            ):
                return False
        q_limbs = config.modulus_limbs
        for split, (i, j) in zip(
            witness.quotient_modulus_splits, _INDEX_PAIRS, strict=True
        ):
            if not _verify_product_split(
                split, witness.quotient.value_limbs[i], q_limbs[j], config
            ):
                return False

        product_carry2, product_carry3 = witness.product_carries
        if product_carry2 not in (0, 1, 2) or product_carry3 not in (0, 1, 2):
            return False
        reduction_carry1, reduction_carry2, reduction_carry3 = (
            witness.reduction_carries
        )
        if reduction_carry1 not in (0, 1):
            return False
        if reduction_carry2 not in (0, 1, 2, 3):
            return False
        if reduction_carry3 not in (0, 1, 2):
            return False

        p00, p01, p10, p11 = witness.xy_splits
        d0, d1, d2, d3 = witness.normalized_digits
        if d0 != p00.low:
            return False
        if p00.high + p01.low + p10.low != d1 + config.base * product_carry2:
            return False
        if (
            p01.high + p10.high + p11.low + product_carry2
            != d2 + config.base * product_carry3
        ):
            return False
        if p11.high + product_carry3 != d3:
            return False

        r00, r01, r10, r11 = witness.quotient_modulus_splits
        z0, z1 = witness.z.value_limbs
        if r00.low + z0 != d0 + config.base * reduction_carry1:
            return False
        if (
            r00.high + r01.low + r10.low + z1 + reduction_carry1
            != d1 + config.base * reduction_carry2
        ):
            return False
        if (
            r01.high + r10.high + r11.low + reduction_carry2
            != d2 + config.base * reduction_carry3
        ):
            return False
        if r11.high + reduction_carry3 != d3:
            return False

        return (
            witness.x.value * witness.y.value
            == witness.z.value + witness.quotient.value * config.foreign_modulus
        )
    except (FieldBridgeError, SplitLimbError, ValueError, OverflowError):
        return False


@dataclass(frozen=True, slots=True)
class SplitLimbScheduleEstimate:
    foreign_products: int
    config: SplitLimbConfig
    range_model: RangeLookupModel
    fresh_values_per_product: int
    native_nonlinear_products: int
    canonical_lookup_events: int
    exact_product_split_lookup_events: int
    normalized_digit_lookup_events: int
    normalization_carry_lookup_events: int
    linear_equations: int
    schema: str = "ranklock-split-limb-schedule-estimate-v1"

    @property
    def total_lookup_events(self) -> int:
        return (
            self.canonical_lookup_events
            + self.exact_product_split_lookup_events
            + self.normalized_digit_lookup_events
            + self.normalization_carry_lookup_events
        )

    @property
    def simple_row_equivalent(self) -> int:
        return self.total_lookup_events + self.native_nonlinear_products

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "foreign_products": self.foreign_products,
            "config": self.config.document(),
            "range_model": self.range_model.document(),
            "fresh_values_per_product": self.fresh_values_per_product,
            "native_nonlinear_products": self.native_nonlinear_products,
            "canonical_lookup_events": self.canonical_lookup_events,
            "exact_product_split_lookup_events": self.exact_product_split_lookup_events,
            "normalized_digit_lookup_events": self.normalized_digit_lookup_events,
            "normalization_carry_lookup_events": self.normalization_carry_lookup_events,
            "logical_lookup_events_total": self.total_lookup_events,
            "linear_equations": self.linear_equations,
            "simple_row_equivalent": self.simple_row_equivalent,
            "per_foreign_product": {
                "native_nonlinear_products": self.native_nonlinear_products
                // self.foreign_products,
                "logical_lookup_events": self.total_lookup_events
                // self.foreign_products,
                "simple_row_equivalent": self.simple_row_equivalent
                // self.foreign_products,
            },
            "scope": (
                "exact split-product witness plus logical range/linear inventory; excludes "
                "PCS, lookup-argument fixed overhead, parser/hash work and conditional disclosure"
            ),
        }


def estimate_split_limb_schedule(
    foreign_products: int,
    config: SplitLimbConfig = SplitLimbConfig(),
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    fresh_values_per_product: int = 2,
) -> SplitLimbScheduleEstimate:
    if foreign_products <= 0:
        raise SplitLimbError("foreign product count must be positive")
    if fresh_values_per_product <= 0:
        raise SplitLimbError("fresh-value count must be positive")

    products = int(foreign_products)
    fresh_values = products * int(fresh_values_per_product)
    chunks_per_limb = range_model.chunks(config.limb_bits)

    # Per canonical value: range-checked serialization chunks whose tuple rows
    # also expose constituent bytes/boundary pieces, two slack-limb ranges, and
    # one carry lookup for value + slack = q - 1.
    serialization_chunks = range_model.chunks(8 * CANONICAL_BYTE_WIDTH)
    canonical_per_value = (
        serialization_chunks
        + config.limbs * chunks_per_limb
        + (config.limbs - 1)
    )
    canonical_events = fresh_values * canonical_per_value

    # Four x*y products and four quotient*q constant products, each split into
    # two 127-bit chunks.
    split_components = (4 + 4) * 2
    split_events = products * split_components * chunks_per_limb

    # d0 aliases p00.low; only d1,d2,d3 need additional range decompositions.
    digit_events = products * 3 * chunks_per_limb
    carry_events = products * 5

    # Two fresh canonical values contribute 3*n equations each.  There are four
    # nonlinear-product split equations, four constant-product split equations,
    # seven normalization equations and three digit recompositions.
    canonical_linear = fresh_values * (3 * config.limbs)
    other_linear = products * (4 + 4 + 7 + 3)

    return SplitLimbScheduleEstimate(
        foreign_products=products,
        config=config,
        range_model=range_model,
        fresh_values_per_product=int(fresh_values_per_product),
        native_nonlinear_products=4 * products,
        canonical_lookup_events=canonical_events,
        exact_product_split_lookup_events=split_events,
        normalized_digit_lookup_events=digit_events,
        normalization_carry_lookup_events=carry_events,
        linear_equations=canonical_linear + other_linear,
    )



def estimate_split_limb_reduced_quotient_schedule(
    foreign_products: int,
    config: SplitLimbConfig = SplitLimbConfig(),
    *,
    range_model: RangeLookupModel = RangeLookupModel(),
    quotient_bits: int = 254,
) -> SplitLimbScheduleEstimate:
    """Four-product split schedule with a bounded internal quotient.

    The output ``z`` retains the complete canonical proof.  The quotient is
    represented by one bounded packed value and two 127-bit arithmetic limbs;
    exact equality forces it to be the unique honest quotient.
    """

    if foreign_products <= 0:
        raise SplitLimbError("foreign product count must be positive")
    if not 1 <= quotient_bits <= 2 * config.limb_bits:
        raise SplitLimbError("quotient bit bound does not fit split limbs")
    if (config.foreign_modulus - 2).bit_length() > quotient_bits:
        raise SplitLimbError("quotient bit bound misses an honest quotient")

    products = int(foreign_products)
    chunks_per_limb = range_model.chunks(config.limb_bits)
    serialization_chunks = range_model.chunks(8 * CANONICAL_BYTE_WIDTH)

    # The output is canonical: value bytes, two slack limbs, and one carry.
    output_canonical_events = products * (
        serialization_chunks
        + config.limbs * chunks_per_limb
        + (config.limbs - 1)
    )
    # The internal quotient only needs an exact bounded serialization.
    quotient_events = products * range_model.chunks(quotient_bits)

    split_components = (4 + 4) * 2
    split_events = products * split_components * chunks_per_limb
    digit_events = products * 3 * chunks_per_limb
    carry_events = products * 5

    # z: six canonical equations. quotient: two byte-to-limb packing equations.
    # Product splits/normalization retain the same eighteen relations.
    output_canonical_linear = products * (3 * config.limbs)
    quotient_pack_linear = products * config.limbs
    other_linear = products * (4 + 4 + 7 + 3)

    return SplitLimbScheduleEstimate(
        foreign_products=products,
        config=config,
        range_model=range_model,
        fresh_values_per_product=2,
        native_nonlinear_products=4 * products,
        canonical_lookup_events=output_canonical_events + quotient_events,
        exact_product_split_lookup_events=split_events,
        normalized_digit_lookup_events=digit_events,
        normalization_carry_lookup_events=carry_events,
        linear_equations=(
            output_canonical_linear + quotient_pack_linear + other_linear
        ),
        schema="ranklock-split-limb-reduced-quotient-schedule-estimate-v1",
    )

def randomized_self_test(
    config: SplitLimbConfig = SplitLimbConfig(), *, cases: int = 200, seed: int = 127
) -> None:
    rng = random.Random(seed)
    edges = (0, 1, 2, config.foreign_modulus - 2, config.foreign_modulus - 1)
    for x in edges:
        for y in edges:
            if not verify_split_limb_mul_witness(
                build_split_limb_mul_witness(x, y, config), config
            ):
                raise AssertionError("split-limb edge multiplication failed")
    for _ in range(cases):
        x = rng.randrange(config.foreign_modulus)
        y = rng.randrange(config.foreign_modulus)
        if not verify_split_limb_mul_witness(
            build_split_limb_mul_witness(x, y, config), config
        ):
            raise AssertionError("split-limb random multiplication failed")
