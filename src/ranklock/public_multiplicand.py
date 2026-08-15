from __future__ import annotations

"""Linearizing the final RankFold product by exposing one opened scalar.

The terminal RankFold check is

    claim = eq * (a*b - c).

For a static delayed-input lock, treating both ``a`` and ``b`` as unknown future
coordinates creates one mixed product.  If the proof format promotes one opened
value (here ``b``) to a delayed *public statement scalar*, the verifier relation
becomes linear in the witness encodings of ``a`` and ``c``:

    (eq*b) [a]_1 = [claim + eq*c]_1.

The public scalar ``b`` must still be bound to the committed B polynomial by a
KZG/PCS opening.  That opening equation is linear because ``b`` is part of the
statement.  This gives a linearly-verifiable terminal normal form without a
hidden source-group scalar multiplication.

The trade-off is projective input size: a 254-bit/32-byte opened scalar must be
supplied through the delayed-input mechanism in addition to the bridge's 132
bytes.  This module models the algebra and the exact naive compact-label cost.
"""

from dataclasses import dataclass
from typing import Sequence

from .field import BN254_BASE_FIELD
from .kzg_we_model import GroupElement, generator
from .projective_kzg_we import compact_projective_catalog_cost


class PublicMultiplicandError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PublicMultiplicandInventory:
    original_projective_bytes: int
    exposed_scalar_bytes: int
    total_projective_bytes: int
    hidden_bilinear_gates: int
    linear_group_equations: int
    naive_compact_catalog_bytes: int
    schema: str = "ranklock-public-multiplicand-inventory-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "original_projective_bytes": self.original_projective_bytes,
            "exposed_scalar_bytes": self.exposed_scalar_bytes,
            "total_projective_bytes": self.total_projective_bytes,
            "hidden_bilinear_gates": self.hidden_bilinear_gates,
            "linear_group_equations": self.linear_group_equations,
            "naive_compact_catalog_bytes": self.naive_compact_catalog_bytes,
            "sub_megabyte_under_naive_labels": self.naive_compact_catalog_bytes < 1024 * 1024,
            "note": (
                "Duty-Free-Bits-style projectivization is needed to beat the naive 256-label catalog"
            ),
        }


def inventory(
    *, original_projective_bytes: int = 132, exposed_scalar_bytes: int = 32
) -> PublicMultiplicandInventory:
    if original_projective_bytes <= 0 or exposed_scalar_bytes <= 0:
        raise PublicMultiplicandError("projective byte counts must be positive")
    total = original_projective_bytes + exposed_scalar_bytes
    cost = compact_projective_catalog_cost((256,) * total)[
        "total_bytes_excluding_payload"
    ]
    return PublicMultiplicandInventory(
        original_projective_bytes=original_projective_bytes,
        exposed_scalar_bytes=exposed_scalar_bytes,
        total_projective_bytes=total,
        hidden_bilinear_gates=0,
        # terminal equation plus B-opening equation; A/C openings are counted elsewhere.
        linear_group_equations=2,
        naive_compact_catalog_bytes=cost,
    )


def verify_linearized_terminal_group_equation(
    *,
    current_claim: int,
    equality_weight: int,
    public_b: int,
    a_g1: GroupElement,
    c_g1: GroupElement,
) -> bool:
    if a_g1.group != "G1" or c_g1.group != "G1":
        raise PublicMultiplicandError("terminal values must be G1 encodings")
    if a_g1.modulus != c_g1.modulus:
        raise PublicMultiplicandError("terminal encodings use different fields")
    modulus = a_g1.modulus
    eq = int(equality_weight) % modulus
    b = int(public_b) % modulus
    claim = int(current_claim) % modulus
    left = a_g1.scale(eq * b)
    right = generator("G1", modulus).scale(claim) + c_g1.scale(eq)
    return left == right


def scalar_bits_le(value: int, *, bits: int = 254) -> tuple[int, ...]:
    if bits <= 0:
        raise PublicMultiplicandError("bit width must be positive")
    value = int(value)
    if not 0 <= value < 1 << bits:
        raise PublicMultiplicandError("scalar does not fit exposed bit width")
    return tuple((value >> index) & 1 for index in range(bits))


def reconstruct_scalar_le(bits: Sequence[int], *, modulus: int = BN254_BASE_FIELD) -> int:
    value = 0
    for index, bit in enumerate(bits):
        if int(bit) not in (0, 1):
            raise PublicMultiplicandError("non-bit in projective scalar encoding")
        value += int(bit) << index
    return value % modulus
