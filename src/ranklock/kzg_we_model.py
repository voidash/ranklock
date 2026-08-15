from __future__ import annotations

"""Exponent-space bilinear-group model.

The model deliberately exposes discrete-log exponents.  It is useful only for
checking algebraic signs, statement binding, and pairing-product normal forms;
it provides no computational security.
"""

from dataclasses import dataclass


class GroupModelError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class GroupElement:
    group: str
    exponent: int
    modulus: int

    def __post_init__(self) -> None:
        if self.group not in {"G1", "G2", "GT"}:
            raise GroupModelError("unknown formal group")
        if self.modulus <= 2:
            raise GroupModelError("formal group modulus must exceed two")
        object.__setattr__(self, "exponent", int(self.exponent) % self.modulus)

    @property
    def is_identity(self) -> bool:
        return self.exponent % self.modulus == 0

    def _compatible(self, other: object) -> "GroupElement":
        if not isinstance(other, GroupElement):
            raise TypeError("group operation requires GroupElement")
        if self.group != other.group or self.modulus != other.modulus:
            raise GroupModelError("group elements are incompatible")
        return other

    def __add__(self, other: object) -> "GroupElement":
        other = self._compatible(other)
        return GroupElement(self.group, self.exponent + other.exponent, self.modulus)

    def __sub__(self, other: object) -> "GroupElement":
        other = self._compatible(other)
        return GroupElement(self.group, self.exponent - other.exponent, self.modulus)

    def __neg__(self) -> "GroupElement":
        return GroupElement(self.group, -self.exponent, self.modulus)

    def scale(self, scalar: int) -> "GroupElement":
        return GroupElement(self.group, self.exponent * int(scalar), self.modulus)

    def encode(self) -> bytes:
        tag = {"G1": 1, "G2": 2, "GT": 3}[self.group]
        width = max(1, (self.modulus.bit_length() + 7) // 8)
        return bytes([tag]) + self.exponent.to_bytes(width, "big")


def generator(group: str, modulus: int) -> GroupElement:
    return GroupElement(group, 1, modulus)


def pairing(left: GroupElement, right: GroupElement) -> GroupElement:
    if left.group != "G1" or right.group != "G2":
        raise GroupModelError("pairing requires G1 x G2")
    if left.modulus != right.modulus:
        raise GroupModelError("pairing fields differ")
    return GroupElement("GT", left.exponent * right.exponent, left.modulus)
