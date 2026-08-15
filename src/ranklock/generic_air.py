from __future__ import annotations

"""Legacy algebra helper for local AIR checks over formal KZG commitments.

SECURITY WARNING: :func:`prove_generic_air` receives ``zeta`` before it builds
quotient commitments.  It is useful for algebraic identity tests only and is
not a sound one-beacon protocol.  ``tests/test_phased_air.py`` contains an
executable late-binding forgery.  Protocol code must use
:mod:`ranklock.phased_air`, which commits trace and quotient polynomials before
deriving ``zeta`` from an external beacon.

The expression and verifier machinery in this file is reused by the phased
wrapper.
"""

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping, Sequence

from .field import BN254_BASE_FIELD, polynomial_evaluate
from .kzg_we_model import GroupElement
from .one_beacon_air import (
    PolynomialOpening,
    interpolate,
    poly_add,
    poly_divmod,
    poly_mul,
    poly_scale,
    poly_shift,
    poly_sub,
    vanishing_polynomial,
)
from .ppe_normal_form import FormalKzgSrs, PairingProductEquation, kzg_opening_equation_g1


class GenericAirError(ValueError):
    pass


class Expr:
    def poly(self, columns: Mapping[str, tuple[int, ...]], modulus: int) -> tuple[int, ...]:
        raise NotImplementedError

    def point(
        self,
        current: Mapping[str, int],
        next_values: Mapping[str, int],
        modulus: int,
    ) -> int:
        raise NotImplementedError

    @property
    def current_columns(self) -> frozenset[str]:
        raise NotImplementedError

    @property
    def next_columns(self) -> frozenset[str]:
        raise NotImplementedError

    def __add__(self, other: object) -> "Expr":
        return BinaryExpr("add", self, as_expr(other))

    def __radd__(self, other: object) -> "Expr":
        return as_expr(other) + self

    def __sub__(self, other: object) -> "Expr":
        return BinaryExpr("sub", self, as_expr(other))

    def __rsub__(self, other: object) -> "Expr":
        return as_expr(other) - self

    def __mul__(self, other: object) -> "Expr":
        return BinaryExpr("mul", self, as_expr(other))

    def __rmul__(self, other: object) -> "Expr":
        return as_expr(other) * self

    def __neg__(self) -> "Expr":
        return Constant(-1) * self


@dataclass(frozen=True, slots=True)
class Constant(Expr):
    value: int

    def poly(self, columns: Mapping[str, tuple[int, ...]], modulus: int) -> tuple[int, ...]:
        return (int(self.value) % modulus,)

    def point(
        self,
        current: Mapping[str, int],
        next_values: Mapping[str, int],
        modulus: int,
    ) -> int:
        return int(self.value) % modulus

    @property
    def current_columns(self) -> frozenset[str]:
        return frozenset()

    @property
    def next_columns(self) -> frozenset[str]:
        return frozenset()


@dataclass(frozen=True, slots=True)
class Current(Expr):
    name: str

    def poly(self, columns: Mapping[str, tuple[int, ...]], modulus: int) -> tuple[int, ...]:
        try:
            return columns[self.name]
        except KeyError as exc:
            raise GenericAirError(f"unknown current AIR column {self.name}") from exc

    def point(
        self,
        current: Mapping[str, int],
        next_values: Mapping[str, int],
        modulus: int,
    ) -> int:
        try:
            return int(current[self.name]) % modulus
        except KeyError as exc:
            raise GenericAirError(f"missing current AIR opening {self.name}") from exc

    @property
    def current_columns(self) -> frozenset[str]:
        return frozenset({self.name})

    @property
    def next_columns(self) -> frozenset[str]:
        return frozenset()


@dataclass(frozen=True, slots=True)
class Next(Expr):
    name: str

    def poly(self, columns: Mapping[str, tuple[int, ...]], modulus: int) -> tuple[int, ...]:
        try:
            return poly_shift(columns[self.name], 1, modulus)
        except KeyError as exc:
            raise GenericAirError(f"unknown next AIR column {self.name}") from exc

    def point(
        self,
        current: Mapping[str, int],
        next_values: Mapping[str, int],
        modulus: int,
    ) -> int:
        try:
            return int(next_values[self.name]) % modulus
        except KeyError as exc:
            raise GenericAirError(f"missing next AIR opening {self.name}") from exc

    @property
    def current_columns(self) -> frozenset[str]:
        return frozenset()

    @property
    def next_columns(self) -> frozenset[str]:
        return frozenset({self.name})


@dataclass(frozen=True, slots=True)
class BinaryExpr(Expr):
    operation: str
    left: Expr
    right: Expr

    def poly(self, columns: Mapping[str, tuple[int, ...]], modulus: int) -> tuple[int, ...]:
        left = self.left.poly(columns, modulus)
        right = self.right.poly(columns, modulus)
        if self.operation == "add":
            return poly_add(left, right, modulus)
        if self.operation == "sub":
            return poly_sub(left, right, modulus)
        if self.operation == "mul":
            return poly_mul(left, right, modulus)
        raise GenericAirError("unknown AIR expression operation")

    def point(
        self,
        current: Mapping[str, int],
        next_values: Mapping[str, int],
        modulus: int,
    ) -> int:
        left = self.left.point(current, next_values, modulus)
        right = self.right.point(current, next_values, modulus)
        if self.operation == "add":
            return (left + right) % modulus
        if self.operation == "sub":
            return (left - right) % modulus
        if self.operation == "mul":
            return left * right % modulus
        raise GenericAirError("unknown AIR expression operation")

    @property
    def current_columns(self) -> frozenset[str]:
        return self.left.current_columns | self.right.current_columns

    @property
    def next_columns(self) -> frozenset[str]:
        return self.left.next_columns | self.right.next_columns


def as_expr(value: object) -> Expr:
    if isinstance(value, Expr):
        return value
    if isinstance(value, int):
        return Constant(value)
    raise TypeError(f"cannot convert {type(value).__name__} to AIR expression")


@dataclass(frozen=True, slots=True)
class AirConstraint:
    label: str
    expression: Expr
    active_rows: tuple[int, ...]

    def __post_init__(self) -> None:
        if not self.label:
            raise GenericAirError("AIR constraint label is empty")
        if not self.active_rows:
            raise GenericAirError("AIR constraint active row set is empty")
        if len(set(self.active_rows)) != len(self.active_rows) or min(self.active_rows) < 0:
            raise GenericAirError("AIR constraint active rows are malformed")


@dataclass(frozen=True, slots=True)
class BoundaryConstraint:
    column: str
    row: int
    value: int
    label: str


@dataclass(frozen=True, slots=True)
class GenericAirProgram:
    columns: tuple[str, ...]
    constraints: tuple[AirConstraint, ...]
    boundaries: tuple[BoundaryConstraint, ...] = ()
    modulus: int = BN254_BASE_FIELD
    schema: str = "ranklock-generic-local-air-program-v1"

    def __post_init__(self) -> None:
        if not self.columns or len(set(self.columns)) != len(self.columns):
            raise GenericAirError("AIR program columns must be non-empty and unique")
        allowed = set(self.columns)
        for constraint in self.constraints:
            referenced = constraint.expression.current_columns | constraint.expression.next_columns
            if not referenced <= allowed:
                raise GenericAirError("AIR constraint references an unknown column")
        for boundary in self.boundaries:
            if boundary.column not in allowed or boundary.row < 0:
                raise GenericAirError("AIR boundary is malformed")


@dataclass(frozen=True, slots=True)
class GenericAirTrace:
    columns: Mapping[str, tuple[int, ...]]
    modulus: int = BN254_BASE_FIELD

    @property
    def rows(self) -> int:
        lengths = {len(values) for values in self.columns.values()}
        if len(lengths) != 1:
            raise GenericAirError("AIR trace columns have different lengths")
        return next(iter(lengths))


@dataclass(frozen=True, slots=True)
class GenericAirProof:
    program_digest: bytes
    rows: int
    zeta: int
    commitments: Mapping[str, GroupElement]
    current_openings: Mapping[str, PolynomialOpening]
    next_openings: Mapping[str, PolynomialOpening]
    boundary_openings: Mapping[str, PolynomialOpening]
    modulus: int = BN254_BASE_FIELD


@dataclass(frozen=True, slots=True)
class GenericAirProverOutput:
    proof: GenericAirProof
    polynomials: Mapping[str, tuple[int, ...]]


def program_digest(program: GenericAirProgram) -> bytes:
    document = {
        "schema": program.schema,
        "columns": list(program.columns),
        "constraints": [
            {
                "label": constraint.label,
                "active_rows": list(constraint.active_rows),
                "current_columns": sorted(constraint.expression.current_columns),
                "next_columns": sorted(constraint.expression.next_columns),
                "expression_repr": repr(constraint.expression),
            }
            for constraint in program.constraints
        ],
        "boundaries": [
            {
                "column": boundary.column,
                "row": boundary.row,
                "value": str(boundary.value % program.modulus),
                "label": boundary.label,
            }
            for boundary in program.boundaries
        ],
        "modulus": str(program.modulus),
    }
    return hashlib.sha256(
        b"ranklock/generic-air-program/v1\x00"
        + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).digest()


def prove_generic_air(
    program: GenericAirProgram,
    trace: GenericAirTrace,
    *,
    zeta: int,
    srs: FormalKzgSrs,
) -> GenericAirProverOutput:
    if trace.modulus != program.modulus or srs.modulus != program.modulus:
        raise GenericAirError("AIR program, trace, and PCS fields differ")
    if set(trace.columns) != set(program.columns):
        raise GenericAirError("AIR trace column set differs from program")
    rows = trace.rows
    if rows < 2:
        raise GenericAirError("AIR trace must have at least two rows")
    for constraint in program.constraints:
        if max(constraint.active_rows) >= rows:
            raise GenericAirError("AIR active row exceeds trace")
        if constraint.expression.next_columns and max(constraint.active_rows) >= rows - 1:
            raise GenericAirError("next-row constraint is active on the last row")
    for boundary in program.boundaries:
        if boundary.row >= rows:
            raise GenericAirError("AIR boundary row exceeds trace")

    domain = tuple(range(rows))
    polynomials: dict[str, tuple[int, ...]] = {
        name: interpolate(domain, trace.columns[name], program.modulus)
        for name in program.columns
    }
    for constraint in program.constraints:
        residual = constraint.expression.poly(polynomials, program.modulus)
        quotient, remainder = poly_divmod(
            residual,
            vanishing_polynomial(constraint.active_rows, program.modulus),
            program.modulus,
        )
        if remainder != (0,):
            raise GenericAirError(f"AIR constraint {constraint.label} does not hold on its domain")
        polynomials[f"q:{constraint.label}"] = quotient

    zeta %= program.modulus
    used_points = set(domain) | {boundary.row for boundary in program.boundaries}
    if zeta in used_points or (zeta + 1) % program.modulus in used_points:
        raise GenericAirError("AIR beacon point collides with trace/boundary domain")
    commitments = {name: srs.commit_g1(poly) for name, poly in polynomials.items()}
    current: dict[str, PolynomialOpening] = {}
    for name, poly in polynomials.items():
        value, opening = srs.opening_g1(poly, zeta)
        current[name] = PolynomialOpening(value, opening)
    next_columns = sorted(
        set().union(*(constraint.expression.next_columns for constraint in program.constraints))
    )
    next_openings: dict[str, PolynomialOpening] = {}
    for name in next_columns:
        value, opening = srs.opening_g1(polynomials[name], (zeta + 1) % program.modulus)
        next_openings[name] = PolynomialOpening(value, opening)
    boundary_openings: dict[str, PolynomialOpening] = {}
    for boundary in program.boundaries:
        key = boundary.label
        if key in boundary_openings:
            raise GenericAirError("duplicate AIR boundary label")
        value, opening = srs.opening_g1(polynomials[boundary.column], boundary.row)
        boundary_openings[key] = PolynomialOpening(value, opening)
    return GenericAirProverOutput(
        GenericAirProof(
            program_digest(program),
            rows,
            zeta,
            commitments,
            current,
            next_openings,
            boundary_openings,
            program.modulus,
        ),
        polynomials,
    )


def _opening_equations(
    program: GenericAirProgram, proof: GenericAirProof, srs: FormalKzgSrs
) -> tuple[PairingProductEquation, ...]:
    expected_polynomials = set(program.columns) | {
        f"q:{constraint.label}" for constraint in program.constraints
    }
    if set(proof.commitments) != expected_polynomials or set(proof.current_openings) != expected_polynomials:
        raise GenericAirError("AIR proof polynomial set differs")
    equations: list[PairingProductEquation] = []
    for name in sorted(expected_polynomials):
        opening = proof.current_openings[name]
        equations.append(
            kzg_opening_equation_g1(
                commitment=proof.commitments[name],
                value=opening.value,
                opening=opening.proof,
                point=proof.zeta,
                srs=srs,
                label=f"air-open-{name}",
            )
        )
    expected_next = set().union(*(constraint.expression.next_columns for constraint in program.constraints))
    if set(proof.next_openings) != expected_next:
        raise GenericAirError("AIR next-opening set differs")
    for name in sorted(expected_next):
        opening = proof.next_openings[name]
        equations.append(
            kzg_opening_equation_g1(
                commitment=proof.commitments[name],
                value=opening.value,
                opening=opening.proof,
                point=(proof.zeta + 1) % proof.modulus,
                srs=srs,
                label=f"air-open-next-{name}",
            )
        )
    if set(proof.boundary_openings) != {boundary.label for boundary in program.boundaries}:
        raise GenericAirError("AIR boundary-opening set differs")
    for boundary in program.boundaries:
        opening = proof.boundary_openings[boundary.label]
        equations.append(
            kzg_opening_equation_g1(
                commitment=proof.commitments[boundary.column],
                value=opening.value,
                opening=opening.proof,
                point=boundary.row,
                srs=srs,
                label=f"air-boundary-{boundary.label}",
            )
        )
    return tuple(equations)


def verify_generic_air(
    program: GenericAirProgram,
    proof: GenericAirProof,
    *,
    srs: FormalKzgSrs,
) -> bool:
    try:
        if proof.program_digest != program_digest(program):
            return False
        if proof.modulus != program.modulus or srs.modulus != program.modulus:
            return False
        if not all(equation.verify() for equation in _opening_equations(program, proof, srs)):
            return False
        current = {
            name: opening.value % proof.modulus
            for name, opening in proof.current_openings.items()
            if name in program.columns
        }
        next_values = {
            name: opening.value % proof.modulus for name, opening in proof.next_openings.items()
        }
        for constraint in program.constraints:
            residual = constraint.expression.point(current, next_values, proof.modulus)
            vanishing = polynomial_evaluate(
                vanishing_polynomial(constraint.active_rows, proof.modulus),
                proof.zeta,
                proof.modulus,
            )
            quotient = proof.current_openings[f"q:{constraint.label}"].value
            if residual != vanishing * quotient % proof.modulus:
                return False
        for boundary in program.boundaries:
            if proof.boundary_openings[boundary.label].value % proof.modulus != boundary.value % proof.modulus:
                return False
        return True
    except (GenericAirError, ValueError, KeyError, OverflowError):
        return False


def generic_air_cost(program: GenericAirProgram, rows: int) -> dict[str, object]:
    next_columns = set().union(*(constraint.expression.next_columns for constraint in program.constraints))
    return {
        "schema": "ranklock-generic-air-cost-v1",
        "rows": rows,
        "trace_columns": len(program.columns),
        "constraint_quotients": len(program.constraints),
        "boundary_openings": len(program.boundaries),
        "next_column_openings": len(next_columns),
        "current_openings": len(program.columns) + len(program.constraints),
        "proof_shape_independent_of_rows": True,
        "beacons": 1,
        "fiat_shamir_hashes_inside_lock": 0,
    }
