from __future__ import annotations

"""Two-beacon KZG permutation argument for static conditional verification.

The protocol is a stripped-down grand-product argument with challenge timing
made explicit:

1. commit to the two sequence polynomials L and R;
2. beacon one supplies beta;
3. compute and commit the grand-product column Z and recurrence quotient Q;
4. beacon two supplies zeta;
5. open at zeta and verify the recurrence plus Z(0)=Z(n)=1.

The first beacon prevents choosing colliding multisets for a known beta.  The
second prevents choosing a fake quotient tailored to the verification point.
No Fiat--Shamir hash is required inside the conditional relation.

This proves multiset equality.  A RankVM memory argument additionally needs a
sorted access trace and local timestamp/read-write consistency constraints; those
fit the one-beacon AIR layer once the permutation is established.
"""

from dataclasses import dataclass, replace
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
    poly_shift,
    poly_sub,
    vanishing_polynomial,
)
from .ppe_normal_form import FormalKzgSrs, PairingProductEquation, kzg_opening_equation_g1


class PermutationArgumentError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PermutationPhaseOne:
    rows: int
    commitment_left: GroupElement
    commitment_right: GroupElement
    transcript_digest: bytes
    modulus: int = BN254_BASE_FIELD


@dataclass(frozen=True, slots=True)
class PermutationProof:
    phase_one: PermutationPhaseOne
    beta: int
    commitment_z: GroupElement
    commitment_q: GroupElement
    zeta: int
    openings_at_zeta: Mapping[str, PolynomialOpening]
    z_at_next: PolynomialOpening
    z_at_zero: PolynomialOpening
    z_at_end: PolynomialOpening
    schema: str = "ranklock-two-beacon-permutation-proof-v1"

    @property
    def digest(self) -> bytes:
        document = {
            "schema": self.schema,
            "rows": self.phase_one.rows,
            "phase_one": self.phase_one.transcript_digest.hex(),
            "beta": str(self.beta),
            "zeta": str(self.zeta),
            "commitment_z": self.commitment_z.encode().hex(),
            "commitment_q": self.commitment_q.encode().hex(),
            "openings": {
                key: {"value": str(value.value), "proof": value.proof.encode().hex()}
                for key, value in sorted(self.openings_at_zeta.items())
            },
        }
        return hashlib.sha256(
            b"ranklock/two-beacon-permutation-proof/v1\x00"
            + json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).digest()


@dataclass(frozen=True, slots=True)
class PermutationProverState:
    phase_one: PermutationPhaseOne
    left_polynomial: tuple[int, ...]
    right_polynomial: tuple[int, ...]
    left_values: tuple[int, ...]
    right_values: tuple[int, ...]


def commit_sequences(
    left: Sequence[int], right: Sequence[int], *, srs: FormalKzgSrs
) -> PermutationProverState:
    if len(left) != len(right) or len(left) < 2:
        raise PermutationArgumentError("permutation sequences must have equal length >=2")
    modulus = srs.modulus
    left_values = tuple(int(value) % modulus for value in left)
    right_values = tuple(int(value) % modulus for value in right)
    domain = tuple(range(len(left_values)))
    left_polynomial = interpolate(domain, left_values, modulus)
    right_polynomial = interpolate(domain, right_values, modulus)
    commitment_left = srs.commit_g1(left_polynomial)
    commitment_right = srs.commit_g1(right_polynomial)
    transcript = hashlib.sha256(
        b"ranklock/permutation/phase-one/v1\x00"
        + len(left_values).to_bytes(8, "big")
        + commitment_left.encode()
        + commitment_right.encode()
    ).digest()
    return PermutationProverState(
        PermutationPhaseOne(
            len(left_values), commitment_left, commitment_right, transcript, modulus
        ),
        left_polynomial,
        right_polynomial,
        left_values,
        right_values,
    )


def _grand_product(values_left: Sequence[int], values_right: Sequence[int], beta: int, modulus: int) -> tuple[int, ...]:
    z = [1]
    for left, right in zip(values_left, values_right, strict=True):
        denominator = (int(right) + beta) % modulus
        if denominator == 0:
            raise PermutationArgumentError("beacon beta hits a right-sequence pole")
        z.append(
            z[-1]
            * ((int(left) + beta) % modulus)
            * pow(denominator, -1, modulus)
            % modulus
        )
    return tuple(z)


def respond_to_beacons(
    state: PermutationProverState,
    *,
    beta: int,
    zeta: int,
    srs: FormalKzgSrs,
) -> PermutationProof:
    if state.phase_one.modulus != srs.modulus:
        raise PermutationArgumentError("permutation and SRS fields differ")
    modulus = srs.modulus
    beta %= modulus
    zeta %= modulus
    rows = state.phase_one.rows
    domain = tuple(range(rows))
    z_domain = tuple(range(rows + 1))
    if zeta in z_domain or (zeta + 1) % modulus in z_domain:
        raise PermutationArgumentError("zeta collides with the permutation domain")

    z_values = _grand_product(state.left_values, state.right_values, beta, modulus)
    z_polynomial = interpolate(z_domain, z_values, modulus)
    # Recurrence on rows 0..n-1:
    # Z(X+1)(R(X)+beta) - Z(X)(L(X)+beta) = 0.
    beta_poly = (beta,)
    residual = poly_sub(
        poly_mul(
            poly_shift(z_polynomial, 1, modulus),
            poly_add(state.right_polynomial, beta_poly, modulus),
            modulus,
        ),
        poly_mul(
            z_polynomial,
            poly_add(state.left_polynomial, beta_poly, modulus),
            modulus,
        ),
        modulus,
    )
    q_polynomial, remainder = poly_divmod(
        residual, vanishing_polynomial(domain, modulus), modulus
    )
    if remainder != (0,):
        raise PermutationArgumentError("grand-product recurrence is not divisible by row domain")

    commitment_z = srs.commit_g1(z_polynomial)
    commitment_q = srs.commit_g1(q_polynomial)
    openings: dict[str, PolynomialOpening] = {}
    for name, polynomial in (
        ("left", state.left_polynomial),
        ("right", state.right_polynomial),
        ("z", z_polynomial),
        ("q", q_polynomial),
    ):
        value, opening = srs.opening_g1(polynomial, zeta)
        openings[name] = PolynomialOpening(value, opening)
    z_next_value, z_next_opening = srs.opening_g1(z_polynomial, (zeta + 1) % modulus)
    z_zero_value, z_zero_opening = srs.opening_g1(z_polynomial, 0)
    z_end_value, z_end_opening = srs.opening_g1(z_polynomial, rows)
    return PermutationProof(
        state.phase_one,
        beta,
        commitment_z,
        commitment_q,
        zeta,
        openings,
        PolynomialOpening(z_next_value, z_next_opening),
        PolynomialOpening(z_zero_value, z_zero_opening),
        PolynomialOpening(z_end_value, z_end_opening),
    )


def _opening_equations(
    proof: PermutationProof, srs: FormalKzgSrs
) -> tuple[PairingProductEquation, ...]:
    commitments = {
        "left": proof.phase_one.commitment_left,
        "right": proof.phase_one.commitment_right,
        "z": proof.commitment_z,
        "q": proof.commitment_q,
    }
    if set(proof.openings_at_zeta) != set(commitments):
        raise PermutationArgumentError("permutation opening set differs")
    equations: list[PairingProductEquation] = []
    for name in sorted(commitments):
        opening = proof.openings_at_zeta[name]
        equations.append(
            kzg_opening_equation_g1(
                commitment=commitments[name],
                value=opening.value,
                opening=opening.proof,
                point=proof.zeta,
                srs=srs,
                label=f"perm-open-{name}",
            )
        )
    for label, point, opening in (
        ("perm-z-next", proof.zeta + 1, proof.z_at_next),
        ("perm-z-zero", 0, proof.z_at_zero),
        ("perm-z-end", proof.phase_one.rows, proof.z_at_end),
    ):
        equations.append(
            kzg_opening_equation_g1(
                commitment=proof.commitment_z,
                value=opening.value,
                opening=opening.proof,
                point=point % srs.modulus,
                srs=srs,
                label=label,
            )
        )
    return tuple(equations)


def verify_permutation(proof: PermutationProof, *, srs: FormalKzgSrs) -> bool:
    try:
        if proof.phase_one.modulus != srs.modulus or proof.phase_one.rows < 2:
            return False
        if not all(equation.verify() for equation in _opening_equations(proof, srs)):
            return False
        modulus = srs.modulus
        values = proof.openings_at_zeta
        zeta = proof.zeta % modulus
        recurrence_left = (
            proof.z_at_next.value * (values["right"].value + proof.beta)
            - values["z"].value * (values["left"].value + proof.beta)
        ) % modulus
        vanishing = polynomial_evaluate(
            vanishing_polynomial(tuple(range(proof.phase_one.rows)), modulus),
            zeta,
            modulus,
        )
        recurrence_right = vanishing * values["q"].value % modulus
        if recurrence_left != recurrence_right:
            return False
        return proof.z_at_zero.value % modulus == 1 and proof.z_at_end.value % modulus == 1
    except (PermutationArgumentError, ValueError, KeyError, OverflowError):
        return False


def permutation_cost_inventory(rows: int) -> dict[str, object]:
    if rows < 2:
        raise PermutationArgumentError("row count must be >=2")
    return {
        "schema": "ranklock-two-beacon-permutation-cost-v1",
        "rows": int(rows),
        "beacons": 2,
        "phase_one_commitments": 2,
        "phase_two_commitments": 2,
        "unbatched_kzg_openings": 7,
        "fiat_shamir_hashes_inside_lock": 0,
        "proof_shape_independent_of_rows": True,
        "soundness_terms": ["grand-product beta collision O(rows/p)", "quotient zeta collision O(degree/p)"],
    }
