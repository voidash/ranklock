from __future__ import annotations

"""Static/projective timing analysis for KZG-opening witness encryption.

Standard KZG witness encryption is concretely tiny, but encapsulation is bound
to a future statement ``(commitment, point, value)``.  This module separates
what can be precomputed projectively from what cannot.

A useful positive result is available when the commitment is fixed at setup:
point and value can be supplied through one-time selected encodings, and a valid
opening recovers a GT-encoded secret.  The unresolved case is a future arbitrary
commitment.  Publishing the randomizer base needed for public affine updates
makes the KZG-WE session public and destroys witness-only decryption.

The model exposes exponents and therefore proves no computational security.
"""

from dataclasses import dataclass
from typing import Mapping, Sequence

from .kzg_we_model import GroupElement, pairing
from .ppe_normal_form import FormalKzgSrs
from .kzg_we_conjunction import KzgOpeningStatement, KzgOpeningWitness


class StaticKzgWeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PublicAffineUpdateMaterial:
    r_tau_g2: GroupElement
    r_g2: GroupElement | None

    @property
    def publicly_updatable(self) -> bool:
        return self.r_g2 is not None


@dataclass(frozen=True, slots=True)
class FixedCommitmentProjectiveArtifact:
    commitment: GroupElement
    masked_base: GroupElement
    point_headers: Mapping[int, GroupElement]
    value_adjustments: Mapping[int, GroupElement]
    modulus: int

    def select(self, *, point: int, value: int) -> tuple[GroupElement, GroupElement]:
        try:
            header = self.point_headers[int(point) % self.modulus]
            payload = self.masked_base + self.value_adjustments[int(value) % self.modulus]
        except KeyError as exc:
            raise StaticKzgWeError("requested point/value was not provisioned") from exc
        return header, payload


def prepare_public_affine_update(
    randomizer: int, *, expose_randomizer_base: bool, srs: FormalKzgSrs
) -> PublicAffineUpdateMaterial:
    r = int(randomizer) % srs.modulus
    if r == 0:
        raise StaticKzgWeError("randomizer must be nonzero")
    return PublicAffineUpdateMaterial(
        srs.tau_g2.scale(r), srs.g2.scale(r) if expose_randomizer_base else None
    )


def public_update_header(
    material: PublicAffineUpdateMaterial, point: int, *, srs: FormalKzgSrs
) -> GroupElement:
    if material.r_g2 is None:
        raise StaticKzgWeError("public point update requires r*[1]_2")
    return material.r_tau_g2 - material.r_g2.scale(int(point) % srs.modulus)


def public_session_without_witness(
    material: PublicAffineUpdateMaterial,
    statement: KzgOpeningStatement,
    *,
    srs: FormalKzgSrs,
) -> GroupElement:
    """Compute the KZG-WE session publicly once ``r*[1]_2`` is exposed."""

    normalized = statement.normalized(srs)
    if material.r_g2 is None:
        raise StaticKzgWeError("session remains hidden without r*[1]_2")
    return pairing(
        normalized.commitment - srs.g1.scale(normalized.value), material.r_g2
    )


def build_fixed_commitment_projective_artifact(
    *,
    commitment: GroupElement,
    secret: GroupElement,
    points: Sequence[int],
    values: Sequence[int],
    randomizer: int,
    srs: FormalKzgSrs,
) -> FixedCommitmentProjectiveArtifact:
    if commitment.group != "G1" or commitment.modulus != srs.modulus:
        raise StaticKzgWeError("fixed commitment must be a G1 element")
    if secret.group != "GT" or secret.modulus != srs.modulus:
        raise StaticKzgWeError("projective secret must be a GT element")
    r = int(randomizer) % srs.modulus
    if r == 0:
        raise StaticKzgWeError("randomizer must be nonzero")
    point_domain = tuple(dict.fromkeys(int(point) % srs.modulus for point in points))
    value_domain = tuple(dict.fromkeys(int(value) % srs.modulus for value in values))
    if not point_domain or not value_domain:
        raise StaticKzgWeError("projective domains must be nonempty")
    r_g2 = srs.g2.scale(r)
    # payload = secret - e(C,rG2) + e(value*G1,rG2)
    masked_base = secret - pairing(commitment, r_g2)
    point_headers = {
        point: (srs.tau_g2 - srs.g2.scale(point)).scale(r)
        for point in point_domain
    }
    value_adjustments = {
        value: pairing(srs.g1.scale(value), r_g2) for value in value_domain
    }
    return FixedCommitmentProjectiveArtifact(
        commitment, masked_base, point_headers, value_adjustments, srs.modulus
    )


def decrypt_selected_projective_ciphertext(
    *,
    header: GroupElement,
    masked_payload: GroupElement,
    witness: KzgOpeningWitness,
    srs: FormalKzgSrs,
) -> GroupElement:
    witness.validate(srs)
    if header.group != "G2" or masked_payload.group != "GT":
        raise StaticKzgWeError("malformed selected projective ciphertext")
    return masked_payload + pairing(witness.opening, header)


def static_timing_inventory(
    *,
    fixed_commitment: bool,
    finite_point_domain: int,
    finite_value_domain: int,
    group_element_bytes: int = 96,
) -> dict[str, object]:
    if finite_point_domain <= 0 or finite_value_domain <= 0:
        raise StaticKzgWeError("projective domains must be positive")
    projective_elements = finite_point_domain + finite_value_domain + 1
    return {
        "schema": "ranklock-static-kzg-we-timing-v1",
        "fixed_commitment": bool(fixed_commitment),
        "point_labels": int(finite_point_domain),
        "value_labels": int(finite_value_domain),
        "fixed_group_elements": int(projective_elements),
        "fixed_bytes_before_delivery_mechanism": int(projective_elements)
        * int(group_element_bytes),
        "future_arbitrary_commitment_supported": False,
        "barrier": (
            None
            if fixed_commitment
            else "the masked payload depends on r*C; public affine update needs r*[1]_2, which reveals the KZG-WE session"
        ),
    }
