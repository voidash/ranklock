from __future__ import annotations

"""Static conditional-lock interface classification.

v0.16 classified identity-normalised pairing equations as unusable.  v0.17
refines that criterion after reproducing KZG-opening witness encryption as a
split-basis special case.  Identity normalisation is not itself fatal: a direct
lock works when a nontrivial statement-side session is fixed at activation and
is algebraically separated from the scaled witness bases.

The real dividing lines are now:

* no future/dynamic G2 element;
* a constant/polylogarithmic fixed-G2 witness basis;
* either a statement-specific session known at activation, or a constructed
  fixed-relation witness lift;
* no public decomposition of the statement session over the scaled witness
  anchors;
* transcript/challenge binding;
* knowledge soundness and malicious activation consistency.
"""

from dataclasses import dataclass


class VerifierShapeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VerifierPairingShape:
    name: str
    dynamic_g1_terms: int
    dynamic_g2_terms: int
    fixed_g2_anchor_rank: int
    normalized_target_is_identity: bool
    statement_session_fixed_at_activation: bool
    statement_basis_separated_from_scaled_witness_anchors: bool
    static_witness_lift_constructed: bool
    transcript_coefficients_bound: bool
    fiat_shamir_or_challenge_consistency_bound: bool
    knowledge_sound_backend_constructed: bool
    verifier_specific_material_small: bool
    activation_ciphertext_consistency_constructed: bool
    schema: str = "ranklock-verifier-pairing-shape-v2"

    def __post_init__(self) -> None:
        if not self.name:
            raise VerifierShapeError("verifier shape name is empty")
        for value in (
            self.dynamic_g1_terms,
            self.dynamic_g2_terms,
            self.fixed_g2_anchor_rank,
        ):
            if value < 0:
                raise VerifierShapeError("verifier shape count is negative")

    @property
    def fixed_g2_shape_holds(self) -> bool:
        return self.dynamic_g1_terms > 0 and self.dynamic_g2_terms == 0

    @property
    def low_rank_shape_holds(self) -> bool:
        return self.fixed_g2_anchor_rank > 0

    @property
    def static_timing_holds(self) -> bool:
        return (
            self.statement_session_fixed_at_activation
            or self.static_witness_lift_constructed
        )

    @property
    def session_separation_holds(self) -> bool:
        return self.statement_basis_separated_from_scaled_witness_anchors

    @property
    def direct_statement_lock_holds(self) -> bool:
        return (
            self.fixed_g2_shape_holds
            and self.low_rank_shape_holds
            and self.statement_session_fixed_at_activation
            and self.session_separation_holds
            and self.transcript_coefficients_bound
            and self.fiat_shamir_or_challenge_consistency_bound
        )

    @property
    def witness_lift_interface_holds(self) -> bool:
        return (
            self.fixed_g2_shape_holds
            and self.low_rank_shape_holds
            and self.static_witness_lift_constructed
            and self.transcript_coefficients_bound
            and self.fiat_shamir_or_challenge_consistency_bound
        )

    @property
    def lock_interface_holds(self) -> bool:
        return self.direct_statement_lock_holds or self.witness_lift_interface_holds

    @property
    def complete_construction_holds(self) -> bool:
        return (
            self.lock_interface_holds
            and self.knowledge_sound_backend_constructed
            and self.verifier_specific_material_small
            and self.activation_ciphertext_consistency_constructed
        )

    @property
    def blockers(self) -> tuple[str, ...]:
        blockers: list[str] = []
        if self.dynamic_g1_terms == 0:
            blockers.append("no future G1 proof/witness terms")
        if self.dynamic_g2_terms:
            blockers.append("future/dynamic G2 proof terms cannot be pre-scaled statically")
        if self.fixed_g2_anchor_rank == 0:
            blockers.append("no fixed G2 anchor basis")
        if not self.static_timing_holds:
            blockers.append(
                "future statement session is unavailable at activation and no static witness lift exists"
            )
        if (
            self.statement_session_fixed_at_activation
            and not self.session_separation_holds
        ):
            blockers.append(
                "statement session decomposes over scaled witness anchors and leaks the unlock key"
            )
        if not self.transcript_coefficients_bound:
            blockers.append("future scalar coefficients are not bound to the proof transcript")
        if not self.fiat_shamir_or_challenge_consistency_bound:
            blockers.append(
                "Fiat-Shamir or hidden-verifier challenge consistency is not enforced"
            )
        if not self.knowledge_sound_backend_constructed:
            blockers.append("knowledge-sound proof backend is not constructed")
        if not self.verifier_specific_material_small:
            blockers.append("verifier-specific retained material is not below the target")
        if not self.activation_ciphertext_consistency_constructed:
            blockers.append(
                "malicious activation does not prove ciphertext/fault-share consistency"
            )
        return tuple(blockers)

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "name": self.name,
            "dynamic_g1_terms": self.dynamic_g1_terms,
            "dynamic_g2_terms": self.dynamic_g2_terms,
            "fixed_g2_anchor_rank": self.fixed_g2_anchor_rank,
            "normalized_target_is_identity": self.normalized_target_is_identity,
            "identity_target_is_automatically_fatal": False,
            "statement_session_fixed_at_activation": (
                self.statement_session_fixed_at_activation
            ),
            "statement_basis_separated_from_scaled_witness_anchors": (
                self.statement_basis_separated_from_scaled_witness_anchors
            ),
            "static_witness_lift_constructed": self.static_witness_lift_constructed,
            "transcript_coefficients_bound": self.transcript_coefficients_bound,
            "fiat_shamir_or_challenge_consistency_bound": (
                self.fiat_shamir_or_challenge_consistency_bound
            ),
            "knowledge_sound_backend_constructed": (
                self.knowledge_sound_backend_constructed
            ),
            "verifier_specific_material_small": self.verifier_specific_material_small,
            "activation_ciphertext_consistency_constructed": (
                self.activation_ciphertext_consistency_constructed
            ),
            "direct_statement_lock_holds": self.direct_statement_lock_holds,
            "witness_lift_interface_holds": self.witness_lift_interface_holds,
            "lock_interface_holds": self.lock_interface_holds,
            "complete_construction_holds": self.complete_construction_holds,
            "blockers": list(self.blockers),
        }


def reference_shape_frontier() -> dict[str, object]:
    shapes = (
        VerifierPairingShape(
            name="fixed-statement KZG-opening witness encryption",
            dynamic_g1_terms=1,
            dynamic_g2_terms=0,
            fixed_g2_anchor_rank=1,
            normalized_target_is_identity=True,
            statement_session_fixed_at_activation=True,
            statement_basis_separated_from_scaled_witness_anchors=True,
            static_witness_lift_constructed=False,
            transcript_coefficients_bound=True,
            fiat_shamir_or_challenge_consistency_bound=True,
            knowledge_sound_backend_constructed=True,
            verifier_specific_material_small=True,
            activation_ciphertext_consistency_constructed=False,
        ),
        VerifierPairingShape(
            name="reusable rank-two KZG anchors with exposed r[1]",
            dynamic_g1_terms=1,
            dynamic_g2_terms=0,
            fixed_g2_anchor_rank=2,
            normalized_target_is_identity=True,
            statement_session_fixed_at_activation=True,
            statement_basis_separated_from_scaled_witness_anchors=False,
            static_witness_lift_constructed=False,
            transcript_coefficients_bound=True,
            fiat_shamir_or_challenge_consistency_bound=True,
            knowledge_sound_backend_constructed=True,
            verifier_specific_material_small=True,
            activation_ciphertext_consistency_constructed=False,
        ),
        VerifierPairingShape(
            name="basis-separated KZG with future commitment/value",
            dynamic_g1_terms=1,
            dynamic_g2_terms=0,
            fixed_g2_anchor_rank=2,
            normalized_target_is_identity=True,
            statement_session_fixed_at_activation=False,
            statement_basis_separated_from_scaled_witness_anchors=True,
            static_witness_lift_constructed=False,
            transcript_coefficients_bound=True,
            fiat_shamir_or_challenge_consistency_bound=True,
            knowledge_sound_backend_constructed=True,
            verifier_specific_material_small=True,
            activation_ciphertext_consistency_constructed=False,
        ),
        VerifierPairingShape(
            name="Groth16 normalized PPE",
            dynamic_g1_terms=2,
            dynamic_g2_terms=1,
            fixed_g2_anchor_rank=3,
            normalized_target_is_identity=False,
            statement_session_fixed_at_activation=True,
            statement_basis_separated_from_scaled_witness_anchors=True,
            static_witness_lift_constructed=False,
            transcript_coefficients_bound=True,
            fiat_shamir_or_challenge_consistency_bound=True,
            knowledge_sound_backend_constructed=True,
            verifier_specific_material_small=True,
            activation_ciphertext_consistency_constructed=False,
        ),
        VerifierPairingShape(
            name="one-sided monomial/KZG wrapper final equation",
            dynamic_g1_terms=2,
            dynamic_g2_terms=0,
            fixed_g2_anchor_rank=2,
            normalized_target_is_identity=True,
            statement_session_fixed_at_activation=False,
            statement_basis_separated_from_scaled_witness_anchors=True,
            static_witness_lift_constructed=False,
            transcript_coefficients_bound=True,
            fiat_shamir_or_challenge_consistency_bound=True,
            knowledge_sound_backend_constructed=False,
            verifier_specific_material_small=True,
            activation_ciphertext_consistency_constructed=False,
        ),
        VerifierPairingShape(
            name="target-separated low-rank fixed-G2 direct-lock target",
            dynamic_g1_terms=11,
            dynamic_g2_terms=0,
            fixed_g2_anchor_rank=2,
            normalized_target_is_identity=False,
            statement_session_fixed_at_activation=True,
            statement_basis_separated_from_scaled_witness_anchors=True,
            static_witness_lift_constructed=False,
            transcript_coefficients_bound=True,
            fiat_shamir_or_challenge_consistency_bound=True,
            knowledge_sound_backend_constructed=False,
            verifier_specific_material_small=True,
            activation_ciphertext_consistency_constructed=False,
        ),
    )
    return {
        "schema": "ranklock-verifier-shape-frontier-v2",
        "evidence_class": (
            "EXACT interface classification; external proof-system and LVA-WE instantiation open"
        ),
        "shapes": [shape.document() for shape in shapes],
        "v018_correction": (
            "The one-sided wrapper now has an executed canonical G1 binding and official-BN256 "
            "Poseidon2 Fiat-Shamir transcript, so challenge consistency is no longer its blocker. "
            "Its remaining direct-lock failure is the lack of a static entropy-bearing session: "
            "the accepting residual is 1_GT and public affine target shifts leak through the "
            "published scaled anchor span."
        ),
        "required_new_object": (
            "Either (a) a direct low-rank statement-specific lock whose session is fixed and "
            "basis-separated at activation, or (b) a real fixed-relation LVA-WE witness lift for "
            "the one-sided RankVM-invalidity wrapper, including hidden challenge consistency and "
            "public ciphertext/share-consistency activation."
        ),
    }
