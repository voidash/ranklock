from __future__ import annotations

"""Audit the hidden-verifier-challenge route for the one-sided wrapper.

A tempting way to avoid verifying Fiat--Shamir inside the static RankLock
relation is to sample the verifier challenges at activation and hide them in the
witness-encryption key.  This only works when every prover response can be
formed from projective encodings by operations that remain linear in those
hidden challenges.

The monomial-basis SNARK profiled in :mod:`one_sided_wrapper_frontier` does not
have that property.  Its early challenges enter a grand-product recurrence,
polynomial shifts, challenge powers, inversions and quotient polynomials.  This
module records the protocol-stage audit and deliberately distinguishes:

* the killed shortcut "hide the published Fiat--Shamir scalars and otherwise run
  the prover unchanged"; and
* the still-open, much stronger possibility of compiling the underlying
  relation to a purpose-built linear interactive proof (LIP/LVA).

This is a protocol-shape audit, not a lower bound against all hidden-challenge
proof systems.
"""

from dataclasses import dataclass


class HiddenChallengeAuditError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ChallengeStage:
    transcript_stage: int
    challenges: tuple[str, ...]
    committed_before: tuple[str, ...]
    prover_outputs_after: tuple[str, ...]
    challenge_uses: tuple[str, ...]
    hidden_response_shape: str
    naive_projective_hidden_challenge_possible: bool
    reason: str
    schema: str = "ranklock-hidden-challenge-stage-v1"

    def __post_init__(self) -> None:
        if self.transcript_stage < 0:
            raise HiddenChallengeAuditError("negative transcript stage")
        if not self.challenges:
            raise HiddenChallengeAuditError("challenge stage has no challenge")
        if not self.reason:
            raise HiddenChallengeAuditError("challenge stage has no decision reason")

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "transcript_stage": self.transcript_stage,
            "challenges": list(self.challenges),
            "committed_before": list(self.committed_before),
            "prover_outputs_after": list(self.prover_outputs_after),
            "challenge_uses": list(self.challenge_uses),
            "hidden_response_shape": self.hidden_response_shape,
            "naive_projective_hidden_challenge_possible": (
                self.naive_projective_hidden_challenge_possible
            ),
            "reason": self.reason,
        }


def monomial_snark_challenge_stages() -> tuple[ChallengeStage, ...]:
    """Return the eight challenge-generating transcript calls (ten scalars)."""

    return (
        ChallengeStage(
            0,
            ("delta_1", "delta_2"),
            ("A_L", "A_R", "A_O", "A_LR"),
            ("A_F_reverse_shift",),
            (
                "grand-product numerator/denominator at every wire row",
                "permutation polynomial F and its shifted reverse",
            ),
            "rational recurrence with products across all rows",
            False,
            (
                "The response contains products of affine functions of both hidden "
                "challenges over the full trace. It is not a linear combination of a "
                "fixed set of challenge-independent prover messages."
            ),
        ),
        ChallengeStage(
            1,
            ("gamma",),
            ("A_F_reverse_shift",),
            ("gamma_LR",),
            (
                "evaluation L⊙R(gamma)",
                "multiplicative shifts L(gamma X), R(gamma X), O(gamma X)",
                "gamma powers and gamma inverse in later identities",
            ),
            "hidden evaluation point and multiplicative polynomial shift",
            False,
            (
                "Evaluating and shifting witness polynomials at an unknown point requires "
                "challenge powers and nonlinear interaction with private coefficients."
            ),
        ),
        ChallengeStage(
            2,
            ("lambda",),
            ("gamma_LR",),
            ("A_gamma_lambda_minus", "A_gamma_lambda_plus"),
            (
                "powers lambda through lambda^4 aggregate distinct constraints",
                "lambda is embedded in low/high-degree polynomial commitments",
            ),
            "polynomial in a hidden challenge multiplied by witness polynomials",
            False,
            (
                "Even though the aggregation degree is small, the prover must commit to "
                "challenge-dependent polynomial products, not only reveal a linear scalar response."
            ),
        ),
        ChallengeStage(
            3,
            ("lambda_b",),
            ("A_gamma_lambda_minus", "A_gamma_lambda_plus"),
            ("A_lambda_b",),
            (
                "lambda_b, lambda_b^2 and lambda_b^3 combine reversed polynomials",
            ),
            "small-degree hidden polynomial combination",
            False,
            (
                "A dedicated encoded-polynomial interface might handle this stage, but the "
                "ordinary prover needs a source-group commitment to a hidden linear combination. "
                "Publishing enough reusable encodings recreates the correlation problem."
            ),
        ),
        ChallengeStage(
            4,
            ("alpha",),
            ("A_lambda_b",),
            (
                "12 field evaluations including beta_L,beta_R,beta_O,beta_LR",
                "beta_gamma_lambda_minus,beta_gamma_lambda_plus,beta_id,beta_sigma",
                "beta_F,beta_pub,nu_gamma_F,nu_gamma_R",
            ),
            (
                "evaluation at alpha and alpha^-1",
                "alpha^n, alpha^(2n), alpha^N and inverse powers",
            ),
            "many hidden-point evaluations plus inversions",
            False,
            (
                "The response requires opening several private polynomials at alpha and "
                "related hidden points. This is a polynomial-commitment/LIP task, not a "
                "projective encoding of a few raw challenge scalars."
            ),
        ),
        ChallengeStage(
            5,
            ("xi", "lambda_e"),
            ("12 field evaluations",),
            ("B_lambda_e",),
            (
                "xi powers through xi^9 aggregate committed polynomials",
                "lambda_e powers batch seven divisibility relations",
                "inverses of seven challenge-dependent linear polynomials",
            ),
            "two domain-separated hidden challenges in aggregation and division",
            False,
            (
                "The prover constructs h_lambda_e using challenge powers and inverses of "
                "linear polynomials whose coefficients already contain earlier hidden challenges."
            ),
        ),
        ChallengeStage(
            6,
            ("alpha_e",),
            ("B_lambda_e",),
            ("beta_1", "beta_2", "beta_3", "beta_4", "beta_5", "beta_6", "beta_7"),
            (
                "seven evaluations h_i(alpha_e)",
                "evaluation of challenge-dependent divisibility polynomials",
            ),
            "hidden-point evaluation of seven derived polynomials",
            False,
            (
                "As at alpha, the response is an opening problem at a hidden point and "
                "cannot be produced by simply multiplying public prover messages by encoded alpha_e."
            ),
        ),
        ChallengeStage(
            7,
            ("xi_e",),
            ("beta_1", "beta_2", "beta_3", "beta_4", "beta_5", "beta_6", "beta_7"),
            ("Q_e",),
            (
                "xi_e powers batch seven quotient identities",
                "Q_e commits to a challenge-dependent quotient polynomial",
            ),
            "hidden quotient-polynomial commitment",
            False,
            (
                "The final message is still a commitment to a quotient formed after the "
                "challenge; it is not a scalar-linear response over precommitted messages."
            ),
        ),
    )


def hidden_challenge_audit() -> dict[str, object]:
    stages = monomial_snark_challenge_stages()
    challenge_count = sum(len(stage.challenges) for stage in stages)
    killed = all(not stage.naive_projective_hidden_challenge_possible for stage in stages)
    return {
        "schema": "ranklock-hidden-challenge-audit-v1",
        "evidence_class": "PROTOCOL-SHAPE AUDIT from the published prover schedule",
        "challenge_generating_hash_calls": len(stages),
        "challenge_scalars": challenge_count,
        "final_transcript_message_without_new_challenge": "Q_e",
        "stages": [stage.document() for stage in stages],
        "naive_hide_raw_fiat_shamir_challenges_killed": killed,
        "scoped_kill_statement": (
            "The published Fiat-Shamir prover cannot be made static merely by hiding its "
            "ten challenge scalars in projective encodings."
        ),
        "not_ruled_out": [
            "a purpose-built linear interactive proof whose prover response is linear in a hidden verifier query",
            "generic MPC/garbling of the prover itself",
            "a public Fiat-Shamir proof with hash consistency verified inside the static relation",
            "a redesigned one- or two-beacon proof system",
        ],
        "surviving_route": (
            "Treat the complete public Fiat-Shamir proof as the future witness and verify a "
            "circuit-friendly transcript plus scalar equations inside a small fixed relation."
        ),
    }
