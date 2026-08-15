from __future__ import annotations

"""Executable nonlinear inventory for the monomial-basis SNARK verifier.

v0.17 reserved 1,024 scalar constraints without compiling the verifier.  This
module follows Protocol 3.1, verifier Steps 23--29 of ePrint 2023/1255 and
counts the variable-variable field products needed to derive every scalar
coefficient used by the final G1 aggregation and pairing equation.

Additions and multiplication by public constants are linear.  A witnessed
inverse costs one multiplication constraint ``x * x_inv = 1``.  Public integer
powers use a left-to-right square-and-multiply addition chain and share
intermediate powers where the paper's equations allow it.

The G1 MSMs are not counted here: they are public linear combinations feeding
the fixed-rank pairing gadget.  Hash permutations, canonical point binding and
fixed wrapper overhead are accounted for in their own ledgers.
"""

from dataclasses import dataclass, field
from typing import Iterable

from .bn254_real import CURVE_ORDER
from .bn254_direct_wrapper import (
    Bn254UncompressedPointBindingCost,
    CanonicalOneSidedProof,
    CanonicalUncompressedG1,
)
from .bn254_real import G1, multiply
from .fixed_statement_wrapper_candidate import PerDepositCandidateCost
from .transcript_mini_lock import (
    Poseidon2ConstraintProfile,
    TranscriptConstraintScenario,
    TranscriptInventory,
)
from .poseidon2_bn254_transcript import (
    OFFICIAL_KAT_INPUT,
    OFFICIAL_KAT_OUTPUT,
    PERMUTATION_CONSTRAINTS,
    execute_one_sided_transcript,
    poseidon2_permutation,
)


class ScalarVerifierError(ValueError):
    pass


@dataclass(slots=True)
class ScalarConstraintCounter:
    multiplications: int = 0
    inversions: int = 0
    labels: dict[str, int] = field(default_factory=dict)

    def bump(self, label: str, amount: int = 1) -> None:
        if amount < 0:
            raise ScalarVerifierError("negative constraint increment")
        self.multiplications += amount
        self.labels[label] = self.labels.get(label, 0) + amount

    def bump_inverse(self, label: str) -> None:
        self.inversions += 1
        self.bump(label, 1)


@dataclass(frozen=True, slots=True)
class TrackedScalar:
    value: int
    counter: ScalarConstraintCounter

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", int(self.value) % CURVE_ORDER)

    @classmethod
    def constant(cls, value: int, counter: ScalarConstraintCounter) -> "TrackedScalar":
        return cls(value, counter)

    def __add__(self, other: int | "TrackedScalar") -> "TrackedScalar":
        return TrackedScalar(self.value + _value(other), self.counter)

    __radd__ = __add__

    def __sub__(self, other: int | "TrackedScalar") -> "TrackedScalar":
        return TrackedScalar(self.value - _value(other), self.counter)

    def __rsub__(self, other: int | "TrackedScalar") -> "TrackedScalar":
        return TrackedScalar(_value(other) - self.value, self.counter)

    def __neg__(self) -> "TrackedScalar":
        return TrackedScalar(-self.value, self.counter)

    def mul(self, other: "TrackedScalar", label: str) -> "TrackedScalar":
        if self.counter is not other.counter:
            raise ScalarVerifierError("tracked scalars use different counters")
        self.counter.bump(label)
        return TrackedScalar(self.value * other.value, self.counter)

    def mul_public(self, constant: int) -> "TrackedScalar":
        return TrackedScalar(self.value * int(constant), self.counter)

    def inv(self, label: str) -> "TrackedScalar":
        if self.value == 0:
            raise ScalarVerifierError(f"zero denominator for {label}")
        self.counter.bump_inverse(label)
        return TrackedScalar(pow(self.value, -1, CURVE_ORDER), self.counter)

    def pow_public(self, exponent: int, label: str) -> "TrackedScalar":
        exponent = int(exponent)
        if exponent < 0:
            return self.inv(f"{label}/negative-inverse").pow_public(-exponent, label)
        if exponent == 0:
            return TrackedScalar(1, self.counter)
        bits = bin(exponent)[2:]
        result = self
        for index, bit in enumerate(bits[1:], start=1):
            result = result.mul(result, f"{label}/square")
            if bit == "1":
                result = result.mul(self, f"{label}/multiply")
        return result


def _value(value: int | TrackedScalar) -> int:
    return value.value if isinstance(value, TrackedScalar) else int(value)


def _sum(values: Iterable[TrackedScalar], counter: ScalarConstraintCounter) -> TrackedScalar:
    result = TrackedScalar(0, counter)
    for value in values:
        result = result + value
    return result


@dataclass(frozen=True, slots=True)
class OneSidedVerifierInputs:
    circuit_size_n: int
    challenges: tuple[int, ...]
    proof_scalars: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.circuit_size_n <= 0:
            raise ScalarVerifierError("circuit size must be positive")
        if len(self.challenges) != 10:
            raise ScalarVerifierError("expected ten Fiat--Shamir challenges")
        if len(self.proof_scalars) != 20:
            raise ScalarVerifierError("expected twenty proof scalars")
        if any(not 0 < int(value) < CURVE_ORDER for value in self.challenges):
            raise ScalarVerifierError("challenge must be a nonzero canonical Fr element")
        if any(not 0 <= int(value) < CURVE_ORDER for value in self.proof_scalars):
            raise ScalarVerifierError("proof scalar is non-canonical")

    @classmethod
    def deterministic(cls, circuit_size_n: int) -> "OneSidedVerifierInputs":
        # Distinct small nonzero values keep every denominator in the reference
        # schedule nonzero.  They are not a proof fixture.
        challenges = (5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
        proof_scalars = tuple(range(41, 61))
        return cls(int(circuit_size_n), challenges, proof_scalars)


@dataclass(frozen=True, slots=True)
class ScalarVerifierExecution:
    circuit_size_n: int
    circuit_size_N: int
    nonlinear_constraints: int
    inversion_constraints: int
    labels: dict[str, int]
    outputs: dict[str, int]
    schema: str = "ranklock-one-sided-scalar-verifier-execution-v1"

    def document(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_class": (
                "EXECUTABLE scalar-operation schedule for Protocol 3.1 verifier Steps 23--29; "
                "not a complete SNARK implementation"
            ),
            "circuit_size_n": self.circuit_size_n,
            "circuit_size_N": self.circuit_size_N,
            "nonlinear_constraints": self.nonlinear_constraints,
            "inversion_constraints_included": self.inversion_constraints,
            "constraint_labels": dict(sorted(self.labels.items())),
            "derived_output_digest_material": self.outputs,
            "excluded": [
                "Fiat--Shamir hash permutations",
                "G1 canonical binding",
                "public G1 MSM work",
                "final pairings",
                "LVA-WE gadget-key serialization",
            ],
        }


def execute_scalar_verifier(inputs: OneSidedVerifierInputs) -> ScalarVerifierExecution:
    counter = ScalarConstraintCounter()
    t = lambda value: TrackedScalar(value, counter)

    (
        delta1,
        delta2,
        gamma,
        lam,
        lam_b,
        alpha,
        xi,
        lam_e,
        alpha_e,
        xi_e,
    ) = tuple(t(value) for value in inputs.challenges)
    (
        gamma_lr,
        beta_l,
        beta_r,
        beta_o,
        beta_lr,
        beta_minus,
        beta_plus,
        beta_id,
        beta_sigma,
        beta_fb,
        nu_gamma_fb,
        nu_gamma_rb,
        beta_pub,
        *beta_openings,
    ) = tuple(t(value) for value in inputs.proof_scalars)
    if len(beta_openings) != 7:
        raise AssertionError("proof-scalar unpacking drifted")

    n = inputs.circuit_size_n
    N = 3 * n

    # Shared powers and ratios used throughout Steps 23--28.
    alpha_n = alpha.pow_public(n, "alpha^n")
    alpha_2n = alpha_n.mul(alpha_n, "alpha^(2n)")
    alpha_N = alpha_n.mul(alpha_2n, "alpha^N")
    alpha_inv = alpha.inv("alpha inverse")
    gamma_inv = gamma.inv("gamma inverse")
    ratio_alpha_gamma = alpha.mul(gamma_inv, "alpha/gamma")
    ratio_N = ratio_alpha_gamma.pow_public(N, "(alpha/gamma)^N")
    ratio_N_plus_1 = ratio_N.mul(ratio_alpha_gamma, "(alpha/gamma)^(N+1)")
    inverse_ratio_N = ratio_N.inv("(gamma/alpha)^N")
    ratio_gamma_alpha = gamma.mul(alpha_inv, "gamma/alpha")

    alpha_n_inv = alpha_n.inv("alpha^-n")
    alpha_1_minus_n = alpha.mul(alpha_n_inv, "alpha^(1-n)")
    alpha_N_inv = alpha_N.inv("alpha^-N")
    alpha_1_minus_N = alpha.mul(alpha_N_inv, "alpha^(1-N)")
    alpha_minus_one_inv = (alpha - 1).inv("(alpha-1)^-1")
    geometric = (alpha_N - 1).mul(alpha_minus_one_inv, "geometric sum")

    lam2 = lam.mul(lam, "lambda powers")
    lam3 = lam2.mul(lam, "lambda powers")
    lam4 = lam2.mul(lam2, "lambda powers")
    lam_b2 = lam_b.mul(lam_b, "lambda_b powers")
    lam_b3 = lam_b2.mul(lam_b, "lambda_b powers")

    xi_powers = [xi]
    for _ in range(2, 10):
        xi_powers.append(xi_powers[-1].mul(xi, "xi powers"))
    lam_e_powers = [t(1), lam_e]
    for _ in range(2, 7):
        lam_e_powers.append(lam_e_powers[-1].mul(lam_e, "lambda_e powers"))
    xi_e_powers = [t(1), xi_e]
    for _ in range(2, 8):
        xi_e_powers.append(xi_e_powers[-1].mul(xi_e, "xi_e powers"))

    # Step 23.
    beta_wires = (
        beta_l
        + alpha_n.mul(beta_r, "beta_wires")
        + alpha_2n.mul(beta_o, "beta_wires")
    )

    # Scalar exponents used to build A_{lambda,alpha} in Step 23.
    exp_lr = beta_l.mul(nu_gamma_rb, "A_lambda_alpha")
    exp_add = lam.mul(beta_l + beta_r - beta_o, "A_lambda_alpha")
    exp_mul = lam2.mul(beta_lr - beta_o, "A_lambda_alpha")
    common_id = (
        beta_wires
        + delta1.mul(beta_id, "A_lambda_alpha")
        + delta2.mul(geometric, "A_lambda_alpha")
    )
    exp_perm_left = lam3.mul(
        nu_gamma_fb.mul(common_id, "A_lambda_alpha"), "A_lambda_alpha"
    )
    common_sigma = (
        beta_wires
        + delta1.mul(beta_sigma, "A_lambda_alpha")
        + delta2.mul(geometric, "A_lambda_alpha")
    )
    exp_perm_right = lam3.mul(common_sigma, "A_lambda_alpha")
    exp_public = lam4.mul(beta_l - beta_pub, "A_lambda_alpha")

    # Step 24.
    beta_xi_terms = (
        beta_l,
        xi_powers[0].mul(beta_r, "beta_xi"),
        xi_powers[1].mul(beta_o, "beta_xi"),
        xi_powers[2].mul(beta_minus, "beta_xi"),
        xi_powers[3].mul(beta_id, "beta_xi"),
        xi_powers[4].mul(beta_sigma, "beta_xi"),
        xi_powers[5].mul(beta_plus, "beta_xi"),
        xi_powers[6].mul(beta_pub, "beta_xi"),
        xi_powers[7].mul(beta_lr, "beta_xi"),
    )
    final_xi_bracket = alpha_inv.mul(beta_fb, "beta_xi") + alpha_N - 1
    beta_xi = _sum(beta_xi_terms, counter) + xi_powers[8].mul(
        final_xi_bracket, "beta_xi"
    )

    # Step 26, factored to minimize products.
    beta_lambda_b = alpha_1_minus_n.mul(
        beta_l
        + lam_b.mul(beta_r, "beta_lambda_b")
        + lam_b2.mul(beta_o, "beta_lambda_b"),
        "beta_lambda_b",
    ) + alpha_1_minus_N.mul(
        lam_b3.mul(beta_minus, "beta_lambda_b"), "beta_lambda_b"
    )

    # Step 27: linear divisor polynomials evaluated at alpha_e.
    e1 = alpha_e - gamma
    e2 = gamma.mul(alpha_e, "divisor evaluations") - alpha
    e3 = alpha_e - alpha
    e4 = alpha_e - alpha_inv
    e5 = alpha_e
    e7 = alpha.mul(alpha_e, "divisor evaluations") - gamma
    e_values = (e1, e2, e3, e4, e5, e2, e7)
    unique_inverse_by_value: dict[int, TrackedScalar] = {}
    e_inverses: list[TrackedScalar] = []
    for index, value in enumerate(e_values, start=1):
        if value.value not in unique_inverse_by_value:
            unique_inverse_by_value[value.value] = value.inv(f"e{index}(alpha_e)^-1")
        e_inverses.append(unique_inverse_by_value[value.value])

    # Remaining scalar exponents in a6 and a7.
    exp_a6 = ratio_gamma_alpha.mul(nu_gamma_fb, "a6/a7 exponents") + ratio_N - 1
    exp_a7 = inverse_ratio_N.mul(nu_gamma_rb, "a6/a7 exponents")

    # Step 28.
    beta_e_left: list[TrackedScalar] = []
    for index, (beta_i, e_inv) in enumerate(
        zip(beta_openings, e_inverses, strict=True)
    ):
        term = beta_i.mul(e_inv, "beta_e opening/divisor")
        if index:
            term = lam_e_powers[index].mul(term, "beta_e lambda weighting")
        beta_e_left.append(term)
    beta_e_right = [
        xi_e_powers[index + 1].mul(beta_i, "beta_e xi weighting")
        for index, beta_i in enumerate(beta_openings)
    ]
    beta_e = _sum((*beta_e_left, *beta_e_right), counter)
    alpha_e_inv = alpha_e.inv("alpha_e inverse")

    outputs = {
        "beta_wires": beta_wires.value,
        "beta_xi": beta_xi.value,
        "beta_lambda_b": beta_lambda_b.value,
        "beta_e": beta_e.value,
        "alpha_e_inverse": alpha_e_inv.value,
        "ratio_N_plus_1": ratio_N_plus_1.value,
        "exp_A_lr": exp_lr.value,
        "exp_A_add": exp_add.value,
        "exp_A_mul": exp_mul.value,
        "exp_A_perm_left": exp_perm_left.value,
        "exp_A_perm_right": exp_perm_right.value,
        "exp_A_public": exp_public.value,
        "exp_a6": exp_a6.value,
        "exp_a7": exp_a7.value,
    }
    return ScalarVerifierExecution(
        circuit_size_n=n,
        circuit_size_N=N,
        nonlinear_constraints=counter.multiplications,
        inversion_constraints=counter.inversions,
        labels=dict(counter.labels),
        outputs=outputs,
    )


def _deterministic_public_proof() -> CanonicalOneSidedProof:
    return CanonicalOneSidedProof(
        tuple(
            CanonicalUncompressedG1.from_point(
                multiply(G1, index + 1, group="g1")
            )
            for index in range(10)
        ),
        tuple(range(20)),
    )


def scalar_verifier_frontier(
    circuit_size_n: int = 2_537_122,
    *,
    context_field: int = 42,
) -> dict[str, object]:
    proof = _deterministic_public_proof()
    transcript_execution = execute_one_sided_transcript(
        proof,
        context_field=context_field,
    )
    execution = execute_scalar_verifier(
        OneSidedVerifierInputs(
            circuit_size_n,
            transcript_execution.challenges.as_tuple(),
            proof.scalars,
        )
    )
    point = Bn254UncompressedPointBindingCost()
    inventory = TranscriptInventory(
        proof_g1_elements=10,
        hashed_g1_elements=9,
        proof_scalar_elements=20,
        challenge_hash_calls=9,
        challenge_scalars=10,
        g1_encoding_field_elements=3,
    )
    scenario = TranscriptConstraintScenario(
        point.exact_logical_rows,
        scalar_verifier_constraints=execution.nonlinear_constraints,
        fixed_wrapper_constraints=512,
        profile=Poseidon2ConstraintProfile(),
        inventory=inventory,
        concrete_permutation_count=transcript_execution.counter.permutations,
    )
    envelope = PerDepositCandidateCost(scenario)
    return {
        "schema": "ranklock-one-sided-scalar-verifier-frontier-v2",
        "paper_protocol": "ePrint 2023/1255 Protocol 3.1, verifier Steps 23--29",
        "execution": execution.document(),
        "transcript": {
            "implementation": "official BN256 Poseidon2 permutation + fixed Protocol-3.1 duplex schedule",
            "official_KAT_passes": (
                poseidon2_permutation(OFFICIAL_KAT_INPUT) == OFFICIAL_KAT_OUTPUT
            ),
            "G1_field_elements_per_point": inventory.g1_encoding_field_elements,
            "hashed_G1_elements": inventory.effective_hashed_g1_elements,
            "final_Qe_hashed": False,
            "final_Qe_binding": "final rank-two pairing equation",
            "encoding": "three injective paired 85-bit x/y limbs",
            "absorbed_field_elements": transcript_execution.absorbed_field_elements,
            "challenge_phases": transcript_execution.challenge_phases,
            "challenge_scalars": len(transcript_execution.challenges.as_tuple()),
            "constraints_per_permutation": PERMUTATION_CONSTRAINTS,
            "hash_constraints": scenario.hash_constraints,
            "total_permutations": scenario.total_permutations,
            "permutation_labels": dict(sorted(transcript_execution.counter.labels.items())),
            "challenge_fixture": [
                hex(value) for value in transcript_execution.challenges.as_tuple()
            ],
        },
        "integrated_envelope": {
            "point_rows_per_G1": point.exact_logical_rows,
            "point_rows_total": scenario.point_binding_constraints,
            "poseidon2_rows": scenario.hash_constraints,
            "scalar_verifier_rows": execution.nonlinear_constraints,
            "fixed_wrapper_rows": scenario.fixed_wrapper_constraints,
            "wrapper_trace_width": scenario.wrapper_trace_width,
            "activation_plus_future_proof_bytes": (
                envelope.activation_plus_future_proof_bytes
            ),
            "margin_to_one_MiB_bytes": envelope.margin_to_one_mib,
            "fits_one_MiB": envelope.fits_one_mib,
        },
        "decision": {
            "old_1024_row_scalar_reserve_replaced": True,
            "old_38_permutation_hash_estimate_replaced": True,
            "measured_scalar_rows": execution.nonlinear_constraints,
            "executed_poseidon2_permutations": transcript_execution.counter.permutations,
            "executed_poseidon2_rows": transcript_execution.counter.multiplication_constraints,
            "scalar_gate_passes": execution.nonlinear_constraints < 1_024,
            "integrated_cost_envelope_passes": envelope.fits_one_mib,
            "breakthrough_target_met": False,
            "remaining_load_bearing_gap": (
                "The complete one-sided prover and verifier G1 aggregation must be "
                "instantiated, the final rank-two session must be compiled into the real "
                "conditional-disclosure backend, and Fiat--Shamir soundness of this exact "
                "typed transcript must be proved."
            ),
        },
    }
