from __future__ import annotations

from dataclasses import replace

from ranklock.ppe_normal_form import FormalKzgSrs, build_terminal_ppe_proof


def test_terminal_rankfold_check_is_four_pairing_product_equations() -> None:
    srs = FormalKzgSrs(tau=19)
    point = 7
    # Choose C=A*B as polynomials only at the sampled point; the terminal PPE
    # cares about the opened values, while global row correctness belongs to the
    # outer trace/wiring argument.
    polynomial_a = (3, 2)
    polynomial_b = (5, 4)
    a = 3 + 2 * point
    b = 5 + 4 * point
    polynomial_c = (a * b,)
    proof = build_terminal_ppe_proof(
        polynomial_a=polynomial_a,
        polynomial_b=polynomial_b,
        polynomial_c=polynomial_c,
        point=point,
        srs=srs,
    )
    equality_weight = 13
    current_claim = equality_weight * (proof.a * proof.b - proof.c) % srs.modulus
    equations = proof.equations(
        current_claim=current_claim,
        equality_weight=equality_weight,
        srs=srs,
    )
    assert len(equations) == 4
    assert all(equation.verify() for equation in equations)
    assert proof.verify(
        current_claim=current_claim,
        equality_weight=equality_weight,
        srs=srs,
    )


def test_tampered_opening_or_terminal_value_breaks_ppe_system() -> None:
    srs = FormalKzgSrs(tau=23)
    proof = build_terminal_ppe_proof(
        polynomial_a=(1, 2, 3),
        polynomial_b=(4, 5),
        polynomial_c=(7,),
        point=11,
        srs=srs,
    )
    equality_weight = 17
    current_claim = equality_weight * (proof.a * proof.b - proof.c) % srs.modulus
    assert proof.verify(
        current_claim=current_claim,
        equality_weight=equality_weight,
        srs=srs,
    )

    assert not replace(proof, a=proof.a + 1).verify(
        current_claim=current_claim,
        equality_weight=equality_weight,
        srs=srs,
    )
    assert not replace(
        proof,
        opening_b=proof.opening_b + srs.g2,
    ).verify(
        current_claim=current_claim,
        equality_weight=equality_weight,
        srs=srs,
    )
